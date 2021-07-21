import os
import traceback
from datetime import timezone, datetime
from typing import Optional, List, Dict, Tuple

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from starlette.responses import FileResponse, Response

from user_manager.common.config import config
from user_manager.common.models import DbGroupMail
from user_manager.common.mongo import async_user_group_collection, async_user_collection, async_group_mail_collection
from user_manager.manager.auth import Authentication
from user_manager.oauth.api.ext_auth_base import AuthenticateClient

client_auth = AuthenticateClient('*ext_mail')

router = APIRouter()

#  1. if not is_mailing_list -> forward directly to dovecot
#  2. if is_mailing_list
#    2.1. save and serve via REST interface
#    2.2. send notification to sender, that the mail is queued (checkbox if want to receive original)
#    2.3. send original mail to mailing list approvers (checkbox if want to receive original)
#    2.3. send notification to mailing list approvers
#  3. approve mail
#    3.1. send mail to all receivers (except approvers)
#    3.2. delete stored mail
#  4. deny mail
#    4.1. delete stored mail


class EmailListMapping(BaseModel):
    email: str
    is_mailing_list: bool
    has_postbox: Optional[bool]
    notify_sender: Optional[bool]
    list_id: Optional[str]
    list_name: Optional[str]
    list_unsubscribe: Optional[str]
    send_original_to_notifiers: Optional[bool]
    notify_addresses: Optional[List[str]]


@router.get(
    '/mail/list/forward/{emails:path}',
    tags=['Extension: Mailing List'],
    response_model=List[EmailListMapping],
    dependencies=[Depends(client_auth)],
)
async def get_mailing_list_types(
    emails: str,
) -> List[EmailListMapping]:
    """Get targets of email addresses, wrt. mailing lists."""
    addresses = emails.split(',')
    addresses_mapping = {
        address: address.rsplit('@')[0]
        for address in addresses
    }
    prefixes = list(set(addresses_mapping.values()))
    mailing_list_groups = async_user_group_collection.find(
        {
            '_id': {'$in': prefixes},
            'enable_email': True,
            'email_managed_mailing_list': True,
        },
        projection={
            '_id': 1,
            'group_name': 1,
            'enable_postbox': 1,
            'email_managed_mailing_list_notify_members': 1,
            'email_managed_mailing_list_forward_to_notifiers': 1,
            'email_managed_mailing_list_send_notification_to_sender': 1,
        },
    )
    group_mapping = {
        group['_id']: group
        async for group in mailing_list_groups
    }
    all_user_emails = {
        user['_id']: (
            f"{user['preferred_username']}@{config.oauth2.mail_domain}"
            if user.get('has_email_alias', False) else
            user['email']
        )
        async for user in async_user_collection.find(
            {
                '_id': {'$in': list({
                    user
                    for group in group_mapping.values()
                    for user in group['email_managed_mailing_list_notify_members']
                })}
            },
            projection={
                'email': 1,
                'has_email_alias': 1,
                'preferred_username': 1,
            }
        )
    }
    group_map = []
    for address, prefix in addresses_mapping.items():
        group = group_mapping.get(prefix)
        if group is not None:
            notify_emails = [
                all_user_emails.get(user_id) for user_id in group['email_managed_mailing_list_notify_members']
            ]
            notify_emails = [email for email in notify_emails if email is not None]
            group_map.append(EmailListMapping(
                email=address,
                is_mailing_list=True,
                has_postbox=group['enable_postbox'],
                notify_sender=group.get('email_managed_mailing_list_send_notification_to_sender', False),
                send_original_to_notifiers=group.get('email_managed_mailing_list_forward_to_notifiers', False),
                notify_addresses=notify_emails,
                list_id=group['_id'] + "." + config.oauth2.mail_domain,
                list_name=group['group_name'],
                list_unsubscribe=f"{config.manager.frontend_base_url}/user",
            ))
        else:
            group_map.append(EmailListMapping(
                email=address,
                is_mailing_list=False,
            ))
    return group_map


class MailPart(BaseModel):

    class Config:

        @staticmethod
        def alias_generator(field_name: str) -> str:
            return "-".join(p.capitalize() for p in field_name.split('_') if p)

    content_type: str
    parts: Optional[List['MailPart']]

    content_disposition: Optional[str]
    content_length: Optional[int]
    filename: Optional[str]


MailPart.update_forward_refs()


class MailMetadata(BaseModel):

    class Config:

        @staticmethod
        def alias_generator(field_name: str) -> str:
            return "-".join(p.capitalize() for p in field_name.split('_') if p)

    envelope_to: str
    envelope_from: str
    return_path: Optional[str]
    date: Optional[str]
    from_: Optional[str]
    sender: Optional[str]
    reply_to: Optional[str]
    to: Optional[str]
    cc: Optional[str]
    bcc: Optional[str]
    subject: Optional[str]
    parts: Optional[MailPart]


class StoreMail(BaseModel):
    id: str
    path: str
    metadata: MailMetadata


@router.post(
    '/mail/list/save/{email:path}',
    tags=['Extension: Mailing List'],
    dependencies=[Depends(client_auth)],
)
async def save_mail(email: str, mail: StoreMail):
    """Saves an email for a mailing list."""
    mail_name = email.rsplit('@', 1)[0]
    group = await async_user_group_collection.find_one({'_id': mail_name}, projection={'_id': 1})
    if group is None:
        raise HTTPException(400, "Mailing list does not exist")
    await async_group_mail_collection.insert_one(DbGroupMail(
        id=mail.id,
        timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
        group_id=mail_name,
        metadata=mail.metadata.dict(by_alias=True, exclude_none=True),
        path=mail.path,
        approved=False,
    ).dict(by_alias=True, exclude_none=True))


async def _get_mailing_list_targets(group_id: str) -> Tuple[List[str], str]:
    """Get target addresses for the given mailing list."""
    mailing_list_group = await async_user_group_collection.find_one(
        {
            '_id': group_id,
            'enable_email': True,
            'email_managed_mailing_list': True,
        },
        projection={
            '_id': 1,
            'group_name': 1,
            'enable_postbox': 1,
            'email_forward_members': 1,
            'email_managed_mailing_list_notify_members': 1,
            'email_managed_mailing_list_forward_to_notifiers': 1,
        },
    )
    if mailing_list_group is None:
        raise HTTPException(404)

    target_users: List[str] = mailing_list_group.get('email_forward_members', [])
    if mailing_list_group.get('email_managed_mailing_list_forward_to_notifiers', False):
        for user in mailing_list_group.get('email_managed_mailing_list_notify_members', []):
            try:
                target_users.remove(user)
            except ValueError:
                pass

    user_emails = [
        f"{user['preferred_username']}@{config.oauth2.mail_domain}"
        if user.get('has_email_alias', False) else
        user['email']
        async for user in async_user_collection.find(
            {
                '_id': {'$in': target_users}
            },
            projection={
                '_id': 0,
                'email': 1,
                'has_email_alias': 1,
            }
        )
    ]
    return user_emails, mailing_list_group['group_name']


class MailDelivery(BaseModel):
    id: str
    path: str

    list_id: str
    list_name: str
    list_unsubscribe: str

    envelope_from: str
    envelope_to: str
    deliver_to: List[str]


@router.get(
    '/mail/list/delivery',
    tags=['Extension: Mailing List'],
    response_model=List[MailDelivery],
    dependencies=[Depends(client_auth)],
)
async def get_mailing_list_delivery() -> List[MailDelivery]:
    """Gets the mails which are ready for delivery."""
    deliveries: List[MailDelivery] = []
    groups_targets: Dict[str, Tuple[List[str], str]] = {}
    async for mail_data in async_group_mail_collection.find(
            {'approved': True},
            projection={'_id': 1, 'group_id': 1, 'path': 1, 'metadata.Envelope-From': 1, 'metadata.Envelope-To': 1},
    ):
        group_targets, group_name = groups_targets.get(mail_data['group_id'])
        if group_targets is None:
            group_targets, group_name = await _get_mailing_list_targets(mail_data['group_id'])
            groups_targets[mail_data['group_id']] = (group_targets, group_name)
        deliveries.append(
            MailDelivery(
                id=mail_data['_id'],
                path=mail_data['path'],
                list_id=mail_data['group_id'] + "." + config.oauth2.mail_domain,
                list_name=group_name,
                list_unsubscribe=f"{config.manager.frontend_base_url}/user",
                envelope_from=mail_data['metadata']['Envelope-From'],
                envelope_to=mail_data['metadata']['Envelope-To'],
                deliver_to=group_targets,
            )
        )
    return deliveries


@router.delete(
    '/mail/list/delivery/{mail_ids:path}',
    tags=['Extension: Mailing List'],
    dependencies=[Depends(client_auth)],
)
async def finalize_mailing_list_delivery(mail_ids: str):
    """Removes the given mails from delivery."""
    await _delete_mails(mail_ids, only_approved=True)


class MailingListEntry(BaseModel):
    id: str
    metadata: MailMetadata


@router.get(
    '/mail/list/{group_id}',
    tags=['Extension: Mailing List'],
    response_model=List[MailingListEntry],
)
async def get_mails(
        group_id: str,
        user: UserInfo = Depends(Authentication())
) -> List[MailingListEntry]:
    """Gets the mails as list."""
    is_admin = 'admin' in user['roles']
    group_data = await async_user_group_collection.find_one({'group_id': group_id})
    if group_data is None:
        raise HTTPException(404, "Group does not exist")
    if not group_data.get('email_managed_mailing_list', False):
        raise HTTPException(404, "Group is not a mailing list")
    if user['sub'] not in group_data.get('email_managed_mailing_list_notify_members', []) and not is_admin:
        raise HTTPException(403, "User not permitted to access mailing list")
    return [
        MailingListEntry(id=mail_data['_id'], metadata=mail_data['metadata'])
        async for mail_data in async_group_mail_collection.find(
            {'group_id': group_id, 'approved': False},
            sort=[('timestamp', -1)],
            projection={'_id': 1, 'metadata': 1},
        )
    ]


@router.get(
    '/mail/list/{group_id}/{mail_id}',
    tags=['Extension: Mailing List'],
    responses={
        200: {
            "content": {"message/rfc822": {}},
            "description": "The mail data",
        },
    },
)
async def get_mail(
        group_id: str,
        mail_id: str,
        user: UserInfo = Depends(Authentication())
):
    """Gets the mail data."""
    is_admin = 'admin' in user['roles']
    group_data = await async_user_group_collection.find_one({'group_id': group_id})
    if group_data is None:
        raise HTTPException(404, "Group does not exist")
    if not group_data.get('email_managed_mailing_list', False):
        raise HTTPException(404, "Group is not a mailing list")
    if user['sub'] not in group_data.get('email_managed_mailing_list_notify_members', []) and not is_admin:
        raise HTTPException(403, "User not permitted to access mailing list")
    mail_data = await async_group_mail_collection.find_one({'_id': mail_id})
    if mail_data is None:
        raise HTTPException(404, "Mail does not exist")
    return FileResponse(
        os.path.join(config.manager.mail_storage_path, mail_data['path']),
        media_type='message/rfc822',
        filename=f"{mail_id}.eml",
    )


@router.put(
    '/mail/list/{group_id}/approve/{mail_ids:path}',
    tags=['Extension: Mailing List'],
)
async def approve_mails(
        group_id: str,
        mail_ids: str,
        user: UserInfo = Depends(Authentication())
):
    """Approves mails for delivery."""
    is_admin = 'admin' in user['roles']
    group_data = await async_user_group_collection.find_one({'group_id': group_id})
    if group_data is None:
        raise HTTPException(404, "Group does not exist")
    if not group_data.get('email_managed_mailing_list', False):
        raise HTTPException(404, "Group is not a mailing list")
    if user['sub'] not in group_data.get('email_managed_mailing_list_notify_members', []) and not is_admin:
        raise HTTPException(403, "User not permitted to access mailing list")
    approved_result = await async_group_mail_collection.update_many({'_id': {'$in': mail_ids.split(',')}}, {'$set': {'approved': True}})
    if approved_result.matched_count == 0:
        raise HTTPException(404, "Mails not found")
    elif approved_result.matched_count < mail_ids.count(',') + 1:
        raise HTTPException(404, f"Only approved {approved_result.matched_count}/{mail_ids.count(',') + 1} mails")
    return Response()


async def _delete_mails(mail_ids: str, only_approved: bool = False):
    separate_ids = mail_ids.split(',')
    mongo_filter: dict = {'_id': {'$in': separate_ids}}
    if only_approved:
        mongo_filter['approved'] = True
    async for mail_data in async_group_mail_collection.find(mongo_filter, {'path': 1}):
        try:
            os.remove(os.path.join(config.manager.mail_storage_path, mail_data['path']))
        except OSError:
            traceback.print_exc()
    delete_result = await async_group_mail_collection.delete_many(mongo_filter)
    if delete_result.matched_count == 0:
        raise HTTPException(404, "Mails not found")
    elif delete_result.matched_count != len(separate_ids):
        raise HTTPException(404, f"Only approved {delete_result.matched_count}/{len(separate_ids)} mails")


@router.delete(
    '/mail/list/{group_id}/{mail_ids:path}',
    tags=['Extension: Mailing List'],
)
async def delete_mails(
        group_id: str,
        mail_ids: str,
        user: UserInfo = Depends(Authentication())
):
    """Deletes mails."""
    is_admin = 'admin' in user['roles']
    group_data = await async_user_group_collection.find_one({'group_id': group_id})
    if group_data is None:
        raise HTTPException(404, "Group does not exist")
    if not group_data.get('email_managed_mailing_list', False):
        raise HTTPException(404, "Group is not a mailing list")
    if user['sub'] not in group_data.get('email_managed_mailing_list_notify_members', []) and not is_admin:
        raise HTTPException(403, "User not permitted to access mailing list")
    await _delete_mails(mail_ids)
    return Response()
