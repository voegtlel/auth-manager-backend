from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from user_manager.common.config import config
from user_manager.common.models import DbGroupMail
from user_manager.common.mongo import async_user_group_collection, async_user_collection, async_group_mail_collection
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
                '_id': 0,
                'email': 1,
                'has_email_alias': 1,
                'forward_emails': 1,
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
            ))
        else:
            group_map.append(EmailListMapping(
                email=address,
                is_mailing_list=False,
            ))
    return group_map


@router.get(
    '/mail/list/send/{email:path}',
    tags=['Extension: Mailing List'],
    response_model=List[str],
    dependencies=[Depends(client_auth)],
)
async def get_mailing_list_targets(
    email: str,
) -> List[EmailListMapping]:
    """Get target addresses for the given mailing list."""
    prefix = email.rsplit('@')[0]
    mailing_list_group = await async_user_group_collection.find_one(
        {
            '_id': prefix,
            'enable_email': True,
            'email_managed_mailing_list': True,
        },
        projection={
            '_id': 1,
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
                'forward_emails': 1,
            }
        )
    ]
    return user_emails


class StoreMail(BaseModel):
    id: str
    path: str
    from_address: str


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
        group_id=mail_name,
        from_address=mail.from_address,
        mail_path=mail.path,
    ))
