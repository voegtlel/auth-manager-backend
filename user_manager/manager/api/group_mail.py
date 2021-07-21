from typing import List

from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import FileResponse

from user_manager.common.models import DbGroupMail
from user_manager.common.mongo import async_user_group_collection, async_group_mail_collection
from user_manager.manager.auth import Authentication
from user_manager.manager.models import GroupMailInList

router = APIRouter()


@router.get(
    '/groups/{group_id}/mails',
    tags=['User Manager'],
    response_model=List[GroupMailInList],
)
async def get_group_mails(
        group_id: str,
        user: UserInfo = Depends(Authentication()),
) -> List[GroupMailInList]:
    """Gets all mails in the group."""
    group = await async_user_group_collection.find_one(
        {
            '_id': group_id,
            'email_managed_mailing_list_notify_members': user.sub,
        },
        projection={'email_managed_mailing_list_notify_members': 1},
    )
    if group is None:
        raise HTTPException(404, "No access to group or group does not exist")
    return [
        GroupMailInList.validate(DbGroupMail.validate_document(group_mail))
        async for group_mail in async_group_mail_collection.find({'group_id': group_id})
    ]


@router.get(
    '/groups/{group_id}/mails/{mail_id}',
    tags=['User Manager'],
)
async def get_group_mail(
        group_id: str,
        mail_id: str,
        user: UserInfo = Depends(Authentication()),
):
    """Gets the contents of a mail."""
    group = await async_user_group_collection.find_one(
        {
            '_id': group_id,
            'email_managed_mailing_list_notify_members': user.sub,
        },
        projection={'email_managed_mailing_list_notify_members': 1},
    )
    if group is None:
        raise HTTPException(404, "No access to group or group does not exist")
    mail_entry = await async_group_mail_collection.find_one({'group_id': group_id, '_id': mail_id})
    if mail_entry is None:
        raise HTTPException(404, "Mail does not exist")
    mail = DbGroupMail.validate_document(mail_entry)
    return FileResponse(mail.mail_path)
