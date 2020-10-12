from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from pydantic import BaseModel, Field

from user_manager.common.config import config
from user_manager.common.models import UserGroup
from user_manager.common.mongo import async_user_group_collection, async_user_collection

router = APIRouter()


class EmailUser(BaseModel):
    __mongo_attrs__ = {
        'email_forward_groups': 1,
        'email_postbox_access_groups': 1,
        'email_alias': 1,
        'has_postbox': 1,
        'postbox_quota': 1,
        'forward_emails': 1,
        'has_email_alias': 1,
        'email': 1,
        'email_verified': 1,
    }

    id: str = Field(..., alias='_id')
    email_forward_groups: List[str] = []
    email_postbox_access_groups: List[str] = []
    email_alias: str = ""
    has_postbox: bool = False
    postbox_quota: int = 0
    forward_emails: bool = False
    has_email_alias: bool = False
    email: str = ""
    email_verified: bool = False


class UserTokenAuthentication:
    async def __call__(
            self,
            authorization_code: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    ) -> EmailUser:
        if authorization_code is None or len(authorization_code.credentials) < 8:
            raise HTTPException(403, "Token invalid or missing")
        result = await async_user_collection.find_one(
            {'access_tokens.token': authorization_code.credentials},
            EmailUser.__mongo_attrs__,
        )
        if result is None:
            raise HTTPException(403, "Token invalid")
        return EmailUser.validate(result)


class MailTokenAuthentication:
    async def __call__(
            self,
            api_key: Optional[str] = Depends(APIKeyHeader(name="X-Api-Key", auto_error=False)),
    ):
        if api_key is None:
            raise HTTPException(403, "Api key missing")
        if api_key != config.oauth2.mail_api_key:
            raise HTTPException(403, "Api key invalid")


class SmtpReceiveResult(BaseModel):
    has_postbox: bool
    quota: int
    redirect_to: List[str] = []


@router.get(
    '/smtp-receive/{address:path}',
    tags=['Mailer Access'],
    dependencies=[Depends(MailTokenAuthentication())],
    response_model=SmtpReceiveResult,
)
async def smtp_receive(address: str) -> SmtpReceiveResult:
    """Gets the SMTP post-in redirects."""
    """
    * SMTP Receive: E-Mail --> Optional[Mailbox], List[Forward], quota
    """
    address = address.lower()
    if '@' not in address:
        raise HTTPException(400, f"Invalid target address: {address}")
    mail_name, domain = address.split('@', 1)
    if domain != config.oauth2.mail_domain:
        raise HTTPException(400, f"Invalid target address: {address}")
    alias_user_data = await async_user_collection.find_one({'email_alias': address}, EmailUser.__mongo_attrs__)
    if alias_user_data is not None:
        user = EmailUser.validate(alias_user_data)
        if user.has_email_alias and address == user.email_alias:
            return SmtpReceiveResult(
                has_postbox=user.has_postbox,
                quota=user.postbox_quota,
                redirect_to=[user.email] if user.forward_emails else []
            )
    email_group_data = await async_user_group_collection.find_one({'_id': mail_name})
    if email_group_data is None:
        raise HTTPException(404, f"Address {address} not existing")
    email_group = UserGroup.validate(email_group_data)
    email_redirects = []
    async for email_user in async_user_collection.find(
        {'_id': {'$in': email_group.email_forward_members}},
        {
            'email': 1,
            'email_alias': 1,
            'has_email_alias': 1,
            'forward_emails': 1,
        },
    ):
        if email_user.get('has_email_alias', False) and email_user.get('email_alias'):
            email_redirects.append(email_user['email_alias'])
        elif email_user.get('forward_emails', False) and email_user.get('email'):
            email_redirects.append(email_user['email'])
    return SmtpReceiveResult(
        has_postbox=email_group.enable_postbox,
        quota=email_group.postbox_quota,
        redirect_to=email_redirects,
    )


@router.get(
    '/smtp-send/{address:path}',
    tags=['Mailer Access'],
    dependencies=[Depends(MailTokenAuthentication())],
)
async def smtp_send(
        address: str,
        user: EmailUser = Depends(UserTokenAuthentication()),
) -> None:
    """Gets if the SMTP post-out is valid."""
    """
    * SMTP Send: E-Mail, User Token --> 200 Success (or 4xx for failure)
    """
    address = address.lower()
    if '@' not in address:
        raise HTTPException(400, f"Invalid target address: {address}")
    mail_name, domain = address.split('@', 1)
    if domain != config.oauth2.mail_domain:
        raise HTTPException(400, f"Invalid target address: {address}")
    if user.has_email_alias and address == user.email_alias:
        return
    if await async_user_group_collection.count_documents(
            {
                '_id': mail_name,
                'enable_email': True,
                '$or': [
                    {'email_allowed_forward_members': user.id},
                    {'email_postbox_access_members': user.id},
                ],
            }
    ) > 0:
        return
    raise HTTPException(401, f"Address {address} not found for user {user.id}")


class ImapLoginResult(BaseModel):
    quota: int


@router.get(
    '/imap-login/{address:path}',
    tags=['Mailer Access'],
    dependencies=[Depends(MailTokenAuthentication())],
    response_model=ImapLoginResult,
)
async def imap_login(
        address: str,
        user: EmailUser = Depends(UserTokenAuthentication()),
) -> ImapLoginResult:
    """Gets the IMAP login user data."""
    """
    * IMAP: E-Mail, User Token --> Mailbox, quota
    """
    address = address.lower()
    if '@' not in address:
        raise HTTPException(400, f"Invalid target address: {address}")
    mail_name, domain = address.split('@', 1)
    if domain != config.oauth2.mail_domain:
        raise HTTPException(400, f"Invalid target address: {address}")
    if user.has_postbox and address == user.email_alias:
        return ImapLoginResult(quota=user.postbox_quota)
    email_group_data = await async_user_group_collection.find_one({'_id': mail_name})
    if email_group_data is None:
        raise HTTPException(404, f"Address {address} not found for user {user.id}")
    email_group = UserGroup.validate(email_group_data)
    if not email_group.enable_postbox or not email_group.enable_email:
        raise HTTPException(404, f"Address {address} not found for user {user.id}")
    if user.id not in email_group.email_postbox_access_members:
        raise HTTPException(403, f"User {user.id} cannot access address {address}")
    return ImapLoginResult(quota=email_group.postbox_quota)
