from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Body, Response, Path
from pydantic import BaseModel

from user_manager.common.config import config
from user_manager.common.mongo import async_user_group_collection, async_user_collection
from user_manager.common.throttle import async_throttle_delay, async_throttle_failure
from user_manager.oauth.api.ext_auth_base import AuthenticateClient

client_auth = AuthenticateClient('*ext_mail')

router = APIRouter()


def extract_email_user(email: str = Path(...)):
    if '@' not in email:
        raise HTTPException(400, "Missing '@' in address")
    mail_name, domain = email.split('@', 1)
    if domain != config.oauth2.mail_domain:
        raise HTTPException(400, "Invalid domain")
    return mail_name.lower()


@router.get(
    '/mail/email-exists/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Depends(client_auth)],
)
async def get_exists_email(
    email_user: str = Depends(extract_email_user),
):
    """Inspect from a client if an email is registered."""
    if await async_user_group_collection.count_documents(
        {
            '_id': email_user,
            'enable_email': True,
        }
    ) > 0:
        return Response(status_code=200)

    if await async_user_collection.count_documents(
        {
            'preferred_username': email_user,
            'has_email_alias': True,
        }
    ) > 0:
        return Response(status_code=200)
    raise HTTPException(404, detail="E-Mail address not found")


@router.get(
    '/mail/quota/{email:path}',
    tags=['Extension: Mail'],
    response_model=int,
    dependencies=[Depends(client_auth)],
)
async def get_quota(
    email_user: str = Depends(extract_email_user),
) -> int:
    """Inspect from a client if an email is registered."""
    user_group = await async_user_group_collection.find_one(
        {
            '_id': email_user,
            'enable_email': True,
            'enable_postbox': True,
        },
        projection={'postbox_quota': 1, '_id': 0}
    )
    if user_group is not None:
        return user_group.get('postbox_quota', 0)

    user = await async_user_collection.find_one(
        {
            'preferred_username': email_user,
            'has_email_alias': True,
            'enable_postbox': True,
        },
        projection={'postbox_quota': 1, '_id': 0}
    )
    if user is not None:
        return user.get('postbox_quota', 0)

    raise HTTPException(404, detail="E-Mail address is not a postbox")


@router.get(
    '/mail/postbox-exists/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Depends(client_auth)],
)
async def get_exists_postbox(
    email: str,
    email_user: str = Depends(extract_email_user),
):
    """Inspect from a client if an email is registered."""
    if await async_user_group_collection.count_documents(
        {
            '_id': email_user,
            'enable_email': True,
            'enable_postbox': True,
        }
    ) > 0:
        return Response(status_code=200)

    if await async_user_collection.count_documents(
        {
            'preferred_username': email_user,
            'has_email_alias': True,
            'enable_postbox': True,
        }
    ) > 0:
        return Response(status_code=200)
    raise HTTPException(404, detail="E-Mail address is not a postbox")


@router.get(
    '/mail/redirects/{email:path}',
    tags=['Extension: Mail'],
    response_model=List[str],
    dependencies=[Depends(client_auth)],
)
async def get_redirects(
    email: str,
    email_user: str = Depends(extract_email_user),
) -> List[str]:
    """Gets the redirects for the passed email address. Includes both, postboxes and redirects."""

    group_forwards = await async_user_group_collection.find_one(
        {
            '_id': email_user,
            'enable_email': True,
        },
        projection={
            'email_forward_members': 1,
            'enable_postbox': 1,
        },
    )
    if group_forwards is not None:
        uids = group_forwards.get('email_forward_members', [])
        members = []
        if uids:
            async for user in async_user_collection.find({'_id': {'$in': uids}}, projection={
                'has_email_alias': 1, 'forward_emails': 1, 'email': 1, '_id': 0,
            }):
                if user.get('has_email_alias', False):
                    # Will also forward it in case forwarding is also enabled
                    members.append(f"{user['preferred_username']}@{config.oauth2.mail_domain}")
                elif user.get('forward_emails', False) and 'email' in user:
                    members.append(user['email'])
        if group_forwards['enable_postbox']:
            members.append(f'{email_user}@{config.oauth2.mail_domain}')
        return members

    user_forwarding = await async_user_collection.find_one(
        {
            'preferred_username': email.lower(),
            'has_email_alias': True,
        },
        projection={'forward_emails': 1, 'email': 1, 'has_postbox': 1, '_id': 0}
    )
    if user_forwarding is not None:
        members = []
        if user_forwarding.get('forward_emails', False) and 'email' in user_forwarding:
            members.append(user_forwarding['email'])
        if user_forwarding.get('has_postbox', False):
            members.append(email)
        return members
    raise HTTPException(404, detail="E-Mail address does not exist")


class Credentials(BaseModel):
    username: Optional[str]
    password: str
    client_ip: str


@router.post(
    '/mail/postbox/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Depends(client_auth)],
)
async def check_postbox_access(
    credentials: Credentials = Body(...),
    email_user: str = Depends(extract_email_user),
):
    """Verifies the login for the given credentials."""

    retry_delay, retry_after = await async_throttle_delay(credentials.client_ip)
    if retry_delay is not None and retry_after is not None:
        raise HTTPException(
            403, "Wait", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )

    search = {
        'access_tokens.token': credentials.password
    }
    if credentials.username is not None:
        search['username'] = credentials.username
    user = await async_user_collection.find_one(
        search, projection={'_id': 1, 'preferred_username': 1, 'has_email_alias': 1, 'has_postbox': 1}
    )

    if user is None:
        retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
        raise HTTPException(
            403, detail="User not authorized", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )
    if user.get('has_postbox', False) and user.get('has_email_alias', False) and \
            user.get('preferred_username') == email_user:
        # User is accessing it's own postbox
        return Response(status_code=200)

    # Check if user is accessing group postbox
    if await async_user_group_collection.count_documents(
        {
            '_id': email_user,
            'enable_email': True,
            'enable_postbox': True,
            'email_postbox_access_members': user['_id'],
        }
    ) > 0:
        # Yes, user is in the group and authenticated
        return Response(status_code=200)

    retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
    raise HTTPException(
        403,
        detail="User cannot access postbox (user not permitted or postbox does not exist)",
        headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
    )


@router.post(
    '/mail/send/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Depends(client_auth)],
)
async def check_send_access(
        credentials: Credentials = Body(...),
        email_user: str = Depends(extract_email_user),
):
    """Verifies the login for the given credentials."""
    retry_delay, retry_after = await async_throttle_delay(credentials.client_ip)
    if retry_delay is not None and retry_after is not None:
        raise HTTPException(
            403, "Wait", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )

    search = {
        'access_tokens.token': credentials.password
    }
    if credentials.username is not None:
        search['username'] = credentials.username
    user = await async_user_collection.find_one(
        search, projection={'_id': 1, 'preferred_username': 1, 'has_email_alias': 1}
    )
    if user is None:
        retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
        raise HTTPException(
            403, detail="User not authorized", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )
    if user.get('has_email_alias', False) and user.get('preferred_username') == email_user:
        # User is sending from it's own alias
        return Response(status_code=200)

    # Check if user wants to send from group email
    if await async_user_group_collection.count_documents(
        {
            '_id': email_user,
            'enable_email': True,
            '$or': [
                {'email_allowed_forward_members': user['_id']},
                {'email_postbox_access_members': user['_id']},
            ],
        }
    ) > 0:
        # Yes, user is in the group and authenticated
        return Response(status_code=200)

    retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
    raise HTTPException(
        403,
        detail="User cannot send from email (user not permitted or email does not exist)",
        headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
    )
