from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Security, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.base import SecurityBase
from pydantic import BaseModel
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

from user_manager.common.config import config
from user_manager.common.mongo import async_client_collection, async_user_group_collection, async_user_collection
from user_manager.common.throttle import async_throttle_delay, async_throttle_failure

router = APIRouter()


class ClientIdSecretQuery(SecurityBase):
    def __init__(
        self, *, scheme_name: Optional[str] = None, auto_error: bool = True
    ):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[HTTPBasicCredentials]:
        client_id: Optional[str] = request.query_params.get('client_id')
        client_secret: Optional[str] = request.query_params.get('client_secret')
        if not client_id or not client_secret:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return HTTPBasicCredentials(username=client_id, password=client_secret)


class ClientIdSecretPost(SecurityBase):
    def __init__(
        self, *, scheme_name: Optional[str] = None, auto_error: bool = True
    ):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[HTTPBasicCredentials]:
        try:
            request_json = await request.json()
            client_id: Optional[str] = request_json.get('client_id')
            client_secret: Optional[str] = request_json.get('client_secret')
        except ValueError:
            client_id = None
            client_secret = None
        if not client_id or not client_secret:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return HTTPBasicCredentials(username=client_id, password=client_secret)


basic_security = HTTPBasic(auto_error=False)
post_security = ClientIdSecretQuery(auto_error=False)


class AuthenticateClient(SecurityBase):

    async def __call__(
            self,
            basic_credentials: Optional[HTTPBasicCredentials] = Depends(HTTPBasic(auto_error=False)),
            post_credentials: Optional[HTTPBasicCredentials] = Security(ClientIdSecretQuery(auto_error=False)),
    ) -> dict:
        credentials = post_credentials or basic_credentials

        if not credentials:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        client_data = await async_client_collection.find_one(
            {'_id': credentials.username, 'client_secret': credentials.password}
        )
        if client_data is None:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        return client_data


def extract_email_user(email: str):
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
    dependencies=[Security(AuthenticateClient)],
)
async def get_exists_email(
    email: str,
    email_user: str = Depends(extract_email_user),
):
    """Inspect from a client if an email is registered."""
    if await async_user_group_collection.count_documents(
        {
            '_id': email_user,
            'enable_email': True,
        }
    ) > 0:
        return

    if await async_user_collection.count_documents(
        {
            'email_alias': email,
            'enable_email': True,
        }
    ) > 0:
        return
    raise HTTPException(404, detail="E-Mail address not found")


@router.get(
    '/mail/quota/{email:path}',
    tags=['Extension: Mail'],
    response_model=int,
    dependencies=[Security(AuthenticateClient)],
)
async def get_quota(
    email: str,
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
            'email_alias': email,
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
    dependencies=[Security(AuthenticateClient)],
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
        return

    if await async_user_collection.count_documents(
        {
            'email_alias': email.lower(),
            'enable_postbox': True,
        }
    ) > 0:
        return
    raise HTTPException(404, detail="E-Mail address is not a postbox")


@router.get(
    '/mail/redirects/{email:path}',
    tags=['Extension: Mail'],
    response_model=List[str],
    dependencies=[Security(AuthenticateClient)],
)
async def get_redirects(
    email: str,
) -> List[str]:
    """Gets the redirects for the passed email address."""

    group_forwards = await async_user_group_collection.find_one(
        {
            '_id': extract_email_user(email),
            'enable_email': True,
        },
        projection={
            'email_forward_members': 1,
        },
    )
    if group_forwards is not None:
        uids = group_forwards.get('email_forward_members', [])
        members = []
        if uids:
            async for user in async_user_collection.find({'_id': {'$in': uids}}, projection={
                'has_email_alias': 1, 'forward_emails': 1, 'email': 1, 'email_alias': 1, '_id': 0,
            }):
                if user.get('has_email_alias', False) and 'email_alias' in user:
                    # Will also forward it in case forwarding is also enabled
                    members.append(user['email_alias'])
                elif user.get('forward_emails', False) and 'email' in user:
                    members.append(user['email'])
        return []

    user_forwarding = await async_user_collection.find_one(
        {
            'email_alias': email.lower(),
            'has_email_alias': True,
        },
        projection={'forward_emails': 1, 'email': 1, '_id': 0}
    )
    if user_forwarding is not None and 'email' in user_forwarding:
        if user_forwarding.get('forward_emails', False) and 'email' in user_forwarding:
            return [user_forwarding['email']]
        return []
    raise HTTPException(404, detail="E-Mail address does not exist")


class Credentials(BaseModel):
    username: Optional[str]
    password: str
    client_ip: str


@router.post(
    '/mail/postbox/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Security(AuthenticateClient)],
)
async def check_postbox_access(
    email: str,
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
        search, projection={'_id': 1, 'email_alias': 1, 'has_email_alias': 1, 'has_postbox': 1}
    )

    if user is None:
        retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
        raise HTTPException(
            403, detail="User not authorized", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )
    if user.get('has_postbox', False) and user.get('has_email_alias', False) and \
            user.get('email_alias') == email.lower():
        # User is accessing it's own postbox
        return

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
        return

    retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
    raise HTTPException(
        403, detail="User cannot access postbox (user not permitted or postbox does not exist)",
        headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
    )


@router.post(
    '/mail/send/{email:path}',
    tags=['Extension: Mail'],
    response_model=None,
    dependencies=[Security(AuthenticateClient)],
)
async def check_send_access(
        email: str,
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
    user = await async_user_collection.find_one(search, projection={'_id': 1, 'email_alias': 1, 'has_email_alias': 1})
    if user is None:
        retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
        raise HTTPException(
            403, detail="User not authorized", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )
    if user.get('has_email_alias', False) and user.get('email_alias') == email.lower():
        # User is sending from it's own alias
        return

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
        return

    retry_after, retry_delay = await async_throttle_failure(credentials.client_ip)
    raise HTTPException(
        403, detail="User cannot send from email (user not permitted or email does not exist)",
        headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
    )
