from typing import Optional

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyQuery
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

from user_manager.common.mongo import async_client_collection


def client_id_secret_query(
        client_id: Optional[str] = Depends(APIKeyQuery(name="client_id", auto_error=False)),
        client_secret: Optional[str] = Depends(APIKeyQuery(name="client_secret", auto_error=False)),
) -> Optional[HTTPBasicCredentials]:
    if not client_id or not client_secret:
        return None
    return HTTPBasicCredentials(username=client_id, password=client_secret)


async def client_id_secret_post(request: Request) -> Optional[HTTPBasicCredentials]:
    try:
        request_json = await request.json()
        client_id: Optional[str] = request_json.get('client_id')
        client_secret: Optional[str] = request_json.get('client_secret')
    except ValueError:
        client_id = None
        client_secret = None
    if not client_id or not client_secret:
        return None
    return HTTPBasicCredentials(username=client_id, password=client_secret)


class AuthenticateClient:

    def __init__(self, scope_name: str, auto_error: bool = True):
        self.scope_name = scope_name
        self.auto_error = auto_error

    async def __call__(
            self,
            basic_credentials: Optional[HTTPBasicCredentials] = Depends(HTTPBasic(auto_error=False)),
            query_credentials: Optional[HTTPBasicCredentials] = Depends(client_id_secret_query),
            post_credentials: Optional[HTTPBasicCredentials] = Depends(client_id_secret_post),
    ) -> Optional[dict]:
        credentials = post_credentials or query_credentials or basic_credentials

        if not credentials:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            return None
        client_data = await async_client_collection.find_one(
            {'_id': credentials.username, 'client_secret': credentials.password, 'allowed_scope': self.scope_name}
        )
        if client_data is None:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            return None
        return client_data
