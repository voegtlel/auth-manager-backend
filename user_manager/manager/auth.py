from authlib.integrations.starlette_client import OAuth as _OAuth, StarletteRemoteApp as _StarletteRemoteApp
from authlib.oidc.core import UserInfo
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.status import HTTP_403_FORBIDDEN

from user_manager.common.config import config

router = APIRouter()


class StarletteRemoteApp(_StarletteRemoteApp):
    async def parse_id_token_raw(self, token: str) -> UserInfo:
        return await self._parse_id_token({'id_token': token, 'access_token': True}, nonce=None, claims_options=None)


class OAuth(_OAuth):
    framework_client_cls = StarletteRemoteApp

    server: StarletteRemoteApp


oauth = OAuth()
oauth.register('server', **config.manager.oauth2.dict())


class Authentication:
    def __init__(self, auto_error: bool = True):
        self.auto_error = auto_error

    async def __call__(
            self,
            authorization_code: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False)),
    ) -> UserInfo:
        if authorization_code is None and self.auto_error:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
            )
        return await oauth.server.parse_id_token_raw(authorization_code.credentials)

