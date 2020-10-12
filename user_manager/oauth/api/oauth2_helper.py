from typing import cast

from authlib.oauth2 import OAuth2Request
from starlette.requests import Request

from user_manager.oauth.oauth2 import TypedRequest


async def oauth2_request(request: Request) -> TypedRequest:
    return cast(TypedRequest, OAuth2Request(request.method, str(request.url), await request.form(), request.headers))
