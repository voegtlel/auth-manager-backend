import os
from typing import Any, List, Optional

from authlib.integrations.starlette_client import OAuth, StarletteRemoteApp
from fastapi import APIRouter, HTTPException, Cookie
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.requests import Request
from starlette.responses import RedirectResponse, HTMLResponse

from user_manager.common.config import UserProperty, config
from user_manager.common.mongo import user_collection

router = APIRouter()


class OAuthTyped(OAuth):
    server: StarletteRemoteApp


oauth = OAuthTyped()
oauth.register('server', **config.manager.oauth2.dict())


class UserPropertyValue(UserProperty):
    value: Any


@router.get(
    '/self',
    tags=['User Manager'],
    response_model=List[UserPropertyValue],
)
def get_self():
    """Get self data."""
    user_collection


@router.get('/')
async def homepage(id_token: Optional[str] = Cookie(None),):
    if id_token is not None:
        html = (
            f'<pre>{id_token}</pre>'
            '<a href="/manager/logout">logout</a>'
        )
        return HTMLResponse(html)
    return HTMLResponse('<a href="/manager/login">login</a>')


@router.get('/login')
async def login(request: Request):
    return await oauth.server.authorize_redirect(
        request, config.manager.base_url + '/manager/auth', scope='openid profile'
    )


@router.get('/auth')
async def auth(request: Request):
    if 'error' in request.query_params:
        raise HTTPException(401, request.query_params.get('error_description'))
    token = await oauth.server.authorize_access_token(request, scope='openid profile')
    if token is None:
        raise HTTPException(401, "Token Invalid")
    if 'id_token' not in token:
        raise HTTPException(401, "Token missing id_token")
    user = await oauth.server.parse_id_token(request, token)
    if user is None:
        raise HTTPException(401, "Cannot retrieve user from token")
    response = RedirectResponse(url='/manager')
    response.set_cookie(
        key='id_token',
        value=token['id_token'],
        max_age=token['expires_in'],
        secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        httponly=True,
    )
    return response


@router.get('/logout')
async def logout():
    response = RedirectResponse(url='/manager')
    response.delete_cookie('id_token')
    return response
