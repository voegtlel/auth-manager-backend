from typing import Dict, Any, Optional

from fastapi import APIRouter
from fastapi.params import Cookie
from starlette.requests import Request

from user_manager.oauth.oauth2 import request_origin_verifier, user_introspection
from .cors_helper import allow_all_get_cors
from .oauth2_helper import oauth2_request
from .session_helper import COOKIE_KEY_STATE, update_session_state

router = APIRouter()


@router.options(
    '/userinfo',
    include_in_schema=False,
    tags=['OAuth2 Provider: Userinfo'],
)
async def get_userinfo_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/userinfo',
    tags=['OAuth2 Provider: Userinfo'],
    response_model=Dict[str, Any],
)
async def get_userinfo(
        request: Request,
        session_state: Optional[str] = Cookie(None, alias=COOKIE_KEY_STATE),
):
    """Introspect self."""
    oauth_request = await oauth2_request(request)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            return origin_response
    response = await user_introspection.create_response(oauth_request)
    allow_all_get_cors.augment(request, response)

    if str(oauth_request.user.last_modified) != session_state:
        update_session_state(response, oauth_request.user)

    return response
