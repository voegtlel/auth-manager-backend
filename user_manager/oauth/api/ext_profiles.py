from typing import Any, Dict

from fastapi import APIRouter
from starlette.requests import Request

from user_manager.oauth.oauth2 import request_origin_verifier, other_user_inspection, other_users_inspection
from .cors_helper import allow_all_get_cors
from .oauth2_helper import oauth2_request

router = APIRouter()


@router.options('/profiles/{user_id}')
async def get_profile_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/profiles/{user_id}',
    response_model=Dict[str, Any],
)
async def get_profile(
        request: Request,
        user_id: str,
):
    """Inspect other user's profile."""
    oauth_request = await oauth2_request(request)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            return origin_response
    response = await other_user_inspection.create_response(oauth_request, user_id)
    allow_all_get_cors.augment(request, response)
    return response


@router.options('/profiles')
async def get_profiles_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/profiles',
    response_model=Dict[str, Any],
)
async def get_profiles(
        request: Request,
):
    """List other user's profiles."""
    oauth_request = await oauth2_request(request)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            return origin_response
    response = await other_users_inspection.create_response(oauth_request)
    allow_all_get_cors.augment(request, response)
    return response
