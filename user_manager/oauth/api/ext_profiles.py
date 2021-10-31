from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from starlette.requests import Request

from user_manager.oauth.oauth2 import request_origin_verifier, other_user_inspection, other_users_inspection
from .cors_helper import allow_all_get_cors
from .ext_auth_base import AuthenticateClient
from .oauth2_helper import oauth2_request
from ...common.models import DbClient

router = APIRouter()


client_auth = AuthenticateClient('*users')


@router.options(
    '/profiles/{user_id}',
    include_in_schema=False,
    tags=['Extension: Profile'],
)
async def get_profile_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/profiles/{user_id}',
    tags=['Extension: Profile'],
    response_model=Dict[str, Any],
)
async def get_profile(
        request: Request,
        user_id: str,
        client: Optional[dict] = Depends(client_auth)
):
    """Inspect other user's profile."""
    oauth_request = await oauth2_request(request)
    if client is not None:
        oauth_request.data['client_id'] = client['_id']
        oauth_request.client = DbClient.validate_document(client)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            allow_all_get_cors.augment(request, origin_response)
            return origin_response
    response = await other_user_inspection.create_response(oauth_request, user_id)
    allow_all_get_cors.augment(request, response)
    return response


@router.options(
    '/profiles',
    include_in_schema=False,
    tags=['Extension: Profile'],
)
async def get_profiles_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/profiles',
    tags=['Extension: Profile'],
    response_model=List[Dict[str, Any]],
)
async def get_profiles(
        request: Request,
        client: Optional[dict] = Depends(client_auth),
):
    """List other user's profiles."""
    oauth_request = await oauth2_request(request)
    if client is not None:
        oauth_request.data['client_id'] = client['_id']
        oauth_request.client = DbClient.validate_document(client)
    origin = request.headers.get("origin")
    if origin is not None:
        origin_response = await request_origin_verifier.create_response(oauth_request, origin)
        if origin_response is not None:
            allow_all_get_cors.augment(request, origin_response)
            return origin_response
    response = await other_users_inspection.create_response(oauth_request)
    allow_all_get_cors.augment(request, response)
    return response
