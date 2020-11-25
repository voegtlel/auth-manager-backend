from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse

from user_manager.common.config import config
from user_manager.common.models import User
from user_manager.common.mongo import async_user_collection
from user_manager.oauth.oauth2 import authorization, ErrorJSONResponse, RedirectResponse, user_introspection
from user_manager.oauth.user_helper import UserWithRoles
from .oauth2_helper import oauth2_request

router = APIRouter()

api_key = APIKeyHeader(name='X-Card-Api-Key')


class CardModel(BaseModel):
    card_id: str


@router.post(
    '/card/authorize',
    tags=['Extension: Card Authentication'],
    response_model=Dict[str, Any],
)
async def authorize_card(
        request: Request,
        card: CardModel = Body(...),
        api_key_auth: str = Security(api_key)
):
    """Authorize by card ID, requires configured Api Token."""
    if not config.oauth2.card_authentication_api_key:
        raise HTTPException(500, "Not configured")
    if api_key_auth != config.oauth2.card_authentication_api_key:
        raise HTTPException(403)

    # Find user by card id and authorize by that.
    user_data = await async_user_collection.find_one({'card_id': card.card_id})
    if user_data is None:
        raise HTTPException(404, "Unknown card")
    user = User.validate(user_data)
    if not user.active:
        raise HTTPException(400, "User not active")

    user_with_groups = await UserWithRoles.async_load_groups(user, config.oauth2.card_authentication_client_id)
    request = await oauth2_request(request)
    request.data['client_id'] = config.oauth2.card_authentication_client_id
    resp = await run_in_threadpool(
        authorization.create_authorization_response,
        request=request,
        grant_user=user_with_groups,
    )
    if isinstance(resp, ErrorJSONResponse):
        return resp
    if isinstance(resp, RedirectResponse):
        return resp.to_json_response()
    assert not isinstance(resp, JSONResponse)


@router.put(
    '/card/register',
    tags=['Extension: Card Authentication'],
    response_model=Dict[str, Any],
)
async def register_card(
        request: Request,
        card: CardModel = Body(...),
        api_key_auth: str = Security(api_key)
):
    """Set card ID for authorized user, requires configured Api Token."""
    if not config.oauth2.card_authentication_api_key:
        raise HTTPException(400, "Not configured")
    if api_key_auth != config.oauth2.card_authentication_api_key:
        raise HTTPException(403)

    oauth_request = await oauth2_request(request)
    response = await user_introspection.create_response(oauth_request)
    if isinstance(response, ErrorJSONResponse):
        return response
    if not oauth_request.user.user.active:
        raise HTTPException(400, "User not active")
    await async_user_collection.update_one({'_id': oauth_request.user.user.id}, {'card_id': card.card_id})
