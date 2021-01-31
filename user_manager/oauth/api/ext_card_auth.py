from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import APIRouter, Body, HTTPException, Depends
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse

from user_manager.common.models import DbUser, DbUserHistory, DbChange
from user_manager.common.mongo import async_user_collection, async_user_history_collection
from user_manager.oauth.oauth2 import authorization, ErrorJSONResponse, RedirectResponse, user_introspection
from user_manager.oauth.user_helper import UserWithRoles
from .ext_auth_base import AuthenticateClient
from .oauth2_helper import oauth2_request

router = APIRouter()


client_auth = AuthenticateClient('*ext_card_auth')


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
        client: dict = Depends(client_auth),
):
    """Authorize by card ID."""

    # Find user by card id and authorize by that.
    user_data = await async_user_collection.find_one({'card_id': card.card_id})
    if user_data is None:
        raise HTTPException(404, "Unknown card")
    user = DbUser.validate(user_data)
    if not user.active:
        raise HTTPException(400, "User not active")

    user_with_groups = await UserWithRoles.async_load_groups(user, client['_id'])
    request = await oauth2_request(request)
    request.data['client_id'] = client['_id']
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
    dependencies=[Depends(client_auth)],
)
async def register_card(
        request: Request,
        card: CardModel = Body(...),
):
    """Set card ID for authorized user."""
    oauth_request = await oauth2_request(request)
    response = await user_introspection.create_response(oauth_request)
    if isinstance(response, ErrorJSONResponse):
        return response
    if not oauth_request.user.user.active:
        raise HTTPException(400, "User not active")
    await async_user_history_collection.insert_one(DbUserHistory(
        id=str(uuid4()),
        user_id=oauth_request.user.user.id,
        timestamp=datetime.utcnow().replace(tzinfo=timezone.utc),
        author_id=oauth_request.user.user.id,
        changes=[DbChange(property='card_id', value=card.card_id)],
    ).dict(by_alias=True, exclude_none=True))
    await async_user_collection.update_one({'_id': oauth_request.user.user.id}, {'card_id': card.card_id})
