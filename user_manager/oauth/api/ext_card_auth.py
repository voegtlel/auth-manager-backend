from typing import Any, Dict

import time
from authlib.oidc.core.grants.util import generate_id_token
from fastapi import APIRouter, Body, HTTPException, Depends
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse

from user_manager.common.config import config
from user_manager.common.models import DbUser
from user_manager.common.mongo import async_user_collection
from user_manager.oauth.oauth2 import authorization, ErrorJSONResponse, RedirectResponse, JwtConfigMixin, \
    user_introspection
from user_manager.oauth.user_helper import UserWithRoles
from .ext_auth_base import AuthenticateClient
from .oauth2_helper import oauth2_request

router = APIRouter()


client_auth = AuthenticateClient('*ext_card_auth')


class CardModel(BaseModel):
    card_id: str


class CardAuthModel(BaseModel):
    update_token: str


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
    user = DbUser.validate_document(user_data)
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


@router.post(
    '/card/userinfo',
    tags=['Extension: Card Authentication'],
    response_model=Dict[str, Any],
)
async def check_card(
        card: CardModel = Body(...),
        client: dict = Depends(client_auth),
) -> Dict[str, Any]:
    """Authorize by card ID."""

    # Find user by card id and authorize by that.
    user_data = await async_user_collection.find_one({'card_id': card.card_id})
    if user_data is None:
        raise HTTPException(404, "Unknown card")
    user = DbUser.validate_document(user_data)
    if not user.active:
        raise HTTPException(400, "User not active")

    user_with_groups = await UserWithRoles.async_load_groups(user, client['_id'])
    return await user_introspection.async_generate_user_info(user_with_groups, client['allowed_scope'])


class UpdateTokenGenerator(JwtConfigMixin):
    jwt_token_expiration = config.oauth2.token_expiration.update_token

    def __call__(self, update: dict):
        jwt_config = self.get_jwt_config()
        jwt_config['auth_time'] = int(time.time())
        jwt_config['aud'] = 'update'

        return generate_id_token({}, update, **jwt_config)


update_token_gen = UpdateTokenGenerator()


@router.put(
    '/card/register',
    tags=['Extension: Card Authentication'],
    response_model=CardAuthModel,
    dependencies=[Depends(client_auth)],
)
async def register_card(
        card: CardModel = Body(...),
) -> CardAuthModel:
    """Creates an update token for setting card ID. The token may be used with user authentication in the manager to
    update the user."""
    update_command = {'card_id': card.card_id}
    token = update_token_gen(update_command)
    return CardAuthModel(update_token=token)
