import os
from datetime import datetime, timedelta
from typing import Optional, Any

import time
from authlib.common.security import generate_token
from authlib.common.urls import url_decode, url_encode
from authlib.consts import default_json_headers
from fastapi import HTTPException, APIRouter
from fastapi.params import Depends, Query, Body, Cookie
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, FileResponse

from user_manager.common.config import config
from user_manager.common.models import DbUser, DbSession
from user_manager.common.mongo import async_user_collection, async_session_collection
from user_manager.common.password_helper import verify_and_update
from user_manager.common.throttle import async_throttle, async_throttle_failure_request
from user_manager.oauth.oauth2 import authorization, ErrorJSONResponse, ErrorRedirectResponse, RedirectResponse
from user_manager.oauth.session import async_validate_session
from user_manager.oauth.user_helper import UserWithRoles
from .error import ErrorResult
from .oauth2_helper import oauth2_request
from .session_helper import (
    add_session_state,
    COOKIE_KEY_SID,
    COOKIE_KEY_STATE,
    update_session_state,
    update_session_sid,
)

router = APIRouter()

authorize_static_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'authorize.html')
logo_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'logo.png')


class OAuthAuthorizeRequestQueryParams:

    def __init__(
            self,
            response_type: str = Query(...),
            client_id: str = Query(...),
            redirect_uri: Optional[str] = Query(None),
            scope: Optional[str] = Query(None),
            code_challenge: Optional[str] = Query(None),
            code_challenge_method: Optional[str] = Query(None),
            state: Optional[str] = Query(None),
    ):
        self.response_type = response_type
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.code_challenge = code_challenge
        self.code_challenge_method = code_challenge_method
        self.state = state


@router.get(
    '/authorize',
    tags=['OAuth2 Provider: Authorize'],
    responses={
        302: {'description': "Redirect to authentication page or redirect_uri if session is valid"},
        200: {'content': {'application/json': {}, 'text/html': {}}},
        400: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def enter_authorization(
        request: Request,
        _query_params: OAuthAuthorizeRequestQueryParams = Depends(OAuthAuthorizeRequestQueryParams),
        sid: Optional[str] = Cookie(None, alias=COOKIE_KEY_SID),
        session_state: Optional[str] = Cookie(None, alias=COOKIE_KEY_STATE),
):
    """Enter the authorization process. May redirect to login page or return directly."""
    user = await async_validate_session(sid)

    if user is not None and user.active:
        user_with_groups = await UserWithRoles.async_load_groups(user, _query_params.client_id)
        resp = await run_in_threadpool(
            authorization.create_authorization_response,
            request=await oauth2_request(request),
            grant_user=user_with_groups,
        )
        if isinstance(resp, RedirectResponse):
            # Directly return the result, optionally redirect directly
            add_session_state(resp, user_with_groups)
            if str(user_with_groups.last_modified) != session_state:
                update_session_state(resp, user_with_groups)
            return resp
        if isinstance(resp, ErrorJSONResponse):
            return resp
        assert not isinstance(resp, JSONResponse)
    return FileResponse(authorize_static_path, media_type='text/html')


class AuthCredentials(BaseModel):
    email: str = ...
    password: str = ...
    remember: bool = ...


class RedirectResult(BaseModel):
    redirect_uri: str


@router.post(
    '/authorize',
    response_model=Any,
    tags=['OAuth2 Provider: Authorize'],
    responses={
        200: {'model': RedirectResult},
        400: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def authorize(
        request: Request,
        _query_params: OAuthAuthorizeRequestQueryParams = Depends(OAuthAuthorizeRequestQueryParams),
        auth_credentials: AuthCredentials = Body(...),
):
    """Perform authorization from given credentials and returns the result."""
    retry_delay, retry_after = await async_throttle(request)
    if retry_delay is not None and retry_after is not None:
        raise HTTPException(
            403, "Wait", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )
    potential_users = async_user_collection.find({'email': auth_credentials.email})
    async for potential_user in potential_users:
        if potential_user.get('password') is not None:
            password_valid, new_hash = verify_and_update(auth_credentials.password, potential_user['password'])
            if password_valid:
                user_data = potential_user
                break
    else:
        retry_after, retry_delay = await async_throttle_failure_request(request)
        raise HTTPException(
            403, "Invalid E-Mail or Password", headers={'X-Retry-After': retry_after, 'X-Retry-Wait': retry_delay}
        )

    user = DbUser.validate_document(user_data)
    if new_hash is not None:
        await async_user_collection.update_one({'_id': user.id}, {'$set': {'password': new_hash}})
        user.password = new_hash
    if user.registration_token:
        # If the user password is correct, but a registration token is pending, redirect to registration page
        from ...manager.api.user_helpers import check_token, create_token
        import urllib.parse
        registration_token = user.registration_token
        try:
            check_token(user.registration_token)
        except HTTPException:
            token_valid_until = int(time.time() + config.manager.token_valid.registration)
            registration_token = create_token(user_data['_id'], token_valid_until)
            await async_user_collection.update_one(
                {'_id': user.id},
                {'$set': {'registration_token': registration_token}},
            )
        args = dict(url_decode(request.url.query))
        args.update((await request.form()) or {})

        #: dict of query and body params
        return_url = urllib.parse.quote_plus(config.oauth2.base_url + '/authorize?' + url_encode(args.items()))
        return JSONResponse(
            content={
                'redirect_uri': f"{config.manager.frontend_base_url}/register/{registration_token}"
                                f"?return_url={return_url}"
            },
            status_code=200,
            headers=dict(default_json_headers),
        )
    user_group_data = await UserWithRoles.async_load_groups(user, _query_params.client_id)
    oauth_request = await oauth2_request(request)
    resp = await run_in_threadpool(
        authorization.create_authorization_response,
        request=oauth_request,
        grant_user=user_group_data,
    )
    if isinstance(resp, ErrorJSONResponse):
        return resp
    elif isinstance(resp, ErrorRedirectResponse):
        return resp.to_json_response()
    elif isinstance(resp, RedirectResponse):
        expires_in = config.oauth2.token_expiration.session
        add_session_state(resp, oauth_request.user)
        resp = resp.to_json_response()
        if auth_credentials.remember:
            now = int(time.time())
            sess = DbSession(
                id=generate_token(config.oauth2.token_length),
                user_id=user.id,
                issued_at=now,
                expires_in=expires_in,
                expiration_time=datetime.utcnow() + timedelta(seconds=expires_in),
            )
            await async_session_collection.insert_one(sess.document())
            update_session_sid(resp, sess.id)
        update_session_state(resp, oauth_request.user)
        return resp
    assert False


@router.get(
    '/logo.png',
    tags=['OAuth2 Provider: Authorize'],
    responses={
        200: {
            "content": {"image/png": {}},
        },
    },
)
async def get_login_status_iframe():
    return FileResponse(logo_path, media_type='image/png')
