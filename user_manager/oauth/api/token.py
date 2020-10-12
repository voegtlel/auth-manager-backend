import os
from typing import Any, Optional

from fastapi import APIRouter
from fastapi.params import Depends, Cookie, Form, Query
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from user_manager.common.config import config
from user_manager.common.throttle import async_throttle_failure_request, async_throttle_sleep
from .cors_helper import allow_all_get_post_cors, allow_all_post_cors
from .error import ErrorResult
from .oauth2_helper import oauth2_request
from .session_helper import COOKIE_KEY_STATE
from ..oauth2 import authorization, ErrorJSONResponse, TypeHint, token_revocation

router = APIRouter()


class TokenRequestQueryParams:

    def __init__(
            self,
            grant_type: Optional[str] = Query(None),
            code: Optional[str] = Query(None),
            redirect_uri: Optional[str] = Query(None),
            client_id: Optional[str] = Query(None),
            client_secret: Optional[str] = Query(None),
            code_verifier: Optional[str] = Query(None),
            username: Optional[str] = Query(None),
            password: Optional[str] = Query(None),
    ):
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.code_verifier = code_verifier
        self.username = username
        self.password = password


class TokenRequestBodyParams:

    def __init__(
        self,
        grant_type: Optional[str] = Form(None),
        code: Optional[str] = Form(None),
        redirect_uri: Optional[str] = Form(None),
        client_id: Optional[str] = Form(None),
        client_secret: Optional[str] = Form(None),
        code_verifier: Optional[str] = Form(None),
        username: Optional[str] = Form(None),
        password: Optional[str] = Form(None),
    ):
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.code_verifier = code_verifier
        self.username = username
        self.password = password


@router.options('/token')
async def issue_token_options(request: Request):
    return allow_all_get_post_cors.options(request)


@router.post(
    '/token',
    tags=['OAuth2 Provider'],
    responses={
        200: {'model': Any},
        302: {'description': 'Redirect to result'},
        400: {'model': ErrorResult},
        401: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def post_issue_token(
        request: Request,
        _body_params: TokenRequestBodyParams = Depends(TokenRequestBodyParams),
        _query_params: TokenRequestQueryParams = Depends(TokenRequestQueryParams),
        session_state: Optional[str] = Cookie(None, alias=COOKIE_KEY_STATE),
):
    """Issues a token for a token request."""
    await async_throttle_sleep(request)
    oauth_request = await oauth2_request(request)
    response: Response = await run_in_threadpool(
        authorization.create_token_response,
        request=oauth_request
    )
    allow_all_get_post_cors.augment(request, response)
    if isinstance(response, ErrorJSONResponse):
        retry_after, retry_delay = await async_throttle_failure_request(request)
        response.headers['X-Retry-After'] = retry_after
        response.headers['X-Retry-Wait'] = retry_delay
    if (isinstance(response, JSONResponse) and not isinstance(response, ErrorJSONResponse) and
            str(oauth_request.user.last_modified) != session_state):
        response.set_cookie(
            key=COOKIE_KEY_STATE,
            value=str(oauth_request.user.last_modified),
            max_age=config.oauth2.token_expiration.session,
            secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        )
    return response


@router.get(
    '/token',
    tags=['OAuth2 Provider'],
    responses={
        200: {'model': Any},
        302: {'description': 'Redirect to result'},
        400: {'model': ErrorResult},
        401: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def get_issue_token(
        request: Request,
        _query_params: TokenRequestQueryParams = Depends(TokenRequestQueryParams),
        session_state: Optional[str] = Cookie(None, alias=COOKIE_KEY_STATE),
):
    """Issues a token for a token request."""
    await async_throttle_sleep(request)
    oauth_request = await oauth2_request(request)
    response: Response = await run_in_threadpool(
        authorization.create_token_response,
        request=oauth_request
    )
    allow_all_get_post_cors.augment(request, response)
    if isinstance(response, ErrorJSONResponse):
        retry_after, retry_delay = await async_throttle_failure_request(request)
        response.headers['X-Retry-After'] = retry_after
        response.headers['X-Retry-Wait'] = retry_delay
    if isinstance(response, JSONResponse) and str(oauth_request.user.last_modified) != session_state:
        response.set_cookie(
            key=COOKIE_KEY_STATE,
            value=str(oauth_request.user.last_modified),
            max_age=config.oauth2.token_expiration.session,
            secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        )
    return response


@router.options('/token/revoke')
async def revoke_token_options(request: Request):
    return allow_all_post_cors.options(request)


@router.post(
    '/token/revoke',
    tags=['OAuth2 Provider'],
    responses={
        200: {'model': Any},
        302: {'description': 'Redirect to result'},
        400: {'model': ErrorResult},
        401: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def post_revoke_token(
        request: Request,
        token: str = Form(...),
        token_type_hint: Optional[TypeHint] = Form(None),
):
    """Revokes a token."""
    response: Response = await token_revocation.create_response(
        token,
        token_type_hint,
        request=await oauth2_request(request),
    )
    allow_all_post_cors.augment(request, response)
    return response
