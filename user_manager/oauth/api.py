import os
import time
from datetime import datetime, timedelta
from typing import Optional, Any, Dict, List, cast

from authlib.common.security import generate_token
from authlib.common.urls import add_params_to_uri
from authlib.oauth2 import OAuth2Request
from fastapi import HTTPException, APIRouter
from fastapi.params import Depends, Query, Body, Cookie, Header, Form
from pydantic import BaseModel
from pymongo.collection import Collection
from starlette.requests import Request
from starlette.responses import JSONResponse, FileResponse, Response

from user_manager.common.config import config
from user_manager.common.models import User, Session
from user_manager.common.mongo import user_collection, session_collection, token_collection
from user_manager.common.password_helper import verify_and_update
from .cors import CORSHelper
from .oauth2 import authorization, ErrorJSONResponse, ErrorRedirectResponse, RedirectResponse, UserWithGroups, \
    user_introspection, token_revocation, TypeHint, TypedRequest
from .oauth2_key import supported_alg_sig, jwks, JSONWebKeySet

router = APIRouter()

authorize_static_path = os.path.join(os.path.dirname(__file__), "static", "authorize.html")
status_iframe_path = os.path.join(os.path.dirname(__file__), "static", "status-iframe.html")


COOKIE_KEY_SID = 'OAUTH_SID'
COOKIE_KEY_STATE = 'OAUTH_STATE'


allow_all_get_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('GET',),
    allow_headers=('authorization',),
    allow_credentials=True,
)
allow_all_get_post_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('GET', 'POST'),
    allow_headers=('authorization',),
    allow_credentials=True,
)
allow_all_post_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('POST',),
    allow_headers=('authorization',),
    allow_credentials=True,
)


async def oauth2_request(request: Request) -> TypedRequest:
    return cast(TypedRequest, OAuth2Request(request.method, str(request.url), await request.form(), request.headers))


def add_session_state(response: RedirectResponse, user: UserWithGroups):
    response.headers['location'] = add_params_to_uri(response.headers['location'], [('session_state', user.last_modified)])


def validate_session(sid: Optional[str], session_collection: Collection, user_collection: Collection) -> Optional[User]:
    if sid is None:
        return None
    session_data = session_collection.find_one({'_id': sid})
    if session_data is None:
        return None
    session = Session.validate(session_data)
    if session.expiration_time < datetime.utcnow():
        return None
    user_data = user_collection.find_one({'_id': session.user_id})
    if user_data is None:
        return None
    return User.validate(user_data)


class ErrorResult(BaseModel):
    error: str
    error_description: Optional[str]
    error_uri: Optional[str]
    state: Optional[str]


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
    tags=['OAuth2 Provider'],
    responses={
        302: {'description': "Redirect to authentication page or redirect_uri if session is valid"},
        400: {'model': ErrorResult},
        401: {'model': ErrorResult},
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
    user = validate_session(sid, session_collection, user_collection)
    if user is not None:
        user_with_groups = UserWithGroups.load_groups(user, _query_params.client_id)
        resp = authorization.create_authorization_response(
            request=await oauth2_request(request),
            grant_user=user_with_groups,
        )
        if isinstance(resp, RedirectResponse):
            # Directly return the result, optionally redirect directly
            add_session_state(resp, user_with_groups)
            if str(user_with_groups.last_modified) != session_state:
                resp.set_cookie(
                    key=COOKIE_KEY_STATE,
                    value=str(user_with_groups.last_modified),
                    max_age=config.oauth2.token_expiration.session,
                    secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
                )
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
    redirect_url: str


@router.post(
    '/authorize',
    response_model=Any,
    tags=['OAuth2 Provider'],
    responses={
        200: {'model': RedirectResult},
        400: {'model': ErrorResult},
        401: {'model': ErrorResult},
        403: {'model': ErrorResult},
    },
)
async def authorize(
        request: Request,
        _query_params: OAuthAuthorizeRequestQueryParams = Depends(OAuthAuthorizeRequestQueryParams),
        auth_credentials: AuthCredentials = Body(...),
):
    """Perform authorization from given credentials and returns the result."""
    user_data = user_collection.find_one({'email': auth_credentials.email})
    if user_data is None:
        raise HTTPException(401)
    user = User.validate(user_data)
    password_valid, new_hash = verify_and_update(auth_credentials.password, user.password)
    if not password_valid:
        raise HTTPException(401)
    if new_hash is not None:
        user_collection.update_one({'_id': user.id}, {'$set': {'password': new_hash}})
        user.password = new_hash
    user_group_data = UserWithGroups.load_groups(user, _query_params.client_id)
    oauth_request = await oauth2_request(request)
    resp = authorization.create_authorization_response(
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
            sess = Session(
                id=generate_token(config.oauth2.token_length),
                user_id=user.id,
                issued_at=now,
                expires_in=expires_in,
                expiration_time=datetime.utcnow() + timedelta(seconds=expires_in),
            )
            session_collection.insert_one(sess.dict(exclude_none=True, by_alias=True))
            resp.set_cookie(
                key=COOKIE_KEY_SID,
                value=sess.id,
                max_age=expires_in,
                secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
            )
        resp.set_cookie(
            key=COOKIE_KEY_STATE,
            value=str(oauth_request.user.last_modified),
            max_age=expires_in,
            secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        )
        return resp
    assert False


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
    oauth_request = await oauth2_request(request)
    response: Response = authorization.create_token_response(request=oauth_request)
    allow_all_get_post_cors.augment(request, response)
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
    oauth_request = await oauth2_request(request)
    response: Response = authorization.create_token_response(request=oauth_request)
    allow_all_get_post_cors.augment(request, response)
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
    response: Response = token_revocation.create_response(token, token_type_hint, request=await oauth2_request(request))
    allow_all_post_cors.augment(request, response)
    return response


@router.options('/me')
async def get_self_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/me',
    response_model=Dict[str, Any],
)
async def get_self(
        request: Request,
        session_state: Optional[str] = Cookie(None, alias=COOKIE_KEY_STATE),
):
    """Introspect self."""
    oauth_request = await oauth2_request(request)
    response: Response = user_introspection.create_response(oauth_request)
    allow_all_get_cors.augment(request, response)

    if str(oauth_request.user.last_modified) != session_state:
        response.set_cookie(
            key=COOKIE_KEY_STATE,
            value=str(oauth_request.user.last_modified),
            max_age=config.oauth2.token_expiration.session,
            secure=os.environ.get('AUTHLIB_INSECURE_TRANSPORT') != 'true',
        )

    return response


@router.get(
    '/login-status-iframe.html',
)
def get_login_status_iframe():
    return FileResponse(status_iframe_path, media_type='text/html')


@router.get(
    '/end_session',
    responses={
        302: {'description': 'Redirect to result'},
    },
)
async def end_session(
        id_token_hint: Optional[str] = Query(None),
        post_logout_redirect_uri: Optional[str] = Query(None),
        state: Optional[str] = Query(None),
        sid: Optional[str] = Cookie(None, alias=COOKIE_KEY_SID),
        referer: Optional[str] = Header(None),
):
    """Ends the session."""
    if sid is not None:
        session_collection.delete_one({'_id': sid})
    if id_token_hint is not None:
        token_collection.delete_one({'access_token': id_token_hint})
    if post_logout_redirect_uri is not None:
        if state is not None:
            if '#' in post_logout_redirect_uri:
                post_logout_redirect_uri, post_logout_redirect_hash = post_logout_redirect_uri.split('#', 1)
                post_logout_redirect_hash = '#' + post_logout_redirect_hash
            else:
                post_logout_redirect_hash = ''
            if '?' in post_logout_redirect_uri[:-1]:
                post_logout_redirect_uri += '&state=' + state
            else:
                post_logout_redirect_uri += '?state=' + state
            post_logout_redirect_uri += post_logout_redirect_hash
    elif referer is not None:
        post_logout_redirect_uri = referer
    else:
        post_logout_redirect_uri = ''
    response = RedirectResponse(
        status_code=302,
        headers={'Location': post_logout_redirect_uri},
    )
    response.delete_cookie(COOKIE_KEY_SID)
    response.delete_cookie(COOKIE_KEY_STATE)
    return response


class RawJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: str) -> bytes:
        return content.encode("utf-8")


@router.options('/.well-known/jwks')
async def get_jwks_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/.well-known/jwks',
    response_model=JSONWebKeySet,
)
async def get_jwks(request: Request):
    response = RawJSONResponse(
        jwks.json(),
        headers={
            'Access-Control-Allow-Origin': '*'
        }
    )
    allow_all_get_cors.augment(request, response)
    return response


class OpenIDConnectResponse(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    registration_endpoint: Optional[str]
    scopes_supported: List[str]
    response_types_supported: List[str] = [
        'code', 'token', 'id_token token', 'code id_token', 'code token', 'code id_token token',
    ]
    response_modes_supported: Optional[List[str]] = ['query', 'fragment']
    grant_types_supported: List[str] = [
        'authorization_code', 'implicit', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwtbearer',
    ]
    subject_types_supported: List[str] = ['public']
    id_token_signing_alg_values_supported: List[str]
    userinfo_signing_alg_values_supported: List[str]
    claims_supported: List[str] = [
        "sub",
        "groupIds",
        "name",
        "preferred_username",
        "picture",
        "locale",
        "email",
        "profile",
        "given_name",
        "family_name",
        "aud",
        "sub",
        "iss",
    ]
    token_endpoint_auth_methods_supported: List[str] = [
        'none', 'client_secret_basic', 'client_secret_post'
    ]

    check_session_iframe: str
    end_session_endpoint: str


@router.options('/.well-known/openid-configuration')
async def get_openid_configuration_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/.well-known/openid-configuration',
    response_model=OpenIDConnectResponse,
)
async def get_openid_configuration(request: Request):
    response = RawJSONResponse(
        OpenIDConnectResponse(
            issuer=config.oauth2.issuer,
            authorization_endpoint=config.oauth2.base_url + '/authorize',
            token_endpoint=config.oauth2.base_url + '/token',
            revocation_endpoint=config.oauth2.base_url + '/token/revoke',
            userinfo_endpoint=config.oauth2.base_url + '/me',
            jwks_uri=config.oauth2.base_url + '/.well-known/jwks',
            scopes_supported=['openid'] + list(config.oauth2.user.scopes.keys()),
            id_token_signing_alg_values_supported=supported_alg_sig,
            userinfo_signing_alg_values_supported=supported_alg_sig,
            check_session_iframe=config.oauth2.base_url + '/login-status-iframe.html',
            end_session_endpoint=config.oauth2.base_url + '/end_session',
        ).json(),
        headers={
            'Access-Control-Allow-Origin': '*'
        }
    )
    allow_all_get_cors.augment(request, response)
    return response
