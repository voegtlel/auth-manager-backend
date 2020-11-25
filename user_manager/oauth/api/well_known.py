from typing import Optional, List

from fastapi import APIRouter
from pydantic import BaseModel
from starlette.requests import Request
from starlette.responses import Response

from user_manager.common.config import config
from user_manager.oauth.oauth2_key import JSONWebKeySet, jwks, supported_alg_sig
from .cors_helper import allow_all_get_cors

router = APIRouter()


class RawJSONResponse(Response):
    media_type = "application/json"

    def render(self, content: str) -> bytes:
        return content.encode("utf-8")


@router.options(
    '/.well-known/jwks',
    include_in_schema=False,
    tags=['.well-known'],
)
async def get_jwks_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/.well-known/jwks',
    tags=['.well-known'],
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
        'code', 'token', 'id_token', 'token id_token', 'code id_token', 'code token', 'code token id_token',
    ]
    response_modes_supported: Optional[List[str]] = ['query', 'fragment']
    grant_types_supported: List[str] = [
        'authorization_code', 'implicit', 'refresh_token', 'password', 'urn:ietf:params:oauth:grant-type:jwtbearer',
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


@router.options(
    '/.well-known/openid-configuration',
    include_in_schema=False,
    tags=['.well-known'],
)
async def get_openid_configuration_options(request: Request):
    return allow_all_get_cors.options(request)


@router.get(
    '/.well-known/openid-configuration',
    tags=['.well-known'],
    response_model=OpenIDConnectResponse,
)
async def get_openid_configuration(request: Request):
    response = RawJSONResponse(
        OpenIDConnectResponse(
            issuer=config.oauth2.issuer,
            authorization_endpoint=config.oauth2.base_url + '/authorize',
            token_endpoint=config.oauth2.base_url + '/token',
            revocation_endpoint=config.oauth2.base_url + '/token/revoke',
            userinfo_endpoint=config.oauth2.base_url + '/userinfo',
            jwks_uri=config.oauth2.base_url + '/.well-known/jwks',
            scopes_supported=['openid', 'offline_access'] + list(config.oauth2.user.scopes.keys()),
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
