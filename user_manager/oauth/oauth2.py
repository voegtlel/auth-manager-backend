import time
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional, Tuple, Dict, Any, Union

from authlib.common.security import generate_token
from authlib.consts import default_json_headers
from authlib.oauth2 import (
    OAuth2Request,
    AuthorizationServer as _AuthorizationServer,
    ResourceProtector as _ResourceProtector,
    OAuth2Error,
    HttpRequest)
from authlib.oauth2.rfc6749 import InvalidClientError
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
    RefreshTokenGrant as _RefreshTokenGrant,
    BaseGrant)
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6750 import BearerTokenValidator as _BearerTokenValidator, BearerToken as _BearerToken
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import (
    OpenIDCode as _OpenIDCode,
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oidc.core.grants.util import is_openid_scope, generate_id_token
from starlette.responses import Response, JSONResponse

from user_manager.common.config import config
from user_manager.common.models import AuthorizationCode, Token, Client
from user_manager.common.mongo import authorization_code_collection, token_collection, \
    client_collection, client_user_cache_collection
from . import oauth2_key
from .user_helper import UserWithRoles


class TypedRequest(OAuth2Request):
    user: UserWithRoles
    credential: Union[AuthorizationCode, Token]
    client: Client


class RedirectResponse(Response):
    def to_json_response(self) -> JSONResponse:
        return JSONResponse(
            content={'redirect_url': self.headers['Location']},
            status_code=401,
            headers=dict(default_json_headers),
        )


class ErrorJSONResponse(JSONResponse):
    pass


class ErrorRedirectResponse(RedirectResponse):
    def to_json_response(self) -> JSONResponse:
        return ErrorJSONResponse(
            content={'redirect_url': self.headers['Location']},
            status_code=401,
            headers=dict(default_json_headers),
        )


class AuthorizationServer(_AuthorizationServer):
    metadata_class = AuthorizationServerMetadata

    def create_oauth2_request(self, request: TypedRequest):
        assert isinstance(request, OAuth2Request)
        return request

    def create_json_request(self, request):
        assert isinstance(request, HttpRequest)
        raise NotImplementedError()
        # TODO: Create HttpRequest with json in body.

    def handle_response(self, status_code: int, payload: Optional[dict], headers: List[Tuple[str, str]]):
        headers = dict(headers)
        if isinstance(payload, dict):
            return JSONResponse(payload, status_code=status_code, headers=headers)
        elif headers.get('Location'):
            assert not payload
            return RedirectResponse(status_code=status_code, headers=headers)
        assert False

    def handle_error_response(self, request: TypedRequest, error: OAuth2Error):
        status_code, body, headers = error(
            translations=self.get_translations(request),
            error_uris=self.get_error_uris(request)
        )
        headers = dict(headers)
        if isinstance(body, dict):
            return ErrorJSONResponse(
                content=body,
                status_code=status_code,
                headers=headers,
            )
        elif headers.get('Location'):
            assert not body
            return ErrorRedirectResponse(
                status_code=status_code,
                headers=headers,
            )
        assert False


def save_authorization_code(code: str, request: TypedRequest):
    nonce = request.data.get('nonce')
    item = AuthorizationCode(
        code=code,
        client_id=request.client.id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=request.user.user.id,
        nonce=nonce,
        auth_time=int(time.time()),
        expiration_time=datetime.utcnow() + timedelta(seconds=config.oauth2.token_expiration.authorization_code),
    )
    authorization_code_collection.insert_one(item.dict(exclude_none=True, by_alias=True))
    return item


class ExistsNonceMixin(object):
    def exists_nonce(self, nonce: str, request: TypedRequest):
        # exists = mongo.authorization_code_collection.count_documents(
        #     {'client_id': request.client_id, 'nonce': nonce},
        #     limit=1,
        # )
        mod_result = authorization_code_collection.update_one(
            {'client_id': request.client_id, 'nonce': nonce},
            {'$set': {'nonce': None}},
        )
        if mod_result.modified_count != 1:
            return False
        return True


class JwtConfigMixin(object):
    jwt_token_expiration: int

    def get_jwt_config(self, *args, **kwargs):
        return {
            'key': oauth2_key.key.key,
            'alg': oauth2_key.key.jwk.alg.value,
            'iss': config.oauth2.issuer,
            'exp': self.jwt_token_expiration,
        }


class UserInfoMixin(object):
    def generate_user_info(self, user: UserWithRoles, scope: str):
        scope_list = scope_to_list(scope)
        includes = set()
        for scope in scope_list:
            if scope not in ('openid', 'offline_access'):
                includes.update(config.oauth2.user.scopes[scope].properties)
        user_data = user.user.dict(include=includes, by_alias=True, exclude_none=True)
        user_data['sub'] = user.user.id
        user_data['roles'] = user.roles
        if 'picture' in user_data:
            user_data['picture'] = f"{config.oauth2.base_url}/picture/{user_data['picture']}"
        return UserInfo(**user_data)


class AuthorizationCodeGrant(_AuthorizationCodeGrant):
    AUTHORIZATION_CODE_LENGTH = config.oauth2.authorization_code_length

    def save_authorization_code(self, code: str, request: TypedRequest):
        return save_authorization_code(code, request)

    def query_authorization_code(self, code: str, client: Client):
        auth_code_data = authorization_code_collection.find_one({'_id': code, 'client_id': client.id})
        if auth_code_data is None:
            return None
        auth_code = AuthorizationCode.validate(auth_code_data)
        if auth_code.is_expired():
            return None
        return auth_code

    def delete_authorization_code(self, authorization_code: AuthorizationCode):
        authorization_code_collection.delete_one({'_id': authorization_code.code})

    def authenticate_user(self, authorization_code: AuthorizationCode):
        return UserWithRoles.load(authorization_code.user_id, authorization_code.client_id)


class OpenIDCode(UserInfoMixin, ExistsNonceMixin, JwtConfigMixin, _OpenIDCode):
    jwt_token_expiration = config.oauth2.token_expiration.authorization_code


class OpenIDImplicitGrant(UserInfoMixin, ExistsNonceMixin, JwtConfigMixin, _OpenIDImplicitGrant):
    jwt_token_expiration = config.oauth2.token_expiration.implicit


class OpenIDHybridGrant(UserInfoMixin, ExistsNonceMixin, JwtConfigMixin, _OpenIDHybridGrant):
    jwt_token_expiration = config.oauth2.token_expiration.implicit

    def create_authorization_code(self, client: Client, grant_user: UserWithRoles, request: TypedRequest):
        return save_authorization_code(generate_token(config.oauth2.authorization_code_length), request)


class RefreshTokenGrant(_RefreshTokenGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['none', 'client_secret_basic']
    INCLUDE_NEW_REFRESH_TOKEN = True

    def authenticate_refresh_token(self, refresh_token: str):
        token_data = token_collection.find_one({'refresh_token': refresh_token})
        if token_data is None:
            return None
        auth_code = Token.validate(token_data)
        if auth_code.is_expired():
            return None
        return auth_code

    def authenticate_user(self, credential: Token):
        return UserWithRoles.load(credential.user_id, credential.client_id)

    def revoke_old_credential(self, credential: Token):
        # token_collection.update_one({'_id': credential.access_token}, {'revoked': True})
        token_collection.delete_one({'_id': credential.access_token})


def save_token(token: Dict[str, Any], request: TypedRequest):
    if request.user:
        user_id = request.user.user.id
    else:
        user_id = None
    now = int(time.time())
    token_data = Token.validate({
        'client_id': request.client.id,
        'user_id': user_id,
        'issued_at': now,
        'expiration_time': datetime.utcnow() + timedelta(seconds=token.get('expires_in', 0)),
        'scope': request.scope,
        'auth_time': request.credential.get_auth_time(),
        **token
    })
    token_collection.insert_one(token_data.dict(exclude_none=True, by_alias=True))
    return token_data


def query_client(client_id: str):
    client_data = client_collection.find_one({'_id': client_id})
    if client_data is None:
        return None
    return Client.validate(client_data)


def token_generator(*_):
    return generate_token(config.oauth2.token_length)


class AccessTokenGenerator(UserInfoMixin, JwtConfigMixin):
    jwt_token_expiration = config.oauth2.token_expiration.authorization_code

    def __call__(self, client: Client, grant_type: str, user: UserWithRoles, scope: str):
        jwt_config = self.get_jwt_config()
        jwt_config['aud'] = [client.get_client_id()]
        jwt_config['auth_time'] = int(time.time())

        user_info = {'sub': user.user.id, 'roles': user.roles}
        return generate_id_token({}, user_info, code=generate_token(config.oauth2.access_token_length), **jwt_config)


def token_expires_in(_, grant_type: str):
    return getattr(config.oauth2.token_expiration, grant_type)


class BearerToken(_BearerToken):
    def __call__(self, client, grant_type, user=None, scope=None,
                 expires_in=None, include_refresh_token=True):
        if 'offline_access' not in scope_to_list(scope):
            include_refresh_token = False
        return super(BearerToken, self).__call__(client, grant_type, user, scope, expires_in, include_refresh_token)


authorization = AuthorizationServer(
    query_client,
    save_token,
    BearerToken(AccessTokenGenerator(), expires_generator=token_expires_in, refresh_token_generator=token_generator),
)


class OpenIDSessionState:

    def __call__(self, grant: BaseGrant):
        grant.register_hook('process_token', self.process_token)

    def process_token(self, grant: BaseGrant, token: dict):
        scope = token.get('scope')
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            return token

        token['session_state'] = str(grant.request.user.last_modified)
        return token


# support all openid grants
authorization.register_grant(AuthorizationCodeGrant, [OpenIDCode(require_nonce=True), OpenIDSessionState()])
authorization.register_grant(OpenIDImplicitGrant)
authorization.register_grant(OpenIDHybridGrant)
authorization.register_grant(RefreshTokenGrant, [OpenIDCode(require_nonce=True), OpenIDSessionState()])


class BearerTokenValidator(_BearerTokenValidator):
    def authenticate_token(self, token_string: str):
        token_data = token_collection.find_one({'_id': token_string})
        if token_data is None:
            return None
        token = Token.validate(token_data)
        if client_user_cache_collection.count_documents({
            'client_id': token.client_id,
            'user_id': token.user_id,
        }) != 1:
            return None
        return token

    def request_invalid(self, request: TypedRequest):
        return False

    def token_revoked(self, token: Token):
        return token.revoked


class ResourceProtector(_ResourceProtector):
    def validate(self, request: OAuth2Request, scope: str = None, scope_operator='AND') -> Token:
        assert isinstance(request, OAuth2Request)
        return self.validate_request(scope, request, scope_operator)


class UserIntrospection(UserInfoMixin):
    def create_response(self, request: TypedRequest) -> Response:
        try:
            assert isinstance(request, OAuth2Request)
            request.token = resource_protector.validate_request(None, request)
            request.user = UserWithRoles.load(request.token.user_id, request.token.client_id)
            user_info = self.generate_user_info(request.user, request.token.scope)
            return JSONResponse(user_info)
        except OAuth2Error as error:
            return authorization.handle_error_response(request, error)


class TypeHint(str, Enum):
    AccessToken = "access_token"
    RefreshToken = "refresh_token"


class RevocationEndpoint:

    def create_response(self, raw_token: str, token_type_hint: Optional[TypeHint], request: TypedRequest) -> Response:
        token_data = None
        if token_type_hint is None or token_type_hint == TypeHint.AccessToken:
            token_data = token_collection.find_one({'_id': raw_token})
        if token_data is None and (token_type_hint is None or token_type_hint == TypeHint.RefreshToken):
            token_data = token_collection.find_one({'refresh_token': raw_token})
        if token_data is None:
            return Response()
        token = Token.validate(token_data)
        try:
            if request.client_id is None:
                request.data['client_id'] = token.client_id
            elif token.client_id != request.client_id:
                raise InvalidClientError(state=request.state, status_code=401)
            authorization.authenticate_client(request, ["none", "client_secret_basic", "client_secret_post"])
            token_collection.update_one({'_id': token.access_token}, {'$set': {'revoked': True}})
            return Response()
        except OAuth2Error as error:
            return authorization.handle_error_response(request, error)


resource_protector = ResourceProtector()
resource_protector.register_token_validator(BearerTokenValidator())

user_introspection = UserIntrospection()
token_revocation = RevocationEndpoint()
