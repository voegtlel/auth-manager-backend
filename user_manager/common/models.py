import re
from datetime import datetime
from time import time
from typing import List, Optional

from authlib.oauth2.rfc6749 import (
    TokenMixin,
    ClientMixin)
from authlib.oauth2.rfc6749.util import list_to_scope, scope_to_list
from authlib.oidc.core import AuthorizationCodeMixin
from pydantic import BaseModel, Field
from pymongo import IndexModel, HASHED, ASCENDING


class BaseCollection(BaseModel):
    __indexes__: List[IndexModel] = []
    __collection_name__: str

    class Config:
        allow_population_by_field_name = True
        validate_assignment = True


class AuthorizationCode(BaseCollection, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
    ]
    __collection_name__ = 'authorization_code'

    code: str = Field(..., alias='_id')

    user_id: str = ...
    client_id: str
    redirect_uri: str
    response_type: Optional[str]
    scope: Optional[str]
    nonce: Optional[str]
    auth_time: int = ...
    expiration_time: datetime = ...

    code_challenge: Optional[str]
    code_challenge_method: Optional[str]

    def is_expired(self):
        return self.expiration_time < datetime.utcnow()

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_scope(self):
        return self.scope

    def get_auth_time(self):
        return self.auth_time

    def get_nonce(self):
        return self.nonce


class Token(BaseCollection, TokenMixin, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('refresh_token', HASHED)]),
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
    ]
    __collection_name__ = 'token'

    access_token: str = Field(..., alias='_id')

    user_id: str
    client_id: str
    token_type: str
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    revoked: bool = False
    auth_time: int = ...
    issued_at: int = ...
    expires_in: int = 0
    expiration_time: datetime = ...

    def is_expired(self):
        return self.expiration_time < datetime.utcnow()

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.expiration_time

    def get_redirect_uri(self):
        return None

    def get_nonce(self):
        return None

    def get_auth_time(self):
        return self.auth_time


class Session(BaseCollection):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
    ]
    __collection_name__ = 'session'

    id: str = Field(..., alias='_id')

    user_id: str = ...
    issued_at: int = ...
    expires_in: int = 0
    expiration_time: datetime = ...


class Client(BaseCollection, ClientMixin):
    __collection_name__ = 'client'

    id: str = Field(..., alias='_id')

    redirect_uri: List[str]
    allowed_scope: List[str]
    client_secret: Optional[str] = None
    token_endpoint_auth_method: List[str] = ['client_secret_basic']
    response_type: List[str] = []
    grant_type: List[str] = []

    def get_client_id(self):
        return self.id

    def get_default_redirect_uri(self):
        return self.redirect_uri[0]

    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        allowed = set(scope_to_list(self.allowed_scope))
        return list_to_scope([s for s in scope.split() if s in allowed])

    def check_redirect_uri(self, redirect_uri):
        return any(re.fullmatch(chk_redirect_uri, redirect_uri) for chk_redirect_uri in self.redirect_uri)

    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return client_secret == self.client_secret

    def check_token_endpoint_auth_method(self, method):
        return any(
            method == chk_token_endpoint_auth_method
            for chk_token_endpoint_auth_method in self.token_endpoint_auth_method
        )

    def check_response_type(self, response_type):
        return any(
            response_type == chk_response_type
            for chk_response_type in self.response_type
        )

    def check_grant_type(self, grant_type):
        return any(
            grant_type == chk_grant_type
            for chk_grant_type in self.grant_type
        )

    access_groups: List[str]


class ClientUserCache(BaseCollection):
    __indexes__ = [
        IndexModel([('client_id', ASCENDING), ('user_id', ASCENDING)]),
    ]
    __collection_name__ = 'client_user_cache'

    id: str = Field(..., alias='_id')

    client_id: str
    user_id: str

    groups: List[str]

    last_modified: int


class UserGroup(BaseCollection):
    __indexes__ = [
        IndexModel([('member_groups', ASCENDING)]),
        IndexModel([('members', ASCENDING)]),
    ]
    __collection_name__ = 'client_access'

    id: str = Field(..., alias='_id')

    group_name: str

    member_groups: List[str] = []
    members: List[str] = []


class User(BaseCollection):
    __indexes__ = [
        IndexModel([('email', HASHED)]),
    ]
    __collection_name__ = 'user'

    id: str = Field(..., alias='_id')

    password: Optional[str] = None

    is_new: bool = True
    mail_verified: bool = False

    email: str

    phone_number: Optional[str] = None
    phone_number_verified: bool = False

    name: str
    family_name: str
    given_name: str
    nickname: Optional[str]

    @property
    def preferred_username(self) -> str:
        return self.email

    profile: Optional[str]
    picture: Optional[str]
    website: Optional[str]

    birthdate: Optional[str]

    locale: Optional[str]
    updated_at: Optional[datetime]

    groups: List[str] = []
