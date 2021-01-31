from datetime import datetime
from typing import Optional

import pytz
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.oidc.core import AuthorizationCodeMixin
from pydantic import Field
from pymongo import IndexModel, HASHED, ASCENDING

from user_manager.common.models.base import BaseDocument


class DbAuthorizationCode(BaseDocument, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
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


class DbToken(BaseDocument, TokenMixin, AuthorizationCodeMixin):
    __indexes__ = [
        IndexModel([('refresh_token', HASHED)]),
        IndexModel([('expiration_time', ASCENDING)], expireAfterSeconds=0),
        IndexModel([('user_id', ASCENDING)]),
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
        return int(self.expiration_time.replace(tzinfo=pytz.UTC).timestamp())

    def get_redirect_uri(self):
        return None

    def get_nonce(self):
        return None

    def get_auth_time(self):
        return self.auth_time
