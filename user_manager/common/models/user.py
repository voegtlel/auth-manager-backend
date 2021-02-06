from typing import List, Optional

from pydantic import Field, Extra
from pymongo import IndexModel, HASHED, ASCENDING

from user_manager.common.models.base import BaseSubDocument, BaseDocument


class DbUserPasswordAccessToken(BaseSubDocument):
    id: str
    description: str
    token: str


class DbUser(BaseDocument):

    class Config:
        extra = Extra.allow

    __indexes__ = [
        IndexModel([('email', ASCENDING)], unique=True),
        IndexModel([('card_id', ASCENDING)], unique=True, sparse=True),
        IndexModel([('preferred_username', ASCENDING)], unique=True),
        IndexModel([('registration_token', HASHED)]),
        IndexModel([('email_verification_token', HASHED)]),
        IndexModel([('password_reset_token', HASHED)]),
        IndexModel([('groups', ASCENDING)]),
        IndexModel([('access_tokens.token', ASCENDING)]),
    ]
    __collection_name__ = 'user'

    id: str = Field(..., alias='_id')
    notes: Optional[str] = Field(None, max_length=1024 * 1024)

    password: Optional[str] = None
    password_reset_token: Optional[str] = None

    active: bool = False

    registration_token: Optional[str] = None

    email: str
    email_verified: bool = False
    email_verification_token: Optional[str] = None

    phone_number: Optional[str] = None
    phone_number_verified: bool = False

    preferred_username: Optional[str]
    given_name: Optional[str]
    family_name: Optional[str]

    picture: Optional[str]

    locale: Optional[str]
    zoneinfo: Optional[str]
    updated_at: Optional[int]

    access_tokens: List[DbUserPasswordAccessToken] = []

    groups: List[str] = []
    email_allowed_forward_groups: List[str] = []
    email_forward_groups: List[str] = []
    email_postbox_access_groups: List[str] = []
    email_postbox_access_token: Optional[str]
    has_email_alias: Optional[bool]
    has_postbox: Optional[bool]
    postbox_quota: Optional[int]
    forward_emails: Optional[bool]
