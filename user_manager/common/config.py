import io
import os
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Union, List, Optional

import oyaml as yaml
from pydantic import BaseModel


def camelcase_to_underscore(camelcase: str) -> str:
    res = ''
    last_was_upper = True
    for i in range(len(camelcase)):
        if camelcase[i].isupper() and not last_was_upper:
            res += '_' + camelcase[i].lower()
        else:
            res += camelcase[i]
            last_was_upper = False
    return res


def config_to_underscore(cfg):
    if isinstance(cfg, dict):
        return {
            camelcase_to_underscore(key): config_to_underscore(value)
            for key, value in cfg.items()
        }
    return cfg


def _assign_key(cfg: Dict[str, Union[dict, Any]], key: str, value: Any, self_path: str):
    found_key = None
    found_key_underscore = None
    first_part = key.split('_', 1)[0]
    for cfg_key in cfg.keys():
        if cfg_key.startswith(first_part):
            if key.startswith(cfg_key):
                found_key = cfg_key
                found_key_underscore = cfg_key
    if found_key is None:
        raise ValueError("Cannot find {} in {}".format(key, self_path))
    if found_key_underscore == key:
        cfg[found_key] = value
    else:
        _assign_key(
            cfg[found_key],
            key[len(found_key_underscore)+1:],
            value,
            self_path + '_' + found_key_underscore
        )


class OAuthFieldType(Enum):
    string = str
    integer = int
    boolean = bool
    datetime = datetime


class UserPropertyType(Enum):
    str = 'str'
    password = 'password'
    datetime = 'datetime'
    bool = 'bool'
    picture = 'picture'
    enum = 'enum'


class CanEditType(Enum):
    self = 'self'
    admin = 'admin'


class EnumValue(BaseModel):
    value: str
    title: str


class UserProperty(BaseModel):
    type: UserPropertyType = ...
    format: Optional[str]
    can_edit: Optional[CanEditType]
    title: Optional[str]
    values: Optional[List[EnumValue]]
    pwned_password_check: bool = True
    template: Optional[str]


class UserScopes(BaseModel):
    properties: Dict[str, UserProperty]
    scopes: Dict[str, List[str]]
    password: Dict[str, Any]


class MongoConfig(BaseModel):
    uri: str = ...


class KeyAlgorithm(Enum):
    HS256 = 'HS256'
    RS256 = 'RS256'
    DS256 = 'DS256'


class KeyUse(Enum):
    sig = 'sig'
    enc = 'enc'


class KeyConfig(BaseModel):
    key_file: Optional[str] = None
    key: Optional[str] = None
    algorithm: KeyAlgorithm = ...
    password: Optional[str] = None
    use: KeyUse = KeyUse.sig
    publish: bool = False
    id: Optional[str] = None


class OAuth2TokenExpiration(BaseModel):
    authorization_code: int = 60 * 60 * 24
    implicit: int = 60*60
    refresh_token: int = 60*60
    password: int = 60 * 60 * 24
    client_credentials: int = 60 * 60 * 24
    session: int = 60 * 60 * 24 * 365


class OAuth2ClientConfig(BaseModel):
    client_id: str
    client_secret: str
    request_token_url: Optional[str]
    request_token_params: Optional[str]
    access_token_url: Optional[str]
    access_token_params: Optional[str]
    refresh_token_url: Optional[str]
    refresh_token_params: Optional[str]
    authorize_url: Optional[str]
    authorize_params: Optional[str]
    api_base_url: Optional[str]
    server_metadata_url: Optional[str]


class OAuth2Config(BaseModel):
    base_url: str

    keys: List[KeyConfig] = ...
    issuer: str = ...

    token_expiration: OAuth2TokenExpiration = OAuth2TokenExpiration()

    token_length: int = ...
    authorization_code_length: int = ...

    user: UserScopes = ...


class ManagerConfig(BaseModel):
    secret_key: str = ...
    backend_base_url: str = ...
    frontend_base_url: str = ...
    oauth2: OAuth2ClientConfig


class Config(BaseModel):
    mongo: MongoConfig
    oauth2: OAuth2Config
    manager: ManagerConfig

    @staticmethod
    def load(config_file: str = 'config.yaml', env_prefix: str = 'api_config_') -> 'Config':
        with open(config_file, 'r') as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        config = config_to_underscore(config)
        for env_key, env_val in os.environ.items():
            lower_key = env_key.lower()
            if lower_key.startswith(env_prefix):
                lower_key = lower_key[len(env_prefix):]

                _assign_key(
                    config, lower_key, yaml.load(io.StringIO(env_val), Loader=yaml.SafeLoader), env_prefix[:-1]
                )
        return Config.validate(config)


config = Config.load()
