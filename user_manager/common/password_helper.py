from typing import Tuple, Optional

from passlib.context import CryptContext

from user_manager.common.config import config

crypt_context = CryptContext(**config.oauth2.user.password)


def create_password(password: str) -> str:
    return crypt_context.hash(password)


def verify_and_update(check_password: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    return crypt_context.verify_and_update(check_password, password_hash)
