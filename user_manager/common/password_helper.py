from typing import Tuple, Optional

from passlib.context import CryptContext

from user_manager.common.config import config

pwned_password_check = False
if 'pwned_password_check' in config.oauth2.password:
    pwned_password_check = config.oauth2.password['pwned_password_check']
    del config.oauth2.password['pwned_password_check']
crypt_context = CryptContext(**config.oauth2.password)


class PasswordLeakedException(Exception):
    pass


def create_password(password: str, skip_password_check: bool = False) -> str:
    if not skip_password_check:
        if pwned_password_check:
            import pwnedpasswords
            if pwnedpasswords.check(password, plain_text=True):
                raise PasswordLeakedException()
    return crypt_context.hash(password)


def verify_and_update(check_password: str, password_hash: str) -> Tuple[bool, Optional[str]]:
    return crypt_context.verify_and_update(check_password, password_hash)
