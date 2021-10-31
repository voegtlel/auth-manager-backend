import pyotp
from authlib.common.security import generate_token

from user_manager.common.config import config
from user_manager.common.models.user import TwoFactorType, DbUserTwoFactor

totp = pyotp.TOTP(config.oauth2.totp_secret, name=config.oauth2.otp_name, issuer=config.manager.name)
hotp = pyotp.HOTP(config.oauth2.hotp_secret, name=config.oauth2.otp_name, issuer=config.manager.name)


def twofactor_init(two_factor_type: TwoFactorType, name: str) -> DbUserTwoFactor:
    if two_factor_type == TwoFactorType.hotp:
        secret = pyotp.random_base32(length=config.auth2.otp_size)
        return DbUserTwoFactor(id=generate_token(), name=name, type=two_factor_type, secret=secret, counter=0)
    elif two_factor_type == TwoFactorType.totp:
        secret = pyotp.random_base32(length=config.auth2.otp_size)
        return DbUserTwoFactor(id=generate_token(), name=name, type=two_factor_type, secret=secret)
    elif two_factor_type == TwoFactorType.email:
        return DbUserTwoFactor(id=generate_token(), name=name, type=two_factor_type)
    elif two_factor_type == TwoFactorType.webauthn:
        return DbUserTwoFactor(id=generate_token(), name=name, type=two_factor_type)

