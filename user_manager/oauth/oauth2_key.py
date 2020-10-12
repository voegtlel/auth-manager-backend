from typing import List, Any, Optional, cast

from authlib.jose import jwk as _jwk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_der_private_key
from pydantic import BaseModel

from user_manager.common.config import KeyConfig, config, KeyUse, KeyAlgorithm


class JSONWebKey(BaseModel):
    kty: str
    use: KeyUse
    key_ops: List[str]
    alg: KeyAlgorithm
    kid: str

    # OCT
    k: Optional[str]
    # RSA
    n: Optional[str]
    e: Optional[str]
    # EC
    crv: Optional[str]
    x: Optional[str]
    y: Optional[str]


class JSONWebKeySet(BaseModel):
    keys: List[JSONWebKey]


class Key(dict):

    def __init__(self, private_key: Any, kid: str):
        super().__init__(kid=kid)
        self.private_key = private_key

    def __call__(self, *args, **kwargs):
        return self.private_key


class KeyData:

    def __init__(self, jwk: JSONWebKey, private_key: Any, publish: bool):
        self.jwk = jwk
        self.private_key = private_key
        self.key = Key(private_key, jwk.kid)
        self.publish = publish


def load_key(key_config: KeyConfig) -> KeyData:
    algorithm = key_config.algorithm.value
    if key_config.key_file is not None:
        with open(key_config.key_file, 'rb') as rf:
            key_data = rf.read()

        if key_data.startswith(b'-----BEGIN'):
            private_key = load_pem_private_key(key_data, key_config.password, default_backend())
            public_key = private_key.public_key()
        else:
            private_key = load_der_private_key(key_data, key_config.password, default_backend())
            public_key = private_key.public_key()
    elif key_config.key is not None:
        if algorithm.startswith('HS'):
            private_key = key_config.key
            public_key = private_key
        elif key_config.key.startswith('-----BEGIN'):
            private_key = load_pem_private_key(cast(Any, key_config.key), key_config.password, default_backend())
            public_key = private_key.public_key()
        else:
            raise ValueError("key invalid")
    else:
        raise ValueError("Need key or key_file")
    if algorithm.startswith('RS'):
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError(f"Need rsa private key for {algorithm}")
    if algorithm.startswith('DS'):
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ValueError(f"Need elliptic curve private key for {algorithm}")

    if key_config.use == KeyUse.sig:
        key_ops = ['verify']
    elif key_config.use == KeyUse.enc:
        key_ops = ['decrypt', 'unwrapKey']
    else:
        key_ops = []

    return KeyData(
        jwk=JSONWebKey(
            alg=algorithm, use=key_config.use, kid=key_config.id, key_ops=key_ops, **_jwk.dumps(public_key)
        ),
        private_key=private_key,
        publish=key_config.publish,
    )


keys = [
    load_key(key_config)
    for key_config in config.oauth2.keys
]

key = keys[0]

jwks = JSONWebKeySet(keys=[key.jwk for key in keys])

supported_alg_sig = [key.jwk.alg.value for key in keys if key.jwk.use == KeyUse.sig]
