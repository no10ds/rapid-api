import jwt
from jwt import PyJWKClient

from api.domain.token import Token
from api.common.config.auth import (
    COGNITO_JWKS_URL,
)

jwks_client = PyJWKClient(COGNITO_JWKS_URL)


def parse_token(token: str) -> Token:
    payload = _get_validated_token_payload(token)
    return Token(payload)


def _get_validated_token_payload(token):
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    return jwt.decode(token, signing_key.key, algorithms=["RS256"])
