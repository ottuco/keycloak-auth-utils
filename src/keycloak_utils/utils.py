import jwt

from .errors import JWTDecodeError


def verify_token(
    access_token: str,
    public_key: str,
    algorithms: list[str],
    audience: str,
) -> dict:
    """
    Verifies a token with Keycloak and returns the validated claims
    """
    try:
        return jwt.decode(
            access_token,
            key=public_key,
            algorithms=algorithms,
            audience=audience,
        )
    except jwt.InvalidTokenError as e:
        raise JWTDecodeError(str(e))
