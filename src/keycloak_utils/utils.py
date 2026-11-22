from __future__ import annotations

import logging
import typing
from functools import wraps

import jwt

from .errors import JWTDecodeError

log = logging.getLogger(__name__)

# A refused issuer is logged, cut to this length (it comes from the token).
_LOGGED_ISSUER_MAX_LENGTH = 200


def verify_token(
    access_token: str,
    public_key: str,
    algorithms: list[str],
    audience: str,
    issuer: typing.Optional[typing.Union[str, typing.Sequence[str]]] = None,
) -> dict:
    """
    Verifies a token with Keycloak and returns the validated claims.

    The token must carry ``exp``. ``issuer`` is the accepted ``iss`` value, or a
    list of them; ``None`` skips the issuer check. The token verifiers always pass
    one: the realm URL the public key comes from, or ``KC_UTILS_KC_ISSUER``.
    """
    required = ["exp"]
    if audience is not None:
        required.append("aud")
    try:
        claims = jwt.decode(
            access_token,
            key=public_key,
            algorithms=algorithms,
            audience=audience,
            options={"require": required},
        )
    except jwt.InvalidTokenError as e:
        raise JWTDecodeError(str(e)) from e
    if issuer is not None:
        check_issuer(claims.get("iss"), issuer)
    return claims


def check_issuer(
    received: typing.Any,
    expected: typing.Union[str, typing.Sequence[str]],
) -> None:
    """
    Refuse a token whose ``iss`` is not one of ``expected``.

    The log names the expected and the received issuer, never the token.
    """
    accepted = [expected] if isinstance(expected, str) else list(expected)
    if isinstance(received, str) and received in accepted:
        return
    if isinstance(received, str):
        received = received[:_LOGGED_ISSUER_MAX_LENGTH]
    log.warning(
        "Keycloak sign-in refused: issuer %r is not the expected %s. "
        "Set KC_UTILS_KC_ISSUER if the public issuer differs from the key URL.",
        received,
        " or ".join(accepted),
    )
    raise JWTDecodeError("Invalid issuer")


def schema_based(func=None, *, schema=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            from django.db import connection
            from django_tenants.utils import get_tenant_model

            from .contrib.django.conf import KC_UTILS_TENANT_SCHEMA

            is_postgres = connection.vendor == "postgresql"
            if not is_postgres:
                return func(*args, **kwargs)

            resolved_schema = schema if schema is not None else KC_UTILS_TENANT_SCHEMA
            TenantModel = get_tenant_model()
            if (
                not TenantModel.objects.filter(schema_name=resolved_schema).exists()
                and resolved_schema != "public"
            ):
                raise RuntimeError(
                    f"TENANT_SCHEMA '{resolved_schema}' is not a valid tenant schema.",
                )

            connection.set_schema(resolved_schema)

            try:
                return func(*args, **kwargs)
            finally:
                connection.set_schema_to_public()

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator
