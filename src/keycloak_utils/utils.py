import jwt
from functools import wraps
from django.db import connection

from .contrib.django.conf import KC_UTILS_TENANT_SCHEMA
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


def schema_based(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        is_postgres = connection.vendor == "postgresql"
        if not is_postgres:
            return func(*args, **kwargs)

        from django_tenants.utils import get_tenant_model

        schema = KC_UTILS_TENANT_SCHEMA
        TenantModel = get_tenant_model()
        if (
            not TenantModel.objects.filter(schema_name=schema).exists()
            and schema != "public"
        ):
            raise RuntimeError(
                f"TENANT_SCHEMA '{schema}' is not a valid tenant schema."
            )

        connection.set_schema(schema)

        try:
            return func(*args, **kwargs)
        finally:
            connection.set_schema_to_public()

    return wrapper
