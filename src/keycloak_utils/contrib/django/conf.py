from typing import List
from django.conf import settings


KC_HOST: str = getattr(settings, "KC_HOST", "")
KC_REALM: str = getattr(settings, "KC_REALM", "")
KC_ALGORITHMS: List[str] = getattr(settings, "KC_ALGORITHMS", ["RS256"])
KC_AUDIENCE: str = getattr(settings, "KC_AUDIENCE", "")
AUTH_SCHEME: str = getattr(settings, "AUTH_SCHEME", "Bearer")

OIDC_AUTHORIZATION_URL: str = getattr(settings, "OIDC_AUTHORIZATION_URL", "")
if not OIDC_AUTHORIZATION_URL:
    OIDC_AUTHORIZATION_URL = (
        f"{KC_HOST}/auth/realms/{KC_REALM}/protocol/openid-connect/auth"
    )

OIDC_END_SESSION_URL: str = getattr(settings, "OIDC_END_SESSION_URL", "")
if not OIDC_END_SESSION_URL:
    OIDC_END_SESSION_URL = (
        f"{KC_HOST}/auth/realms/{KC_REALM}/protocol/openid-connect/logout"
    )

OIDC_TOKEN_URL: str = getattr(settings, "OIDC_TOKEN_URL", "")
if not OIDC_TOKEN_URL:
    OIDC_TOKEN_URL = f"{KC_HOST}/auth/realms/{KC_REALM}/protocol/openid-connect/token"

# Redirect field query parameter name
OIDC_REDIRECT_OK_FIELD_NAME: str = getattr(
    settings, "OIDC_REDIRECT_OK_FIELD_NAME", "next"
)
OIDC_REDIRECT_ERROR_FIELD_NAME: str = getattr(
    settings, "OIDC_REDIRECT_ERROR_FIELD_NAME", "error"
)

# OIDC Client id and Secret
OIDC_RP_CLIENT_ID: str = getattr(settings, "OIDC_RP_CLIENT_ID", "")
OIDC_RP_CLIENT_SECRET: str = getattr(settings, "OIDC_RP_CLIENT_SECRET", "")

OIDC_RP_SCOPES: List[str] = getattr(
    settings, "OIDC_RP_SCOPES", ["openid", "email", "profile", "offline_access"]
)
OIDC_USE_PKCE: bool = getattr(settings, "OIDC_USE_PKCE", True)
OIDC_RANDOM_SIZE: int = getattr(settings, "OIDC_RANDOM_SIZE", 32)
OIDC_CALLBACK: str = getattr(settings, "oidc_callback", "callback")

# OIDC url name
OIDC_CALLBACK_URL_NAME: str = getattr(
    settings, "OIDC_CALLBACK_URL_NAME", "oidc_callback"
)
OIDC_AUTHENTICATE_URL_NAME: str = getattr(
    settings, "OIDC_AUTHENTICATE_URL_NAME", "oidc_authentication"
)
OIDC_LOGOUT_URL_NAME: str = getattr(settings, "OIDC_LOGOUT_URL_NAME", "oidc_logout")

SESSION_ENGINE: str = getattr(settings, "SESSION_ENGINE", "")
USER_SUPERADMIN_ROLE: str = getattr(settings, "USER_SUPERADMIN_ROLE", "super_admin")
