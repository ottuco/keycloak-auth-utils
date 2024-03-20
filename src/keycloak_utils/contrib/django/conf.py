from typing import List
from django.conf import settings


KC_UTILS_KC_HOST: str = getattr(settings, "KC_UTILS_KC_HOST", "")
KC_UTILS_KC_REALM: str = getattr(settings, "KC_UTILS_KC_REALM", "")
KC_UTILS_KC_ALGORITHMS: List[str] = getattr(
    settings, "KC_UTILS_KC_ALGORITHMS", ["RS256"]
)
KC_UTILS_KC_AUDIENCE: str = getattr(settings, "KC_UTILS_KC_AUDIENCE", "")
KC_UTILS_AUTH_SCHEME: str = getattr(settings, "KC_UTILS_AUTH_SCHEME", "Bearer")

KC_UTILS_OIDC_AUTHORIZATION_URL: str = getattr(
    settings, "KC_UTILS_OIDC_AUTHORIZATION_URL", ""
)
if not KC_UTILS_OIDC_AUTHORIZATION_URL:
    KC_UTILS_OIDC_AUTHORIZATION_URL = f"{KC_UTILS_KC_HOST}/auth/realms/{KC_UTILS_KC_REALM}/protocol/openid-connect/auth"

KC_UTILS_OIDC_END_SESSION_URL: str = getattr(
    settings, "KC_UTILS_OIDC_END_SESSION_URL", ""
)
if not KC_UTILS_OIDC_END_SESSION_URL:
    KC_UTILS_OIDC_END_SESSION_URL = f"{KC_UTILS_KC_HOST}/auth/realms/{KC_UTILS_KC_REALM}/protocol/openid-connect/logout"

KC_UTILS_OIDC_TOKEN_URL: str = getattr(settings, "KC_UTILS_OIDC_TOKEN_URL", "")
if not KC_UTILS_OIDC_TOKEN_URL:
    KC_UTILS_OIDC_TOKEN_URL = f"{KC_UTILS_KC_HOST}/auth/realms/{KC_UTILS_KC_REALM}/protocol/openid-connect/token"

# Redirect field query parameter name
KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME: str = getattr(
    settings, "KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME", "next"
)
KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME: str = getattr(
    settings, "KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME", "error"
)

# OIDC Client id and Secret
KC_UTILS_OIDC_RP_CLIENT_ID: str = getattr(settings, "KC_UTILS_OIDC_RP_CLIENT_ID", "")
KC_UTILS_OIDC_RP_CLIENT_SECRET: str = getattr(
    settings, "KC_UTILS_OIDC_RP_CLIENT_SECRET", ""
)

KC_UTILS_OIDC_RP_SCOPES: List[str] = getattr(
    settings,
    "KC_UTILS_OIDC_RP_SCOPES",
    ["openid", "email", "profile", "offline_access"],
)
KC_UTILS_OIDC_USE_PKCE: bool = getattr(settings, "KC_UTILS_OIDC_USE_PKCE", True)
KC_UTILS_OIDC_RANDOM_SIZE: int = getattr(settings, "KC_UTILS_OIDC_RANDOM_SIZE", 32)
KC_UTILS_OIDC_CALLBACK: str = getattr(settings, "KC_UTILS_OIDC_CALLBACK", "callback")

# OIDC url name
KC_UTILS_OIDC_CALLBACK_URL_NAME: str = getattr(
    settings, "KC_UTILS_OIDC_CALLBACK_URL_NAME", "oidc_callback"
)
KC_UTILS_OIDC_AUTHENTICATE_URL_NAME: str = getattr(
    settings, "KC_UTILS_OIDC_AUTHENTICATE_URL_NAME", "oidc_authentication"
)
KC_UTILS_OIDC_LOGOUT_URL_NAME: str = getattr(
    settings, "KC_UTILS_OIDC_LOGOUT_URL_NAME", "oidc_logout"
)

KC_UTILS_SESSION_ENGINE: str = getattr(settings, "SESSION_ENGINE", "")
KC_UTILS_USER_SUPERADMIN_ROLE: str = getattr(
    settings, "KC_UTILS_USER_SUPERADMIN_ROLE", "super_admin"
)
