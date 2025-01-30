"""
OIDC authentication backends
"""

from django.contrib.auth import get_user_model
from django.urls import reverse

from ...authentication.rest_framework import BaseKCSSODjangoAuthBackend
from ...backend.rest_framework import DjangoKeycloakSSOAuthBackend as SSOAuthBackend
from . import conf

User = get_user_model()


class KCUtilsSSOBackend(SSOAuthBackend):
    def get_token_request_payload(self) -> dict:
        return {
            "grant_type": "authorization_code",
            "client_id": conf.KC_UTILS_OIDC_RP_CLIENT_ID,
            "client_secret": conf.KC_UTILS_OIDC_RP_CLIENT_SECRET,
            "redirect_uri": self.request.build_absolute_uri(
                reverse(conf.KC_UTILS_OIDC_CALLBACK_URL_NAME),
            ),
            "code": self.auth_code,
            "code_verifier": self.auth_code_verifier,
        }


class AuthenticationBackend(BaseKCSSODjangoAuthBackend):
    kc_host = conf.KC_UTILS_KC_HOST
    kc_realm = conf.KC_UTILS_KC_REALM
    kc_algorithms = conf.KC_UTILS_KC_ALGORITHMS
    kc_audience = conf.KC_UTILS_KC_AUDIENCE
    backend = KCUtilsSSOBackend

    def get_or_create_user(self, claims: dict) -> User:
        email: str = claims.get("email", "")
        username: str = claims.get("preferred_username", "")
        first_name: str = claims.get("given_name", "")
        last_name: str = claims.get("family_name", "")
        roles: list[str] = claims.get("realm_access", {}).get("roles", [])
        is_superuser: bool = conf.KC_UTILS_USER_SUPERADMIN_ROLE in roles
        is_staff: bool = is_superuser

        user, _ = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "is_staff": is_staff,
                "is_superuser": is_superuser,
                "is_active": True,
            },
        )
        return user

    def get_user(self, user_id):
        try:
            user = User.objects.get(pk=user_id)
            return user
        except User.DoesNotExist:
            return None
