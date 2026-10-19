"""
OIDC authentication backends
"""

from django.contrib.auth import get_user_model
from django.urls import reverse

from ...authentication.rest_framework import BaseKCSSODjangoAuthBackend
from ...backend.rest_framework import DjangoKeycloakSSOAuthBackend as SSOAuthBackend
from . import conf

User = get_user_model()


def stored_username(claims: dict) -> str:
    """
    Return the username to look up the token's user by.

    Keycloak lowercases usernames, so a Django user saved as "Sara.K" signs
    in as "sara.k". Use the exact spelling if a user has it, else the user
    that matches ignoring case (lowest pk), else the token's username.
    Superadmin tokens (staff, services) match exactly only, so they never
    take a look-alike user someone created.
    """
    username: str = claims.get("preferred_username", "")
    roles: list[str] = claims.get("realm_access", {}).get("roles", [])
    if (
        not username
        or conf.KC_UTILS_USER_SUPERADMIN_ROLE in roles
        or User.objects.filter(username=username).exists()
    ):
        return username
    stored = (
        User.objects.filter(username__iexact=username)
        .order_by("pk")
        .values_list("username", flat=True)
        .first()
    )
    return stored or username


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

    def post_authenticate_hooks(self, claims: dict) -> dict:
        """
        This method is called after obtaining the claims from the token.
        Set the idp_provider from claims to django session.
        """
        self.request.session["idp_provider"] = claims.get("idp_provider", "keycloak")
        return claims


class AuthenticationBackend(BaseKCSSODjangoAuthBackend):
    kc_host = conf.KC_UTILS_KC_HOST
    kc_realm = conf.KC_UTILS_KC_REALM
    kc_algorithms = conf.KC_UTILS_KC_ALGORITHMS
    kc_audience = conf.KC_UTILS_KC_AUDIENCE
    backend = KCUtilsSSOBackend

    def get_or_create_user(self, claims: dict) -> User:
        email: str = claims.get("email", "")
        username: str = stored_username(claims)
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
