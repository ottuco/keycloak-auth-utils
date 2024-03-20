"""
OIDC authentication backends
"""

import logging
from typing import Any, Dict, Optional

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AbstractBaseUser
from django.http import HttpRequest
from django.urls import reverse
from requests import post as request_post

from . import conf
from ...backend.base import BaseKCAuthBackend
from ...manager.rest_framework import DjangoKeyManager
from ...verifier.rest_framework import DjangoTokenVerifier


log = logging.getLogger(__name__)


class AuthenticationBackend(BaseKCAuthBackend, ModelBackend):
    def __init__(self, *args, **kwargs) -> None:
        self.UserModel = get_user_model()
        self.request: Optional[HttpRequest] = None
        self.kc_host: str = conf.KC_HOST
        self.kc_realm: str = conf.KC_REALM
        self.kc_algorithms: list[str] = conf.KC_ALGORITHMS
        self.kc_audience: str = conf.KC_AUDIENCE
        self.auth_scheme: str = conf.AUTH_SCHEME
        self.manager = DjangoKeyManager
        self.verifier = DjangoTokenVerifier
        super().__init__(request=self.request, *args, **kwargs)

    def get_or_create_user(self, claims: Dict[str, Any]) -> AbstractBaseUser:
        email: str = claims.get("email", "")
        username: str = claims.get("preferred_username", "")
        first_name: str = claims.get("given_name", "")
        last_name: str = claims.get("family_name", "")
        roles: list[str] = claims.get("realm_access", {}).get("roles", [])
        is_superuser: bool = conf.USER_SUPERADMIN_ROLE in roles
        is_staff: bool = is_superuser

        user, created = self.UserModel.objects.get_or_create(
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

    def authenticate(
        self,
        request: HttpRequest,
        code: str,
        code_verifier: Optional[str] = None,
        **kwargs,
    ) -> Optional[AbstractBaseUser]:
        """Authenticates users using OpenID Connect Authorization code flow."""
        if not request or not code or not code_verifier:
            return None
        self.request = request

        params: Dict[str, str] = {
            "grant_type": "authorization_code",
            "client_id": conf.OIDC_RP_CLIENT_ID,
            "client_secret": conf.OIDC_RP_CLIENT_SECRET,
            "redirect_uri": request.build_absolute_uri(
                reverse(conf.OIDC_CALLBACK_URL_NAME)
            ),
            "code": code,
            "code_verifier": code_verifier,
        }

        try:
            resp = request_post(conf.OIDC_TOKEN_URL, data=params)
            resp.raise_for_status()
        except Exception as e:
            log.warning(f"Authentication request failed: {e}")
            return None

        result: Dict[str, Any] = resp.json()
        access_token: str = result.get("access_token", "")
        id_token: str = result.get("id_token", "")

        try:
            claims: Dict[str, Any] = self.verify_access_token(access_token)
            if not claims:
                return None
        except Exception as e:
            log.warning(f"Unable to verify and decode access token: {e}")
            return None

        user: AbstractBaseUser = self.get_or_create_user(claims)
        request.session["session_id_token"] = id_token
        request.session.save()
        return user
