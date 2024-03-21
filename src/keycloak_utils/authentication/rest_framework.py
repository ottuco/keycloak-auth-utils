import typing

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend as DjangoBaseAuth
from django.http import HttpRequest
from rest_framework.authentication import BaseAuthentication as DRFBaseAuth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from ..backend.rest_framework import (
    DjangoKeycloakSSOAuthBackend,
    DRFKeycloakAuthBackend,
)

User = get_user_model()


class GetOrCreateUserMixin:
    def get_or_create_user(self, claims: dict) -> User:
        raise NotImplementedError


class BaseDRFKCAuthentication(GetOrCreateUserMixin, DRFBaseAuth):
    kc_host: str
    kc_realm: str
    kc_algorithms: list[str]
    kc_audience: str

    auth_scheme = "Bearer"
    backend = DRFKeycloakAuthBackend
    AuthFailedError: Exception = AuthenticationFailed

    def get_kc_host(self, request: Request) -> str:
        return self.kc_host

    def get_kc_realm(self, request: Request) -> str:
        return self.kc_realm

    def get_kc_algorithms(self, request: Request) -> list[str]:
        return self.kc_algorithms

    def get_kc_audience(self, request: Request) -> str:
        return self.kc_audience

    def get_auth_scheme(self, request: Request) -> str:
        return self.auth_scheme

    def authenticate(
        self,
        request: Request,
    ) -> typing.Optional[typing.Tuple[User, None]]:
        try:
            backend = self.backend(
                request,
                host=self.get_kc_host(request),
                realm=self.get_kc_realm(request),
                algorithms=self.get_kc_algorithms(request),
                audience=self.get_kc_audience(request),
                auth_scheme=self.get_auth_scheme(request),
            )
            claims = backend.authenticate()
        except self.backend.AuthError as e:
            raise self.AuthFailedError(e.msg)

        if not claims:
            return None

        user = self.get_or_create_user(claims=claims)
        return user, None

    def authenticate_header(self, request) -> str:
        return self.auth_scheme


class BaseKCSSODjangoAuthBackend(GetOrCreateUserMixin, DjangoBaseAuth):
    kc_host: str
    kc_realm: str
    kc_algorithms: list[str]
    kc_audience: str

    backend = DjangoKeycloakSSOAuthBackend

    def authenticate(
        self,
        request: HttpRequest,
        code: typing.Optional[str] = None,
        code_verifier: typing.Optional[str] = None,
        *args,
        **kwargs,
    ) -> typing.Optional[User]:
        if not all([request, code, code_verifier]):
            # `request`, `code` and `code_verifier` are required
            # They are set as optional to match the signature of the
            # `authenticate` method in the base class
            return None

        try:
            backend = self.backend(
                request,
                host=self.kc_host,
                realm=self.kc_realm,
                algorithms=self.kc_algorithms,
                audience=self.kc_audience,
                auth_code=code,
                auth_code_verifier=code_verifier,
            )
            claims = backend.authenticate()
        except self.backend.AuthError:
            return None

        user = self.get_or_create_user(claims=claims)
        return user
