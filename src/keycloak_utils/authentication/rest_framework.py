import typing

from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication as DRFBaseAuth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request

from ..backend.rest_framework import DRFKeycloakAuthBackend

User = get_user_model()


class BaseDRFKCAuthentication(DRFBaseAuth):
    kc_host: str
    kc_realm: str
    kc_algorithms: list[str]
    kc_audience: str

    auth_scheme = "Bearer"
    backend = DRFKeycloakAuthBackend
    AuthFailedError: Exception = AuthenticationFailed

    def get_or_create_user(self, claims: dict) -> User:
        raise NotImplementedError

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
