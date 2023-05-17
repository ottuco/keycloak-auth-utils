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

    keyword = "Bearer"
    backend = DRFKeycloakAuthBackend
    AuthFailedError: Exception = AuthenticationFailed

    def get_or_create_user(self, claims: dict) -> User:
        raise NotImplementedError

    def authenticate(
        self,
        request: Request,
    ) -> typing.Optional[typing.Tuple[User, None]]:
        try:
            backend = self.backend(
                request,
                host=self.kc_host,
                realm=self.kc_realm,
                algorithms=self.kc_algorithms,
                audience=self.kc_audience,
            )
            claims = backend.authenticate()
        except self.backend.AuthError as e:
            raise self.AuthFailedError(e.msg)

        if not claims:
            return None

        user = self.get_or_create_user(claims=claims)
        return user, None

    def authenticate_header(self, request) -> str:
        return self.keyword
