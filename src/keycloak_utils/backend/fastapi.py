import typing

from ..verifier.fastapi import AsyncFastAPITokenVerifier, FastAPITokenVerifier
from ..errors import JWTDecodeError
from .base import APIAuthMixin, BaseKCAuthBackend


class AsyncFastAPIKeycloakAuthBackend:
    """Async Keycloak authentication backend for FastAPI."""

    def __init__(
        self,
        request,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
        algorithms: typing.Optional[list[str]] = None,
        audience: typing.Optional[str] = None,
        auth_scheme: typing.Optional[str] = None,
        *args,
        **kwargs,
    ):
        self.request = request
        self.kc_host = host or self.get_kc_host()
        self.kc_realm = realm or self.get_kc_realm()
        self.kc_algorithms = algorithms or self.get_kc_algorithms()
        self.kc_audience = audience or self.get_kc_audience()
        self.auth_scheme = auth_scheme or "Bearer"

        from ..errors import AuthInterruptedError

        self.AuthError = AuthInterruptedError

    def get_kc_audience(self) -> str:
        try:
            return self.kc_audience
        except AttributeError:
            msg = (
                f"'{self.__class__.__name__}' should either include a "
                f"`kc_audience` attribute, or override the "
                f"`get_kc_audience()` method."
            )
            raise NotImplementedError(msg)

    def get_kc_algorithms(self) -> list[str]:
        try:
            return self.kc_algorithms
        except AttributeError:
            msg = (
                f"'{self.__class__.__name__}' should either include a "
                f"`kc_algorithms` attribute, or override the "
                f"`get_kc_algorithms()` method."
            )
            raise NotImplementedError(msg)

    def get_kc_host(self) -> str:
        try:
            return self.kc_host
        except AttributeError:
            msg = (
                f"'{self.__class__.__name__}' should either include a "
                f"`kc_host` attribute, or override the "
                f"`get_kc_host()` method."
            )
            raise NotImplementedError(msg)

    def get_kc_realm(self) -> str:
        try:
            return self.kc_realm
        except AttributeError:
            msg = (
                f"'{self.__class__.__name__}' should either include a "
                f"`kc_realm` attribute, or override the "
                f"`get_kc_realm()` method."
            )
            raise NotImplementedError(msg)

    def get_auth_header(self) -> str:
        return self.request.headers.get("Authorization", "")

    def validate_auth_headers(self) -> typing.Optional[str]:
        headers = self.get_auth_header().split()
        if len(headers) == 0:
            return None
        elif len(headers) == 1:
            msg = "Invalid token header. No credentials provided."
            raise self.AuthError(msg)
        elif len(headers) > 2:
            msg = "Invalid token header. Token string should not contain spaces."
            raise self.AuthError(msg)

        token_type, token = headers
        if token_type.lower() != self.auth_scheme.lower():
            return None
        return token

    def get_access_token(self) -> str:
        return self.validate_auth_headers()

    async def verify_access_token(self, token: str) -> dict:
        try:
            verifier = AsyncFastAPITokenVerifier(
                access_token=token,
                host=self.kc_host,
                realm=self.kc_realm,
                algorithms=self.kc_algorithms,
                audience=self.kc_audience,
            )
            claims = await verifier.get_claims()
            return await self.post_authenticate_hooks(claims)
        except JWTDecodeError as e:
            raise self.AuthError(e)

    async def post_authenticate_hooks(self, claims: dict) -> dict:
        return claims

    async def authenticate(self) -> typing.Optional[dict]:
        token = self.get_access_token()
        if not token:
            return None
        return await self.verify_access_token(token=token)


class FastAPIKeycloakAuthBackend(APIAuthMixin, BaseKCAuthBackend):
    verifier = FastAPITokenVerifier
