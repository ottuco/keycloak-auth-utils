import typing

from ..errors import AuthInterruptedError, JWTDecodeError
from ..verifier.base import BaseTokenVerifier


def _safe_decode(s: typing.Union[bytes, str]) -> str:
    try:
        return s.decode()
    except AttributeError:
        return s


class APIAuthMixin:
    auth_scheme = "Bearer"

    def __init__(self, *args, auth_scheme: typing.Optional[str] = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_scheme = auth_scheme or self.auth_scheme

    def get_auth_header(self) -> bytes:
        try:
            # Django/DRF
            return self.request.META.get("HTTP_AUTHORIZATION", b"")
        except AttributeError:
            # FastAPI
            return self.request.headers.get("Authorization", b"")

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
        # decode
        token_type, token = _safe_decode(token_type), _safe_decode(token)
        if token_type.lower() != self.auth_scheme.lower():
            # The auth scheme must support arbitrary token types,
            # it could be `Bearer`, `JWT`, `Basic`, `Token` etc.
            return None

        return token

    def get_access_token(self, *args, **kwargs) -> str:
        return self.validate_auth_headers()


class BaseKCAuthBackend:
    kc_host: str
    kc_realm: str
    kc_algorithms: list[str]
    kc_audience: str

    verifier: typing.Type[BaseTokenVerifier]
    AuthError = AuthInterruptedError

    def __init__(
        self,
        request,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
        algorithms: typing.Optional[list[str]] = None,
        audience: typing.Optional[str] = None,
        *args,
        **kwargs,
    ):
        self.request = request
        self.kc_host = host or self.get_kc_host()
        self.kc_realm = realm or self.get_kc_realm()
        self.kc_algorithms = algorithms or self.get_kc_algorithms()
        self.kc_audience = audience or self.get_kc_audience()

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

    def post_authenticate_hooks(self, claims: dict) -> dict:
        """
        This method is called after obtaining the claims from the token.
        """
        return claims

    def verify_access_token(self, token: str) -> dict:
        try:
            verifier = self.verifier(
                access_token=token,
                host=self.kc_host,
                realm=self.kc_realm,
                algorithms=self.kc_algorithms,
                audience=self.kc_audience,
            )
            claims = verifier.get_claims()
            return self.post_authenticate_hooks(claims)
        except JWTDecodeError as e:
            raise self.AuthError(e)

    def get_access_token(self, *args, **kwargs) -> str:
        raise NotImplementedError

    def authenticate(self, *args, **kwargs) -> typing.Optional[dict]:
        token = self.get_access_token(*args, **kwargs)
        if not token:
            # Could not find token in headers,
            # maybe some other authentication method is used
            return None

        return self.verify_access_token(token=token)
