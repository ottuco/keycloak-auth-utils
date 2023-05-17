import typing

from ..errors import JWTDecodeError, KeycloakError
from ..verifier.base import BaseTokenVerifier


def _safe_decode(s: typing.Union[bytes, str]) -> str:
    try:
        return s.decode()
    except AttributeError:
        return s


class BaseKCAuthBackend:
    kc_host: str
    kc_realm: str
    kc_algorithms: list[str]
    kc_audience: str

    verifier: typing.Type[BaseTokenVerifier]
    AuthError = KeycloakError
    token_type = "Bearer"

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
        self.kc_host = host or self.kc_host
        self.kc_realm = realm or self.kc_realm
        self.kc_algorithms = algorithms or self.kc_algorithms
        self.kc_audience = audience or self.kc_audience

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
        if token_type.lower() != self.token_type.lower():
            msg = "Invalid token type. Token type should be Bearer."
            raise self.AuthError(msg)

        return token

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

    def authenticate(self) -> typing.Optional[dict]:
        token = self.validate_auth_headers()
        if not token:
            # Could not find token in headers,
            # maybe some other authentication method is used
            return None

        return self.verify_access_token(token=token)
