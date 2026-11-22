import typing
from functools import lru_cache

from ..manager.base import BasePublicKeyManager
from ..utils import verify_token

IssuerSetting = typing.Optional[typing.Union[str, typing.Sequence[str]]]


_ISSUER_SETTING_ERROR = (
    "KC_UTILS_KC_ISSUER (the issuer argument) must be a string or a list of "
    "non-empty strings, got {kind}."
)


def expected_issuers(issuer: IssuerSetting, realm: str, host: str) -> list[str]:
    """
    The ``iss`` values a token may carry.

    Without an override it is the realm URL the public key is fetched from
    (``https://<host>/auth/realms/<realm>``), so a working setup keeps working.
    A trailing slash in the host is dropped and the host is also accepted in
    lower case, as Keycloak writes it. An override is one issuer or a list;
    ``{realm}`` in it becomes the realm.
    """
    if not issuer:
        host = (host or "").strip().rstrip("/")
        built = [f"https://{name}/auth/realms/{realm}" for name in (host, host.lower())]
        return list(dict.fromkeys(built))
    if isinstance(issuer, str):
        items = [issuer]
    elif isinstance(issuer, (list, tuple)):
        items = list(issuer)
    else:
        raise TypeError(_ISSUER_SETTING_ERROR.format(kind=type(issuer).__name__))
    for item in items:
        if not isinstance(item, str) or not item.strip():
            kind = f"an item of type {type(item).__name__}"
            raise TypeError(_ISSUER_SETTING_ERROR.format(kind=kind))
    return [item.replace("{realm}", realm) for item in items]


class BaseTokenVerifier:
    manager: typing.Type[BasePublicKeyManager]

    def __init__(
        self,
        access_token: str,
        host: str,
        realm: str,
        algorithms: list[str],
        audience: str,
        issuer: IssuerSetting = None,
    ):
        self.access_token = access_token
        self.host = host
        self.realm = realm
        self.algorithms = algorithms
        self.audience = audience
        self.issuer = issuer

    def get_issuer_setting(self) -> IssuerSetting:
        """The issuer override: the ``issuer`` argument, else framework settings."""
        return self.issuer

    @lru_cache
    def get_claims(self, force=False, *args, **kwargs) -> dict:
        """
        Verify the token using Public Key
        """
        manager = self.manager(host=self.host, realm=self.realm)
        public_key = manager.get_key(force=force)
        return verify_token(
            access_token=self.access_token,
            public_key=public_key,
            algorithms=self.algorithms,
            audience=self.audience,
            issuer=expected_issuers(
                self.get_issuer_setting(),
                realm=self.realm,
                host=self.host,
            ),
        )
