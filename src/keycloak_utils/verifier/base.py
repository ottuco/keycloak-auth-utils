import typing
from functools import lru_cache

from ..manager.base import BasePublicKeyManager
from ..utils import verify_token

IssuerSetting = typing.Optional[typing.Union[str, typing.Sequence[str]]]


def expected_issuers(issuer: IssuerSetting, realm: str, url_realm: str) -> list[str]:
    """
    The ``iss`` values a token may carry.

    Without an override it is the realm URL the public key is fetched from
    (``https://<host>/auth/realms/<realm>``), so a working setup keeps working.
    An override is one issuer or a list; ``{realm}`` in it becomes the realm.
    """
    if not issuer:
        return [url_realm]
    items = [issuer] if isinstance(issuer, str) else list(issuer)
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
                url_realm=manager.url_realm,
            ),
        )
