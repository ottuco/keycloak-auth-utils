import typing
from functools import lru_cache

from ..manager.base import BasePublicKeyManager
from ..utils import verify_token


class BaseTokenVerifier:
    manager: typing.Type[BasePublicKeyManager]

    def __init__(
        self,
        access_token: str,
        host: str,
        realm: str,
        algorithms: list[str],
        audience: str,
    ):
        self.access_token = access_token
        self.host = host
        self.realm = realm
        self.algorithms = algorithms
        self.audience = audience

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
        )
