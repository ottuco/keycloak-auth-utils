import typing
from functools import lru_cache

import requests

from ..errors import PublicKeyNotFound


class BasePublicKeyManager:
    ttl: int = 60 * 60 * 24  # 1 day
    host: str
    realm: str

    def __init__(
        self,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
    ):
        self.host = host or ""
        self.realm = realm or ""

    @property
    def url_realm(self) -> str:
        return f"https://{self.host}/auth/realms/{self.realm}"

    def get_fresh_key_from_upstream(self) -> str:
        response = requests.get(self.url_realm)
        if response.status_code != 200:
            msg = f"Public key for Keycloak realm `{self.realm}` not found."
            raise PublicKeyNotFound(msg)
        return response.json().get("public_key")

    def get_fresh_pem_key(self) -> str:
        key = self.get_fresh_key_from_upstream()
        return f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"

    def clear_cache(self, *args, **kwargs):
        self.get_key_from_cache.cache_clear()

    @lru_cache
    def get_key_from_cache(self, *args, **kwargs) -> typing.Optional[str]:
        return self.get_fresh_pem_key()

    def set_key(self, key: str, *args, **kwargs) -> str:
        ...

    def get_or_set_key(self, *args, **kwargs) -> str:
        key = self.get_key_from_cache(*args, **kwargs)
        if key:
            return key
        key = self.get_fresh_pem_key()
        self.set_key(key, *args, **kwargs)
        return key

    def get_key(self, force: bool = False, *args, **kwargs) -> str:
        if force:
            self.clear_cache(*args, **kwargs)
        return self.get_or_set_key(*args, **kwargs)
