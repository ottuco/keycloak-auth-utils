import asyncio
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


class BaseAsyncPublicKeyManager(BasePublicKeyManager):
    """Asynchronous variant of :class:`BasePublicKeyManager`."""

    _cache: dict = {}
    _cache_lock = asyncio.Lock()

    @property
    def cache_key(self) -> str:
        return f"keycloak_public_key_{self.realm}"

    async def get_fresh_key_from_upstream(self) -> str:  # type: ignore[override]
        raise NotImplementedError

    async def get_fresh_pem_key(self) -> str:  # type: ignore[override]
        key = await self.get_fresh_key_from_upstream()
        return f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"

    async def clear_cache(self, *args, **kwargs) -> None:  # type: ignore[override]
        async with self._cache_lock:
            self._cache.pop(self.cache_key, None)

    # type: ignore[override]
    async def get_key_from_cache(self, *args, **kwargs) -> typing.Optional[str]:
        async with self._cache_lock:
            cached = self._cache.get(self.cache_key)
        if not cached:
            return None
        key, ts = cached
        if ts + self.ttl < asyncio.get_running_loop().time():
            return None
        return key

    async def set_key(self, key: str, *args, **kwargs) -> str:  # type: ignore[override]
        async with self._cache_lock:
            self._cache[self.cache_key] = (key, asyncio.get_running_loop().time())
        return key

    async def get_or_set_key(self, *args, **kwargs) -> str:  # type: ignore[override]
        key = await self.get_key_from_cache(*args, **kwargs)
        if key:
            return key
        key = await self.get_fresh_pem_key()
        await self.set_key(key, *args, **kwargs)
        return key

    # type: ignore[override]
    async def get_key(self, force: bool = False, *args, **kwargs) -> str:
        if force:
            await self.clear_cache(*args, **kwargs)
        return await self.get_or_set_key(*args, **kwargs)
