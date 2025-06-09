import asyncio
import typing

import httpx

from ..errors import PublicKeyNotFound
from .base import BasePublicKeyManager


class AsyncFastAPIKeyManager:
    """Asynchronous public key manager for FastAPI."""

    ttl: int = 60 * 60 * 24  # 1 day
    host: str
    realm: str
    _cache: dict = {}
    _cache_lock = asyncio.Lock()

    def __init__(
        self,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
        ttl: typing.Optional[int] = None,
    ) -> None:
        self.host = host or ""
        self.realm = realm or ""
        self._cache_key = f"keycloak_public_key_{self.realm}"
        if ttl is not None:
            self.ttl = ttl

    @property
    def url_realm(self) -> str:
        return f"https://{self.host}/auth/realms/{self.realm}"

    async def get_fresh_key_from_upstream(self) -> str:
        """Fetch the public key from Keycloak using ``httpx``."""

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(self.url_realm)
                if response.status_code != 200:
                    msg = (
                        f"Public key for Keycloak realm `{self.realm}` not found. "
                        f"Status: {response.status_code}"
                    )
                    raise PublicKeyNotFound(msg)

                data = response.json()
                key = data.get("public_key")
                if not key:
                    raise PublicKeyNotFound(
                        f"Public key for Keycloak realm `{self.realm}` not found",
                    )
                return key
        except httpx.RequestError as e:
            raise PublicKeyNotFound(f"Failed to fetch public key: {str(e)}") from e
        except asyncio.TimeoutError:
            raise PublicKeyNotFound(
                f"Timeout fetching public key from {self.url_realm}",
            )

    async def get_fresh_pem_key(self) -> str:
        key = await self.get_fresh_key_from_upstream()
        return f"-----BEGIN PUBLIC KEY-----\n{key}\n-----END PUBLIC KEY-----"

    async def clear_cache(self) -> None:
        async with self._cache_lock:
            self._cache.clear()

    async def get_key_from_cache(self) -> typing.Optional[str]:
        async with self._cache_lock:
            cached = self._cache.get(self._cache_key)
        if not cached:
            return None
        key, ts = cached
        if ts + self.ttl < asyncio.get_running_loop().time():
            # expired
            return None
        return key

    async def set_key(self, key: str) -> str:
        async with self._cache_lock:
            self._cache[self._cache_key] = (key, asyncio.get_running_loop().time())
        return key

    async def get_or_set_key(self) -> str:
        key = await self.get_key_from_cache()
        if key:
            return key
        key = await self.get_fresh_pem_key()
        await self.set_key(key)
        return key

    async def get_key(self, force: bool = False) -> str:
        if force:
            await self.clear_cache()
        return await self.get_or_set_key()


class FastAPIKeyManager(BasePublicKeyManager):
    """Synchronous version retained for backwards compatibility."""

    pass
