import asyncio
import typing

import httpx

from ..errors import PublicKeyNotFound
from .base import BaseAsyncPublicKeyManager, BasePublicKeyManager


class AsyncFastAPIKeyManager(BaseAsyncPublicKeyManager):
    """Asynchronous public key manager for FastAPI."""

    def __init__(
        self,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
        ttl: typing.Optional[int] = None,
    ) -> None:
        super().__init__(host=host, realm=realm)
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


class FastAPIKeyManager(BasePublicKeyManager):
    """Synchronous version retained for backwards compatibility."""

    pass
