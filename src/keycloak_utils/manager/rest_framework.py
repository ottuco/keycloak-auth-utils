import typing

from django.core.cache import cache

from .base import BasePublicKeyManager


class DjangoKeyManager(BasePublicKeyManager):
    cache_key_prefix = "keycloak_public_key"

    @property
    def cache_key(self) -> str:
        return f"{self.cache_key_prefix}_{self.realm}"

    def set_key(self, key: str, *args, **kwargs) -> str:
        cache.set(self.cache_key, key, timeout=self.ttl)
        return key

    def clear_cache(self, *args, **kwargs):
        ...

    def get_key_from_cache(self, *args, **kwargs) -> typing.Optional[str]:
        return cache.get(self.cache_key)
