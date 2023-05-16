import typing

from django.core.cache import cache

from .base import BasePublicKeyManager


class DjangoKeyManager(BasePublicKeyManager):
    cache_key = "keycloak_public_key"

    def set_key(self, key: str, *args, **kwargs) -> str:
        cache.set(self.cache_key, key, timeout=self.ttl)
        return key

    def clear_cache(self, *args, **kwargs):
        ...

    def get_key_from_cache(self, *args, **kwargs) -> typing.Optional[str]:
        return cache.get(self.cache_key)
