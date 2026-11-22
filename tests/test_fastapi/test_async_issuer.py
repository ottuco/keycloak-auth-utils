"""
Issuer check on the async FastAPI path (#161493): AsyncFastAPIKeycloakAuthBackend
passes ``kc_issuer`` to AsyncFastAPITokenVerifier, which checks ``iss``.
"""

import asyncio
from types import SimpleNamespace
from unittest import mock

import pytest

from keycloak_utils.backend.fastapi import AsyncFastAPIKeycloakAuthBackend
from keycloak_utils.errors import AuthInterruptedError
from keycloak_utils.manager.fastapi import AsyncFastAPIKeyManager
from tests import constants

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.fastapi.AsyncFastAPIKeyManager.get_fresh_key_from_upstream"
)


class AsyncBackend(AsyncFastAPIKeycloakAuthBackend):
    # constants.ACCESS_TOKEN is issued by https://localhost:8088/auth/realms/test-realm
    kc_host = "localhost:8088"
    kc_realm = "test-realm"
    kc_algorithms = ["RS256"]
    kc_audience = "account"


@pytest.fixture(autouse=True)
def clear_key_cache():
    AsyncFastAPIKeyManager._cache.clear()
    yield
    AsyncFastAPIKeyManager._cache.clear()


def authenticate(backend_class):
    request = SimpleNamespace(
        headers={"Authorization": f"Bearer {constants.ACCESS_TOKEN}"},
    )
    with mock.patch(
        get_fresh_key_from_upstream,
        new=mock.AsyncMock(return_value=constants.PUBLIC_KEY),
    ):
        return asyncio.run(backend_class(request=request).authenticate())


class TestAsyncIssuer:
    def test_issuer_from_host_and_realm_passes(self):
        claims = authenticate(AsyncBackend)
        assert claims["email"] == "john@test.dev"

    def test_token_of_another_host_is_refused(self):
        class OtherHostBackend(AsyncBackend):
            kc_host = "sso.example.test"

        with pytest.raises(AuthInterruptedError) as e:
            authenticate(OtherHostBackend)
        assert "Invalid issuer" in str(e.value)

    def test_issuer_attribute_overrides_the_built_issuer(self):
        class PublicNameBackend(AsyncBackend):
            kc_host = "kc.internal.test"
            kc_issuer = "https://localhost:8088/auth/realms/{realm}"

        claims = authenticate(PublicNameBackend)
        assert claims["email"] == "john@test.dev"
