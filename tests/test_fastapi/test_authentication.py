from types import SimpleNamespace
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from tests import constants

from .app import app

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.base.BasePublicKeyManager.get_fresh_key_from_upstream"
)
client = TestClient(app)


class TestAuthenticationAPI:
    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_with_different_auth_scheme(self, mock_):
        response = client.get(
            "/",
            headers={"Authorization": f"Anything {constants.ACCESS_TOKEN}"},
        )
        assert response.status_code == 403  # Since user has not been authenticated
        assert response.json() == {"detail": "Not authenticated"}

    def test_without_auth_header(self):
        response = client.get("/")
        assert response.status_code == 403
        assert response.json() == {"detail": "Not authenticated"}

    def test_empty_authorization(self):
        response = client.get("/", headers={"Authorization": ""})
        assert response.status_code == 403
        assert response.json() == {"detail": "Not authenticated"}

    def test_auth_with_prefix_only(self):
        response = client.get("/", headers={"Authorization": "Bearer"})
        assert response.status_code == 401
        assert response.json() == {
            "detail": "Invalid token header. No credentials provided.",
        }

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_invalid_key(self, mock_):
        response = client.get("/", headers={"Authorization": "Bearer invalid-key"})
        assert response.status_code == 401
        assert response.json() == {"detail": "Not enough segments"}

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth(self, mock_):
        response = client.get(
            "/",
            headers={"Authorization": f"Bearer {constants.ACCESS_TOKEN}"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "user": {"email": "john@test.dev", "name": "John Doe"},
        }

    @pytest.mark.parametrize("auth_scheme", ["Token", "Random", "Bearer"])
    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_with_random_auth_scheme(self, mock_, auth_scheme):
        response = client.get(
            "/",
            headers={"Authorization": f"{auth_scheme} {constants.ACCESS_TOKEN}"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "user": {"email": "john@test.dev", "name": "John Doe"},
        }

    @mock.patch("requests.get")
    def test_auth_with_dynamic_realm(self, mock_):
        mock_.return_value.json.return_value = {"public_key": constants.PUBLIC_KEY}
        mock_.return_value.status_code = 200
        response = client.get(
            "/",
            headers={
                "Authorization": f"Dynamic {constants.ACCESS_TOKEN}",
                "X-Service-ID": "test-realm",
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "user": {"email": "john@test.dev", "name": "John Doe"},
        }
        mock_.assert_called_once_with("https://localhost:8088/auth/realms/test-realm")

    @mock.patch("requests.get")
    def test_dynamic_realm_refuses_a_token_of_another_realm(self, mock_):
        """The fixture token is from test-realm; foo-realm must not accept it."""
        mock_.return_value.json.return_value = {"public_key": constants.PUBLIC_KEY}
        mock_.return_value.status_code = 200
        response = client.get(
            "/",
            headers={
                "Authorization": f"Dynamic {constants.ACCESS_TOKEN}",
                "X-Service-ID": "foo-realm",
            },
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid issuer"}

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_backend_issuer_attribute_overrides_the_built_issuer(self, mock_):
        from keycloak_utils.backend.fastapi import FastAPIKeycloakAuthBackend

        class PublicNameBackend(FastAPIKeycloakAuthBackend):
            kc_host = "kc.internal.test"
            kc_realm = "test-realm"
            kc_issuer = "https://localhost:8088/auth/realms/{realm}"
            kc_algorithms = ["RS256"]
            kc_audience = "account"

        request = SimpleNamespace(
            headers={"Authorization": f"Bearer {constants.ACCESS_TOKEN}"},
        )
        claims = PublicNameBackend(request=request).authenticate()
        assert claims["email"] == "john@test.dev"
