from unittest import mock

from fastapi.testclient import TestClient

from tests import constants

from .app import app

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.base.BasePublicKeyManager.get_fresh_key_from_upstream"
)
client = TestClient(app)


class TestAuthenticationAPI:
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
