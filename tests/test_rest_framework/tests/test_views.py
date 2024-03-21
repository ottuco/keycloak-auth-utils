from unittest import mock

import pytest
from rest_framework.test import APIRequestFactory

from tests import constants
from tests.test_rest_framework.polls.views import UserTestAPI

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.base.BasePublicKeyManager.get_fresh_key_from_upstream"
)

pytestmark = pytest.mark.django_db


class TestAuthenticationAPI:
    def test_without_auth_header(self):
        drf_request = APIRequestFactory().get("/", headers={"x-anything": "anything"})
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 401
        assert response.data == {
            "detail": "Authentication credentials were not provided.",
        }

    @mock.patch(get_fresh_key_from_upstream, return_value="123")
    def test_empty_authorization(self, mock_):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"x-anything": "anything", "Authorization": ""},
        )
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 401
        assert response.data == {
            "detail": "Authentication credentials were not provided.",
        }

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_with_prefix_only(self, mock_):
        drf_request = APIRequestFactory().get("/", headers={"Authorization": "Bearer"})
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 401
        assert response.data == {
            "detail": "Invalid token header. No credentials provided.",
        }

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_invalid_key(self, mock_):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": "Bearer invalid-key"},
        )
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 401
        assert response.data == {"detail": "Not enough segments"}

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth(self, mock_):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": f"Bearer {constants.ACCESS_TOKEN}"},
        )
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 200
        assert response.data["user"] == "john@test.dev"

    @pytest.mark.parametrize("auth_scheme", ["Token", "Random", "Bearer"])
    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_with_random_auth_scheme(self, mock_, auth_scheme):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": f"{auth_scheme} {constants.ACCESS_TOKEN}"},
        )
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 200
        assert response.data["user"] == "john@test.dev"

    @mock.patch("requests.get")
    def test_auth_with_dynamic_realm(self, mock_):
        mock_.return_value.json.return_value = {"public_key": constants.PUBLIC_KEY}
        mock_.return_value.status_code = 200
        drf_request = APIRequestFactory().get(
            "/",
            headers={
                "Authorization": f"Dynamic {constants.ACCESS_TOKEN}",
                "X-Service-ID": "foo-realm",
            },
        )
        view = UserTestAPI.as_view()
        response = view(drf_request)
        assert response.status_code == 200
        assert response.data["user"] == "john@test.dev"
        mock_.assert_called_once_with("https://localhost:8443/auth/realms/foo-realm")
