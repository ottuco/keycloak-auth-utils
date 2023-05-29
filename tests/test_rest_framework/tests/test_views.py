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
