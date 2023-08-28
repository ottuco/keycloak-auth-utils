from unittest import mock

import pytest
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from tests import constants
from tests.test_rest_framework.polls.authentication import BearerAuthentication

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.base.BasePublicKeyManager.get_fresh_key_from_upstream"
)

pytestmark = pytest.mark.django_db


@pytest.fixture()
def auth():
    yield BearerAuthentication()


class TestDRFKeycloakAuthBackend:
    def test_with_different_auth_scheme(self, auth):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": f"Anything {constants.ACCESS_TOKEN}"},
        )
        user = auth.authenticate(request=drf_request)
        assert user is None

    def test_without_auth_header(self, auth):
        drf_request = APIRequestFactory().get("/", headers={"x-anything": "anything"})
        result = auth.authenticate(request=drf_request)
        assert result is None

    @mock.patch(get_fresh_key_from_upstream, return_value="123")
    def test_empty_authorization(self, mock_, auth):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"x-anything": "anything", "Authorization": ""},
        )
        result = auth.authenticate(request=drf_request)
        assert result is None

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_with_prefix_only(self, mock_, auth):
        drf_request = APIRequestFactory().get("/", headers={"Authorization": "Bearer"})
        with pytest.raises(AuthenticationFailed) as e:
            auth.authenticate(request=drf_request)
        assert e.value.detail == "Invalid token header. No credentials provided."

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth_invalid_key(self, mock_, auth):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": "Bearer invalid-key"},
        )
        with pytest.raises(AuthenticationFailed) as e:
            auth.authenticate(request=drf_request)
        assert e.value.detail == "Not enough segments"

    @mock.patch(get_fresh_key_from_upstream, return_value=constants.PUBLIC_KEY)
    def test_auth(self, mock_, auth):
        drf_request = APIRequestFactory().get(
            "/",
            headers={"Authorization": f"Bearer {constants.ACCESS_TOKEN}"},
        )
        user, _ = auth.authenticate(request=drf_request)
        assert user.username == "john@test.dev"
