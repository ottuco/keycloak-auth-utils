"""Redirect-target validation in the OIDC views (#159271).

Every `next` / `error` value comes from the caller, either as a query parameter or
through the session it was stored in. None may reach a `Location` header unless it
is relative or on an allowed host, and a rejected request must leave the session
alone: a failed attempt is not a logout.
"""

import pytest
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.backends.cache import SessionStore
from django.test import RequestFactory

from keycloak_utils.contrib.django import conf, views

pytestmark = [
    pytest.mark.django_db,
    pytest.mark.urls("tests.test_rest_framework.oidc_urls"),
]

OFF_HOST_TARGETS = [
    pytest.param("https://evil.com", id="absolute"),
    pytest.param("//evil.com", id="protocol-relative"),
    pytest.param("/\\evil.com", id="backslash"),
    pytest.param("javascript:alert(1)", id="javascript-scheme"),
]


def _request(path, params=None, *, session=None, user=None, secure=False):
    request = RequestFactory().get(path, params or {}, secure=secure)
    request.session = SessionStore()
    request.session.update(session or {})
    request.session.save()
    request.user = user or AnonymousUser()
    return request


def _assert_rejected(response, field_name):
    assert response.status_code == 400
    assert not response.has_header("Location")
    assert f"{field_name} parameter" in response.content.decode()


class TestLogoutView:
    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_rejects_off_host_error_when_id_token_is_missing(self, target):
        request = _request("/oidc/logout", {"next": "/dashboard", "error": target})

        response = views.LogoutView.as_view()(request)

        _assert_rejected(response, "error")

    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_rejects_off_host_next(self, target):
        request = _request(
            "/oidc/logout",
            {"next": target, "error": "/error"},
            session={"session_id_token": "id-token"},
        )

        response = views.LogoutView.as_view()(request)

        _assert_rejected(response, "next")

    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_rejects_off_host_error_when_id_token_is_present(self, target):
        request = _request(
            "/oidc/logout",
            {"next": "/dashboard", "error": target},
            session={"session_id_token": "id-token"},
        )

        response = views.LogoutView.as_view()(request)

        _assert_rejected(response, "error")

    def test_rejected_request_leaves_the_session_intact(self):
        request = _request(
            "/oidc/logout",
            {"next": "https://evil.com", "error": "/error"},
            session={"session_id_token": "id-token", "marker": "kept"},
        )
        session_key = request.session.session_key

        views.LogoutView.as_view()(request)

        assert request.session.session_key == session_key
        assert request.session["session_id_token"] == "id-token"
        assert request.session["marker"] == "kept"
        assert "session_next_url" not in request.session
        assert "session_logout_state" not in request.session

    def test_relative_targets_go_to_the_end_session_endpoint(self):
        request = _request(
            "/oidc/logout",
            {"next": "/dashboard", "error": "/error"},
            session={"session_id_token": "id-token"},
        )

        response = views.LogoutView.as_view()(request)

        assert response.status_code == 302
        assert response["Location"].startswith(conf.KC_UTILS_OIDC_END_SESSION_URL)
        assert request.session["session_next_url"] == "/dashboard"
        assert request.session["session_fail_url"] == "/error"

    def test_absolute_target_on_the_request_host_is_accepted(self):
        request = _request(
            "/oidc/logout",
            {"next": "http://testserver/dashboard", "error": "/error"},
            session={"session_id_token": "id-token"},
        )

        response = views.LogoutView.as_view()(request)

        assert response.status_code == 302
        assert request.session["session_next_url"] == "http://testserver/dashboard"


class TestAuthenticateView:
    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_rejects_off_host_next(self, target):
        request = _request("/oidc/login", {"next": target, "error": "/error"})

        response = views.AuthenticateView.as_view()(request)

        _assert_rejected(response, "next")
        assert "session_next_url" not in request.session
        assert "session_challenge" not in request.session

    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_rejects_off_host_error(self, target):
        request = _request("/oidc/login", {"next": "/dashboard", "error": target})

        response = views.AuthenticateView.as_view()(request)

        _assert_rejected(response, "error")
        assert "session_fail_url" not in request.session

    def test_relative_targets_start_the_login(self):
        request = _request("/oidc/login", {"next": "/dashboard", "error": "/error"})

        response = views.AuthenticateView.as_view()(request)

        assert response.status_code == 302
        assert response["Location"].startswith(conf.KC_UTILS_OIDC_AUTHORIZATION_URL)
        assert request.session["session_next_url"] == "/dashboard"


class TestCallbackView:
    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_logout_leg_rejects_an_off_host_next_from_the_session(self, target):
        request = _request(
            "/oidc/callback",
            {"state": "state-1"},
            session={
                "session_next_url": target,
                "session_fail_url": "/error",
                "session_logout_state": "state-1",
                "marker": "kept",
            },
        )

        response = views.CallbackView.as_view()(request)

        _assert_rejected(response, "next")
        assert request.session["marker"] == "kept"

    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_auth_leg_rejects_an_off_host_next_from_the_session(
        self,
        target,
        monkeypatch,
    ):
        user = get_user_model().objects.create_user(username="kc-user")
        # Without the check, a good code logs the user in and sends them to `target`.
        monkeypatch.setattr(views.auth, "authenticate", lambda *a, **kw: user)
        request = _request(
            "/oidc/callback",
            {"code": "auth-code", "session_state": "kc-session"},
            session={
                "session_next_url": target,
                "session_fail_url": "/error",
                "session_challenge": "verifier",
            },
        )

        response = views.CallbackView.as_view()(request)

        _assert_rejected(response, "next")
        assert SESSION_KEY not in request.session

    @pytest.mark.parametrize("target", OFF_HOST_TARGETS)
    def test_error_leg_rejects_an_off_host_error_from_the_session(self, target):
        user = get_user_model().objects.create_user(username="kc-user")
        request = _request(
            "/oidc/callback",
            {"error": "access_denied"},
            session={
                "session_next_url": "/dashboard",
                "session_fail_url": target,
                "marker": "kept",
            },
            user=user,
        )

        response = views.CallbackView.as_view()(request)

        _assert_rejected(response, "error")
        # A rejected callback is not a logout.
        assert request.session["marker"] == "kept"

    def test_unknown_callback_rejects_an_off_host_error_from_the_session(self):
        request = _request(
            "/oidc/callback",
            session={
                "session_next_url": "/dashboard",
                "session_fail_url": "//evil.com",
            },
        )

        response = views.CallbackView.as_view()(request)

        _assert_rejected(response, "error")


class TestLogoutThenCallback:
    def test_target_planted_through_logout_is_not_cashed_out_on_callback(self):
        request = _request(
            "/oidc/logout",
            {"next": "https://evil.com", "error": "/error"},
            session={"session_id_token": "id-token"},
        )
        logout_response = views.LogoutView.as_view()(request)
        state = request.session.get("session_logout_state", "no-state")

        callback = RequestFactory().get("/oidc/callback", {"state": state})
        callback.session = request.session
        callback.user = AnonymousUser()
        callback_response = views.CallbackView.as_view()(callback)

        _assert_rejected(logout_response, "next")
        assert "evil.com" not in callback_response.get("Location", "")

    def test_relative_target_survives_logout_and_callback(self):
        request = _request(
            "/oidc/logout",
            {"next": "/dashboard", "error": "/error"},
            session={"session_id_token": "id-token"},
        )
        views.LogoutView.as_view()(request)

        callback = RequestFactory().get(
            "/oidc/callback",
            {"state": request.session["session_logout_state"]},
        )
        callback.session = request.session
        callback.user = AnonymousUser()
        response = views.CallbackView.as_view()(callback)

        assert response.status_code == 302
        assert response["Location"] == "/dashboard"


class TestAllowedHosts:
    def test_listed_host_is_accepted_and_others_still_rejected(self, monkeypatch):
        monkeypatch.setattr(
            conf,
            "KC_UTILS_ALLOWED_REDIRECT_HOSTS",
            ["app.example.com"],
            raising=False,
        )

        listed = views.AuthenticateView.as_view()(
            _request(
                "/oidc/login",
                {"next": "https://app.example.com/home", "error": "/e"},
            ),
        )
        other = views.AuthenticateView.as_view()(
            _request("/oidc/login", {"next": "https://evil.com", "error": "/e"}),
        )

        assert listed.status_code == 302
        _assert_rejected(other, "next")

    def test_https_request_rejects_an_http_target_on_its_own_host(self):
        request = _request(
            "/oidc/login",
            {"next": "http://testserver/dashboard", "error": "/error"},
            secure=True,
        )

        response = views.AuthenticateView.as_view()(request)

        _assert_rejected(response, "next")
