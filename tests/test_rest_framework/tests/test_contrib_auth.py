"""Tests for keycloak_utils.contrib.django.auth."""

import pytest
from django.contrib.auth import get_user_model

from keycloak_utils.contrib.django import auth, conf

pytestmark = pytest.mark.django_db

User = get_user_model()

# Keycloak always sends usernames lowercased.
SARA_CLAIMS = {"preferred_username": "sara.k", "email": "sara@example.com"}
SUPERADMIN_CLAIMS = {
    "preferred_username": "event-ms",
    "email": "event-ms@example.com",
    "realm_access": {"roles": [conf.KC_UTILS_USER_SUPERADMIN_ROLE]},
}


def _users():
    return list(
        User.objects.order_by("pk").values_list("pk", "username", "is_superuser"),
    )


class TestStoredUsername:
    """Tests for the username a token's user is looked up by."""

    @pytest.mark.parametrize(
        "stored,claims,expected",
        [
            pytest.param(["Sara.K"], SARA_CLAIMS, "Sara.K", id="stored-with-capitals"),
            pytest.param(
                ["Sara.K", "sara.k"],
                SARA_CLAIMS,
                "sara.k",
                id="exact-spelling-wins",
            ),
            pytest.param(
                ["Sara.K", "SARA.K"],
                SARA_CLAIMS,
                "Sara.K",
                id="lowest-pk-wins",
            ),
            pytest.param(
                ["Event-MS"],
                SUPERADMIN_CLAIMS,
                "event-ms",
                id="superadmin-matches-exactly",
            ),
            pytest.param([], SARA_CLAIMS, "sara.k", id="unknown-user"),
            pytest.param([], {}, "", id="no-username"),
        ],
    )
    def test_stored_username(self, stored, claims, expected):
        for username in stored:
            User.objects.create_user(username=username)

        assert auth.stored_username(claims) == expected


class TestAuthenticationBackendGetOrCreateUser:
    """SSO sign-in uses the Django user whose username differs only in case."""

    def test_reuses_the_user_stored_with_capitals_and_keeps_its_spelling(self):
        sara = User.objects.create_user(username="Sara.K")

        signed_in = auth.AuthenticationBackend().get_or_create_user(SARA_CLAIMS)

        assert signed_in.pk == sara.pk
        assert _users() == [(sara.pk, "Sara.K", False)]

    def test_exact_spelling_wins_when_both_exist(self):
        sara = User.objects.create_user(username="Sara.K")
        exact = User.objects.create_user(username="sara.k")

        signed_in = auth.AuthenticationBackend().get_or_create_user(SARA_CLAIMS)

        assert signed_in.pk == exact.pk
        assert _users() == [(sara.pk, "Sara.K", False), (exact.pk, "sara.k", False)]

    def test_superadmin_token_never_takes_a_look_alike_row(self):
        look_alike = User.objects.create_user(username="Event-MS")

        signed_in = auth.AuthenticationBackend().get_or_create_user(SUPERADMIN_CLAIMS)

        assert signed_in.pk != look_alike.pk
        assert _users() == [
            (look_alike.pk, "Event-MS", False),
            (signed_in.pk, "event-ms", True),
        ]

    def test_creates_an_unknown_user_with_the_token_spelling(self):
        signed_in = auth.AuthenticationBackend().get_or_create_user(SARA_CLAIMS)

        assert _users() == [(signed_in.pk, "sara.k", False)]
