"""
Token checks in ``verify_token`` and the verifiers (#161493, decision
keycloak-auth-utils-D1 (a)): ``exp`` is required and ``iss`` must be the realm
URL the key is fetched from, or the ``KC_UTILS_KC_ISSUER`` override.

Tokens here are signed with a throwaway key made for the test run. Assertions
never put a token or a key in their message.
"""

import logging
import time
from unittest import mock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keycloak_utils.contrib.django import conf
from keycloak_utils.errors import JWTDecodeError
from keycloak_utils.utils import verify_token
from keycloak_utils.verifier.rest_framework import DjangoTokenVerifier
from tests import constants

HOST = "kc.example.test"
REALM = "shop"
ISSUER = f"https://{HOST}/auth/realms/{REALM}"
AUDIENCE = "account"

get_fresh_key_from_upstream = (
    "keycloak_utils.manager.base.BasePublicKeyManager.get_fresh_key_from_upstream"
)


@pytest.fixture(scope="module")
def keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_key, public_pem


def make_token(private_key, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
        "preferred_username": "john",
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return jwt.encode(claims, private_key, algorithm="RS256")


def verify(token, public_pem, **kwargs):
    kwargs.setdefault("audience", AUDIENCE)
    kwargs.setdefault("issuer", ISSUER)
    return verify_token(
        access_token=token,
        public_key=public_pem,
        algorithms=["RS256"],
        **kwargs,
    )


class TestVerifyTokenExp:
    def test_token_without_exp_is_refused(self, keypair):
        private_key, public_pem = keypair
        token = make_token(private_key, exp=None)
        with pytest.raises(JWTDecodeError) as e:
            verify(token, public_pem)
        assert "exp" in str(e.value), "a token without exp must be refused"

    def test_expired_token_is_still_refused(self, keypair):
        private_key, public_pem = keypair
        token = make_token(private_key, exp=int(time.time()) - 60)
        with pytest.raises(JWTDecodeError):
            verify(token, public_pem)


class TestVerifyTokenIssuer:
    def test_matching_issuer_passes(self, keypair):
        private_key, public_pem = keypair
        claims = verify(make_token(private_key), public_pem)
        assert claims["sub"] == "user-1"

    def test_other_realm_is_refused(self, keypair, caplog):
        private_key, public_pem = keypair
        other = f"https://{HOST}/auth/realms/other-shop"
        token = make_token(private_key, iss=other)
        with caplog.at_level(logging.WARNING, logger="keycloak_utils"):
            with pytest.raises(JWTDecodeError) as e:
                verify(token, public_pem)
        assert str(e.value) == "Invalid issuer"
        assert ISSUER in caplog.text, "the log names the expected issuer"
        assert other in caplog.text, "the log names the received issuer"
        # Booleans only, so a failure never prints the token.
        leaked = token in caplog.text or token.split(".")[1] in caplog.text
        assert not leaked, "the log never holds the token"

    def test_token_without_iss_is_refused(self, keypair):
        private_key, public_pem = keypair
        token = make_token(private_key, iss=None)
        with pytest.raises(JWTDecodeError):
            verify(token, public_pem)

    def test_any_issuer_of_a_list_passes(self, keypair):
        private_key, public_pem = keypair
        public_name = f"https://sso.example.test/auth/realms/{REALM}"
        token = make_token(private_key, iss=public_name)
        claims = verify(token, public_pem, issuer=[ISSUER, public_name])
        assert claims["iss"] == public_name

    def test_received_issuer_in_log_is_cut_short(self, keypair, caplog):
        private_key, public_pem = keypair
        token = make_token(private_key, iss="x" * 5000)
        with caplog.at_level(logging.WARNING, logger="keycloak_utils"):
            with pytest.raises(JWTDecodeError):
                verify(token, public_pem)
        too_long = "x" * 300 in caplog.text
        assert not too_long, "the received issuer is cut short in the log"

    def test_without_issuer_argument_iss_is_not_checked(self, keypair):
        """Direct callers that pass no issuer keep today's behavior."""
        private_key, public_pem = keypair
        token = make_token(private_key, iss="https://anything.test/auth/realms/x")
        claims = verify(token, public_pem, issuer=None)
        assert claims["sub"] == "user-1"


class TestBeforeAfter:
    def test_fixture_token_gives_the_same_claims_as_before(self):
        """Normal token: the old call and the new one return identical claims."""
        token = constants.ACCESS_TOKEN
        pem = f"-----BEGIN PUBLIC KEY-----\n{constants.PUBLIC_KEY}\n-----END PUBLIC KEY-----"
        unverified = jwt.decode(token, options={"verify_signature": False})
        old = jwt.decode(
            token,
            key=pem,
            algorithms=["RS256"],
            audience=AUDIENCE,
        )
        new = verify_token(
            access_token=token,
            public_key=pem,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=unverified["iss"],
        )
        assert new == old


@pytest.fixture()
def no_override(monkeypatch):
    monkeypatch.setattr(conf, "KC_UTILS_KC_ISSUER", None, raising=False)


class TestDjangoTokenVerifierIssuer:
    def run(self, token, public_pem, realm=REALM, host=HOST):
        with mock.patch(get_fresh_key_from_upstream, return_value=public_pem):
            return DjangoTokenVerifier(
                access_token=token,
                host=host,
                realm=realm,
                algorithms=["RS256"],
                audience=AUDIENCE,
            ).get_claims()

    @pytest.fixture(autouse=True)
    def clear_key_cache(self):
        from django.core.cache import cache

        cache.clear()
        yield
        cache.clear()

    @pytest.fixture()
    def raw_key(self, keypair):
        # The manager wraps the raw key from Keycloak in PEM armor itself.
        private_key, public_pem = keypair
        body = "".join(public_pem.strip().splitlines()[1:-1])
        return private_key, body

    def test_issuer_from_host_and_realm_passes(self, raw_key, no_override):
        private_key, body = raw_key
        claims = self.run(make_token(private_key), body)
        assert claims["iss"] == ISSUER

    def test_token_of_another_realm_is_refused(self, raw_key, no_override):
        private_key, body = raw_key
        token = make_token(private_key, iss=f"https://{HOST}/auth/realms/other")
        with pytest.raises(JWTDecodeError):
            self.run(token, body)

    def test_token_of_another_host_is_refused(self, raw_key, no_override):
        private_key, body = raw_key
        token = make_token(private_key, iss=f"https://evil.test/auth/realms/{REALM}")
        with pytest.raises(JWTDecodeError):
            self.run(token, body)

    def test_override_setting_replaces_the_built_issuer(self, raw_key, monkeypatch):
        private_key, body = raw_key
        public_name = f"https://sso.example.test/auth/realms/{REALM}"
        monkeypatch.setattr(conf, "KC_UTILS_KC_ISSUER", public_name, raising=False)
        token = make_token(private_key, iss=public_name)
        assert self.run(token, body)["iss"] == public_name
        # The built URL is no longer accepted once the override is set.
        with pytest.raises(JWTDecodeError):
            self.run(make_token(private_key), body)

    def test_override_list_with_realm_placeholder(self, raw_key, monkeypatch):
        private_key, body = raw_key
        monkeypatch.setattr(
            conf,
            "KC_UTILS_KC_ISSUER",
            [
                "https://sso.example.test/auth/realms/{realm}",
                "https://kc.internal.test/auth/realms/{realm}",
            ],
            raising=False,
        )
        for name in ("sso.example.test", "kc.internal.test"):
            token = make_token(private_key, iss=f"https://{name}/auth/realms/{REALM}")
            assert self.run(token, body)["sub"] == "user-1"
        token = make_token(private_key, iss="https://sso.example.test/auth/realms/x")
        with pytest.raises(JWTDecodeError):
            self.run(token, body)
