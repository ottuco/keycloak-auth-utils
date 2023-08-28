from django.contrib.auth import get_user_model
from rest_framework.request import Request

from keycloak_utils.authentication.rest_framework import BaseDRFKCAuthentication

User = get_user_model()


class BearerAuthentication(BaseDRFKCAuthentication):
    kc_host = "http://localhost:8080"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"

    def get_or_create_user(self, claims: dict):
        filter_args = {User.USERNAME_FIELD: claims["email"]}
        user, _ = User.objects.get_or_create(**filter_args)
        return user


class TokenAuthentication(BearerAuthentication):
    auth_scheme = "Token"


class RandomAuthentication(BearerAuthentication):
    auth_scheme = "Random"


class DynamicAuthentication(BearerAuthentication):
    auth_scheme = "Dynamic"

    def get_kc_realm(self, request: Request) -> str:
        return request.META.get("HTTP_X_SERVICE_ID", "default-value")
