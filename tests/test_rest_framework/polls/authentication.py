from django.contrib.auth import get_user_model

from keycloak_utils.authentication.rest_framework import BaseDRFKCAuthentication

User = get_user_model()


class CustomDRFKCAuthentication(BaseDRFKCAuthentication):
    kc_host = "http://localhost:8080"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    keyword = "Bearer"

    def get_or_create_user(self, claims: dict):
        filter_args = {User.USERNAME_FIELD: claims["email"]}
        user, _ = User.objects.get_or_create(**filter_args)
        return user
