from django.apps import AppConfig


class KeycloakAuthConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "keycloak_utils.contrib.django"
    label = "keycloak_auth"
    verbose_name = "Keycloak Auth"
