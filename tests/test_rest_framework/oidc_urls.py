from django.urls import include, path

urlpatterns = [
    path("", include("keycloak_utils.contrib.django.urls")),
]
