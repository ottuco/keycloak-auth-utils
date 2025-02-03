"""
********************************************************

© YYYY - 2024 Ottu All Rights Reserved.

********************************************************

Keyloop Facilitator URL's

"""

from django.conf import settings
from django.urls import path

from . import conf
from .views import (
    AuthenticateView,
    CallbackView,
    DjangoAdminLoginView,
    DjangoAdminLogoutView,
    ErrorView,
    LogoutView,
)

urlpatterns = [
    path(
        f"{settings.ADMIN_URL}/login/",
        DjangoAdminLoginView.as_view(),
        name="admin_login",
    ),
    path(
        f"{settings.ADMIN_URL}/logout/",
        DjangoAdminLogoutView.as_view(),
        name="admin_logout",
    ),
    path(
        f"error/",
        ErrorView.as_view(),
        name="error",
    ),
    path(
        f"oidc/login",
        AuthenticateView.as_view(),
        name=conf.KC_UTILS_OIDC_AUTHENTICATE_URL_NAME,
    ),
    path(
        f"oidc/callback",
        CallbackView.as_view(),
        name=conf.KC_UTILS_OIDC_CALLBACK_URL_NAME,
    ),
    path(f"oidc/logout", LogoutView.as_view(), name=conf.KC_UTILS_OIDC_LOGOUT_URL_NAME),
]
