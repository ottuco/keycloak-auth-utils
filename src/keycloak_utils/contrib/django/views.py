import logging
import typing
from base64 import urlsafe_b64encode
from hashlib import sha256

from django.contrib import auth
from django.http import (
    HttpRequest,
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import urlencode
from django.views.generic import RedirectView, View

from ...errors import AuthenticationError
from . import conf

log = logging.getLogger(__name__)


class AuthenticateView(View):
    """
    Ask the OP for a temporary code (auth code flow),
    Using at least the openid scope (OIDC).
    Ends with a redirect.
    """

    http_method_names = ["get"]

    def get(self, request: HttpRequest) -> HttpResponse:
        next_url: str = request.GET.get(conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME, "")
        failure_url: str = request.GET.get(
            conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME,
            "",
        )

        if not next_url:
            raise AuthenticationError(
                f"{conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME} parameter is required",
            )
        if not failure_url:
            raise AuthenticationError(
                f"{conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required",
            )

        request.session["session_next_url"] = next_url
        request.session["session_fail_url"] = failure_url

        url: str = conf.KC_UTILS_OIDC_AUTHORIZATION_URL
        scopes: list[str] = conf.KC_UTILS_OIDC_RP_SCOPES
        auth_params: dict[str, typing.Any] = {
            "response_type": "code",
            "client_id": conf.KC_UTILS_OIDC_RP_CLIENT_ID,
            "scope": " ".join(scopes),
            "prompt": "consent",
            "redirect_uri": request.build_absolute_uri(
                reverse(conf.KC_UTILS_OIDC_CALLBACK_URL_NAME),
            ),
            "code_challenge_method": "S256",
        }

        code_verifier: str = get_random_string(
            length=100,
            allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
        )
        code_challenge: str = (
            urlsafe_b64encode(sha256(code_verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        auth_params["code_challenge"] = code_challenge
        request.session["session_challenge"] = code_verifier
        request.session.save()
        redirect_url: str = f"{url}?{urlencode(auth_params)}"

        return HttpResponseRedirect(redirect_url)


class CallbackView(View):
    """
    Callback from the OP.
    Ends with a redirect.
    """

    http_method_names = ["get"]

    def get(self, request: HttpRequest) -> HttpResponse:
        next_url: str = request.session.get("session_next_url")
        failure_url: str = request.session.get("session_fail_url")

        if not next_url or not failure_url:
            return HttpResponseBadRequest(
                f"{conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME} and {conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME} session parameters should be filled",
            )

        if "error" in request.GET:
            log.error(request.GET["error"])
            if request.user.is_authenticated:
                auth.logout(request)
            url = f"{failure_url}?{urlencode({'error': request.GET['error']})}"
            return HttpResponseRedirect(url)

        if "code" in request.GET and "session_state" in request.GET:
            return self.auth_callback(request, next_url, failure_url)

        if "session_logout_state" in request.session and "state" in request.GET:
            return self.logout_callback(request, next_url, failure_url)

        url = f"{failure_url}?{urlencode({'error': 'Unknown OIDC callback'})}"
        return HttpResponseRedirect(url)

    def auth_callback(
        self,
        request: HttpRequest,
        next_url: str,
        failure_url: str,
    ) -> HttpResponse:
        url: str = failure_url
        code: str = request.GET["code"]
        session_challenge: str = request.session.pop("session_challenge", None)
        if not session_challenge:
            raise AuthenticationError("OIDC callback: challenge not found in session")

        user = auth.authenticate(
            request,
            code=code,
            code_verifier=session_challenge,
        )
        if user and user.is_active:
            # keep old session items as auth.login will probably flush the session
            old_session_items: dict[str, typing.Any] = dict(request.session.items())
            auth.login(request, user)
            for key, value in old_session_items.items():
                if key not in request.session:
                    request.session[key] = value
            url = next_url
        else:
            url += f"?{urlencode({'error': 'OIDC authenticate callback error, User not found or User is not active.'})}"

        return HttpResponseRedirect(url)

    def logout_callback(
        self,
        request: HttpRequest,
        next_url: str,
        failure_url: str,
    ) -> HttpResponse:
        url: str = failure_url
        state: str = request.GET["state"]
        session_state: str = request.session.get("session_logout_state")
        if state == session_state:
            if request.user.is_authenticated:
                auth.logout(request)
            url = next_url
        else:
            request.session.pop("session_logout_state", None)
            request.session.save()
            url += f"?{urlencode({'error': 'OIDC logout callback, bad session state error'})}"

        return HttpResponseRedirect(url)


class LogoutView(View):
    """
    Logout user from the application, called by RP user-agent.
    """

    http_method_names = ["get"]

    def get(self, request: HttpRequest) -> HttpResponse:
        next_url: str = request.GET.get(conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME, "")
        failure_url: str = request.GET.get(
            conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME,
            "",
        )

        if not next_url:
            return HttpResponseBadRequest(
                f"{conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME} parameter is required",
            )
        if not failure_url:
            return HttpResponseBadRequest(
                f"{conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required",
            )

        if "session_id_token" not in request.session:
            return HttpResponseRedirect(
                f"{failure_url}?{urlencode({'error': 'id_token is missing from the session, cannot logout'})}",
            )

        id_token: str = request.session["session_id_token"]
        return self.logout(request, id_token, next_url, failure_url)

    def logout(
        self,
        request: HttpRequest,
        id_token: str,
        next_url: str,
        failure_url: str,
    ) -> HttpResponseRedirect:
        end_session_url: str = conf.KC_UTILS_OIDC_END_SESSION_URL

        state: str = get_random_string(conf.KC_UTILS_OIDC_RANDOM_SIZE)
        logout_params: dict[str, typing.Any] = {
            "id_token_hint": id_token,
            "post_logout_redirect_uri": request.build_absolute_uri(
                reverse(conf.KC_UTILS_OIDC_CALLBACK_URL_NAME),
            ),
            "state": state,
        }

        request.session["session_next_url"] = next_url
        request.session["session_fail_url"] = failure_url
        request.session["session_id_token"] = id_token
        request.session["session_logout_state"] = state
        request.session.save()

        redirect_url: str = f"{end_session_url}?{urlencode(logout_params)}"
        return HttpResponseRedirect(redirect_url)


class AdminRedirectView(RedirectView):
    def get_url(self) -> str:
        """
        Generate URL for OIDC redirect.
        """
        oidc_url: str = reverse(conf.KC_UTILS_OIDC_AUTHENTICATE_URL_NAME)
        next_url: str = self.request.GET.get(
            conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME,
            reverse("admin:index"),
        )
        fail_url: str = reverse(conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME)

        return (
            f"{oidc_url}?{conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME}"
            f"={next_url}&{conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME}"
            f"={fail_url}"
        )


class DjangoAdminLoginView(AdminRedirectView):
    """
    Custom Django admin login view to redirect to OIDC provider.
    """

    def get_redirect_url(self, *args, **kwargs) -> str:
        """
        If user is not authenticated redirect to OIDC provider login else
        check for permissions.
        """
        if self.request.user.is_authenticated:
            if not (self.request.user.is_superuser and self.request.user.is_staff):
                msg: str = (
                    f"You are authenticated as {self.request.user.username}, "
                    f"but are not authorized to access this page."
                )
                url: str = reverse(conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME)
                return f"{url}?error={msg}"

        return super().get_url()


class DjangoAdminLogoutView(AdminRedirectView):
    """
    Custom Django admin logout view to redirect to OIDC provider.
    """

    def get_redirect_url(self, *args, **kwargs) -> str:
        """
        If user is authenticated redirect to OIDC provider logout,
        else redirect to OIDC provider login.
        """
        if self.request.user.is_authenticated:
            params: str = urlencode(
                {
                    conf.KC_UTILS_OIDC_REDIRECT_OK_FIELD_NAME: self.get_url(),
                    conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME: reverse(
                        conf.KC_UTILS_OIDC_REDIRECT_ERROR_FIELD_NAME,
                    ),
                },
            )
            logout_url: str = f"{reverse(conf.KC_UTILS_OIDC_LOGOUT_URL_NAME)}?{params}"
            return logout_url

        return super().get_url()


class ErrorView(View):
    """
    Error view to render errors.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        return HttpResponse(request.GET.items())
