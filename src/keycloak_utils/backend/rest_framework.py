import requests

from ..verifier.rest_framework import DjangoTokenVerifier
from .base import APIAuthMixin, BaseKCAuthBackend


class DRFKeycloakAuthBackend(APIAuthMixin, BaseKCAuthBackend):
    verifier = DjangoTokenVerifier


class DjangoKeycloakSSOAuthBackend(BaseKCAuthBackend):
    verifier = DjangoTokenVerifier

    def __init__(
        self,
        *args,
        auth_code: str,
        auth_code_verifier: str,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.auth_code = auth_code
        self.auth_code_verifier = auth_code_verifier

    @property
    def token_url(self) -> str:
        return (
            f"https://{self.kc_host}/auth/realms/"
            f"{self.kc_realm}/protocol/openid-connect/token"
        )

    def get_token_request_payload(self) -> dict:
        """
        {
            "grant_type": "authorization_code",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "redirect_uri": "your-redirect-uri",
            "code": self.auth_code,
            "code_verifier": self.auth_code_verifier,
        }
        """
        raise NotImplementedError

    def get_access_token(self, *args, **kwargs) -> str:
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = self.get_token_request_payload()
        try:
            response = requests.post(self.token_url, headers=headers, data=data)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise self.AuthError(str(e))

        result = response.json()
        access_token = result.get("access_token", "")
        id_token = result.get("id_token", "")

        # Set `id_token` in the session
        self.request.session["session_id_token"] = id_token
        self.request.session.save()

        return access_token
