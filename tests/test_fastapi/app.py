import typing

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import HTTPException
from pydantic import BaseModel

from keycloak_utils.authentication.fastapi import BaseFastAPIKCAuthentication
from keycloak_utils.backend.fastapi import (
    FastAPIKeycloakAuthBackend as _FastAPIKeycloakAuthBackend,
)


class User(BaseModel):
    name: str
    email: str


class BearerAuthBackend(_FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Bearer"


class TokenAuthBackend(_FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Token"


class RandomAuthBackend(_FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_realm = "test"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Random"


class DynamicAuthBackend(_FastAPIKeycloakAuthBackend):
    kc_host = "localhost:8443"
    kc_algorithms = ["RS256"]
    kc_audience = "account"
    auth_scheme = "Dynamic"

    def get_kc_realm(self):
        return self.request.headers.get("x-service-id", "default-value")


class AuthenticationMiddleware(BaseFastAPIKCAuthentication):
    backends = [
        RandomAuthBackend,
        BearerAuthBackend,
        TokenAuthBackend,
        DynamicAuthBackend,
    ]

    def generate_user(self, claims: dict) -> User:
        return User.model_validate(claims)

    def post_process_claims(
        self,
        claims: typing.Optional[dict],
        request: Request,
    ) -> Request:
        if not claims:
            return request

        request.state.user = self.generate_user(claims=claims)
        return request


app = FastAPI()
app.add_middleware(AuthenticationMiddleware)


def is_authenticated(request: Request):
    user = getattr(request.state, "user", None)
    if user:
        return user
    raise HTTPException(status_code=403, detail="Not authenticated")


@app.get("/")
def user_details(user=Depends(is_authenticated)):
    return {"user": user}
