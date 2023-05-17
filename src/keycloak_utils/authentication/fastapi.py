import typing

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ..backend.fastapi import FastAPIKeycloakAuthBackend


class BaseFastAPIKCAuthentication(BaseHTTPMiddleware):
    backend = FastAPIKeycloakAuthBackend

    def __init__(
        self,
        host: typing.Optional[str] = None,
        realm: typing.Optional[str] = None,
        algorithms: typing.Optional[list[str]] = None,
        audience: typing.Optional[str] = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.host = host or self.kc_host
        self.realm = realm or self.kc_realm
        self.algorithms = algorithms or self.kc_algorithms
        self.audience = audience or self.kc_audience

    def authenticate(self, request: Request) -> typing.Optional[dict]:
        backend = self.backend(
            request=request,
            host=self.host,
            realm=self.realm,
            algorithms=self.algorithms,
            audience=self.audience,
        )
        return backend.authenticate()

    def post_process_claims(
        self,
        claims: typing.Optional[dict],
        request: Request,
    ) -> Request:
        return request

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            claims = self.authenticate(request=request)
        except self.backend.AuthError as e:
            return JSONResponse(status_code=401, content={"detail": str(e)})
        request = self.post_process_claims(claims=claims, request=request)
        response = await call_next(request)
        return response
