import typing

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ..backend.fastapi import FastAPIKeycloakAuthBackend
from ..errors import AuthInterruptedError, AuthSkipError


class BaseFastAPIKCAuthentication(BaseHTTPMiddleware):
    backends: typing.List[typing.Type[FastAPIKeycloakAuthBackend]]

    def get_backend_context(
        self,
        request: Request,
        **kwargs,
    ) -> dict:
        context = {"request": request, **kwargs}
        return context

    def authenticate(self, request: Request) -> typing.Optional[dict]:
        for backend in self.backends:
            context = self.get_backend_context(request=request)
            try:
                claims = backend(**context).authenticate()
            except AuthSkipError:
                # Skip authentication for this backend
                continue
            except backend.AuthError as e:
                raise AuthInterruptedError(msg=str(e.msg))
            if claims:
                return claims

    def post_process_claims(
        self,
        claims: typing.Optional[dict],
        request: Request,
    ) -> Request:
        return request

    def is_already_authenticated(self, request: Request) -> bool:
        try:
            return request.state.user.is_authenticated
        except AttributeError:
            return False

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        already_authenticated = self.is_already_authenticated(request=request)
        if not already_authenticated:
            try:
                claims = self.authenticate(request=request)
            except AuthInterruptedError as e:
                return JSONResponse(status_code=401, content={"detail": str(e)})
            request = self.post_process_claims(claims=claims, request=request)
        response = await call_next(request)
        return response
