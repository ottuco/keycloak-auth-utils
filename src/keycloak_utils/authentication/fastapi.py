import inspect
import typing

from asgiref.sync import sync_to_async
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from ..backend.fastapi import (
    AsyncFastAPIKeycloakAuthBackend,
    FastAPIKeycloakAuthBackend,
)
from ..errors import AuthInterruptedError, AuthSkipError


class _AbstractFastAPIKCAuthentication(BaseHTTPMiddleware):
    """Common logic for FastAPI authentication middlewares."""

    def get_backend_context(self, request: Request, **kwargs) -> dict:
        context = {"request": request, **kwargs}
        return context

    async def authenticate(self, request: Request) -> typing.Optional[dict]:
        raise NotImplementedError

    async def post_process_claims(
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
                claims = await self.authenticate(request=request)
            except AuthInterruptedError as e:
                return JSONResponse(status_code=401, content={"detail": str(e)})
            result = self.post_process_claims(claims=claims, request=request)
            if inspect.isawaitable(result):
                request = await result
            else:
                request = result
        response = await call_next(request)
        return response


class BaseFastAPIKCAuthentication(_AbstractFastAPIKCAuthentication):
    """Synchronous backend middleware retained for backwards compatibility."""

    backends: typing.List[typing.Type[FastAPIKeycloakAuthBackend]]

    async def authenticate(self, request: Request) -> typing.Optional[dict]:
        for backend in self.backends:
            context = self.get_backend_context(request=request)
            try:
                backend_instance = backend(**context)
                claims = await sync_to_async(backend_instance.authenticate)()
            except AuthSkipError:
                continue
            except backend_instance.AuthError as e:
                raise AuthInterruptedError(msg=str(e.msg))
            if claims:
                return claims


class AsyncFastAPIKCAuthentication(_AbstractFastAPIKCAuthentication):
    """Async FastAPI Keycloak Authentication Middleware."""

    backends: typing.List[typing.Type[AsyncFastAPIKeycloakAuthBackend]]

    async def authenticate(self, request: Request) -> typing.Optional[dict]:
        for backend in self.backends:
            context = self.get_backend_context(request=request)
            try:
                backend_instance = backend(**context)
                claims = await backend_instance.authenticate()
            except AuthSkipError:
                continue
            except backend_instance.AuthError as e:
                raise AuthInterruptedError(msg=str(e.msg))
            if claims:
                return claims
