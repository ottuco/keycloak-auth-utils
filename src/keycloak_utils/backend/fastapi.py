import typing

from asgiref.sync import sync_to_async

from ..errors import JWTDecodeError
from ..verifier.fastapi import AsyncFastAPITokenVerifier, FastAPITokenVerifier
from .base import APIAuthMixin, BaseKCAuthBackend


class AsyncFastAPIKeycloakAuthBackend(APIAuthMixin, BaseKCAuthBackend):
    """Async Keycloak authentication backend for FastAPI."""

    verifier = AsyncFastAPITokenVerifier

    async def verify_access_token(self, token: str) -> dict:
        """Verify the access token asynchronously."""

        try:
            verifier = self.verifier(
                access_token=token,
                host=self.kc_host,
                realm=self.kc_realm,
                algorithms=self.kc_algorithms,
                audience=self.kc_audience,
            )
            claims = await verifier.get_claims()
            return await sync_to_async(self.post_authenticate_hooks)(claims)
        except JWTDecodeError as e:
            raise self.AuthError(e)

    async def authenticate(self) -> typing.Optional[dict]:
        token = self.get_access_token()
        if not token:
            return None
        return await self.verify_access_token(token=token)


class FastAPIKeycloakAuthBackend(APIAuthMixin, BaseKCAuthBackend):
    verifier = FastAPITokenVerifier
