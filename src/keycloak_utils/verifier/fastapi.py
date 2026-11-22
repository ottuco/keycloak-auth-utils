from asgiref.sync import sync_to_async

from ..manager.fastapi import AsyncFastAPIKeyManager, FastAPIKeyManager
from ..utils import verify_token
from .base import BaseTokenVerifier, IssuerSetting, expected_issuers


class AsyncFastAPITokenVerifier:
    """Async token verifier for FastAPI."""

    def __init__(
        self,
        access_token: str,
        host: str,
        realm: str,
        algorithms: list[str],
        audience: str,
        issuer: IssuerSetting = None,
    ):
        self.access_token = access_token
        self.host = host
        self.realm = realm
        self.algorithms = algorithms
        self.audience = audience
        self.issuer = issuer
        self.manager = AsyncFastAPIKeyManager(host=host, realm=realm)

    async def get_claims(self, force: bool = False) -> dict:
        """Verify the token asynchronously using the public key."""

        public_key = await self.manager.get_key(force=force)
        return await sync_to_async(verify_token)(
            access_token=self.access_token,
            public_key=public_key,
            algorithms=self.algorithms,
            audience=self.audience,
            issuer=expected_issuers(
                self.issuer,
                realm=self.realm,
                url_realm=self.manager.url_realm,
            ),
        )


class FastAPITokenVerifier(BaseTokenVerifier):
    """Synchronous verifier retained for backwards compatibility."""

    manager = FastAPIKeyManager
