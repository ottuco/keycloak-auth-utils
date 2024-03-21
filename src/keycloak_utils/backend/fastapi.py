from ..verifier.fastapi import FastAPITokenVerifier
from .base import APIAuthMixin, BaseKCAuthBackend


class FastAPIKeycloakAuthBackend(APIAuthMixin, BaseKCAuthBackend):
    verifier = FastAPITokenVerifier
