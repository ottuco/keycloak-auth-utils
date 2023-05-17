from ..verifier.fastapi import FastAPITokenVerifier
from .base import BaseKCAuthBackend


class FastAPIKeycloakAuthBackend(BaseKCAuthBackend):
    verifier = FastAPITokenVerifier
