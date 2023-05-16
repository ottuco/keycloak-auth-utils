from ..verifier.rest_framework import DjangoTokenVerifier
from .base import BaseKCAuthBackend


class DRFKeycloakAuthBackend(BaseKCAuthBackend):
    verifier = DjangoTokenVerifier
