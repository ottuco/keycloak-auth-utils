from ..manager.rest_framework import DjangoKeyManager
from .base import BaseTokenVerifier


class DjangoTokenVerifier(BaseTokenVerifier):
    manager = DjangoKeyManager
