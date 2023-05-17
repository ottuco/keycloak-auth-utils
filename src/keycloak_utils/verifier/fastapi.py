from ..manager.fastapi import FastAPIKeyManager
from .base import BaseTokenVerifier


class FastAPITokenVerifier(BaseTokenVerifier):
    manager = FastAPIKeyManager
