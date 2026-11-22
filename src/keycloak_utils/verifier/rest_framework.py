from ..manager.rest_framework import DjangoKeyManager
from .base import BaseTokenVerifier, IssuerSetting


class DjangoTokenVerifier(BaseTokenVerifier):
    manager = DjangoKeyManager

    def get_issuer_setting(self) -> IssuerSetting:
        if self.issuer:
            return self.issuer
        from ..contrib.django import conf

        return conf.KC_UTILS_KC_ISSUER
