class KeyCloakBaseError(Exception):
    """
    Base class for all Keycloak errors
    """

    def __init__(self, msg, *args, **kwargs):
        self.msg = msg

    def __str__(self):
        return str(self.msg)

    def __repr__(self):
        return f"{self.__class__.__name__}({self})"


class KeycloakError(KeyCloakBaseError):
    """
    Base class for all Keycloak errors
    """


class PublicKeyNotFound(KeycloakError):
    """
    Base class for all Keycloak errors
    """


class JWTDecodeError(KeycloakError):
    """
    Error while decoding the JWT token
    """
