class KeyCloakBaseError(Exception):
    """
    Abstract base class for all Keycloak errors
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


class AuthenticationError(KeycloakError):
    """
    Errors that are raised while trying to authenticate a request
    """


class AuthSkipError(AuthenticationError):
    """
    Errors that are raised while trying to
    authenticate a request to skip any further authentication.

    This is useful for cases where you want
    to skip authentication due to missing headers.
    """


class AuthInterruptedError(AuthenticationError):
    """
    Base class for all authentication authe
    Errors that interrupt the authentication process
    """


class PublicKeyNotFound(AuthInterruptedError):
    """
    Base class for all Keycloak errors
    """


class JWTDecodeError(AuthInterruptedError):
    """
    Error while decoding the JWT token
    """
