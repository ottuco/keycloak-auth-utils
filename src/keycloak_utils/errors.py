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
    Base class for all authentication auth
    Errors that interrupt the authentication process
    """


class PublicKeyNotFound(AuthInterruptedError):
    """
    Authentication interrupted because the public key
    was not found at
    `https://<KeyCloakDomain>/auth/realms/<RealmName>/` URL

    Possible cases
        1. the URL may be incorrect
        2. the realm name may be incorrect
        3. the realm may not exist
    """


class JWTDecodeError(AuthInterruptedError):
    """
    Error while decoding the JWT token
    """
