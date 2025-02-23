import warnings

try:
    from .sync.tasks import *
except ImportError:
    warnings.warn(
        "Celery is not installed. Delegating to Celery wont be available. "
        "Install with `pip install keycloak-utils[celery]` to enable full features.",
        ImportWarning,
    )
