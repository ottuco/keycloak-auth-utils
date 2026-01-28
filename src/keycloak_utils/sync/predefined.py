import importlib

from keycloak_utils.contrib.django import conf


def load_callable_from_path(dotted_path: str):
    """
    Load a callable from a dotted path:
    'module.submodule.callable'
    """
    try:
        module_path, attr = dotted_path.rsplit(".", 1)
    except ValueError:
        raise RuntimeError(
            f"Invalid callable path '{dotted_path}'. "
            "Expected format: module.submodule.callable"
        )

    module = importlib.import_module(module_path)

    try:
        fn = getattr(module, attr)
    except AttributeError:
        raise RuntimeError(f"Callable '{attr}' not found in module '{module_path}'")

    if not callable(fn):
        raise RuntimeError(f"'{dotted_path}' is not callable")

    return fn


class PredefinedRolesProviderNotConfigured(RuntimeError):
    """
    Raised when predefined roles are required but no provider is configured.
    """

    def __init__(self, env_var: str):
        super().__init__(
            f"Predefined roles provider is not configured. "
            f"Set the environment variable '{env_var}' "
            f"to a dotted callable path."
        )


if not conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER:
    raise PredefinedRolesProviderNotConfigured("KC_UTILS_PREDEFINED_ROLES_PROVIDER")
