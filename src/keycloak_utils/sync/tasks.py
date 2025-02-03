import importlib
import logging
from typing import Any, Dict

from celery import shared_task
from keycloak import KeycloakConnectionError

logger = logging.getLogger(__name__)


@shared_task(
    name="keycloak_utils.sync.run_sync_routine_by_class_name",  # Task name used for Celery
    soft_time_limit=90,  # Soft time limit for task execution (in seconds)
    autoretry_for=(
        KeycloakConnectionError,
    ),  # Auto-retry on specific error (KeycloakConnectionError)
    retry_backoff=True,  # Enable exponential backoff for retries
    max_retries=5,  # Max retries before failing the task
)
def run_sync_routine_by_class_name(
    config: Dict[str, Any],  # Configuration dictionary for KeycloakAdmin
    class_name: str,  # Name of the class to run the routine for
    *args: Any,  # Additional arguments passed to the class constructor
    framework: str = "django",  # Framework to be used (default is Django)
) -> None:
    from .kc_admin import kc_admin

    """
    Runs a synchronization routine for the specified class name (e.g., KeycloakBase)
    by dynamically importing and initializing the corresponding class.

    Args:
        config: Configuration dictionary for KeycloakAdmin.
        class_name: Name of the class to invoke.
        *args: Additional arguments passed to the class constructor.
        framework: Framework type (default is "django").

    Raises:
        Exception: Any exception raised during the routine execution is logged and re-raised.
    """
    # Check if class_name is "KeycloakBase" and remove the "realm_name" from the config
    if class_name == "KeycloakBase":
        config.pop(
            "realm_name",
        )  # Remove realm_name from the configuration if it's KeycloakBase

    try:
        # Initialize KeycloakAdmin instance using the provided config
        logger.info("Initializing KeycloakAdmin instance...")
        kc_admin.initialize(
            **config,
        )  # Initialize the KeycloakAdmin object with the configuration
        logger.info("KeycloakAdmin initialized successfully.")
    except KeycloakConnectionError:
        # Log an error message if there is a connection issue with Keycloak
        logger.error(
            f"Unsuccessful connection attempt to the server. Please make sure that Keycloak is running on the provided URL "
            f"and verify the provided credentials.",
        )

    try:
        # Construct the full class path and import the class dynamically
        # Full class path including framework
        class_path = f"keycloak_utils.sync.{framework}.core.{class_name}"
        module_name, class_name = class_path.rsplit(
            ".",
            1,
        )  # Split class path to get module name and class name
        module = importlib.import_module(module_name)  # Import the module dynamically
        cls = getattr(module, class_name)  # Get the class reference from the module
        instance = cls(*args)  # Instantiate the class with the provided arguments
        instance.run_routine()  # Run the routine method of the class
        logger.info(f"Successfully ran routine for {class_name}.")  # Log success
    except Exception as e:
        # Log and raise any exceptions encountered while running the routine
        logger.error(f"Error running routine for {class_name}: {e}")
        raise e
