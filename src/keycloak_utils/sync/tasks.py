import importlib
import logging
from typing import Any, Dict

from celery import shared_task
from keycloak import KeycloakConnectionError

from . import kc_admin

logger = logging.getLogger(__name__)


@shared_task(
    name="keycloak_utils.sync.run_sync_routine_by_class_name",
    soft_time_limit=90,
    autoretry_for=(KeycloakConnectionError,),
    retry_backoff=True,
    max_retries=5,
)
def run_sync_routine_by_class_name(
    config: Dict[str, Any], class_name: str, *args: Any, framework: str = "django"
) -> None:
    if class_name == "KeycloakBase":
        config.pop("realm_name")
    try:
        logger.info("Initializing KeycloakAdmin instance...")
        kc_admin.initialize(**config)
        logger.info("KeycloakAdmin initialized successfully.")
    except KeycloakConnectionError:
        logger.error(
            f"unsuccessful connection attempt to server please make sure that keycloack is running on provided url and verify provided credentials"
        )

    try:
        class_path = f"keycloak_utils.sync.{framework}.core.{class_name}"
        module_name, class_name = class_path.rsplit(".", 1)
        module = importlib.import_module(module_name)
        cls = getattr(module, class_name)
        instance = cls(*args)
        instance.run_routine()
        logger.info(f"Successfully ran routine for {class_name}.")
    except Exception as e:
        logger.error(f"Error running routine for {class_name}: {e}")
        raise e
