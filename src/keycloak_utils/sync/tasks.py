from celery import shared_task
from importlib import import_module

from keycloak_utils.sync.kc_admin import kc_admin

@shared_task(name="keycloak_utils.sync.run_sync_routine_by_class_name")
def run_sync_routine_by_class_name(kc_admin_config, classpath, *args, **kwargs):
    """
    Celery task to run Keycloak synchronization routines.
    
    Args:
        kc_admin_config (dict): Configuration for Keycloak admin client containing:
            - server_url: Keycloak server URL
            - username: Admin username
            - password: Admin password
            - client_id: Admin client ID
            - user_realm_name: Admin realm name
            - realm_name: Target realm name
        classpath (str): Full import path to the sync class (e.g., 'keycloak_utils.sync.django.core.KeycloakBase')
    
    Returns:
        bool: True if synchronization completes successfully
    
    Raises:
        ImportError: If the specified classpath cannot be imported
        AttributeError: If the specified class does not exist in the module
        Exception: Any other exceptions that occur during sync routine execution
    """
    try:
        kc_admin.initialize(**kc_admin_config)
        
        # Dynamic import using classpath
        module_path, class_name = classpath.rsplit('.', 1)
        module = import_module(module_path)
        sync_class = getattr(module, class_name)
        
        # Initialize and run the sync routine
        sync_instance = sync_class(*args)
        sync_instance.run_routine()
        
        return True
    except Exception as e:
        logger.error(f"Error running sync routine for {classpath}: {str(e)}")
        raise
