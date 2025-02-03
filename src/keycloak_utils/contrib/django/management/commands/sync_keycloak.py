import logging
from contextlib import contextmanager

from django.core.management.base import BaseCommand
from keycloak import KeycloakConnectionError, KeycloakGetError

from keycloak_utils.sync.django.core import (
    KeycloakBase,
    KeycloakPermission,
    KeycloakRole,
    KeycloakUser,
)
from keycloak_utils.sync.kc_admin import kc_admin

from ...conf import (
    KC_UTILS_KC_ADMIN_ID,
    KC_UTILS_KC_ADMIN_PASSWORD,
    KC_UTILS_KC_ADMIN_REALM,
    KC_UTILS_KC_ADMIN_USER,
    KC_UTILS_KC_REALM,
    KC_UTILS_KC_SERVER_URL,
)

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Sync Keycloak roles to Django groups and assign permissions"
    desired_models_perms_map = {}
    kc_admin_config = {}
    clients = {}
    perms = {}

    def add_arguments(self, parser):
        parser.add_argument(
            "-migrate-groups",
            action="store_true",
            help="Run KeycloakRole routine",
            default=False,
        )

        parser.add_argument(
            "-migrate-users",
            action="store_true",
            help="Migrate users from Django to Keycloak",
            default=False,
        )
        parser.add_argument(
            "-migrate-permissions",
            action="store_true",
            help="Migrate permissions from Django to Keycloak",
            default=False,
        )
        parser.add_argument(
            "-migrate-base",
            action="store_true",
            help="Migrate base from Django to Keycloak",
            default=False,
        )

        parser.add_argument(
            "-delegate-celery",
            action="store_true",
            help="Determines if Celery is configured in project to delegate tasks to.",
            default=False,
        )
        parser.add_argument(
            "--server-url",
            type=str,
            help="Keycloak server URL (overrides environment variable)",
            default=KC_UTILS_KC_SERVER_URL,
        )
        parser.add_argument(
            "--admin-username",
            type=str,
            help="Keycloak admin ID (overrides environment variable)",
            default=KC_UTILS_KC_ADMIN_USER,
        )
        parser.add_argument(
            "--admin-secret",
            type=str,
            help="Keycloak admin secret (overrides environment variable)",
            default=KC_UTILS_KC_ADMIN_PASSWORD,
        )
        parser.add_argument(
            "--realm-name",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=KC_UTILS_KC_REALM,
        )
        parser.add_argument(
            "--admin-id",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=KC_UTILS_KC_ADMIN_ID,
        )
        parser.add_argument(
            "--admin-realm",
            type=str,
            help="Keycloak realm name (overrides environment variable)",
            default=KC_UTILS_KC_ADMIN_REALM,
        )
        parser.add_argument(
            "--public-clients",
            nargs="+",
            type=str,
            required=False,
            help="List of clients to create in the specified realm.",
        )
        parser.add_argument(
            "--private-clients",
            nargs="+",
            type=str,
            required=False,
            help="List of clients to create in the specified realm.",
        )

    def _validate_options(self, options): ...

    @classmethod
    @contextmanager
    def update_event_listeners(cls, realm_name):
        try:
            attrs = kc_admin.get_realm(realm_name)
            attrs |= {"eventsListeners": []}
            kc_admin.update_realm(realm_name, attrs)
        except KeycloakGetError:
            pass
        finally:
            yield
            attrs = kc_admin.get_realm(realm_name)
            attrs |= {"eventsListeners": ["custom-event-listener", "jboss-logging"]}
            kc_admin.update_realm(realm_name, attrs)

    def handle(self, *args, **options):
        self._validate_options(options)
        self.perms = (
            self.desired_models_perms_map if self.desired_models_perms_map else {}
        )

        self.clients = {
            "private": options["private_clients"],
            "public": options["public_clients"],
        }

        self.kc_admin_config = {
            "server_url": options["server_url"],
            "username": options["admin_username"],
            "password": options["admin_secret"],
            "client_id": options["admin_id"],
            "user_realm_name": options["admin_realm"],
        }

        with self.update_event_listeners(options["realm_name"]):
            handler_routine = (
                self.async_handle if options["delegate_celery"] else self.sync_handle
            )
            handler_routine(options)

    def sync_handle(self, options):
        try:
            kc_admin.initialize(**self.kc_admin_config)
        except KeycloakConnectionError as e:
            logger.error(
                "unsuccessful connection attempt to server please make sure that keycloak is running on provided url and verify provided credentials",
            )
        #

        if options["migrate_base"]:
            KeycloakBase(options["realm_name"], self.clients).run_routine()

        kc_admin.connection.realm_name = options["realm_name"]
        remaining_sync_classes = {
            "migrate_groups": lambda: KeycloakRole().run_routine(),
            "migrate_users": lambda: KeycloakUser().run_routine(),
            "migrate_permissions": lambda: KeycloakPermission(self.perms).run_routine(),
        }

        for option, sync_func in remaining_sync_classes.items():
            if options.get(option):
                sync_func()

    def async_handle(self, options):
        TASK = "keycloak_utils.sync.run_sync_routine_by_class_name"
        from celery import chain, chord, current_app

        self.kc_admin_config |= {"realm_name": options["realm_name"]}
        if options["migrate_base"]:
            # TODO: make this as a chord or a chain with groups instead of .get to block connection
            base_sync_result = current_app.send_task(
                TASK,
                args=(
                    self.kc_admin_config,
                    "KeycloakBase",
                    options["realm_name"],
                    self.clients,
                ),
            )
            logger.info("Keycloak Base sync routine is delegated successfully.")
            base_sync_result.get()  # Await the base init of kc realm
            logger.info("Keycloak Base sync routine is complete.")

        if options["migrate_groups"]:
            current_app.send_task(
                TASK,
                args=(
                    self.kc_admin_config,
                    "KeycloakRole",
                ),
            )
            logger.info("Keycloak Role sync routine is delegated successfully.")

        if options["migrate_permissions"]:
            current_app.send_task(
                TASK,
                args=(
                    self.kc_admin_config,
                    "KeycloakPermission",
                    self.perms,
                ),
                soft_time_limit=1000,
            )
            logger.info("Keycloak Permission sync routine is delegated successfully.")

        if options["migrate_users"]:
            current_app.send_task(
                TASK,
                args=(
                    self.kc_admin_config,
                    "KeycloakUser",
                ),
            )
            logger.info("Keycloak User sync routine is delegated successfully.")
