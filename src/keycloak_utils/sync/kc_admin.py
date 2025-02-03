import json
import logging

from keycloak import KeycloakAdmin, KeycloakPostError
from keycloak.exceptions import (
    KeycloakGetError,
    KeycloakPutError,
    raise_error_from_response,
)

from ..contrib.django import conf as settings

logger = logging.Logger(__name__)


class KeycloakAdminSingleton:
    _instance = None
    _initialized = False
    _admin = None
    _params = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
            cls._instance._admin = None
        return cls._instance

    @property
    def initialized(self):
        return self._initialized

    def validate_params_override(self, current_params):
        for key, value in current_params.items():
            if key not in self._params or self._params[key] != value:
                break
        else:
            # If all provided params match, skip re-initialization
            logger.info("KeycloakAdmin already initialized with matching parameters.")
            return False
        return True

    def initialize(
        self,
        server_url=settings.KC_UTILS_KC_SERVER_URL,
        username=settings.KC_UTILS_KC_ADMIN_USER,
        password=settings.KC_UTILS_KC_ADMIN_PASSWORD,
        realm_name=None,
        user_realm_name=settings.KC_UTILS_KC_ADMIN_REALM,
        client_id=settings.KC_UTILS_KC_ADMIN_ID,
    ):
        current_params = {
            "server_url": server_url,
            "username": username,
            "password": password,
            "realm_name": realm_name,
            "user_realm_name": user_realm_name,
            "client_id": client_id,
        }

        if not self.validate_params_override(current_params):
            return

        self._admin = KeycloakAdmin(**current_params)

        logger.info(
            "KeycloakAdmin initialized with server_url=%s, realm_name=%s",
            server_url,
            realm_name,
        )
        self._initialized = True

    def __getattr__(self, item):
        if not self._initialized:
            raise Exception(
                "KeycloakAdmin is not initialized. Call 'initialize()' first.",
            )
        return getattr(self._admin, item)

    def update_realm_upconfig(self, realm_name, payload):
        """Update a realm ui-ext.

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :param payload: RealmRepresentation
        :type payload: dict
        :return: Http response
        :rtype: dict
        """
        ADMIN_UI_URL = "/auth/admin/realms/{realm-name}/users/profile"
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_put(
            ADMIN_UI_URL.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[200],
        )

    def get_realm_upconfig(self, realm_name):
        """Get a specific realm.

        RealmRepresentation:
        https://www.keycloak.org/docs-api/24.0.2/rest-api/index.html#_realmrepresentation

        :param realm_name: Realm name (not the realm id)
        :type realm_name: str
        :return: RealmRepresentation
        :rtype: dict
        """
        REALM_UPCONFIG_URL = "admin/realms/{realm-name}/users/profile"
        params_path = {"realm-name": realm_name}
        data_raw = self.connection.raw_get(REALM_UPCONFIG_URL.format(**params_path))
        return raise_error_from_response(
            data_raw,
            KeycloakGetError,
            expected_codes=[200],
        )

    def get_client_resource_server(self, client_id):
        CLIENT_RESOURCE_SERVER_URL = (
            "/auth/admin/realms/{realm-name}/clients/{id}/authz/resource-server"
        )
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_get(
            CLIENT_RESOURCE_SERVER_URL.format(**params_path),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakGetError,
            expected_codes=[200],
        )

    def update_client_resource_server(self, client_id, payload):
        CLIENT_RESOURCE_SERVER_URL = (
            "/auth/admin/realms/{realm-name}/clients/{id}/authz/resource-server"
        )
        params_path = {"realm-name": self.connection.realm_name, "id": client_id}
        data_raw = self.connection.raw_put(
            CLIENT_RESOURCE_SERVER_URL.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPutError,
            expected_codes=[204],
        )

    def create_client_scope_mapper(self, client_scope_id, payload, skip_exists=True):
        PROTOCOL_MAPPERS_URL = "/auth/admin/realms/{realm-name}/client-scopes/{client-scope-id}/protocol-mappers/models"
        params_path = {
            "realm-name": self.connection.realm_name,
            "client-scope-id": client_scope_id,
        }
        data_raw = self.connection.raw_post(
            PROTOCOL_MAPPERS_URL.format(**params_path),
            data=json.dumps(payload),
        )
        return raise_error_from_response(
            data_raw,
            KeycloakPostError,
            expected_codes=[201],
            skip_exists=skip_exists,
        )


kc_admin: KeycloakAdmin = KeycloakAdminSingleton()
kc_admin.initialize()
