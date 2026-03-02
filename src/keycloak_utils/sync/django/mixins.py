import json
import logging

from keycloak_utils.sync.kc_admin import kc_admin

logger = logging.getLogger(__name__)


class ProtocolMapperMixin:
    """
    Mixin that syncs a role-permissions protocol mapper to the frontend client.

    The mapper embeds a JSON claim (role_permissions) in the access token,
    keyed by service name so each microservice can publish its own
    role → permissions mapping independently.

    Claim structure:
        {
            "payout": {"admin": ["add_payment", "view_payment"]},
            "other":  {"editor": ["change_article"]}
        }
    """

    MAPPER_NAME = "role-permissions-mapper"
    FRONTEND_CLIENT_ID = "frontend"

    def get_role_permissions_map(self) -> dict:
        from django.contrib.auth.models import Group

        role_perms = {}
        for group in Group.objects.prefetch_related("permissions").all():
            perms = list(group.permissions.values_list("codename", flat=True))
            if perms:
                role_perms[group.name] = perms
        return role_perms

    def _get_frontend_client_uuid(self) -> str:
        clients = kc_admin.get_clients()
        for client in clients:
            if client["clientId"] == self.FRONTEND_CLIENT_ID:
                return client["id"]
        return None

    def _get_mapper_url(self, client_uuid: str) -> str:
        realm = kc_admin.connection.realm_name
        return f"/auth/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models"

    def _build_mapper_payload(self, service_map: dict) -> dict:
        return {
            "name": self.MAPPER_NAME,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "consentRequired": False,
            "config": {
                "access.token.claim": "true",
                "id.token.claim": "false",
                "userinfo.token.claim": "false",
                "claim.name": "role_permissions",
                "claim.value": json.dumps(service_map),
                "jsonType.label": "JSON",
            },
        }

    def sync_protocol_mapper(self, client_id: str):
        from django.db import connection

        kc_admin.connection.realm_name = connection.schema_name

        frontend_uuid = self._get_frontend_client_uuid()
        if not frontend_uuid:
            logger.error("Frontend client not found, cannot sync mapper")
            return

        role_perms = self.get_role_permissions_map()

        url = self._get_mapper_url(frontend_uuid)

        # Read existing mapper to preserve other services' data
        service_map = {}
        existing_mapper_id = None
        existing = kc_admin.connection.raw_get(url).json()
        for mapper in existing:
            if mapper["name"] == self.MAPPER_NAME:
                existing_mapper_id = mapper["id"]
                try:
                    service_map = json.loads(
                        mapper.get("config", {}).get("claim.value", "{}")
                    )
                except (json.JSONDecodeError, TypeError):
                    service_map = {}
                break

        # Update this service's key (or remove it if no perms)
        if role_perms:
            service_map[client_id] = role_perms
        else:
            service_map.pop(client_id, None)

        if not service_map:
            logger.info(f"No role_permissions for any service, skipping")
            return

        # Delete old mapper if exists, then create updated one
        if existing_mapper_id:
            kc_admin.connection.raw_delete(f"{url}/{existing_mapper_id}")

        payload = self._build_mapper_payload(service_map)
        response = kc_admin.connection.raw_post(url, data=json.dumps(payload))

        if response.status_code in (200, 201):
            logger.info(
                f"Synced mapper → '{self.FRONTEND_CLIENT_ID}' "
                f"(service '{client_id}': {len(role_perms)} roles)"
            )
        else:
            logger.error(
                f"Mapper failed for '{self.FRONTEND_CLIENT_ID}': "
                f"{response.status_code} {response.text}"
            )
