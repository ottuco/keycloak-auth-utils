import json
import logging
import time
from contextlib import contextmanager
from typing import Optional

from django.core.cache import cache

from ...contrib.django.conf import KC_UTILS_KC_FRONTEND_CLIENT_ID
from ..kc_admin import kc_admin

logger = logging.getLogger(__name__)

# Default lock settings — override via Django settings if needed.
_LOCK_TIMEOUT = 30  # seconds before the lock auto-expires (safety net)
_LOCK_RETRY_INTERVAL = 0.5  # seconds between retry attempts
_LOCK_MAX_RETRIES = 20  # give up after 10 seconds total


@contextmanager
def _mapper_lock(realm: str, frontend_client_id: str):
    """Distributed lock scoped to a realm + frontend client.

    Uses Django's cache.add() which is atomic on shared backends
    (Redis, Memcached).  Falls back gracefully on LocMemCache
    (single-process safety only).
    """
    lock_key = f"sync_protocol_mapper:{realm}:{frontend_client_id}"
    acquired = False

    for _ in range(_LOCK_MAX_RETRIES):
        if cache.add(lock_key, "1", _LOCK_TIMEOUT):
            acquired = True
            break
        time.sleep(_LOCK_RETRY_INTERVAL)

    if not acquired:
        raise TimeoutError(
            f"Could not acquire mapper lock for realm='{realm}', "
            f"client='{frontend_client_id}' after "
            f"{_LOCK_MAX_RETRIES * _LOCK_RETRY_INTERVAL}s."
        )

    try:
        yield
    finally:
        cache.delete(lock_key)


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

    Subclasses may override FRONTEND_CLIENT_ID to target a different client.
    KC_UTILS_KC_FRONTEND_CLIENT_ID (default: "frontend") controls the default.
    """

    MAPPER_NAME = "role-permissions-mapper"
    FRONTEND_CLIENT_ID: str = KC_UTILS_KC_FRONTEND_CLIENT_ID

    # ------------------------------------------------------------------ #
    # Data helpers                                                         #
    # ------------------------------------------------------------------ #

    def get_role_permissions_map(self) -> dict:
        from django.contrib.auth.models import Group

        role_perms = {}
        for group in Group.objects.prefetch_related("permissions").all():
            perms = list(group.permissions.values_list("codename", flat=True))
            if perms:
                role_perms[group.name] = perms
        return role_perms

    # ------------------------------------------------------------------ #
    # Keycloak API helpers                                                 #
    # ------------------------------------------------------------------ #

    def _get_frontend_client_uuid(self) -> Optional[str]:
        clients = kc_admin.get_clients()
        for client in clients:
            if client["clientId"] == self.FRONTEND_CLIENT_ID:
                return client["id"]
        return None

    def _mapper_base_url(self, client_uuid: str) -> str:
        realm = kc_admin.connection.realm_name
        return (
            f"/auth/admin/realms/{realm}/clients/{client_uuid}"
            f"/protocol-mappers/models"
        )

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

    # ------------------------------------------------------------------ #
    # Main sync entry point                                                #
    # ------------------------------------------------------------------ #

    def sync_protocol_mapper(self, client_id: str) -> None:
        """
        Merge this service's role→permissions map into the shared
        role_permissions claim on the frontend client's protocol mapper.

        In multi-tenant / consumer contexts the caller is responsible for
        having set kc_admin.connection.realm_name to the correct realm
        before invoking this method.  The method reads that value when
        building Keycloak API URLs via _mapper_base_url().
        """
        # ---- 1. Locate the frontend client --------------------------------
        frontend_uuid = self._get_frontend_client_uuid()
        if not frontend_uuid:
            logger.error(
                "Frontend client '%s' not found in Keycloak — cannot sync mapper.",
                self.FRONTEND_CLIENT_ID,
            )
            return

        base_url = self._mapper_base_url(frontend_uuid)
        realm = kc_admin.connection.realm_name

        # Acquire a distributed lock so concurrent callers (Celery tasks,
        # consumer workers) serialise their GET → merge → PUT cycles and
        # don't overwrite each other's service entries.
        try:
            lock_ctx = _mapper_lock(realm, self.FRONTEND_CLIENT_ID)
            lock_ctx.__enter__()
        except TimeoutError:
            logger.error(
                "Could not acquire mapper lock for '%s' in realm '%s' "
                "— skipping sync to avoid stale-read overwrite.",
                self.FRONTEND_CLIENT_ID,
                realm,
            )
            return

        try:
            self._sync_protocol_mapper_locked(client_id, base_url)
        finally:
            lock_ctx.__exit__(None, None, None)

    def _sync_protocol_mapper_locked(self, client_id: str, base_url: str) -> None:
        """Inner method that runs inside the distributed lock."""

        # ---- 2. Fetch existing protocol mappers with status validation -----
        try:
            get_response = kc_admin.connection.raw_get(base_url)
        except Exception as e:
            logger.error(
                "Network error fetching protocol mappers for client '%s': %s",
                self.FRONTEND_CLIENT_ID,
                e,
            )
            return

        if get_response.status_code != 200:
            logger.error(
                "Failed to fetch protocol mappers for client '%s': %s — %s",
                self.FRONTEND_CLIENT_ID,
                get_response.status_code,
                get_response.text,
            )
            return

        # ---- 3. Find the role-permissions mapper and read its service map --
        existing_mapper_id: Optional[str] = None
        service_map: dict = {}

        try:
            mappers = get_response.json()
        except ValueError as e:
            logger.error(
                "Keycloak returned a non-JSON response when listing mappers "
                "for client '%s': %s",
                self.FRONTEND_CLIENT_ID,
                e,
            )
            return

        for mapper in mappers:
            if mapper["name"] == self.MAPPER_NAME:
                existing_mapper_id = mapper["id"]
                try:
                    service_map = json.loads(
                        mapper.get("config", {}).get("claim.value", "{}")
                    )
                except (json.JSONDecodeError, TypeError):
                    logger.warning(
                        "Mapper '%s' has corrupt claim.value — resetting to empty.",
                        self.MAPPER_NAME,
                    )
                    service_map = {}
                break

        # ---- 4. Merge this service's permissions into the shared map -------
        role_perms = self.get_role_permissions_map()
        if role_perms:
            service_map[client_id] = role_perms
        else:
            service_map.pop(client_id, None)

        # ---- 5. If no permissions remain for ANY service, clean up mapper --
        if not service_map:
            if existing_mapper_id:
                try:
                    del_response = kc_admin.connection.raw_delete(
                        f"{base_url}/{existing_mapper_id}"
                    )
                except Exception as e:
                    logger.error(
                        "Network error deleting mapper from '%s': %s",
                        self.FRONTEND_CLIENT_ID,
                        e,
                    )
                    return

                if del_response.status_code == 204:
                    logger.info(
                        "Deleted role-permissions mapper from '%s' "
                        "(no permissions remain for any service).",
                        self.FRONTEND_CLIENT_ID,
                    )
                else:
                    logger.error(
                        "Failed to delete mapper from '%s': %s — %s",
                        self.FRONTEND_CLIENT_ID,
                        del_response.status_code,
                        del_response.text,
                    )
            return

        # ---- 6. Persist the updated mapper ---------------------------------
        payload = self._build_mapper_payload(service_map)

        try:
            if existing_mapper_id:
                payload["id"] = existing_mapper_id
                response = kc_admin.connection.raw_put(
                    f"{base_url}/{existing_mapper_id}",
                    data=json.dumps(payload),
                )
                success_codes = (204,)
            else:
                response = kc_admin.connection.raw_post(
                    base_url, data=json.dumps(payload)
                )
                success_codes = (201,)
        except Exception as e:
            logger.error(
                "Network error persisting mapper on '%s': %s",
                self.FRONTEND_CLIENT_ID,
                e,
            )
            return

        if response.status_code in success_codes:
            logger.info(
                "Synced role-permissions mapper on '%s' "
                "(service '%s': %d roles).",
                self.FRONTEND_CLIENT_ID,
                client_id,
                len(role_perms),
            )
        else:
            logger.error(
                "Failed to sync mapper on '%s': %s — %s",
                self.FRONTEND_CLIENT_ID,
                response.status_code,
                response.text,
            )
