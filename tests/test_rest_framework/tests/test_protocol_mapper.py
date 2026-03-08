import json
from unittest import mock

import pytest

from keycloak_utils.sync.django.mixins import ProtocolMapperMixin

pytestmark = pytest.mark.django_db

# Patch targets
_kc_admin = "keycloak_utils.sync.django.mixins.kc_admin"
_strategies_kc_admin = "keycloak_utils.sync.kc_admin.kc_admin"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class ConcreteMapper(ProtocolMapperMixin):
    """Concrete subclass so we can instantiate the mixin for testing."""

    pass


def _mock_response(status_code=200, json_data=None, text=""):
    resp = mock.MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    return resp


# ===================================================================
# 1. sync_protocol_mapper — Missing Frontend Client
# ===================================================================


class TestSyncProtocolMapperMissingFrontendClient:
    def test_returns_early_when_frontend_client_not_found(self):
        mapper = ConcreteMapper()
        with mock.patch.object(mapper, "_get_frontend_client_uuid", return_value=None):
            result = mapper.sync_protocol_mapper("my-service")

        assert result is None

    def test_logs_error_when_frontend_client_not_found(self):
        mapper = ConcreteMapper()
        with (
            mock.patch.object(mapper, "_get_frontend_client_uuid", return_value=None),
            mock.patch("keycloak_utils.sync.django.mixins.logger") as mock_logger,
        ):
            mapper.sync_protocol_mapper("my-service")

        mock_logger.error.assert_called_once()
        assert "not found" in mock_logger.error.call_args[0][0]

    def test_no_keycloak_calls_when_frontend_client_missing(self):
        mapper = ConcreteMapper()
        with (
            mock.patch.object(mapper, "_get_frontend_client_uuid", return_value=None),
            mock.patch(_kc_admin) as mock_admin,
        ):
            mapper.sync_protocol_mapper("my-service")

        mock_admin.connection.raw_get.assert_not_called()
        mock_admin.connection.raw_post.assert_not_called()
        mock_admin.connection.raw_put.assert_not_called()


# ===================================================================
# 2. Merge Logic — Corrupt, Invalid, Missing JSON
# ===================================================================


class TestSyncProtocolMapperMergeLogic:
    def _setup_mapper_with_existing(self, claim_value, mapper_id="mapper-uuid-1"):
        """Helper: sets up a mapper instance with a mocked existing mapper."""
        mapper = ConcreteMapper()
        existing_mapper = {
            "name": mapper.MAPPER_NAME,
            "id": mapper_id,
            "config": {"claim.value": claim_value},
        }
        return mapper, [existing_mapper]

    def test_corrupt_json_resets_to_empty(self):
        """When claim.value is not valid JSON, service_map resets to {}."""
        mapper, mappers = self._setup_mapper_with_existing("not-valid-json{{{")
        get_resp = _mock_response(status_code=200, json_data=mappers)
        post_resp = _mock_response(status_code=201)

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch.object(
                mapper,
                "get_role_permissions_map",
                return_value={"admin": ["view_user"]},
            ),
            mock.patch(
                "keycloak_utils.sync.django.mixins.logger"
            ) as mock_logger,
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.raw_put.return_value = post_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        mock_logger.warning.assert_called_once()
        assert "corrupt" in mock_logger.warning.call_args[0][0]

    def test_none_claim_value_treated_as_empty(self):
        """When claim.value is None, json.loads(None) raises TypeError — resets."""
        mapper = ConcreteMapper()
        existing_mapper = {
            "name": mapper.MAPPER_NAME,
            "id": "mapper-uuid",
            "config": {"claim.value": None},
        }
        get_resp = _mock_response(status_code=200, json_data=[existing_mapper])
        put_resp = _mock_response(status_code=204)

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch.object(
                mapper,
                "get_role_permissions_map",
                return_value={"editor": ["edit_post"]},
            ),
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.raw_put.return_value = put_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        # Should have called PUT to update the existing mapper
        mock_admin.connection.raw_put.assert_called_once()
        payload = json.loads(mock_admin.connection.raw_put.call_args[1]["data"])
        assert payload["config"]["claim.value"] == json.dumps(
            {"svc": {"editor": ["edit_post"]}}
        )

    def test_missing_config_key_uses_default(self):
        """When mapper has no 'config' key, .get('config', {}) returns {}."""
        mapper = ConcreteMapper()
        existing_mapper = {
            "name": mapper.MAPPER_NAME,
            "id": "mapper-uuid",
            # no "config" key at all
        }
        get_resp = _mock_response(status_code=200, json_data=[existing_mapper])
        put_resp = _mock_response(status_code=204)

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch.object(
                mapper,
                "get_role_permissions_map",
                return_value={"viewer": ["view_item"]},
            ),
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.raw_put.return_value = put_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        mock_admin.connection.raw_put.assert_called_once()

    def test_missing_claim_value_key_defaults_to_empty_dict(self):
        """When config exists but has no 'claim.value', default '{}' is used."""
        mapper = ConcreteMapper()
        existing_mapper = {
            "name": mapper.MAPPER_NAME,
            "id": "mapper-uuid",
            "config": {},  # no claim.value
        }
        get_resp = _mock_response(status_code=200, json_data=[existing_mapper])
        put_resp = _mock_response(status_code=204)

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch.object(
                mapper,
                "get_role_permissions_map",
                return_value={"admin": ["manage"]},
            ),
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.raw_put.return_value = put_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        payload = json.loads(mock_admin.connection.raw_put.call_args[1]["data"])
        assert "svc" in json.loads(payload["config"]["claim.value"])

    def test_partially_valid_json_preserves_other_services(self):
        """Existing valid JSON with another service key is preserved during merge."""
        mapper = ConcreteMapper()
        existing_data = {"other-svc": {"role1": ["perm1"]}}
        existing_mapper = {
            "name": mapper.MAPPER_NAME,
            "id": "mapper-uuid",
            "config": {"claim.value": json.dumps(existing_data)},
        }
        get_resp = _mock_response(status_code=200, json_data=[existing_mapper])
        put_resp = _mock_response(status_code=204)

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch.object(
                mapper,
                "get_role_permissions_map",
                return_value={"admin": ["view"]},
            ),
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.raw_put.return_value = put_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("my-svc")

        payload = json.loads(mock_admin.connection.raw_put.call_args[1]["data"])
        merged = json.loads(payload["config"]["claim.value"])
        assert merged["other-svc"] == {"role1": ["perm1"]}
        assert merged["my-svc"] == {"admin": ["view"]}

    def test_non_json_response_from_keycloak_returns_early(self):
        """When get_response.json() raises ValueError, method returns early."""
        mapper = ConcreteMapper()
        get_resp = _mock_response(status_code=200)
        get_resp.json.side_effect = ValueError("bad json")

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch("keycloak_utils.sync.django.mixins.logger") as mock_logger,
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        mock_logger.error.assert_called_once()
        assert "non-JSON" in mock_logger.error.call_args[0][0]
        mock_admin.connection.raw_post.assert_not_called()
        mock_admin.connection.raw_put.assert_not_called()

    def test_failed_get_status_returns_early(self):
        """When fetching mappers returns non-200, method returns early."""
        mapper = ConcreteMapper()
        get_resp = _mock_response(status_code=500, text="Internal Server Error")

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch("keycloak_utils.sync.django.mixins.logger") as mock_logger,
        ):
            mock_admin.connection.raw_get.return_value = get_resp
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        mock_logger.error.assert_called_once()
        mock_admin.connection.raw_post.assert_not_called()

    def test_network_error_fetching_mappers_returns_early(self):
        """When raw_get raises an exception, method logs and returns."""
        mapper = ConcreteMapper()

        with (
            mock.patch.object(
                mapper, "_get_frontend_client_uuid", return_value="fe-uuid"
            ),
            mock.patch(_kc_admin) as mock_admin,
            mock.patch("keycloak_utils.sync.django.mixins.logger") as mock_logger,
        ):
            mock_admin.connection.raw_get.side_effect = ConnectionError("timeout")
            mock_admin.connection.realm_name = "test-realm"

            mapper.sync_protocol_mapper("svc")

        mock_logger.error.assert_called_once()
        assert "Network error" in mock_logger.error.call_args[0][0]


# ===================================================================
# 3. _handle_delete — Exception Propagation
# ===================================================================


class TestHandleDeleteExceptionPropagation:
    def test_sync_mapper_exception_is_caught_and_logged(self):
        """When sync_protocol_mapper raises, _handle_delete catches and logs."""
        from django.contrib.auth.models import Group

        group = Group.objects.create(name="test-role")

        from keycloak_utils.consumer.django.strategies import RoleEventStrategy

        strategy = RoleEventStrategy()

        with (
            mock.patch.object(
                strategy,
                "sync_protocol_mapper",
                side_effect=RuntimeError("KC down"),
            ),
            mock.patch(
                "keycloak_utils.consumer.django.strategies.logger"
            ) as mock_logger,
        ):
            strategy._handle_delete(group_name="test-role", role_id="role-123")

        mock_logger.error.assert_called_once()
        assert "syncing protocol mapper" in mock_logger.error.call_args[0][0]
        assert not Group.objects.filter(name="test-role").exists()

    def test_group_deletion_failure_skips_mapper_sync(self):
        """When group.delete() fails, sync_protocol_mapper is NOT called."""
        from keycloak_utils.consumer.django.strategies import RoleEventStrategy

        strategy = RoleEventStrategy()

        with (
            mock.patch.object(strategy, "sync_protocol_mapper") as mock_sync,
            mock.patch(
                "keycloak_utils.consumer.django.strategies.logger"
            ) as mock_logger,
        ):
            # Group doesn't exist — .get() will raise DoesNotExist
            strategy._handle_delete(group_name="nonexistent-group", role_id="role-x")

        mock_sync.assert_not_called()
        mock_logger.error.assert_called_once()

    def test_successful_delete_calls_sync_mapper(self):
        """On successful group deletion, sync_protocol_mapper IS called."""
        from django.contrib.auth.models import Group

        from keycloak_utils.consumer.django.strategies import RoleEventStrategy

        Group.objects.create(name="deletable-role")
        strategy = RoleEventStrategy()

        with mock.patch.object(strategy, "sync_protocol_mapper") as mock_sync:
            strategy._handle_delete(group_name="deletable-role", role_id="role-456")

        mock_sync.assert_called_once_with(strategy.ms_name)
        assert not Group.objects.filter(name="deletable-role").exists()

    def test_no_partial_mutation_on_sync_failure(self):
        """Group IS deleted even if sync_protocol_mapper raises (deletion committed)."""
        from django.contrib.auth.models import Group

        from keycloak_utils.consumer.django.strategies import RoleEventStrategy

        Group.objects.create(name="role-to-delete")
        strategy = RoleEventStrategy()

        with mock.patch.object(
            strategy,
            "sync_protocol_mapper",
            side_effect=Exception("fail"),
        ):
            strategy._handle_delete(group_name="role-to-delete", role_id="r1")

        # Group deletion still committed
        assert not Group.objects.filter(name="role-to-delete").exists()


# ===================================================================
# 4. get_role_permissions_map
# ===================================================================


class TestGetRolePermissionsMap:
    def test_normal_role_mapping(self):
        from django.contrib.auth.models import Group, Permission
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.get_for_model(Group)
        perm = Permission.objects.create(
            codename="test_perm_normal", name="Test Perm Normal", content_type=ct
        )
        group = Group.objects.create(name="editors")
        group.permissions.add(perm)

        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        assert "editors" in result
        assert "test_perm_normal" in result["editors"]

    def test_empty_roles(self):
        """When no groups exist, returns empty dict."""
        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        assert result == {}

    def test_roles_without_permissions_excluded(self):
        """Groups with no permissions are NOT included in the map."""
        from django.contrib.auth.models import Group

        Group.objects.create(name="empty-group")

        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        assert "empty-group" not in result

    def test_multiple_roles_with_permissions(self):
        from django.contrib.auth.models import Group, Permission
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.get_for_model(Group)
        perm1 = Permission.objects.create(
            codename="perm_a", name="Perm A", content_type=ct
        )
        perm2 = Permission.objects.create(
            codename="perm_b", name="Perm B", content_type=ct
        )

        g1 = Group.objects.create(name="role_alpha")
        g1.permissions.add(perm1)

        g2 = Group.objects.create(name="role_beta")
        g2.permissions.add(perm1, perm2)

        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        assert set(result["role_alpha"]) == {"perm_a"}
        assert set(result["role_beta"]) == {"perm_a", "perm_b"}

    def test_duplicate_group_names_not_possible(self):
        """Django enforces unique group names — verify via ORM constraint."""
        from django.contrib.auth.models import Group
        from django.db import IntegrityError

        Group.objects.create(name="unique-group")
        with pytest.raises(IntegrityError):
            Group.objects.create(name="unique-group")

    def test_returns_dict_type(self):
        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        assert isinstance(result, dict)

    def test_permission_codenames_are_strings(self):
        from django.contrib.auth.models import Group, Permission
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.get_for_model(Group)
        perm = Permission.objects.create(
            codename="str_perm", name="Str Perm", content_type=ct
        )
        group = Group.objects.create(name="str-group")
        group.permissions.add(perm)

        mapper = ConcreteMapper()
        result = mapper.get_role_permissions_map()

        for codename in result["str-group"]:
            assert isinstance(codename, str)


# ===================================================================
# 5. _build_mapper_payload
# ===================================================================


class TestBuildMapperPayload:
    def test_exact_structure(self):
        mapper = ConcreteMapper()
        service_map = {"svc": {"admin": ["perm1"]}}

        payload = mapper._build_mapper_payload(service_map)

        assert payload == {
            "name": "role-permissions-mapper",
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

    def test_correct_top_level_keys(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({})

        expected_keys = {
            "name",
            "protocol",
            "protocolMapper",
            "consentRequired",
            "config",
        }
        assert set(payload.keys()) == expected_keys

    def test_correct_config_keys(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({})

        expected_config_keys = {
            "access.token.claim",
            "id.token.claim",
            "userinfo.token.claim",
            "claim.name",
            "claim.value",
            "jsonType.label",
        }
        assert set(payload["config"].keys()) == expected_config_keys

    def test_no_extra_fields(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({"x": 1})

        assert len(payload) == 5
        assert len(payload["config"]) == 6

    def test_claim_value_is_json_string(self):
        mapper = ConcreteMapper()
        service_map = {"app": {"role": ["p1", "p2"]}}
        payload = mapper._build_mapper_payload(service_map)

        claim_value = payload["config"]["claim.value"]
        assert isinstance(claim_value, str)
        assert json.loads(claim_value) == service_map

    def test_consent_required_is_false(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({})

        assert payload["consentRequired"] is False

    def test_access_token_claim_enabled(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({})

        assert payload["config"]["access.token.claim"] == "true"
        assert payload["config"]["id.token.claim"] == "false"
        assert payload["config"]["userinfo.token.claim"] == "false"

    def test_empty_service_map(self):
        mapper = ConcreteMapper()
        payload = mapper._build_mapper_payload({})

        assert payload["config"]["claim.value"] == "{}"

    def test_uses_mapper_name_attribute(self):
        mapper = ConcreteMapper()
        mapper.MAPPER_NAME = "custom-mapper-name"
        payload = mapper._build_mapper_payload({})

        assert payload["name"] == "custom-mapper-name"


# ===================================================================
# 6. KeycloakRolePermsMapper Instantiation
# ===================================================================


class TestKeycloakRolePermsMapperInstantiation:
    @pytest.fixture(autouse=True)
    def _import_mapper_class(self):
        """Import KeycloakRolePermsMapper, bypassing the predefined module guard."""
        import sys

        import keycloak_utils.contrib.django.conf as conf

        original = conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER
        conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER = "os.path.exists"

        # Clear failed import cache so module re-imports with patched value
        for key in list(sys.modules):
            if key in (
                "keycloak_utils.sync.predefined",
                "keycloak_utils.sync.django.core",
            ):
                del sys.modules[key]

        from keycloak_utils.sync.django.core import KeycloakRolePermsMapper, KeycloakSync

        self.KeycloakRolePermsMapper = KeycloakRolePermsMapper
        self.KeycloakSync = KeycloakSync

        yield

        conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER = original

    def test_inherits_protocol_mapper_mixin(self):
        assert issubclass(self.KeycloakRolePermsMapper, ProtocolMapperMixin)

    def test_instantiation(self):
        instance = self.KeycloakRolePermsMapper()
        assert instance is not None

    def test_has_mapper_name(self):
        instance = self.KeycloakRolePermsMapper()
        assert instance.MAPPER_NAME == "role-permissions-mapper"

    def test_has_frontend_client_id(self):
        instance = self.KeycloakRolePermsMapper()
        assert isinstance(instance.FRONTEND_CLIENT_ID, str)
        assert len(instance.FRONTEND_CLIENT_ID) > 0

    def test_has_run_routine(self):
        instance = self.KeycloakRolePermsMapper()
        assert hasattr(instance, "run_routine")
        assert callable(instance.run_routine)

    def test_run_routine_calls_sync_protocol_mapper(self):
        instance = self.KeycloakRolePermsMapper()
        with mock.patch.object(instance, "sync_protocol_mapper") as mock_sync:
            instance.run_routine()

        mock_sync.assert_called_once()

    def test_run_routine_passes_client_id(self):
        instance = self.KeycloakRolePermsMapper()
        with mock.patch.object(instance, "sync_protocol_mapper") as mock_sync:
            instance.run_routine()

        args = mock_sync.call_args[0]
        assert len(args) == 1
        assert isinstance(args[0], str)

    def test_has_build_mapper_payload(self):
        instance = self.KeycloakRolePermsMapper()
        assert hasattr(instance, "_build_mapper_payload")

    def test_has_get_role_permissions_map(self):
        instance = self.KeycloakRolePermsMapper()
        assert hasattr(instance, "get_role_permissions_map")

    def test_does_not_inherit_keycloak_sync(self):
        """KeycloakRolePermsMapper intentionally avoids KeycloakSync base."""
        assert not issubclass(self.KeycloakRolePermsMapper, self.KeycloakSync)
