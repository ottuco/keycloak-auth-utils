from unittest import mock

import pytest

from keycloak_utils.consumer.django.strategies import schema_based

pytestmark = pytest.mark.django_db

# Patch targets
_kc_admin = "keycloak_utils.consumer.django.strategies.kc_admin"
_connection = "keycloak_utils.consumer.django.strategies.connection"


class TestSchemaBased:
    """Tests for the schema_based wrapper's realm-name save/restore logic."""

    def test_restores_realm_name_after_success(self):
        """Realm name is restored to its original value after the wrapped
        function completes successfully."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection),
        ):
            mock_admin.connection.realm_name = "original-realm"

            def inner():
                # During execution, realm should be set to the schema
                assert mock_admin.connection.realm_name == "new-realm"

            wrapped = schema_based(inner, "new-realm", True)
            wrapped()

        assert mock_admin.connection.realm_name == "original-realm"

    def test_restores_realm_name_after_exception(self):
        """Realm name is restored even when the wrapped function raises."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection),
        ):
            mock_admin.connection.realm_name = "original-realm"

            def inner():
                raise RuntimeError("boom")

            wrapped = schema_based(inner, "new-realm", True)

            with pytest.raises(RuntimeError, match="boom"):
                wrapped()

        assert mock_admin.connection.realm_name == "original-realm"

    def test_custom_schema_skips_set_schema_to_public_after_success(self):
        """When is_custom_schema is True, set_schema_to_public() is NOT
        called (caller manages schema externally)."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection) as mock_conn,
        ):
            mock_admin.connection.realm_name = "original"

            wrapped = schema_based(lambda: None, "tenant-a", True)
            wrapped()

        mock_conn.set_schema_to_public.assert_not_called()

    def test_custom_schema_skips_set_schema_to_public_after_exception(self):
        """When is_custom_schema is True, set_schema_to_public() is NOT
        called even when the wrapped function raises."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection) as mock_conn,
        ):
            mock_admin.connection.realm_name = "original"

            def inner():
                raise ValueError("fail")

            wrapped = schema_based(inner, "tenant-b", True)

            with pytest.raises(ValueError):
                wrapped()

        mock_conn.set_schema_to_public.assert_not_called()

    def test_non_custom_schema_calls_set_schema_to_public_after_success(self):
        """When is_custom_schema is False, set_schema_to_public() IS called."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection) as mock_conn,
            mock.patch(
                "django_tenants.utils.get_tenant_model"
            ) as mock_get_tenant,
        ):
            mock_admin.connection.realm_name = "original"
            mock_tenant_model = mock.MagicMock()
            mock_tenant_model.objects.filter.return_value.exists.return_value = True
            mock_get_tenant.return_value = mock_tenant_model

            wrapped = schema_based(lambda: None, "tenant-a", False)
            wrapped()

        mock_conn.set_schema_to_public.assert_called_once()

    def test_sets_realm_name_during_execution(self):
        """The realm name is set to the schema value while the wrapped
        function executes."""
        observed_realm = {}

        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection),
        ):
            mock_admin.connection.realm_name = "before"

            def inner():
                observed_realm["during"] = mock_admin.connection.realm_name

            wrapped = schema_based(inner, "during-realm", True)
            wrapped()

        assert observed_realm["during"] == "during-realm"
        assert mock_admin.connection.realm_name == "before"

    def test_non_custom_schema_sets_tenant_schema(self):
        """When is_custom_schema is False, connection.set_schema is
        called with the schema value."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection) as mock_conn,
            mock.patch(
                "django_tenants.utils.get_tenant_model"
            ) as mock_get_tenant,
        ):
            mock_admin.connection.realm_name = "original"
            mock_conn.vendor = "postgresql"
            mock_tenant_model = mock.MagicMock()
            mock_tenant_model.objects.filter.return_value.exists.return_value = True
            mock_get_tenant.return_value = mock_tenant_model

            wrapped = schema_based(lambda: None, "tenant-x", False)
            wrapped()

        mock_conn.set_schema.assert_called_once_with("tenant-x")

    def test_custom_schema_skips_set_schema(self):
        """When is_custom_schema is True, connection.set_schema is NOT
        called (caller manages schema externally)."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection) as mock_conn,
        ):
            mock_admin.connection.realm_name = "original"

            wrapped = schema_based(lambda: None, "tenant-y", True)
            wrapped()

        mock_conn.set_schema.assert_not_called()

    def test_return_value_is_propagated(self):
        """The return value of the wrapped function is passed through."""
        with (
            mock.patch(_kc_admin) as mock_admin,
            mock.patch(_connection),
        ):
            mock_admin.connection.realm_name = "original"

            wrapped = schema_based(lambda: "result-42", "realm", True)
            result = wrapped()

        assert result == "result-42"
