import sys
from types import SimpleNamespace
from unittest import mock

import pytest

import keycloak_utils.contrib.django.conf as conf

pytestmark = pytest.mark.django_db


@pytest.fixture
def predefined_role_cls():
    """Import KeycloakPredefinedRole with a stubbed provider path."""
    original = conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER
    conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER = "os.path.exists"

    for key in list(sys.modules):
        if key in (
            "keycloak_utils.sync.predefined",
            "keycloak_utils.sync.django.core",
        ):
            del sys.modules[key]

    from keycloak_utils.sync.django.core import KeycloakPredefinedRole

    yield KeycloakPredefinedRole

    conf.KC_UTILS_PREDEFINED_ROLES_PROVIDER = original


def _make_instance(cls):
    """Construct a KeycloakPredefinedRole bypassing the live Keycloak __post_init__."""
    instance = cls.__new__(cls)
    instance._predefined_cache = None
    instance.current_role = None
    instance.current_policy = None
    return instance


def _make_role(name, permissions):
    return SimpleNamespace(name=name, permissions=permissions)


# ===================================================================
# 1. _seed_django_groups — creates/updates Django Groups + permissions
# ===================================================================


class TestSeedDjangoGroups:
    def test_creates_django_group_when_missing(self, predefined_role_cls):
        from django.contrib.auth.models import Group, Permission
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.get_for_model(Group)
        perm = Permission.objects.create(
            codename="seed_create_perm", name="p", content_type=ct
        )
        role = _make_role("seed-new-group", [perm])

        instance = _make_instance(predefined_role_cls)
        instance._predefined_cache = [role]

        assert not Group.objects.filter(name="seed-new-group").exists()

        instance._seed_django_groups()

        group = Group.objects.get(name="seed-new-group")
        assert list(group.permissions.values_list("codename", flat=True)) == [
            "seed_create_perm"
        ]

    def test_updates_existing_group_replacing_permissions(self, predefined_role_cls):
        from django.contrib.auth.models import Group, Permission
        from django.contrib.contenttypes.models import ContentType

        ct = ContentType.objects.get_for_model(Group)
        old_perm = Permission.objects.create(
            codename="seed_old_perm", name="old", content_type=ct
        )
        new_perm = Permission.objects.create(
            codename="seed_new_perm", name="new", content_type=ct
        )
        group = Group.objects.create(name="seed-update-group")
        group.permissions.add(old_perm)

        role = _make_role("seed-update-group", [new_perm])
        instance = _make_instance(predefined_role_cls)
        instance._predefined_cache = [role]

        instance._seed_django_groups()

        group.refresh_from_db()
        codenames = set(group.permissions.values_list("codename", flat=True))
        assert codenames == {"seed_new_perm"}

    def test_handles_role_with_empty_permissions(self, predefined_role_cls):
        from django.contrib.auth.models import Group

        role = _make_role("seed-empty-perms", [])
        instance = _make_instance(predefined_role_cls)
        instance._predefined_cache = [role]

        instance._seed_django_groups()

        group = Group.objects.get(name="seed-empty-perms")
        assert group.permissions.count() == 0


# ===================================================================
# 2. _load_predefined — caching semantics
# ===================================================================


class TestLoadPredefinedCache:
    def test_provider_invoked_once_across_multiple_calls(self, predefined_role_cls):
        provider_factory = mock.MagicMock()
        provider_factory.return_value = iter([_make_role("r1", [])])

        with mock.patch(
            "keycloak_utils.sync.django.core.get_predefined_roles_provider",
            return_value=provider_factory,
        ):
            instance = _make_instance(predefined_role_cls)
            instance._load_predefined()
            instance._load_predefined()
            instance._load_predefined()

        assert provider_factory.call_count == 1

    def test_empty_provider_result_is_cached(self, predefined_role_cls):
        """Sentinel bug fix: empty list result must not trigger re-invocation."""
        provider_factory = mock.MagicMock(return_value=iter([]))

        with mock.patch(
            "keycloak_utils.sync.django.core.get_predefined_roles_provider",
            return_value=provider_factory,
        ):
            instance = _make_instance(predefined_role_cls)
            assert instance._load_predefined() == []
            assert instance._load_predefined() == []
            assert instance._load_predefined() == []

        assert provider_factory.call_count == 1

    def test_cache_returns_materialized_list(self, predefined_role_cls):
        role = _make_role("r1", [])
        provider_factory = mock.MagicMock(return_value=iter([role]))

        with mock.patch(
            "keycloak_utils.sync.django.core.get_predefined_roles_provider",
            return_value=provider_factory,
        ):
            instance = _make_instance(predefined_role_cls)
            result = instance._load_predefined()

        assert isinstance(result, list)
        assert result == [role]


# ===================================================================
# 3. run_routine — seeds Django Groups before parent's KC push
# ===================================================================


class TestRunRoutineOrdering:
    def test_seeds_before_parent_run_routine(self, predefined_role_cls):
        instance = _make_instance(predefined_role_cls)
        call_order = []

        from keycloak_utils.sync.django.core import KeycloakRole

        with (
            mock.patch.object(
                predefined_role_cls,
                "_seed_django_groups",
                side_effect=lambda: call_order.append("seed"),
            ),
            mock.patch.object(
                KeycloakRole,
                "run_routine",
                side_effect=lambda self_: call_order.append("parent"),
                autospec=True,
            ),
        ):
            instance.run_routine()

        assert call_order == ["seed", "parent"]

    def test_parent_run_routine_called_once(self, predefined_role_cls):
        instance = _make_instance(predefined_role_cls)

        from keycloak_utils.sync.django.core import KeycloakRole

        with (
            mock.patch.object(predefined_role_cls, "_seed_django_groups"),
            mock.patch.object(
                KeycloakRole, "run_routine", autospec=True
            ) as mock_parent,
        ):
            instance.run_routine()

        mock_parent.assert_called_once_with(instance)
