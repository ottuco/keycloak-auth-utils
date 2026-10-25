"""The shared role-authoring mechanism (#159879).

A consuming project supplies its manifest content, its template content and one
fingerprint model (`polls.SeededRole` here, standing in for a real service) and gets
seeding, drift detection and reset-to-template from the library.
"""

from unittest import mock

import pytest
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

from keycloak_utils.rbac import (
    ADVANCED,
    CURATED,
    Manifest,
    ManifestEntry,
    ManifestIncompleteError,
    RoleTemplate,
    SeedOutcome,
    TemplateRegistry,
    UnknownTemplateRuleError,
    advanced_entry,
    assert_complete,
    check_completeness,
    decide_seed,
    fingerprint_for,
)
from keycloak_utils.rbac.django import ResetGuard, RoleSeeder
from tests.test_rest_framework.polls.models import SeededRole

READ = "polls.view_poll"
WRITE = "polls.change_poll"
DROP = "polls.delete_poll"


def _entry(rule, permission, group="Polls"):
    return ManifestEntry(rule, permission, rule.title(), f"{rule} polls", group)


def _manifest():
    return Manifest(
        [
            _entry("read", READ),
            _entry("write", WRITE),
            _entry("drop", DROP),
        ],
        excluded={"internal": "operator-only, never on a role"},
    )


def _registry(*templates, manifest=None):
    return TemplateRegistry(manifest or _manifest(), templates)


def _codenames(group):
    return sorted(
        f"{a}.{c}"
        for a, c in group.permissions.values_list("content_type__app_label", "codename")
    )


def _perm(label):
    app_label, codename = label.split(".")
    return Permission.objects.get(content_type__app_label=app_label, codename=codename)


# ---------------------------------------------------------------- pure: no Django


class TestTheDeclarativeHalfImportsNoDjango:
    @pytest.mark.parametrize(
        "module", ["manifest", "templates", "seeding", "completeness"]
    )
    def test_the_declarative_modules_import_no_django(self, module):
        """A project declares its manifest at import time, whether or not the library
        is in INSTALLED_APPS, so the modules it declares with must not need Django.
        Only `keycloak_utils.rbac.django` may."""
        import ast
        import pathlib

        import keycloak_utils.rbac as package

        source = pathlib.Path(package.__file__).with_name(f"{module}.py").read_text()
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported.add(node.module)
        assert (
            sorted(
                m for m in imported if m.split(".")[0] in ("django", "rest_framework")
            )
            == []
        )


class TestSeedDecision:
    """The six outcomes, as a pure function of the inputs."""

    WANTED = [READ, WRITE]

    def test_created(self):
        decision = decide_seed(
            wanted=self.WANTED,
            current=[],
            group_created=True,
            recorded_fingerprint=None,
        )
        assert (
            decision.outcome,
            decision.write_permissions,
            decision.create_record,
        ) == (
            SeedOutcome.CREATED,
            True,
            True,
        )
        assert decision.fingerprint == fingerprint_for(self.WANTED)

    def test_skipped_foreign_for_a_group_that_already_existed(self):
        """An existing group with no record is the tenant's, even an empty one."""
        decision = decide_seed(
            wanted=self.WANTED,
            current=[],
            group_created=False,
            recorded_fingerprint=None,
        )
        assert decision.outcome is SeedOutcome.SKIPPED_FOREIGN
        assert not (decision.write_permissions or decision.create_record)

    def test_skipped_foreign_even_when_the_composition_matches(self):
        decision = decide_seed(
            wanted=self.WANTED,
            current=self.WANTED,
            group_created=False,
            recorded_fingerprint=None,
        )
        assert decision.outcome is SeedOutcome.SKIPPED_FOREIGN

    def test_unchanged(self):
        decision = decide_seed(
            wanted=self.WANTED,
            current=self.WANTED,
            group_created=False,
            recorded_fingerprint=fingerprint_for(self.WANTED),
        )
        assert decision.outcome is SeedOutcome.UNCHANGED
        assert not decision.write_permissions

    def test_upgraded_when_the_template_moved_and_the_group_did_not(self):
        decision = decide_seed(
            wanted=self.WANTED + [DROP],
            current=self.WANTED,
            group_created=False,
            recorded_fingerprint=fingerprint_for(self.WANTED),
        )
        assert (decision.outcome, decision.write_permissions) == (
            SeedOutcome.UPGRADED,
            True,
        )
        assert decision.fingerprint == fingerprint_for(self.WANTED + [DROP])

    def test_detached_when_the_group_was_edited(self):
        decision = decide_seed(
            wanted=self.WANTED + [DROP],
            current=[READ],
            group_created=False,
            recorded_fingerprint=fingerprint_for(self.WANTED),
        )
        assert (decision.outcome, decision.detach, decision.write_permissions) == (
            SeedOutcome.DETACHED,
            True,
            False,
        )

    def test_skipped_detached(self):
        decision = decide_seed(
            wanted=self.WANTED,
            current=[READ],
            group_created=False,
            recorded_fingerprint=fingerprint_for(self.WANTED),
            detached=True,
        )
        assert decision.outcome is SeedOutcome.SKIPPED_DETACHED
        assert not (decision.write_permissions or decision.detach)

    def test_the_fingerprint_ignores_order_and_duplicates(self):
        assert fingerprint_for([WRITE, READ, READ]) == fingerprint_for([READ, WRITE])


class TestManifest:
    def test_a_rule_listed_twice_is_refused(self):
        with pytest.raises(ValueError, match="duplicate"):
            Manifest([_entry("read", READ), _entry("read", WRITE)])

    def test_a_rule_both_listed_and_excluded_is_refused(self):
        with pytest.raises(ValueError, match="both listed and excluded"):
            Manifest([_entry("read", READ)], excluded={"read": "no"})

    def test_an_exclusion_needs_a_reason(self):
        with pytest.raises(ValueError, match="no reason"):
            Manifest([], excluded={"internal": "  "})

    def test_three_buckets(self):
        manifest = Manifest(
            [_entry("read", READ), advanced_entry("write", WRITE, "Polls")],
            excluded={"drop": "destructive"},
        )
        assert [e.rule for e in manifest.in_bucket(CURATED)] == ["read"]
        assert [e.rule for e in manifest.in_bucket(ADVANCED)] == ["write"]
        assert manifest.entry_for("write").label == "Change poll"
        assert (manifest.is_known("drop"), manifest.entry_for("drop")) == (True, None)

    def test_groups_are_sorted_by_label(self):
        groups = _manifest().groups()
        assert [e.rule for e in groups["Polls"]] == ["drop", "read", "write"]


class TestCompletenessGate:
    """Run from a consuming repo's suite against its own rule registry."""

    def test_an_unclassified_rule_fails_the_gate(self):
        registered = {"read", "write", "drop", "internal", "brand_new"}
        with pytest.raises(ManifestIncompleteError, match="brand_new"):
            assert_complete(_manifest(), registered)

    def test_classifying_it_makes_the_gate_pass(self):
        registered = {"read", "write", "drop", "internal", "brand_new"}
        manifest = Manifest(
            [_entry("read", READ), _entry("write", WRITE), _entry("drop", DROP)],
            excluded={"internal": "operator-only", "brand_new": "not for roles yet"},
        )
        assert_complete(manifest, registered)

    def test_stale_entries_and_exclusions_are_reported(self):
        report = check_completeness(_manifest(), {"read", "write"})
        assert (report.uncurated, report.stale_entries, report.stale_exclusions) == (
            (),
            ("drop",),
            ("internal",),
        )
        assert not report.ok

    def test_it_is_an_assertion_error_so_a_test_fails_as_a_test(self):
        assert issubclass(ManifestIncompleteError, AssertionError)


class TestTemplates:
    def test_a_template_naming_an_unknown_rule_raises_when_the_registry_is_built(self):
        with pytest.raises(UnknownTemplateRuleError, match="nonexistent"):
            _registry(RoleTemplate("viewer", "Viewer", "", ("read", "nonexistent")))

    def test_a_duplicate_key_is_refused(self):
        t = RoleTemplate("viewer", "Viewer", "", ("read",))
        with pytest.raises(ValueError, match="duplicate"):
            _registry(t, t)

    def test_permissions_are_sorted_and_deduped(self):
        manifest = Manifest(
            [_entry("read", READ), _entry("see", READ), _entry("write", WRITE)]
        )
        registry = _registry(
            RoleTemplate("editor", "Editor", "", ("write", "see", "read")),
            manifest=manifest,
        )
        assert registry.permissions_for("editor") == sorted([READ, WRITE])


# ---------------------------------------------------------------- Django adapter

pytestmark_db = pytest.mark.django_db


@pytest.fixture
def poll_perms(db):
    """The three polls permissions Django creates for the test model."""
    ContentType.objects.clear_cache()
    return {label: _perm(label) for label in (READ, WRITE, DROP)}


def _seeder(*templates, **kwargs):
    return RoleSeeder(_registry(*templates), SeededRole, **kwargs)


VIEWER = RoleTemplate("viewer", "Viewer", "Read polls", ("read",))
VIEWER_V2 = RoleTemplate("viewer", "Viewer", "Read and edit polls", ("read", "write"))


@pytest.mark.django_db
class TestRoleSeeder:
    def test_created_fills_the_group_and_records_it(self, poll_perms):
        created = []
        outcome = _seeder(VIEWER, on_created=created.append).seed_template(VIEWER)

        group = Group.objects.get(name="viewer")
        assert outcome is SeedOutcome.CREATED
        assert _codenames(group) == [READ]
        record = SeededRole.objects.get(group=group)
        assert (record.template_key, record.fingerprint, record.detached) == (
            "viewer",
            fingerprint_for([READ]),
            False,
        )
        assert created == [group]

    def test_a_second_run_is_unchanged(self, poll_perms):
        seeder = _seeder(VIEWER)
        seeder.seed_template(VIEWER)
        assert seeder.seed_template(VIEWER) is SeedOutcome.UNCHANGED

    def test_a_template_update_reaches_an_untouched_group(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)

        outcome = _seeder(VIEWER_V2).seed_template(VIEWER_V2)

        group = Group.objects.get(name="viewer")
        assert outcome is SeedOutcome.UPGRADED
        assert _codenames(group) == sorted([READ, WRITE])
        assert SeededRole.objects.get(group=group).fingerprint == fingerprint_for(
            [READ, WRITE]
        )

    def test_an_edited_group_detaches_and_is_not_modified(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        group = Group.objects.get(name="viewer")
        group.permissions.add(poll_perms[DROP])  # the tenant's own edit

        first = _seeder(VIEWER_V2).seed_template(VIEWER_V2)
        second = _seeder(VIEWER_V2).seed_template(VIEWER_V2)

        assert (first, second) == (SeedOutcome.DETACHED, SeedOutcome.SKIPPED_DETACHED)
        assert _codenames(group) == sorted([READ, DROP])
        assert SeededRole.objects.get(group=group).detached is True

    def test_a_group_the_seeder_did_not_create_is_left_alone(self, poll_perms):
        mine = Group.objects.create(name="viewer")
        mine.permissions.add(poll_perms[DROP])

        outcome = _seeder(VIEWER).seed_template(VIEWER)

        assert outcome is SeedOutcome.SKIPPED_FOREIGN
        assert _codenames(mine) == [DROP]
        assert not SeededRole.objects.filter(group=mine).exists()

    def test_reset_restores_the_composition_and_reattaches(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        group = Group.objects.get(name="viewer")
        group.permissions.add(poll_perms[DROP])
        _seeder(VIEWER).seed_template(VIEWER)  # detaches

        report = _seeder(VIEWER).reset_to_template(group)

        record = SeededRole.objects.get(group=group)
        assert (report.outcome, report.pending) == (SeedOutcome.UPGRADED, ())
        assert _codenames(group) == [READ]
        assert record.detached is False
        assert _seeder(VIEWER_V2).seed_template(VIEWER_V2) is SeedOutcome.UPGRADED

    def test_reset_of_a_group_the_seeder_does_not_own_raises(self, poll_perms):
        mine = Group.objects.create(name="hand-made")
        with pytest.raises(SeededRole.DoesNotExist):
            _seeder(VIEWER).reset_to_template(mine)

    def test_seed_all_covers_every_template(self, poll_perms):
        editor = RoleTemplate("editor", "Editor", "", ("read", "write"))
        outcomes = _seeder(VIEWER, editor).seed_all()
        assert outcomes == {
            "viewer": SeedOutcome.CREATED,
            "editor": SeedOutcome.CREATED,
        }

    def test_a_missing_permission_row_is_named(self, poll_perms):
        manifest = Manifest([_entry("ghost", "polls.haunt_poll")])
        ghost = RoleTemplate("ghost", "Ghost", "", ("ghost",))
        seeder = RoleSeeder(TemplateRegistry(manifest, [ghost]), SeededRole)
        with pytest.raises(LookupError, match="polls.haunt_poll"):
            seeder.seed_template(ghost)

    def test_seeding_makes_no_keycloak_call(self, poll_perms):
        """Seeding must work on a deployment with Keycloak switched off."""
        with mock.patch("keycloak_utils.sync.kc_admin.kc_admin") as kc:
            _seeder(VIEWER).seed_template(VIEWER)
            _seeder(VIEWER_V2).seed_template(VIEWER_V2)
        assert kc.mock_calls == []

    def test_the_model_can_be_named_lazily(self, poll_perms):
        seeder = RoleSeeder(_registry(VIEWER), "polls.SeededRole")
        assert seeder.seed_template(VIEWER) is SeedOutcome.CREATED


class _ApprovalGuard(ResetGuard):
    """A project's approval flow, reduced to the shape the reset asks for."""

    def __init__(self, gated, *, approve_now=False, refuse=()):
        self.gated, self.approve_now, self.refuse = set(gated), approve_now, set(refuse)
        self.requested = []

    def check_removals(self, group, removing):
        blocked = [p for p in removing if f"polls.{p.codename}" in self.refuse]
        if blocked:
            raise PermissionError(blocked)

    def gated_additions(self, group, adding):
        return [p for p in adding if f"polls.{p.codename}" in self.gated]

    def request_addition(self, group, permission, actor):
        self.requested.append((permission.codename, actor))
        if self.approve_now:
            group.permissions.add(permission)
        return not self.approve_now


@pytest.mark.django_db
class TestResetGuard:
    def _detached_viewer_v2(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        group = Group.objects.get(name="viewer")
        group.permissions.add(poll_perms[DROP])
        _seeder(VIEWER_V2).seed_template(VIEWER_V2)  # detaches
        return group

    def test_a_gated_addition_is_requested_and_the_role_stays_detached(
        self, poll_perms
    ):
        group = self._detached_viewer_v2(poll_perms)
        guard = _ApprovalGuard(gated={WRITE})

        report = _seeder(VIEWER_V2, reset_guard=guard).reset_to_template(
            group, actor="maker"
        )

        assert report.pending == (WRITE,)
        assert guard.requested == [("change_poll", "maker")]
        assert _codenames(group) == [READ]
        assert SeededRole.objects.get(group=group).detached is True

    def test_once_approved_the_role_reattaches_at_parity(self, poll_perms):
        group = self._detached_viewer_v2(poll_perms)
        seeder = _seeder(VIEWER_V2, reset_guard=_ApprovalGuard(gated={WRITE}))
        seeder.reset_to_template(group)

        group.permissions.add(poll_perms[WRITE])  # the checker approved
        assert seeder.reattach_if_at_parity(group) is True
        assert SeededRole.objects.get(group=group).detached is False

    def test_an_addition_the_flow_lets_through_is_not_pending(self, poll_perms):
        group = self._detached_viewer_v2(poll_perms)
        guard = _ApprovalGuard(gated={WRITE}, approve_now=True)

        report = _seeder(VIEWER_V2, reset_guard=guard).reset_to_template(group)

        assert report.pending == ()
        assert SeededRole.objects.get(group=group).detached is False

    def test_a_refused_removal_writes_nothing(self, poll_perms):
        group = self._detached_viewer_v2(poll_perms)
        before = _codenames(group)

        with pytest.raises(PermissionError):
            _seeder(
                VIEWER_V2, reset_guard=_ApprovalGuard(gated=(), refuse={DROP})
            ).reset_to_template(group)

        assert _codenames(group) == before


@pytest.mark.django_db
class TestPredefinedRoleWithAFingerprintModel:
    """`KeycloakPredefinedRole` with `KC_UTILS_SEEDED_ROLE_MODEL` set (#159879 R2)."""

    @pytest.fixture
    def predefined(self, settings):
        import keycloak_utils.contrib.django.conf as conf
        from keycloak_utils.sync.django.core import KeycloakPredefinedRole

        with mock.patch.object(conf, "KC_UTILS_SEEDED_ROLE_MODEL", "polls.SeededRole"):

            def make(roles, adopt=False):
                instance = KeycloakPredefinedRole.__new__(KeycloakPredefinedRole)
                instance._predefined_cache = list(roles)
                instance.adopt_existing = adopt
                return instance

            yield make

    @staticmethod
    def _role(name, perms):
        from types import SimpleNamespace

        return SimpleNamespace(name=name, permissions=perms)

    def test_an_untouched_group_is_upgraded(self, predefined, poll_perms):
        predefined([self._role("clerk", [poll_perms[READ]])])._seed_django_groups()
        predefined(
            [self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])]
        )._seed_django_groups()

        assert _codenames(Group.objects.get(name="clerk")) == sorted([READ, WRITE])

    def test_an_edited_group_detaches_and_keeps_the_edit(self, predefined, poll_perms):
        predefined([self._role("clerk", [poll_perms[READ]])])._seed_django_groups()
        group = Group.objects.get(name="clerk")
        group.permissions.add(poll_perms[DROP])

        predefined(
            [self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])]
        )._seed_django_groups()

        assert _codenames(group) == sorted([READ, DROP])
        assert SeededRole.objects.get(group=group).detached is True

    def test_adopt_existing_takes_over_a_group_that_still_matches(
        self, predefined, poll_perms
    ):
        group = Group.objects.create(name="clerk")
        group.permissions.add(poll_perms[READ])

        predefined(
            [self._role("clerk", [poll_perms[READ]])], adopt=True
        )._seed_django_groups()
        predefined(
            [self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])]
        )._seed_django_groups()

        assert SeededRole.objects.filter(group=group).exists()
        assert _codenames(group) == sorted([READ, WRITE])

    def test_without_adopt_an_existing_group_is_foreign(self, predefined, poll_perms):
        group = Group.objects.create(name="clerk")
        group.permissions.add(poll_perms[READ])

        predefined(
            [self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])]
        )._seed_django_groups()

        assert _codenames(group) == [READ]
        assert not SeededRole.objects.filter(group=group).exists()


@pytest.mark.django_db
class TestRoleNamePushWritesNoAuthorization:
    """#159879 R3: a role-name push performs no Authorization Services write."""

    def _sync(self, cls):
        from keycloak_utils.contrib.django.conf import KC_UTILS_KC_CLIENT_ID

        kc = mock.MagicMock()
        kc.get_clients.return_value = [{"clientId": KC_UTILS_KC_CLIENT_ID, "id": "cid"}]
        kc.get_client_roles.side_effect = lambda *_: [
            {"name": g.name, "id": f"rid-{g.pk}"} for g in Group.objects.all()
        ]
        with mock.patch("keycloak_utils.sync.django.core.kc_admin", kc):
            cls().run_routine()
        return kc

    def test_the_name_push_touches_no_scope_permission_or_policy(self, poll_perms):
        from keycloak_utils.sync.django.core import KeycloakRoleName

        group = Group.objects.create(name="viewer")
        group.permissions.add(poll_perms[READ], poll_perms[WRITE])

        kc = self._sync(KeycloakRoleName)

        authz = [call for call in kc.mock_calls if "authz" in call[0]]
        assert authz == []
        assert [call[0] for call in kc.mock_calls] == [
            "get_clients",
            "get_client_roles",
        ]

    def test_the_full_sync_still_writes_policies(self, poll_perms):
        from keycloak_utils.sync.django.core import KeycloakRole

        Group.objects.create(name="viewer")
        with mock.patch.object(
            KeycloakRole, "get_or_create_policy"
        ) as policy, mock.patch.object(
            KeycloakRole, "add_policies_to_permissions"
        ) as attach, mock.patch.object(
            KeycloakRole, "sync_protocol_mapper"
        ):
            self._sync(KeycloakRole)
        assert (policy.called, attach.called) == (True, True)

    def test_a_missing_role_is_created_by_name_alone(self, poll_perms):
        from keycloak_utils.contrib.django.conf import KC_UTILS_KC_CLIENT_ID
        from keycloak_utils.sync.django.core import KeycloakRoleName

        Group.objects.create(name="viewer")
        realm_roles = []

        def create_role(client_id, payload, skip_exists=True):
            realm_roles.append({"name": payload["name"], "id": "rid"})
            return payload["name"]

        kc = mock.MagicMock()
        kc.get_clients.return_value = [{"clientId": KC_UTILS_KC_CLIENT_ID, "id": "cid"}]
        kc.get_client_roles.side_effect = lambda *_: list(realm_roles)
        kc.create_client_role.side_effect = create_role
        with mock.patch("keycloak_utils.sync.django.core.kc_admin", kc):
            KeycloakRoleName().run_routine()

        assert [role["name"] for role in realm_roles] == ["viewer"]
        assert [call[0] for call in kc.mock_calls] == [
            "get_clients",
            "get_client_roles",
            "create_client_role",
            "get_client_roles",
        ]


@pytest.mark.django_db
class TestReviewFollowUps:
    """What the review of #159879 found, each pinned."""

    def test_a_group_edited_into_the_new_template_still_detaches(self, poll_perms):
        """Any edit detaches, even one that lands on what the template then becomes:
        the seeder never guesses that a hand edit was meant as an upgrade."""
        _seeder(VIEWER).seed_template(VIEWER)
        group = Group.objects.get(name="viewer")
        group.permissions.add(poll_perms[WRITE])  # by hand, what V2 then adds

        outcome = _seeder(VIEWER_V2).seed_template(VIEWER_V2)

        assert outcome is SeedOutcome.DETACHED
        assert SeededRole.objects.get(group=group).detached is True
        assert _codenames(group) == sorted([READ, WRITE])

    def test_reset_of_a_role_whose_template_is_gone_says_so(self, poll_perms):
        from keycloak_utils.rbac import UnknownTemplateError

        _seeder(VIEWER).seed_template(VIEWER)
        group = Group.objects.get(name="viewer")

        with pytest.raises(UnknownTemplateError, match="'viewer'.*does not hold"):
            _seeder().reset_to_template(group)
        assert issubclass(UnknownTemplateError, KeyError)

    def test_on_created_runs_after_the_seed_transaction(self, poll_perms):
        from django.db import connection

        outside = len(connection.savepoint_ids)
        seen = []
        _seeder(
            VIEWER, on_created=lambda _: seen.append(len(connection.savepoint_ids))
        ).seed_template(VIEWER)

        assert seen == [outside]

    def test_a_record_holds_a_name_as_long_as_a_group_name(self):
        assert (
            SeededRole._meta.get_field("template_key").max_length
            == Group._meta.get_field("name").max_length
        )


@pytest.mark.django_db
@pytest.mark.parametrize("name", ["view_poll", "polls.", ".view_poll", ""])
def test_a_malformed_permission_name_is_refused_by_name(name):
    from keycloak_utils.rbac.django import resolve_permissions

    with pytest.raises(ValueError, match="app_label.codename") as raised:
        resolve_permissions(["polls.view_poll", name])

    assert repr(name) in str(raised.value)


class TestPredefinedRoleFollowUps:
    @staticmethod
    def _role(name, perms):
        from types import SimpleNamespace

        return SimpleNamespace(name=name, permissions=perms)

    @pytest.fixture
    def with_model(self):
        import keycloak_utils.contrib.django.conf as conf

        with mock.patch.object(conf, "KC_UTILS_SEEDED_ROLE_MODEL", "polls.SeededRole"):
            yield

    def _instance(self, cls, roles):
        instance = cls.__new__(cls)
        instance._predefined_cache = list(roles)
        instance.adopt_existing = cls.adopt_existing
        return instance

    def test_keycloak_is_told_what_an_edited_group_holds(self, with_model, poll_perms):
        """The provider still lists a permission the tenant took off the role; the
        push must not keep granting it."""
        from keycloak_utils.sync.django.core import KeycloakPredefinedRole

        role = self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])
        sync = self._instance(KeycloakPredefinedRole, [role])
        sync._seed_django_groups()
        group = Group.objects.get(name="clerk")
        group.permissions.remove(poll_perms[WRITE])
        sync._seed_django_groups()  # detaches

        pushed = sorted(p.codename for p in sync._get_permissions(role))

        assert SeededRole.objects.get(group=group).detached is True
        assert pushed == ["view_poll"]

    def test_an_attached_group_is_pushed_as_the_provider_lists_it(
        self, with_model, poll_perms
    ):
        from keycloak_utils.sync.django.core import KeycloakPredefinedRole

        role = self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])
        sync = self._instance(KeycloakPredefinedRole, [role])
        sync._seed_django_groups()

        pushed = sorted(p.codename for p in sync._get_permissions(role))

        assert pushed == ["change_poll", "view_poll"]

    def test_an_unrecorded_group_is_warned_about_by_name(
        self, with_model, poll_perms, caplog
    ):
        from keycloak_utils.sync.django.core import KeycloakPredefinedRole

        Group.objects.create(name="clerk").permissions.add(poll_perms[READ])
        role = self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])

        with caplog.at_level("WARNING", logger="keycloak_utils.sync.django.core"):
            self._instance(KeycloakPredefinedRole, [role])._seed_django_groups()

        assert [r.levelname for r in caplog.records] == ["WARNING"]
        assert "'clerk'" in caplog.text and "-adopt-predefined-groups" in caplog.text

    def test_the_adoption_routine_records_a_matching_group(
        self, with_model, poll_perms
    ):
        from keycloak_utils.sync.django.core import KeycloakPredefinedRoleAdoption

        group = Group.objects.create(name="clerk")
        group.permissions.add(poll_perms[READ])
        role = self._role("clerk", [poll_perms[READ]])

        self._instance(KeycloakPredefinedRoleAdoption, [role])._seed_django_groups()

        assert SeededRole.objects.get(group=group).fingerprint == fingerprint_for(
            [READ]
        )

    def test_the_adoption_log_tells_adopted_from_already_recorded(
        self, with_model, poll_perms, caplog
    ):
        from keycloak_utils.sync.django.core import KeycloakPredefinedRoleAdoption

        Group.objects.create(name="clerk").permissions.add(poll_perms[READ])
        role = self._role("clerk", [poll_perms[READ]])
        routine = self._instance(KeycloakPredefinedRoleAdoption, [role])

        with caplog.at_level("INFO", logger="keycloak_utils.sync.django.core"):
            routine._seed_django_groups()
            first = caplog.text
            caplog.clear()
            routine._seed_django_groups()

        assert "'clerk': adopted" in first
        assert "'clerk': unchanged" in caplog.text

    def test_adoption_does_not_point_a_differing_group_back_at_itself(
        self, with_model, poll_perms, caplog
    ):
        from keycloak_utils.sync.django.core import KeycloakPredefinedRoleAdoption

        Group.objects.create(name="clerk").permissions.add(poll_perms[READ])
        role = self._role("clerk", [poll_perms[READ], poll_perms[WRITE]])

        with caplog.at_level("WARNING", logger="keycloak_utils.sync.django.core"):
            self._instance(KeycloakPredefinedRoleAdoption, [role])._seed_django_groups()

        assert "'clerk'" in caplog.text and "not adopted" in caplog.text
        assert "-adopt-predefined-groups" not in caplog.text
        assert not SeededRole.objects.exists()

    def test_adoption_without_the_model_is_refused(self, poll_perms):
        from django.core.exceptions import ImproperlyConfigured

        from keycloak_utils.sync.django.core import KeycloakPredefinedRoleAdoption

        group = Group.objects.create(name="clerk")
        group.permissions.add(poll_perms[READ])
        role = self._role("clerk", [poll_perms[READ]])

        with pytest.raises(ImproperlyConfigured, match="KC_UTILS_SEEDED_ROLE_MODEL"):
            self._instance(KeycloakPredefinedRoleAdoption, [role])._seed_django_groups()

        assert not SeededRole.objects.exists()

    def test_the_command_refuses_adoption_without_the_model(self):
        from django.core.management import CommandError, load_command_class

        command = load_command_class("keycloak_utils.contrib.django", "sync_keycloak")
        parser = command.create_parser("manage.py", "sync_keycloak")
        options = vars(
            parser.parse_args(
                ["-adopt-predefined-groups", "--server-url", "http://keycloak.invalid/"]
            )
        )

        with mock.patch(
            "keycloak_utils.contrib.django.management.commands.sync_keycloak.kc_admin"
        ) as kc_admin:
            with pytest.raises(CommandError, match="KC_UTILS_SEEDED_ROLE_MODEL"):
                command.handle(**options)

        kc_admin.initialize.assert_not_called()

    def test_the_command_can_run_the_adoption(self):
        from django.core.management import load_command_class

        command = load_command_class("keycloak_utils.contrib.django", "sync_keycloak")
        parser = command.create_parser("manage.py", "sync_keycloak")

        assert parser.parse_args(["-adopt-predefined-groups"]).adopt_predefined_groups
        assert command.sync_routines["adopt_predefined_groups"]["classpath"] == (
            "keycloak_utils.sync.django.core.KeycloakPredefinedRoleAdoption"
        )


@pytest.mark.django_db
class TestUpgradeHoldsGatedAdditions:
    """A template upgrade meets the project's approval flow the way a reset does.

    Found in the core review (#156770): a release that added a gated permission to a
    standard role reached every untouched tenant with no checker, while a reset of the
    same role held it.
    """

    def test_a_gated_addition_waits_and_the_role_detaches(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        guard = _ApprovalGuard(gated={WRITE})

        outcome = _seeder(VIEWER_V2, reset_guard=guard).seed_template(VIEWER_V2)

        group = Group.objects.get(name="viewer")
        record = SeededRole.objects.get(group=group)
        assert outcome is SeedOutcome.UPGRADED_AWAITING_APPROVAL
        assert guard.requested == [("change_poll", None)]
        assert _codenames(group) == [READ]
        assert (record.detached, record.fingerprint) == (True, fingerprint_for([READ]))

    def test_the_next_run_does_not_write_the_held_permission(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        seeder = _seeder(VIEWER_V2, reset_guard=_ApprovalGuard(gated={WRITE}))
        seeder.seed_template(VIEWER_V2)

        assert seeder.seed_template(VIEWER_V2) is SeedOutcome.SKIPPED_DETACHED
        assert _codenames(Group.objects.get(name="viewer")) == [READ]

    def test_once_approved_the_role_reattaches_and_upgrades_resume(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        seeder = _seeder(VIEWER_V2, reset_guard=_ApprovalGuard(gated={WRITE}))
        seeder.seed_template(VIEWER_V2)
        group = Group.objects.get(name="viewer")

        group.permissions.add(poll_perms[WRITE])  # the checker approved
        assert seeder.reattach_if_at_parity(group) is True
        assert seeder.seed_template(VIEWER_V2) is SeedOutcome.UNCHANGED

    def test_an_addition_the_flow_lets_through_upgrades_normally(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        guard = _ApprovalGuard(gated={WRITE}, approve_now=True)

        outcome = _seeder(VIEWER_V2, reset_guard=guard).seed_template(VIEWER_V2)

        group = Group.objects.get(name="viewer")
        assert outcome is SeedOutcome.UPGRADED
        assert _codenames(group) == sorted([READ, WRITE])
        assert SeededRole.objects.get(group=group).detached is False

    def test_an_ungated_addition_is_written_straight_on(self, poll_perms):
        _seeder(VIEWER).seed_template(VIEWER)
        guard = _ApprovalGuard(gated={DROP})

        outcome = _seeder(VIEWER_V2, reset_guard=guard).seed_template(VIEWER_V2)

        assert outcome is SeedOutcome.UPGRADED
        assert guard.requested == []

    def test_creation_is_the_baseline_and_not_gated(self, poll_perms):
        guard = _ApprovalGuard(gated={WRITE})

        outcome = _seeder(VIEWER_V2, reset_guard=guard).seed_template(VIEWER_V2)

        assert outcome is SeedOutcome.CREATED
        assert guard.requested == []
        assert _codenames(Group.objects.get(name="viewer")) == sorted([READ, WRITE])

    def test_a_release_narrowing_a_template_is_not_refused(self, poll_perms):
        """Removals are the operator's call: an upgrade does not ask check_removals."""
        _seeder(VIEWER_V2).seed_template(VIEWER_V2)
        guard = _ApprovalGuard(gated=(), refuse={WRITE})

        outcome = _seeder(VIEWER, reset_guard=guard).seed_template(VIEWER)

        assert outcome is SeedOutcome.UPGRADED
        assert _codenames(Group.objects.get(name="viewer")) == [READ]

