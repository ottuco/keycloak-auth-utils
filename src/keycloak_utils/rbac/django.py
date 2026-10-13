"""Apply role templates to Django groups without ever clobbering a tenant's edits.

:mod:`keycloak_utils.rbac.seeding` decides; this module does. It needs
``django.contrib.auth`` and one model from the consuming project -- the fingerprint
record -- and nothing else: it does not talk to Keycloak, and this library does not
have to be in ``INSTALLED_APPS``. Seeding therefore works on a local-auth deployment
exactly as it does on a Keycloak one.

The fingerprint model
---------------------
The record lives in the project, because this library ships no models and no
migrations. Any model with these four fields works::

    class SeededRole(models.Model):
        group = models.OneToOneField("auth.Group", on_delete=models.CASCADE)
        template_key = models.CharField(max_length=150)
        fingerprint = models.CharField(max_length=64)
        detached = models.BooleanField(default=False)

``template_key`` is as long as ``auth.Group.name``: a predefined role is recorded
under its own name. A ``modified`` timestamp field, if the model has one, is kept
current.

Caller owns the tenant context: every method reads and writes the active schema.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from functools import reduce
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

from django.apps import apps
from django.contrib.auth.models import Group, Permission
from django.db import transaction
from django.db.models import Q

from .seeding import SeedOutcome, at_parity, decide_seed, fingerprint_for
from .templates import RoleTemplate, TemplateRegistry, UnknownTemplateError


def permission_label(permission: Permission) -> str:
    """``app_label.codename`` -- how a manifest and ``has_perm()`` name a permission."""
    return f"{permission.content_type.app_label}.{permission.codename}"


def group_codenames(group: Group) -> List[str]:
    """What a group holds right now, as ``app_label.codename`` strings."""
    return [
        f"{app_label}.{codename}"
        for app_label, codename in group.permissions.values_list(
            "content_type__app_label", "codename"
        )
    ]


def current_fingerprint(group: Group) -> str:
    """Fingerprint of what the group holds right now."""
    return fingerprint_for(group_codenames(group))


def resolve_permissions(codenames: Iterable[str]) -> List[Permission]:
    """Resolve ``app_label.codename`` strings to Permission rows in the active schema.

    One query, not one per name: a full-access template can name dozens of entries, and
    a lookup each would hold a connection across that many round trips inside the
    seeder's transaction, multiplied by every tenant a command walks.

    ``select_related`` on the content type because callers label what they are handed.

    Raises ``ValueError`` naming an entry that is not ``app_label.codename``, and
    ``LookupError`` naming the first entry with no row. A seed that hits it stops
    there, so a composition is applied whole or not at all, and the templates after it
    are not attempted: a missing permission means migrations have not run, which is the
    thing to fix.
    """
    pairs = []
    for name in codenames:
        app_label, dot, codename = name.partition(".")
        if not (app_label and dot and codename):
            raise ValueError(
                f"manifest permission {name!r} is not of the form app_label.codename"
            )
        pairs.append((app_label, codename))
    if not pairs:
        return []
    rows = Permission.objects.select_related("content_type").filter(
        reduce(
            operator.or_,
            (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in pairs
            ),
        )
    )
    by_pair = {(p.content_type.app_label, p.codename): p for p in rows}

    resolved = []
    for app_label, codename in pairs:
        permission = by_pair.get((app_label, codename))
        if permission is None:
            # Name it. A bare DoesNotExist aborts a tenant's whole seed with nothing
            # saying which entry was missing, and any schema can hit it: an app dropped
            # from INSTALLED_APPS, an incomplete post_migrate, a contenttype sweep.
            raise LookupError(
                f"manifest permission {app_label}.{codename} has no Permission row "
                "in this schema"
            )
        resolved.append(permission)
    return resolved


def seed_group(
    *,
    name: str,
    wanted: Iterable[str],
    resolve: Callable[[], List[Permission]],
    model: Optional[type],
    template_key: Optional[str] = None,
    adopt_matching: bool = False,
    on_created: Optional[Callable[[Group], None]] = None,
) -> SeedOutcome:
    """Seed one group from one composition, and say what happened.

    ``wanted`` is the composition as ``app_label.codename`` strings and ``resolve``
    returns the matching Permission rows -- called only when something is written.

    ``model`` is the project's fingerprint model. With ``None`` there is nowhere to
    remember what was last written, so an edit cannot be told from an older template:
    a group this call creates is filled, and an existing one is left exactly as it is.

    ``adopt_matching`` starts a record for a group that already exists, has none, and
    holds exactly ``wanted``. Off by default, because a matching name and composition
    can be a coincidence; it is the explicit one-off for a project whose groups were
    created by an earlier, record-less seeder.

    ``on_created`` is called after this function's own transaction has closed, so a
    callback that talks to an identity provider neither holds the write open across
    the network nor announces a group that was rolled back. A caller that wraps the
    seed in a wider transaction owns that deferral itself.
    """
    wanted = list(wanted)
    with transaction.atomic():
        group, outcome = _seed(
            name=name,
            wanted=wanted,
            resolve=resolve,
            model=model,
            template_key=template_key or name,
            adopt_matching=adopt_matching,
        )
    # Only on CREATED: an upgrade changes a composition, which an identity provider
    # that carries role names alone has nothing to learn from.
    if outcome is SeedOutcome.CREATED and on_created:
        on_created(group)
    return outcome


def _seed(
    *,
    name: str,
    wanted: List[str],
    resolve: Callable[[], List[Permission]],
    model: Optional[type],
    template_key: str,
    adopt_matching: bool,
) -> Tuple[Group, SeedOutcome]:
    """The writes of :func:`seed_group`; the caller holds the transaction.

    Not serialised against a second seed of the same group: of two that race on a new
    one, the loser fails on the group's or the record's uniqueness and rolls back,
    leaving the winner's rows whole. Seeding belongs to a deploy step, not a request.
    """
    group, created = Group.objects.get_or_create(name=name)
    current = [] if created else group_codenames(group)

    if model is None:
        if created:
            group.permissions.set(resolve())
            return group, SeedOutcome.CREATED
        if at_parity(wanted=wanted, current=current):
            return group, SeedOutcome.UNCHANGED
        return group, SeedOutcome.SKIPPED_FOREIGN

    record = model.objects.filter(group=group).first()
    if (
        record is None
        and not created
        and adopt_matching
        and at_parity(wanted=wanted, current=current)
    ):
        model.objects.create(
            group=group,
            template_key=template_key,
            fingerprint=fingerprint_for(wanted),
        )
        return group, SeedOutcome.UNCHANGED

    decision = decide_seed(
        wanted=wanted,
        current=current,
        group_created=created,
        recorded_fingerprint=record.fingerprint if record else None,
        detached=bool(record and record.detached),
    )
    if decision.write_permissions:
        group.permissions.set(resolve())
    if decision.create_record:
        model.objects.create(
            group=group,
            template_key=template_key,
            fingerprint=decision.fingerprint,
        )
    elif decision.write_permissions:
        record.fingerprint = decision.fingerprint
        record.template_key = template_key
        _save(record, "fingerprint", "template_key")
    elif decision.detach:
        record.detached = True
        _save(record, "detached")
    return group, decision.outcome


def _save(record, *fields: str) -> None:
    """Save the named fields, and a ``modified`` timestamp if the model keeps one."""
    names = list(fields)
    if any(f.name == "modified" for f in record._meta.fields):
        names.append("modified")
    record.save(update_fields=names)


class ResetGuard:
    """What a project may want to say before a reset changes a role.

    The default says nothing, and a reset then simply writes the template. A project
    with an approval flow subclasses this so a reset cannot be used to walk around it.
    """

    def check_removals(self, group: Group, removing: List[Permission]) -> None:
        """Raise to refuse a reset that would take these permissions off the role."""

    def gated_additions(
        self, group: Group, adding: List[Permission]
    ) -> Iterable[Permission]:
        """The additions that must be requested rather than written directly."""
        return ()

    def request_addition(
        self, group: Group, permission: Permission, actor: Any
    ) -> bool:
        """Request one gated addition. Return ``True`` if it is still waiting.

        ``False`` means the project's own flow attached it immediately -- to this
        ``group``, since the reset reads the group back to decide whether it reached
        the template.
        """
        raise NotImplementedError


@dataclass(frozen=True)
class ResetReport:
    """What a reset did.

    ``pending`` names the additions a project's guard is still holding. Empty means the
    role is at template parity and was re-attached.
    """

    outcome: SeedOutcome
    pending: Tuple[str, ...]


class RoleSeeder:
    """Seeding, drift detection and reset-to-template for one project.

    ``seeded_role_model`` is the project's fingerprint model, or ``"app_label.Model"``
    to resolve it lazily. ``on_created`` is called with the group the first time a
    template's role is created: the place to tell an identity provider its name.
    """

    def __init__(
        self,
        registry: TemplateRegistry,
        seeded_role_model: Union[str, type],
        *,
        on_created: Optional[Callable[[Group], None]] = None,
        reset_guard: Optional[ResetGuard] = None,
    ) -> None:
        self.registry = registry
        self._model = seeded_role_model
        self.on_created = on_created
        self.reset_guard = reset_guard or ResetGuard()

    @property
    def model(self):
        if isinstance(self._model, str):
            self._model = apps.get_model(self._model)
        return self._model

    def seed_template(self, template: RoleTemplate) -> SeedOutcome:
        """Apply one template to its group in the active schema."""
        wanted = self.registry.permissions_for(template)
        return seed_group(
            name=template.key,
            wanted=wanted,
            resolve=lambda: resolve_permissions(wanted),
            model=self.model,
            template_key=template.key,
            on_created=self.on_created,
        )

    def seed_all(self) -> Dict[str, SeedOutcome]:
        """Apply every template in the active schema, keyed by template key.

        Stops at the first template that cannot be resolved (see
        :func:`resolve_permissions`); the ones already seeded stay seeded.
        """
        return {
            key: self.seed_template(template)
            for key, template in self.registry.templates.items()
        }

    def reattach_if_at_parity(self, group: Group) -> bool:
        """Re-attach a detached role once it matches its template again.

        A reset leaves a role detached while a gated addition is waiting; without this
        an approved addition left the role at exact parity and shut out of upgrades for
        good. Only parity re-attaches: a role whose composition still differs is the
        tenant's. Returns whether it re-attached.
        """
        record = self.model.objects.filter(group=group).first()
        if record is None or not record.detached:
            return False
        template = self.registry.template_for(record.template_key)
        if template is None:
            # Retired while this role still named it: nothing to be at parity with.
            return False
        current = group_codenames(group)
        if not at_parity(
            wanted=self.registry.permissions_for(template), current=current
        ):
            return False
        record.detached = False
        record.fingerprint = fingerprint_for(current)
        _save(record, "detached", "fingerprint")
        return True

    def reset_to_template(self, group: Group, *, actor: Any = None) -> ResetReport:
        """Re-apply a group's template and re-attach it.

        Raises the model's ``DoesNotExist`` when the seeder does not own the group:
        resetting a hand-made role has no meaning, and creating a record for one would
        hand it to the seeder without anyone asking. Raises
        :class:`~keycloak_utils.rbac.UnknownTemplateError` when the group is recorded
        under a template this registry does not hold.

        Additions the project's guard gates are requested through it instead of being
        written, and the role stays detached while any is outstanding -- re-attaching
        would record a fingerprint for a composition that is not the template's, and
        the next seeding run would then "upgrade" the role and apply the held
        permission unapproved.
        """
        with transaction.atomic():
            record = self.model.objects.get(group=group)
            template = self.registry.template_for(record.template_key)
            if template is None:
                raise UnknownTemplateError(
                    f"role {group.name!r} is recorded under template "
                    f"{record.template_key!r}, which this registry does not hold"
                )

            wanted = resolve_permissions(self.registry.permissions_for(template))
            wanted_ids = {permission.id for permission in wanted}
            held_now = list(group.permissions.select_related("content_type"))
            current_ids = {permission.id for permission in held_now}

            # Before anything is written: `set()` below removes as well as adds.
            self.reset_guard.check_removals(
                group, [p for p in held_now if p.id not in wanted_ids]
            )

            adding = [p for p in wanted if p.id not in current_ids]
            gated = list(self.reset_guard.gated_additions(group, adding))
            gated_ids = {permission.id for permission in gated}

            group.permissions.set([p for p in wanted if p.id not in gated_ids])
            held = [
                permission
                for permission in gated
                if self.reset_guard.request_addition(group, permission, actor)
            ]

            pending = tuple(sorted(permission_label(p) for p in held))
            record.fingerprint = current_fingerprint(group)
            record.detached = bool(pending)
            _save(record, "fingerprint", "detached")
        return ResetReport(outcome=SeedOutcome.UPGRADED, pending=pending)
