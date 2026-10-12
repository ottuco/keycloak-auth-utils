"""The seed decision: whether a template may be written to a group, as a pure function.

A release can add a permission to a standard role, and every tenant that has not
customised that role should get it. A tenant that HAS customised it must keep exactly
what they built. The group alone cannot tell those apart -- a composition that differs
from the template is either an edit or simply an older template -- so a seeder records
a fingerprint of the composition it last wrote and compares on the next run.

This module is that comparison and nothing else: no database, no Django, no Keycloak.
The fingerprint record belongs to each project, because a table whose existence depends
on this library being installed has no place in a project's migrations
(:mod:`keycloak_utils.rbac.django` applies the decision to real rows).

One case the design accepts on purpose: a role edited and then edited back to match the
template exactly is indistinguishable from one never touched, and upgrades resume. The
fingerprint describes the composition, not its history, and treating an identical role
as customised would strand it for no reason anyone could observe. The same holds for a
role edited into exactly what the template has since become: it is at parity, so it is
recorded as upgraded and not detached.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional


class SeedOutcome(str, Enum):
    """What one seeding run did, or declined to do, for one template."""

    CREATED = "created"
    UPGRADED = "upgraded"
    UNCHANGED = "unchanged"
    DETACHED = "detached"
    SKIPPED_DETACHED = "skipped_detached"
    # A group of this name exists but the seeder did not create it, so it is the
    # tenant's and not the platform's. Distinct from DETACHED, which means "ours, and
    # edited": this one is not ours at all and there is no record of it.
    SKIPPED_FOREIGN = "skipped_foreign"

    def __str__(self) -> str:
        return self.value


def fingerprint_for(codenames: Iterable[str]) -> str:
    """Stable hash of a permission set.

    Sorted and deduped first, so one set always hashes the same whatever order the
    caller produced it in.
    """
    joined = "\n".join(sorted(set(codenames)))
    return hashlib.sha256(joined.encode()).hexdigest()


@dataclass(frozen=True)
class SeedDecision:
    """What to do about one template and one group.

    ``write_permissions`` -- set the group's permissions to the template's. False on
    an upgrade the group already matches: only the record moves.
    ``create_record`` -- this is the first write; start a fingerprint record.
    ``detach`` -- mark the existing record detached and never write again until a reset.
    ``fingerprint`` -- the value to record after a write; ``None`` if nothing is.
    """

    outcome: SeedOutcome
    write_permissions: bool = False
    create_record: bool = False
    detach: bool = False
    fingerprint: Optional[str] = None


def decide_seed(
    *,
    wanted: Iterable[str],
    current: Iterable[str],
    group_created: bool,
    recorded_fingerprint: Optional[str],
    detached: bool = False,
) -> SeedDecision:
    """Decide what a seeding run does for one template.

    ``wanted`` is the template's composition and ``current`` the group's, both as
    ``app_label.codename`` strings. ``recorded_fingerprint`` is what the seeder last
    wrote, or ``None`` when it holds no record for the group. ``group_created`` says
    whether THIS run created the group.
    """
    wanted_fingerprint = fingerprint_for(wanted)

    if recorded_fingerprint is None:
        if group_created:
            # Creation is the whole condition, deliberately -- emptiness is NOT a
            # licence to fill. Login paths create permission-less groups for realm
            # roles they have not seen, so an empty group with a template's name is
            # usually a tenant's own role and not a blank waiting for the platform.
            return SeedDecision(
                SeedOutcome.CREATED,
                write_permissions=True,
                create_record=True,
                fingerprint=wanted_fingerprint,
            )
        # The group was already there, so it is the tenant's. Recording it would be an
        # ownership claim, and the claim is what makes a group resettable -- a
        # hand-built role could then be replaced by a template. An exact match is
        # skipped too: adopting on a coincidence hands the role to future upgrades.
        return SeedDecision(SeedOutcome.SKIPPED_FOREIGN)

    if detached:
        return SeedDecision(SeedOutcome.SKIPPED_DETACHED)

    current_fingerprint = fingerprint_for(current)
    if current_fingerprint != recorded_fingerprint:
        if current_fingerprint == wanted_fingerprint:
            # Edited into exactly what the template now is. Nothing to write and
            # nothing of the tenant's to protect: move the record, keep it attached.
            return SeedDecision(SeedOutcome.UPGRADED, fingerprint=wanted_fingerprint)
        # Edited since the last write. Never write to it again until a reset.
        return SeedDecision(SeedOutcome.DETACHED, detach=True)

    if wanted_fingerprint == recorded_fingerprint:
        return SeedDecision(SeedOutcome.UNCHANGED)

    return SeedDecision(
        SeedOutcome.UPGRADED, write_permissions=True, fingerprint=wanted_fingerprint
    )


def at_parity(*, wanted: Iterable[str], current: Iterable[str]) -> bool:
    """Whether a group holds exactly its template's composition."""
    return fingerprint_for(wanted) == fingerprint_for(current)
