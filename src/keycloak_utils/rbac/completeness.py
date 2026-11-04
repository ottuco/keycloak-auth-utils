"""The gate that keeps a manifest honest against the rules a project really enforces.

A new enforcement point with no manifest decision is a permission no role can be given
and no reviewer noticed. A manifest entry for a rule that no longer exists is the
mirror: it offers a permission that gates nothing.

The registry is the project's own -- ``bridgekeeper.perms`` for the Ottu services --
and it is only complete once the project has imported every app's permission module.
That is why this is a helper each project calls from its own test suite, not a script
this library runs::

    from bridgekeeper import perms
    from keycloak_utils.rbac import assert_complete

    def test_every_rule_is_curated():
        assert_complete(MANIFEST, perms)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

from .manifest import Manifest


class ManifestIncompleteError(AssertionError):
    """The manifest and the registered rules disagree.

    An ``AssertionError`` so a test that calls :func:`assert_complete` fails as a test
    failure, with the message as its explanation.
    """


@dataclass(frozen=True)
class CompletenessReport:
    """Where a manifest and a rule registry disagree. Empty tuples mean they agree."""

    uncurated: Tuple[str, ...]
    stale_entries: Tuple[str, ...]
    stale_exclusions: Tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not (self.uncurated or self.stale_entries or self.stale_exclusions)

    def describe(self) -> str:
        parts = []
        if self.uncurated:
            parts.append(
                "These registered rules have no manifest decision:\n  "
                + "\n  ".join(self.uncurated)
                + "\nList each in the manifest if a role may carry it, or exclude it "
                "with a reason if not."
            )
        if self.stale_entries:
            parts.append(
                "These manifest entries name rules that are not registered:\n  "
                + "\n  ".join(self.stale_entries)
                + "\nRemove them, or fix the rule name."
            )
        if self.stale_exclusions:
            parts.append(
                "These exclusions name rules that are not registered:\n  "
                + "\n  ".join(self.stale_exclusions)
            )
        return "\n\n".join(parts)


def check_completeness(
    manifest: Manifest, registered_rules: Iterable[str]
) -> CompletenessReport:
    """Compare a manifest with the rule names a project has registered."""
    registered = set(registered_rules)
    return CompletenessReport(
        uncurated=tuple(sorted(r for r in registered if not manifest.is_known(r))),
        stale_entries=tuple(sorted(r for r in manifest if r not in registered)),
        stale_exclusions=tuple(
            sorted(r for r in manifest.excluded if r not in registered)
        ),
    )


def assert_complete(manifest: Manifest, registered_rules: Iterable[str]) -> None:
    """Raise :class:`ManifestIncompleteError` unless every rule has one decision."""
    report = check_completeness(manifest, registered_rules)
    if not report.ok:
        raise ManifestIncompleteError(report.describe())
