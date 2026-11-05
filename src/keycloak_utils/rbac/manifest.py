"""Which permissions a project lets a role carry, and what to call them.

Raw ``auth_permission`` is unusable as an authoring surface: it carries Django's
generated add/change/delete/view rows for every model, per-object rows created at
runtime, and internal codenames nobody should be handed. A manifest is the reviewed
subset a role editor renders and role templates draw from.

Every rule a project enforces lands in exactly one of three buckets:

* **curated** -- listed with a label and a description a person can read;
* **advanced** -- offered, but only behind an "advanced" switch, with a label the
  project did not hand-write (see :func:`advanced_entry`);
* **excluded** -- deliberately not offered, with the reason written down.

A rule in none of them is what :mod:`keycloak_utils.rbac.completeness` exists to catch.

Nothing here imports Django, so a project can declare its manifest at import time
without this library being in ``INSTALLED_APPS``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

CURATED = "curated"
ADVANCED = "advanced"
BUCKETS = (CURATED, ADVANCED)


@dataclass(frozen=True)
class ManifestEntry:
    """One role-assignable permission, as the person composing a role sees it.

    Frozen because a manifest is built once at import and shared across threads and
    tenants; a caller mutating an entry would change it for every other caller.

    ``rule`` is the name the project's permission registry knows it by (a bridgekeeper
    rule name, for the Ottu services) and ``permission`` is the ``app_label.codename``
    that rule checks. ``label`` and ``description`` may be lazy translation proxies.
    """

    rule: str
    permission: str
    label: Any
    description: Any
    group: str
    bucket: str = CURATED

    def __post_init__(self) -> None:
        if self.bucket not in BUCKETS:
            raise ValueError(
                f"manifest entry {self.rule!r} has unknown bucket {self.bucket!r}; "
                f"expected one of {BUCKETS}"
            )
        if "." not in self.permission:
            raise ValueError(
                f"manifest entry {self.rule!r} names permission {self.permission!r}; "
                "expected 'app_label.codename'"
            )


def advanced_entry(
    rule: str, permission: str, group: str, description: Any = ""
) -> ManifestEntry:
    """An entry for the advanced bucket, labelled from its own codename.

    For the long tail a project wants grantable but will not hand-curate: the label is
    the codename with its underscores opened up, which is honest about being generated.
    """
    codename = permission.split(".", 1)[1]
    return ManifestEntry(
        rule=rule,
        permission=permission,
        label=codename.replace("_", " ").capitalize(),
        description=description,
        group=group,
        bucket=ADVANCED,
    )


class Manifest:
    """A project's catalogue: its entries, and the rules it deliberately leaves out.

    Built once, at import. Construction is where mistakes are refused -- a rule listed
    twice, a rule both listed and excluded, an exclusion with no reason -- because a
    catalogue that is quietly wrong is discovered much later, as a role that grants
    nothing.
    """

    def __init__(
        self,
        entries: Iterable[ManifestEntry],
        excluded: Optional[Mapping[str, str]] = None,
    ) -> None:
        by_rule: Dict[str, ManifestEntry] = {}
        for entry in entries:
            if entry.rule in by_rule:
                raise ValueError(f"duplicate manifest entry for rule {entry.rule!r}")
            by_rule[entry.rule] = entry
        self.entries: Dict[str, ManifestEntry] = by_rule

        self.excluded: Dict[str, str] = dict(excluded or {})
        for rule, reason in self.excluded.items():
            if rule in self.entries:
                raise ValueError(f"rule {rule!r} is both listed and excluded; pick one")
            if not str(reason).strip():
                raise ValueError(
                    f"exclusion of rule {rule!r} gives no reason; the reason is the "
                    "record of why nobody may be granted it"
                )

    def __contains__(self, rule: object) -> bool:
        return rule in self.entries

    def __iter__(self) -> Iterator[str]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def entry_for(self, rule: str) -> Optional[ManifestEntry]:
        """The entry for a rule name, or ``None`` if it is not offered."""
        return self.entries.get(rule)

    def is_known(self, rule: str) -> bool:
        """Whether this rule has a decision: offered, or left out on purpose."""
        return rule in self.entries or rule in self.excluded

    def in_bucket(self, bucket: str) -> List[ManifestEntry]:
        return [entry for entry in self.entries.values() if entry.bucket == bucket]

    def groups(self, bucket: Optional[str] = None) -> Dict[str, List[ManifestEntry]]:
        """Entries by their module group, each group sorted by label.

        Sorted here rather than by each caller so a role editor, the templates and any
        API all present one order.
        """
        bucketed: Dict[str, List[ManifestEntry]] = {}
        for entry in self.entries.values():
            if bucket is not None and entry.bucket != bucket:
                continue
            bucketed.setdefault(entry.group, []).append(entry)
        for entries in bucketed.values():
            entries.sort(key=lambda entry: str(entry.label))
        return bucketed
