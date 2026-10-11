"""Standard roles, declared in code and composed from manifest entries.

Nobody should have to build "Finance" out of ninety checkboxes on day one. A template
is a role every tenant is seeded with, and because it lives in code a release can
upgrade it: add a rule to a template and the seeder carries it into every tenant that
has not customised that role (:mod:`keycloak_utils.rbac.seeding`).

Templates name rules, never permissions, and resolve through the manifest -- so a
template cannot grant something the catalogue does not offer. That is checked when the
registry is built, which for a project is import time: a template naming an unknown rule
raises there, instead of seeding a role that grants nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from .manifest import Manifest


class UnknownTemplateRuleError(Exception):
    """A template names a rule that is not in the manifest."""


@dataclass(frozen=True)
class RoleTemplate:
    """One standard role, as it appears in a role list.

    ``key`` is the group name the seeder creates. ``label`` and ``description`` may be
    lazy translation proxies. Frozen for the reason :class:`ManifestEntry` is.
    """

    key: str
    label: Any
    description: Any
    rules: Tuple[str, ...]


class TemplateRegistry:
    """A project's templates, validated against its manifest."""

    def __init__(self, manifest: Manifest, templates: Iterable[RoleTemplate]) -> None:
        self.manifest = manifest
        by_key: Dict[str, RoleTemplate] = {}
        for template in templates:
            if template.key in by_key:
                raise ValueError(f"duplicate role template {template.key!r}")
            unknown = [rule for rule in template.rules if rule not in manifest]
            if unknown:
                raise UnknownTemplateRuleError(
                    f"role template {template.key!r} names unknown rule(s): {unknown}"
                )
            by_key[template.key] = template
        self.templates: Dict[str, RoleTemplate] = by_key

    def __contains__(self, key: object) -> bool:
        return key in self.templates

    def __iter__(self) -> Iterator[str]:
        return iter(self.templates)

    def __len__(self) -> int:
        return len(self.templates)

    def template_for(self, key: str) -> Optional[RoleTemplate]:
        """The template for a key, or ``None`` if there is no such standard role."""
        return self.templates.get(key)

    def permissions_for(self, template: Union[RoleTemplate, str]) -> List[str]:
        """The ``app_label.codename`` strings a template grants, sorted and deduped.

        Sorted so the seeder's fingerprint is stable across runs, and deduped because
        two rules can resolve to one codename and a role must not carry it twice.
        """
        if isinstance(template, str):
            found = self.templates.get(template)
            if found is None:
                raise KeyError(f"no role template {template!r}")
            template = found
        codenames = set()
        for rule in template.rules:
            entry = self.manifest.entry_for(rule)
            if entry is None:
                # Only reachable for a template built outside this registry.
                raise UnknownTemplateRuleError(
                    f"template {template.key!r} names unknown rule {rule!r}"
                )
            codenames.add(entry.permission)
        return sorted(codenames)
