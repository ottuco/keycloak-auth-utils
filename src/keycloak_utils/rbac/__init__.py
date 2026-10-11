"""Role authoring that a project configures instead of porting.

A project supplies three things -- its manifest content, its template content and one
fingerprint model -- and gets seeding, drift detection and reset-to-template from here.

The modules behind the names exported here (manifest, templates, seeding, completeness)
import no Django, so a manifest and its templates can be declared at import time whether
or not this library is in ``INSTALLED_APPS``. The part that touches the database is
:mod:`keycloak_utils.rbac.django`.
"""

from .completeness import (
    CompletenessReport,
    ManifestIncompleteError,
    assert_complete,
    check_completeness,
)
from .manifest import ADVANCED, CURATED, Manifest, ManifestEntry, advanced_entry
from .seeding import SeedDecision, SeedOutcome, at_parity, decide_seed, fingerprint_for
from .templates import RoleTemplate, TemplateRegistry, UnknownTemplateRuleError

__all__ = [
    "ADVANCED",
    "CURATED",
    "CompletenessReport",
    "Manifest",
    "ManifestEntry",
    "ManifestIncompleteError",
    "RoleTemplate",
    "SeedDecision",
    "SeedOutcome",
    "TemplateRegistry",
    "UnknownTemplateRuleError",
    "advanced_entry",
    "assert_complete",
    "at_parity",
    "check_completeness",
    "decide_seed",
    "fingerprint_for",
]
