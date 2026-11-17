"""License catalog, offline known AI assets database, and remediation alternatives."""

from ai_sbom_gate.catalog.alternatives import get_alternatives
from ai_sbom_gate.catalog.known_assets import lookup_known_asset
from ai_sbom_gate.catalog.spdx_licenses import (
    LICENSE_PROFILES,
    LicenseProfile,
    normalize_license_id,
    resolve_license_profile,
)

__all__ = [
    "LICENSE_PROFILES",
    "LicenseProfile",
    "get_alternatives",
    "lookup_known_asset",
    "normalize_license_id",
    "resolve_license_profile",
]
