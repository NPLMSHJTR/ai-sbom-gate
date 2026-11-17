"""AI-SBOM-Gate: Unified license compliance & CycloneDX 1.6 ML-BOM generator for AI projects."""

from ai_sbom_gate.models import (
    AIAsset,
    AssetType,
    ComplianceFinding,
    ComplianceReport,
    LicenseCategory,
    PolicyMode,
    Severity,
)
from ai_sbom_gate.policy_engine import ComplianceEngine

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AIAsset",
    "AssetType",
    "ComplianceEngine",
    "ComplianceFinding",
    "ComplianceReport",
    "LicenseCategory",
    "PolicyMode",
    "Severity",
]
