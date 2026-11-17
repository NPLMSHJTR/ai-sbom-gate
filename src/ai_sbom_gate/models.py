"""Core domain models for AI-SBOM-Gate."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class AssetType(str, Enum):
    """Category of discovered software or AI artifact."""

    PYTHON_PACKAGE = "python-package"
    NODE_PACKAGE = "node-package"
    HF_MODEL = "hf-model"
    HF_DATASET = "hf-dataset"
    PROJECT_ROOT = "project-root"


class LicenseCategory(str, Enum):
    """Normalized licensing taxonomy covering OSI and AI-specific licenses."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak-copyleft"
    STRONG_COPYLEFT = "strong-copyleft"
    SHARE_ALIKE = "share-alike"
    CUSTOM_AI_COMMERCIAL = "custom-ai-commercial"
    NON_COMMERCIAL = "non-commercial"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class PolicyMode(str, Enum):
    """Target distribution / deployment compliance profile."""

    COMMERCIAL_CLOSED_SOURCE = "commercial-closed-source"
    OPEN_SOURCE_PERMISSIVE = "open-source-permissive"
    APACHE_2_STRICT = "apache-2.0-strict"
    ACADEMIC_RESEARCH = "academic-research"

    @classmethod
    def parse(cls, value: str) -> "PolicyMode":
        norm = value.strip().lower()
        for member in cls:
            if member.value == norm:
                return member
        raise ValueError(f"Unsupported policy '{value}'. Expected one of: {[m.value for m in cls]}")


class Severity(str, Enum):
    """Compliance finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def penalty(self) -> int:
        return {
            Severity.CRITICAL: 30,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        norm = value.strip().upper()
        for member in cls:
            if member.value == norm:
                return member
        raise ValueError(f"Unsupported severity '{value}'. Expected one of: {[m.value for m in cls]}")


@dataclass
class AIAsset:
    """Single discovered code package, Hugging Face model, or dataset."""

    name: str
    asset_type: AssetType
    version: str = ""
    raw_license: str = "UNKNOWN"
    normalized_license: str = "UNKNOWN"
    license_category: LicenseCategory = LicenseCategory.UNKNOWN
    source_file: str = ""
    line_number: int = 1
    discovery_method: str = ""
    purl: str = ""
    homepage: str = ""
    gated: bool = False
    extra_terms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "asset_type": self.asset_type.value,
            "version": self.version,
            "raw_license": self.raw_license,
            "normalized_license": self.normalized_license,
            "license_category": self.license_category.value,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "discovery_method": self.discovery_method,
            "purl": self.purl,
            "homepage": self.homepage,
            "gated": self.gated,
            "extra_terms": list(self.extra_terms),
        }


@dataclass
class ComplianceFinding:
    """Policy conflict or compliance warning raised for an AIAsset."""

    rule_id: str
    title: str
    severity: Severity
    asset_name: str
    asset_type: AssetType
    detected_license: str
    license_category: LicenseCategory
    source_file: str
    line_number: int
    message: str
    remediation: str
    suggested_alternatives: list[str] = field(default_factory=list)
    reference_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type.value,
            "detected_license": self.detected_license,
            "license_category": self.license_category.value,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "message": self.message,
            "remediation": self.remediation,
            "suggested_alternatives": list(self.suggested_alternatives),
            "reference_url": self.reference_url,
        }


@dataclass
class ComplianceReport:
    """Complete AI-SBOM compliance scan output for a repository."""

    target: str
    policy: PolicyMode
    declared_project_license: str = "UNDECLARED"
    assets: list[AIAsset] = field(default_factory=list)
    findings: list[ComplianceFinding] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def asset_type_counts(self) -> dict[str, int]:
        counts = {t.value: 0 for t in AssetType if t != AssetType.PROJECT_ROOT}
        for a in self.assets:
            if a.asset_type.value in counts:
                counts[a.asset_type.value] += 1
        return counts

    @property
    def compliance_score(self) -> int:
        penalty = sum(f.severity.penalty for f in self.findings)
        return max(0, 100 - penalty)

    def passes(self, fail_on: Severity | None = Severity.HIGH) -> bool:
        if fail_on is None:
            return True
        return not any(f.severity.rank >= fail_on.rank for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "policy": self.policy.value,
            "declared_project_license": self.declared_project_license,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "compliance_score": self.compliance_score,
            "assets_count": len(self.assets),
            "asset_type_counts": self.asset_type_counts,
            "severity_counts": self.severity_counts,
            "findings_count": len(self.findings),
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.findings],
        }
