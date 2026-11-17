"""Self-compliance test: ai-sbom-gate must pass its own permissive compliance gate at 100/100."""

from __future__ import annotations

from pathlib import Path

from ai_sbom_gate.models import PolicyMode, Severity
from ai_sbom_gate.policy_engine import ComplianceEngine

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_repository_passes_self_compliance_gate() -> None:
    report = ComplianceEngine().scan_directory(
        REPO_ROOT,
        policy=PolicyMode.OPEN_SOURCE_PERMISSIVE,
        excludes=["examples"],
    )
    assert report.declared_project_license == "Apache-2.0"
    assert report.compliance_score == 100, f"Unexpected findings: {report.findings}"
    assert report.passes(fail_on=Severity.LOW)
