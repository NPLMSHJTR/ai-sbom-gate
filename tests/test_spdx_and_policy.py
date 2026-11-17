"""Unit tests for SPDX/AI license normalization and policy evaluation matrix."""

from __future__ import annotations

from ai_sbom_gate.catalog.spdx_licenses import normalize_license_id, resolve_license_profile
from ai_sbom_gate.models import AIAsset, AssetType, LicenseCategory, PolicyMode, Severity
from ai_sbom_gate.policy_engine import ComplianceEngine


def test_license_expression_normalization() -> None:
    assert normalize_license_id("MIT OR Apache-2.0") == "MIT"
    assert normalize_license_id("MIT AND GPL-3.0") == "GPL-3.0-only"
    assert normalize_license_id("Apache License 2.0") == "Apache-2.0"
    assert normalize_license_id("GNU Affero General Public License v3") == "AGPL-3.0-only"
    assert normalize_license_id("llama3.1") == "Llama-3.1-Community"
    assert resolve_license_profile("CC-BY-NC-4.0").category == LicenseCategory.NON_COMMERCIAL


def test_policy_matrix_behaviors_across_modes() -> None:
    nc_model = AIAsset(
        name="black-forest-labs/FLUX.1-dev",
        asset_type=AssetType.HF_MODEL,
        raw_license="FLUX-1-dev-Non-Commercial",
        normalized_license="FLUX-1-dev-Non-Commercial",
        license_category=LicenseCategory.NON_COMMERCIAL,
        source_file="app.py",
    )
    agpl_pkg = AIAsset(
        name="PyMuPDF",
        asset_type=AssetType.PYTHON_PACKAGE,
        raw_license="AGPL-3.0-only",
        normalized_license="AGPL-3.0-only",
        license_category=LicenseCategory.STRONG_COPYLEFT,
        source_file="requirements.txt",
    )
    llama_model = AIAsset(
        name="meta-llama/Llama-3.1-8B-Instruct",
        asset_type=AssetType.HF_MODEL,
        raw_license="Llama-3.1-Community",
        normalized_license="Llama-3.1-Community",
        license_category=LicenseCategory.CUSTOM_AI_COMMERCIAL,
        source_file="app.py",
    )

    engine = ComplianceEngine()

    # Commercial policy fails on NC and AGPL, warns MEDIUM on Llama
    comm_findings = engine.evaluate_assets(
        [nc_model, agpl_pkg, llama_model], PolicyMode.COMMERCIAL_CLOSED_SOURCE
    )
    by_name = {f.asset_name: f for f in comm_findings}
    assert by_name["black-forest-labs/FLUX.1-dev"].severity == Severity.CRITICAL
    assert "FLUX.1-schnell" in by_name["black-forest-labs/FLUX.1-dev"].suggested_alternatives[0]
    assert by_name["PyMuPDF"].severity == Severity.CRITICAL
    assert "pypdfium2" in by_name["PyMuPDF"].suggested_alternatives[0]
    assert by_name["meta-llama/Llama-3.1-8B-Instruct"].severity == Severity.MEDIUM

    # Academic research permits NC model and lowers AGPL notice
    acad_findings = engine.evaluate_assets(
        [nc_model, agpl_pkg], PolicyMode.ACADEMIC_RESEARCH
    )
    assert len(acad_findings) == 1
    assert acad_findings[0].asset_name == "PyMuPDF"
    assert acad_findings[0].severity == Severity.LOW
