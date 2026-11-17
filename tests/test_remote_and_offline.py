"""Tests for RemoteInspector with deterministic mocked HF Hub and PyPI JSON payloads."""

from __future__ import annotations

from ai_sbom_gate.models import AIAsset, AssetType, LicenseCategory
from ai_sbom_gate.scanners.remote_inspector import RemoteInspector


def test_remote_inspector_resolves_unknown_pypi_and_hf_assets() -> None:
    def fake_fetch(url: str, timeout: float) -> dict:
        if "pypi.org/pypi/obscure-mit-pkg/json" in url:
            return {"info": {"version": "1.2.3", "license_expression": "MIT"}}
        if "huggingface.co/api/models/org/custom-nc-model" in url:
            return {
                "gated": True,
                "cardData": {"license": "other", "license_name": "custom-non-commercial-v1"},
                "tags": ["license:other"],
            }
        if "huggingface.co/api/datasets/org/clean-data" in url:
            return {
                "gated": False,
                "cardData": {"license": "cc-by-4.0"},
                "tags": ["license:cc-by-4.0"],
            }
        raise RuntimeError(f"Unexpected URL: {url}")

    inspector = RemoteInspector(fetch_json=fake_fetch)

    pkg = inspector.enrich_asset(AIAsset(name="obscure-mit-pkg", asset_type=AssetType.PYTHON_PACKAGE))
    assert pkg.normalized_license == "MIT"
    assert pkg.version == "1.2.3"
    assert pkg.license_category == LicenseCategory.PERMISSIVE

    model = inspector.enrich_asset(AIAsset(name="org/custom-nc-model", asset_type=AssetType.HF_MODEL))
    assert model.gated is True
    assert model.normalized_license == "CC-BY-NC-4.0"
    assert model.license_category == LicenseCategory.NON_COMMERCIAL

    ds = inspector.enrich_asset(AIAsset(name="org/clean-data", asset_type=AssetType.HF_DATASET))
    assert ds.normalized_license == "CC-BY-4.0"
    assert ds.license_category == LicenseCategory.PERMISSIVE
