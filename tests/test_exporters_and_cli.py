"""Tests for CycloneDX 1.6 ML-BOM, THIRD_PARTY_NOTICES, SARIF, HTML, Markdown, and CLI."""

from __future__ import annotations

import json
from pathlib import Path

from ai_sbom_gate.cli import execute_scan_for_action, main
from ai_sbom_gate.exporters.cyclonedx_mlbom import build_cyclonedx_mlbom
from ai_sbom_gate.exporters.html_reporter import render_html_report
from ai_sbom_gate.exporters.notices_md import render_third_party_notices
from ai_sbom_gate.exporters.sarif_reporter import build_sarif_dict
from ai_sbom_gate.models import PolicyMode
from ai_sbom_gate.policy_engine import ComplianceEngine

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_compliant_and_risky_examples_end_to_end(tmp_path: Path) -> None:
    compliant_dir = REPO_ROOT / "examples" / "compliant_rag_app"
    risky_dir = REPO_ROOT / "examples" / "risky_ai_startup_app"

    engine = ComplianceEngine()
    clean_report = engine.scan_directory(compliant_dir, policy=PolicyMode.COMMERCIAL_CLOSED_SOURCE)
    assert clean_report.compliance_score == 100
    assert clean_report.findings == []
    assert clean_report.asset_type_counts["hf-model"] == 2
    assert clean_report.asset_type_counts["hf-dataset"] == 1
    assert clean_report.passes() is True

    risky_report = engine.scan_directory(risky_dir, policy=PolicyMode.COMMERCIAL_CLOSED_SOURCE)
    assert risky_report.passes() is False
    flagged_names = {f.asset_name for f in risky_report.findings}
    assert {"PyMuPDF", "ultralytics", "black-forest-labs/FLUX.1-dev", "tatsu-lab/alpaca"}.issubset(
        flagged_names
    )

    # CycloneDX 1.6 ML-BOM validation
    mlbom = build_cyclonedx_mlbom(risky_report)
    assert mlbom["bomFormat"] == "CycloneDX"
    assert mlbom["specVersion"] == "1.6"
    comp_types = {c["name"]: c["type"] for c in mlbom["components"]}
    assert comp_types["black-forest-labs/FLUX.1-dev"] == "machine-learning-model"
    assert comp_types["tatsu-lab/alpaca"] == "data"
    assert comp_types["PyMuPDF"] == "library"

    # SARIF 2.1.0 validation
    sarif = build_sarif_dict(risky_report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 4

    # THIRD_PARTY_NOTICES.md validation
    notices = render_third_party_notices(risky_report)
    assert "# Third-Party Notices & AI Asset Attributions" in notices
    assert "PyMuPDF" in notices

    # HTML5 dashboard & XSS escape check
    risky_report.target = '<script>alert("xss")</script>'
    html_out = render_html_report(risky_report)
    assert '<script>alert("xss")</script>' not in html_out
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html_out

    # CLI & GitHub Action wrapper checks
    mlbom_file = tmp_path / "bom.cdx.json"
    rc_clean = main(
        [
            "scan",
            str(compliant_dir),
            "--policy",
            "commercial-closed-source",
            "--mlbom-out",
            str(mlbom_file),
            "--fail-on",
            "low",
        ]
    )
    assert rc_clean == 0
    assert json.loads(mlbom_file.read_text(encoding="utf-8"))["specVersion"] == "1.6"

    rc_risky = main(["scan", str(risky_dir), "--policy", "commercial-closed-source", "--fail-on", "high"])
    assert rc_risky == 1

    action_res = execute_scan_for_action(
        target_path=str(compliant_dir),
        policy="commercial-closed-source",
        fail_on="low",
    )
    assert action_res["passed"] is True
    assert action_res["score"] == 100


def test_cli_check_asset_and_licenses(capsys) -> None:
    rc_bad = main(["check-asset", "black-forest-labs/FLUX.1-dev", "--type", "hf-model"])
    assert rc_bad == 1
    bad_json = json.loads(capsys.readouterr().out)
    assert bad_json["compatible"] is False
    assert "FLUX.1-schnell" in bad_json["suggested_alternatives"][0]

    rc_ok = main(["check-asset", "Qwen/Qwen2.5-7B-Instruct", "--type", "hf-model"])
    assert rc_ok == 0
    _ = capsys.readouterr()

    rc_lic = main(["licenses", "--format", "json"])
    assert rc_lic == 0
    lics = json.loads(capsys.readouterr().out)
    assert len(lics) >= 20
