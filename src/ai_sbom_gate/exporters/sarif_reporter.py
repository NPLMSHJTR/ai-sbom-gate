"""SARIF 2.1.0 report generator compatible with GitHub Code Scanning."""

from __future__ import annotations

import json
from typing import Any

from ai_sbom_gate import __version__
from ai_sbom_gate.models import ComplianceReport, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def _to_sarif_level(sev: Severity) -> str:
    if sev in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def build_sarif_dict(report: ComplianceReport) -> dict[str, Any]:
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "help": {"text": f.remediation},
                "defaultConfiguration": {"level": _to_sarif_level(f.severity)},
                "properties": {"tags": ["license-compliance", "ai-sbom", f.asset_type.value]},
            }

        msg = f"[{f.asset_type.value}] {f.asset_name} ({f.detected_license}): {f.message}"
        if f.suggested_alternatives:
            msg += f" Suggested alternatives: {'; '.join(f.suggested_alternatives)}"

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _to_sarif_level(f.severity),
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.source_file or report.target},
                            "region": {"startLine": max(1, f.line_number)},
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "detectedLicense": f.detected_license,
                    "licenseCategory": f.license_category.value,
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-SBOM-Gate",
                        "version": __version__,
                        "informationUri": "https://github.com/NPLMSHJTR/ai-sbom-gate",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif_report(report: ComplianceReport) -> str:
    return json.dumps(build_sarif_dict(report), indent=2, ensure_ascii=False)
