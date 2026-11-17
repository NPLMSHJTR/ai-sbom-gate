"""GitHub-Flavored Markdown compliance report generator."""

from __future__ import annotations

from ai_sbom_gate.models import ComplianceReport


def _esc(val: str) -> str:
    return val.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def render_markdown_report(report: ComplianceReport) -> str:
    counts = report.severity_counts
    type_counts = report.asset_type_counts
    status = "PASS" if report.passes() else "FAIL"

    lines: list[str] = [
        f"## AI-SBOM Compliance Report ({status})",
        "",
        f"- **Target**: `{report.target}`",
        f"- **Policy**: `{report.policy.value}` (Project License: `{report.declared_project_license}`)",
        f"- **Compliance Score**: **{report.compliance_score} / 100**",
        (
            f"- **Assets Discovered**: {len(report.assets)} "
            f"(Python: {type_counts['python-package']}, Node: {type_counts['node-package']}, "
            f"Models: {type_counts['hf-model']}, Datasets: {type_counts['hf-dataset']})"
        ),
        (
            f"- **Findings**: {len(report.findings)} "
            f"(CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, "
            f"MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})"
        ),
        "",
    ]

    if not report.findings:
        lines.append("> All discovered code dependencies, models, and datasets comply with the selected policy.")
    else:
        lines.append("### Compliance Findings & Remediation")
        lines.append("")
        lines.append("| Severity | Asset | Type | License | Source | Suggested Fix / Alternative |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in report.findings:
            fix = "; ".join(f.suggested_alternatives) if f.suggested_alternatives else f.remediation
            lines.append(
                f"| **{f.severity.value}** | `{_esc(f.asset_name)}` | `{f.asset_type.value}` | "
                f"`{_esc(f.detected_license)}` | `{_esc(f.source_file)}:{f.line_number}` | {_esc(fix)} |"
            )

    lines.append("")
    return "\n".join(lines)
