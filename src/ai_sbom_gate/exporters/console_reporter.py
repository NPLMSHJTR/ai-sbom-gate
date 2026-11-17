"""Terminal console report renderer for AI-SBOM-Gate."""

from __future__ import annotations

from ai_sbom_gate.models import ComplianceReport, Severity

_RESET = "\033[0m"
_BOLD = "\033[1m"
_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[34m",
}


def render_console_report(report: ComplianceReport, color: bool = True) -> str:
    def paint(txt: str, code: str) -> str:
        return f"{code}{txt}{_RESET}" if color else txt

    counts = report.severity_counts
    tc = report.asset_type_counts
    lines: list[str] = [
        "=" * 74,
        paint("  AI-SBOM-Gate Compliance Report", _BOLD),
        "=" * 74,
        f"Target          : {report.target}",
        f"Policy          : {report.policy.value} (Project License: {report.declared_project_license})",
        f"Compliance Score: {report.compliance_score} / 100",
        (
            f"Assets Scanned  : {len(report.assets)} "
            f"[Py:{tc['python-package']} Node:{tc['node-package']} Model:{tc['hf-model']} Data:{tc['hf-dataset']}]"
        ),
        (
            f"Findings        : {len(report.findings)} "
            f"(CRITICAL:{counts['CRITICAL']} HIGH:{counts['HIGH']} MEDIUM:{counts['MEDIUM']} LOW:{counts['LOW']})"
        ),
        "-" * 74,
    ]

    if not report.findings:
        lines.append(paint("[PASS] Zero license compliance conflicts detected.", "\033[92m"))
    else:
        for idx, f in enumerate(report.findings, 1):
            badge = paint(f"[{f.severity.value:<8}]", _COLORS.get(f.severity, ""))
            lines.append(f"{idx:>2}. {badge} {f.rule_id} | {f.asset_name} ({f.asset_type.value})")
            lines.append(f"    License    : {f.detected_license} [{f.license_category.value}]")
            lines.append(f"    Location   : {f.source_file}:{f.line_number}")
            lines.append(f"    Detail     : {f.message}")
            if f.suggested_alternatives:
                lines.append(f"    Replace    : {'; '.join(f.suggested_alternatives)}")
            lines.append("")

    lines.append("=" * 74)
    return "\n".join(lines)
