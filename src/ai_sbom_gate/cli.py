"""Command-line interface for AI-SBOM-Gate."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from ai_sbom_gate import __version__
from ai_sbom_gate.catalog.alternatives import get_alternatives
from ai_sbom_gate.catalog.known_assets import lookup_known_asset
from ai_sbom_gate.catalog.spdx_licenses import LICENSE_PROFILES, resolve_license_profile
from ai_sbom_gate.exporters.console_reporter import render_console_report
from ai_sbom_gate.exporters.cyclonedx_mlbom import render_cyclonedx_mlbom
from ai_sbom_gate.exporters.html_reporter import render_html_report
from ai_sbom_gate.exporters.markdown_reporter import render_markdown_report
from ai_sbom_gate.exporters.notices_md import render_third_party_notices
from ai_sbom_gate.exporters.sarif_reporter import render_sarif_report
from ai_sbom_gate.models import AIAsset, AssetType, ComplianceReport, PolicyMode, Severity
from ai_sbom_gate.policy_engine import ComplianceEngine
from ai_sbom_gate.scanners.remote_inspector import RemoteInspector


def format_report(report: ComplianceReport, fmt: str, color: bool = True) -> str:
    f = fmt.strip().lower()
    if f == "console":
        return render_console_report(report, color=color)
    if f == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if f == "markdown":
        return render_markdown_report(report)
    if f == "sarif":
        return render_sarif_report(report)
    if f == "html":
        return render_html_report(report)
    if f == "cyclonedx":
        return render_cyclonedx_mlbom(report)
    if f == "notices":
        return render_third_party_notices(report)
    raise ValueError(f"Unsupported output format: {fmt}")


def execute_scan_for_action(
    target_path: str = ".",
    policy: str = "commercial-closed-source",
    excludes: list[str] | None = None,
    online: bool = False,
    report_format: str = "markdown",
    output_file: str | None = None,
    mlbom_output: str | None = None,
    fail_on: str = "high",
) -> dict[str, Any]:
    """Programmatic entrypoint for GitHub Action (`action.yml`)."""
    engine = ComplianceEngine()
    pol = PolicyMode.parse(policy)
    report = engine.scan_directory(target_path, policy=pol, excludes=excludes, online=online)

    rendered = format_report(report, report_format, color=False)
    if output_file:
        out_p = Path(output_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(rendered + "\n", encoding="utf-8")

    if mlbom_output:
        ml_p = Path(mlbom_output)
        ml_p.parent.mkdir(parents=True, exist_ok=True)
        ml_p.write_text(render_cyclonedx_mlbom(report) + "\n", encoding="utf-8")

    fail_sev = None if fail_on.strip().lower() == "none" else Severity.parse(fail_on)
    passed = report.passes(fail_on=fail_sev)
    return {
        "assets_count": len(report.assets),
        "findings_count": len(report.findings),
        "score": report.compliance_score,
        "passed": passed,
        "markdown_summary": render_markdown_report(report),
    }


def _emit(text: str, output: str | None) -> None:
    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _handle_scan(args: argparse.Namespace) -> int:
    pol = PolicyMode.parse(args.policy)
    excludes = [x.strip() for x in (args.exclude or []) if x.strip()]
    report = ComplianceEngine().scan_directory(
        args.path, policy=pol, excludes=excludes, online=args.online
    )

    if args.mlbom_out:
        p = Path(args.mlbom_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render_cyclonedx_mlbom(report) + "\n", encoding="utf-8")

    if args.notices_out:
        p = Path(args.notices_out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(render_third_party_notices(report) + "\n", encoding="utf-8")

    use_color = (not args.no_color) and sys.stdout.isatty()
    rendered = format_report(report, args.format, color=use_color)
    _emit(rendered, args.output)

    fail_sev = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    return 0 if report.passes(fail_on=fail_sev) else 1


def _handle_check_asset(args: argparse.Namespace) -> int:
    atype = AssetType(args.type)
    pol = PolicyMode.parse(args.policy)
    known = lookup_known_asset(args.name, atype)
    raw_lic = known.license_id if known is not None else "UNKNOWN"
    prof = resolve_license_profile(raw_lic)
    asset = AIAsset(
        name=args.name,
        asset_type=atype,
        raw_license=raw_lic,
        normalized_license=prof.spdx_id,
        license_category=prof.category,
        source_file="cli-input",
        discovery_method="manual-check",
        homepage=known.homepage if known else "",
        gated=known.gated if known else False,
    )
    if args.online:
        asset = RemoteInspector().enrich_asset(asset)

    findings = ComplianceEngine().evaluate_assets([asset], policy=pol)
    alts = get_alternatives(asset.name, asset.asset_type, asset.license_category)
    payload = {
        "asset": asset.to_dict(),
        "policy": pol.value,
        "compatible": len(findings) == 0,
        "findings": [f.to_dict() for f in findings],
        "suggested_alternatives": alts,
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if not findings else 1


def _handle_licenses(args: argparse.Namespace) -> int:
    profiles = [p for k, p in LICENSE_PROFILES.items() if k != "UNKNOWN"]
    if args.format == "json":
        print(json.dumps([p.to_dict() for p in profiles], indent=2, ensure_ascii=False))
    else:
        for p in profiles:
            comm = "commercial-ok" if p.commercial_allowed else "NO-COMMERCIAL"
            print(f"{p.spdx_id:<28} [{p.category.value:<20}] ({comm}) {p.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-sbom-gate",
        description="Unified license compliance gate & CycloneDX 1.6 ML-BOM generator for AI projects.",
    )
    parser.add_argument("--version", action="version", version=f"ai-sbom-gate {__version__}")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    p_scan = sub.add_parser("scan", help="Scan a repository for Python/Node/HF Model/Dataset licenses.")
    p_scan.add_argument("path", nargs="?", default=".", help="Target repository directory.")
    p_scan.add_argument(
        "--policy",
        default="commercial-closed-source",
        choices=[p.value for p in PolicyMode],
    )
    p_scan.add_argument("--exclude", action="append", default=[], help="Directory or prefix to exclude (repeatable).")
    p_scan.add_argument("--online", action="store_true", help="Query live PyPI and HF Hub APIs for unknown assets.")
    p_scan.add_argument(
        "--format",
        default="console",
        choices=["console", "json", "markdown", "sarif", "html", "cyclonedx", "notices"],
    )
    p_scan.add_argument("--output", help="Write primary report to file.")
    p_scan.add_argument("--mlbom-out", help="Also export CycloneDX 1.6 ML-BOM JSON to file.")
    p_scan.add_argument("--notices-out", help="Also export THIRD_PARTY_NOTICES.md to file.")
    p_scan.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low", "none"],
    )
    p_scan.add_argument("--no-color", action="store_true")

    p_chk = sub.add_parser("check-asset", help="Check a single package, HF model, or HF dataset against a policy.")
    p_chk.add_argument("name", help="Package name or Hugging Face repo ID (e.g. black-forest-labs/FLUX.1-dev).")
    p_chk.add_argument(
        "--type",
        default=AssetType.HF_MODEL.value,
        choices=[AssetType.PYTHON_PACKAGE.value, AssetType.NODE_PACKAGE.value, AssetType.HF_MODEL.value, AssetType.HF_DATASET.value],
    )
    p_chk.add_argument("--policy", default="commercial-closed-source", choices=[p.value for p in PolicyMode])
    p_chk.add_argument("--online", action="store_true")

    p_lic = sub.add_parser("licenses", help="List built-in SPDX and AI-specific license profiles.")
    p_lic.add_argument("--format", default="console", choices=["console", "json"])
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "scan":
        return _handle_scan(args)
    if args.subcommand == "check-asset":
        return _handle_check_asset(args)
    if args.subcommand == "licenses":
        return _handle_licenses(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
