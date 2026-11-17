"""Compliance policy inference engine across code dependencies, HF models, and datasets."""

from __future__ import annotations

import time
from pathlib import Path

from ai_sbom_gate.catalog.alternatives import get_alternatives
from ai_sbom_gate.catalog.spdx_licenses import resolve_license_profile
from ai_sbom_gate.models import (
    AIAsset,
    AssetType,
    ComplianceFinding,
    ComplianceReport,
    LicenseCategory,
    PolicyMode,
    Severity,
)
from ai_sbom_gate.scanners.code_ast_finder import scan_code_assets
from ai_sbom_gate.scanners.node_deps import scan_node_dependencies
from ai_sbom_gate.scanners.python_deps import detect_declared_project_license, scan_python_dependencies
from ai_sbom_gate.scanners.remote_inspector import RemoteInspector


class ComplianceEngine:
    """Evaluates discovered AI and software assets against a target licensing policy."""

    def __init__(self, remote_inspector: RemoteInspector | None = None) -> None:
        self.remote_inspector = remote_inspector

    def scan_directory(
        self,
        target: str | Path,
        policy: PolicyMode = PolicyMode.COMMERCIAL_CLOSED_SOURCE,
        excludes: list[str] | None = None,
        online: bool = False,
    ) -> ComplianceReport:
        start = time.perf_counter()
        root = Path(target).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Target path does not exist: {root}")

        declared = detect_declared_project_license(root)
        assets: list[AIAsset] = []
        assets.extend(scan_python_dependencies(root, excludes=excludes))
        assets.extend(scan_node_dependencies(root, excludes=excludes))
        assets.extend(scan_code_assets(root, excludes=excludes))

        if online:
            inspector = self.remote_inspector or RemoteInspector()
            assets = [inspector.enrich_asset(a) for a in assets]

        findings = self.evaluate_assets(assets, policy=policy, declared_project_license=declared)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return ComplianceReport(
            target=str(target),
            policy=policy,
            declared_project_license=declared,
            assets=assets,
            findings=findings,
            duration_ms=elapsed_ms,
        )

    def evaluate_assets(
        self,
        assets: list[AIAsset],
        policy: PolicyMode,
        declared_project_license: str = "UNDECLARED",
    ) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []
        for asset in assets:
            finding = self._evaluate_single_asset(asset, policy, declared_project_license)
            if finding is not None:
                findings.append(finding)
        findings.sort(key=lambda f: (-f.severity.rank, f.asset_name))
        return findings

    @staticmethod
    def _evaluate_single_asset(
        asset: AIAsset,
        policy: PolicyMode,
        declared_project_license: str,
    ) -> ComplianceFinding | None:
        prof = resolve_license_profile(asset.normalized_license)
        cat = prof.category
        alts = get_alternatives(asset.name, asset.asset_type, cat)

        # 1. Permissive licenses are always compliant across all policies
        if cat == LicenseCategory.PERMISSIVE:
            return None

        # 2. Non-Commercial models / datasets
        if cat == LicenseCategory.NON_COMMERCIAL:
            if policy == PolicyMode.ACADEMIC_RESEARCH:
                return None
            return ComplianceFinding(
                rule_id="AI-LIC-001",
                title="Non-Commercial AI Model/Dataset Conflict",
                severity=Severity.CRITICAL,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license=prof.spdx_id,
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=(
                    f"{asset.asset_type.value} '{asset.name}' carries non-commercial license "
                    f"'{prof.spdx_id}', violating policy '{policy.value}'."
                ),
                remediation=prof.notes or "Replace with a commercially permissive asset.",
                suggested_alternatives=alts,
                reference_url=prof.url,
            )

        # 3. Strong Copyleft (AGPL-3.0 / GPL-3.0 / GPL-2.0)
        if cat == LicenseCategory.STRONG_COPYLEFT:
            if policy == PolicyMode.ACADEMIC_RESEARCH:
                return ComplianceFinding(
                    rule_id="AI-LIC-002",
                    title="Strong Copyleft Redistribution Notice",
                    severity=Severity.LOW,
                    asset_name=asset.name,
                    asset_type=asset.asset_type,
                    detected_license=prof.spdx_id,
                    license_category=cat,
                    source_file=asset.source_file,
                    line_number=asset.line_number,
                    message=(
                        f"'{asset.name}' is licensed under '{prof.spdx_id}'. External distribution "
                        "or network SaaS exposure (for AGPL) triggers source disclosure obligations."
                    ),
                    remediation=prof.notes,
                    suggested_alternatives=alts,
                    reference_url=prof.url,
                )
            sev = Severity.CRITICAL if "AGPL" in prof.spdx_id else Severity.HIGH
            return ComplianceFinding(
                rule_id="AI-LIC-002",
                title="Strong Copyleft / Network Copyleft Contagion",
                severity=sev,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license=prof.spdx_id,
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=(
                    f"Dependency '{asset.name}' uses '{prof.spdx_id}', which is incompatible with "
                    f"policy '{policy.value}' (project license: {declared_project_license})."
                ),
                remediation=prof.notes or "Replace with an Apache-2.0/MIT/BSD equivalent.",
                suggested_alternatives=alts,
                reference_url=prof.url,
            )

        # 4. Custom AI Commercial Licenses with Thresholds / AUP / Pass-through clauses
        if cat == LicenseCategory.CUSTOM_AI_COMMERCIAL:
            if policy in {PolicyMode.OPEN_SOURCE_PERMISSIVE, PolicyMode.APACHE_2_STRICT}:
                return ComplianceFinding(
                    rule_id="AI-LIC-003",
                    title="Custom AI License Incompatible with Pure OSI Permissive Redistribution",
                    severity=Severity.MEDIUM,
                    asset_name=asset.name,
                    asset_type=asset.asset_type,
                    detected_license=prof.spdx_id,
                    license_category=cat,
                    source_file=asset.source_file,
                    line_number=asset.line_number,
                    message=(
                        f"Model '{asset.name}' uses '{prof.spdx_id}', which imposes custom AUP, "
                        "revenue/MAU thresholds, or attribution clauses beyond standard OSI permissive licenses."
                    ),
                    remediation=prof.notes,
                    suggested_alternatives=alts,
                    reference_url=prof.url,
                )
            return ComplianceFinding(
                rule_id="AI-LIC-003",
                title="Custom AI Commercial Clause Review Required",
                severity=Severity.MEDIUM,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license=prof.spdx_id,
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=(
                    f"Model '{asset.name}' ({prof.spdx_id}) permits commercial use with conditions: {prof.notes}"
                ),
                remediation="Verify MAU/revenue thresholds, Acceptable Use Policy, and required attribution.",
                suggested_alternatives=alts,
                reference_url=prof.url,
            )

        # 5. ShareAlike (CC-BY-SA-4.0)
        if cat == LicenseCategory.SHARE_ALIKE:
            if policy == PolicyMode.ACADEMIC_RESEARCH:
                return None
            return ComplianceFinding(
                rule_id="AI-LIC-004",
                title="ShareAlike Derivative Obligation",
                severity=Severity.MEDIUM,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license=prof.spdx_id,
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=(
                    f"Dataset '{asset.name}' uses '{prof.spdx_id}'. Derivative/curated datasets "
                    "must be redistributed under the identical ShareAlike license."
                ),
                remediation=prof.notes,
                suggested_alternatives=alts,
                reference_url=prof.url,
            )

        # 6. Weak Copyleft (MPL-2.0, LGPL-2.1, LGPL-3.0)
        if cat == LicenseCategory.WEAK_COPYLEFT:
            if policy == PolicyMode.APACHE_2_STRICT and "LGPL" in prof.spdx_id:
                return ComplianceFinding(
                    rule_id="AI-LIC-005",
                    title="Weak Copyleft Linking Obligation",
                    severity=Severity.MEDIUM,
                    asset_name=asset.name,
                    asset_type=asset.asset_type,
                    detected_license=prof.spdx_id,
                    license_category=cat,
                    source_file=asset.source_file,
                    line_number=asset.line_number,
                    message=(
                        f"'{asset.name}' uses '{prof.spdx_id}'. Ensure dynamic linking compliance "
                        "or replace with a pure permissive package."
                    ),
                    remediation=prof.notes,
                    suggested_alternatives=alts,
                    reference_url=prof.url,
                )
            return ComplianceFinding(
                rule_id="AI-LIC-005",
                title="Weak Copyleft Compliance Notice",
                severity=Severity.LOW,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license=prof.spdx_id,
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=f"'{asset.name}' uses weak copyleft '{prof.spdx_id}': {prof.notes}",
                remediation="Avoid modifying component files without preserving original license headers.",
                suggested_alternatives=alts,
                reference_url=prof.url,
            )

        # 7. Unknown / Unverified License
        if cat == LicenseCategory.UNKNOWN:
            return ComplianceFinding(
                rule_id="AI-LIC-006",
                title="Unverified or Missing License Metadata",
                severity=Severity.MEDIUM,
                asset_name=asset.name,
                asset_type=asset.asset_type,
                detected_license="UNKNOWN",
                license_category=cat,
                source_file=asset.source_file,
                line_number=asset.line_number,
                message=(
                    f"Could not verify license for {asset.asset_type.value} '{asset.name}'. "
                    "Re-run with `--online` to query Hugging Face Hub / PyPI or verify manually."
                ),
                remediation="Verify upstream repository LICENSE file or pass `--online` during scan.",
                suggested_alternatives=alts,
                reference_url=asset.homepage,
            )

        return None
