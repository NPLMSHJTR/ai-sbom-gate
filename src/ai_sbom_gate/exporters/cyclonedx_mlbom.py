"""CycloneDX 1.6 AI/ML Bill of Materials (ML-BOM) JSON generator."""

from __future__ import annotations

import json
import uuid
from typing import Any

from ai_sbom_gate import __version__
from ai_sbom_gate.catalog.spdx_licenses import resolve_license_profile
from ai_sbom_gate.models import AssetType, ComplianceReport


def _map_component_type(asset_type: AssetType) -> str:
    if asset_type == AssetType.HF_MODEL:
        return "machine-learning-model"
    if asset_type == AssetType.HF_DATASET:
        return "data"
    return "library"


def build_cyclonedx_mlbom(report: ComplianceReport) -> dict[str, Any]:
    """Generate a CycloneDX 1.6 ML-BOM JSON dictionary from a ComplianceReport."""
    root_ref = "pkg:generic/target-project@0.1.0"
    components: list[dict[str, Any]] = []
    dep_refs: list[str] = []

    for idx, asset in enumerate(report.assets, 1):
        bom_ref = asset.purl or f"asset:{asset.asset_type.value}:{asset.name}:{idx}"
        if bom_ref in dep_refs:
            bom_ref = f"{bom_ref}#{idx}"
        dep_refs.append(bom_ref)

        prof = resolve_license_profile(asset.normalized_license)
        lic_entry = (
            {"license": {"id": prof.spdx_id}}
            if prof.spdx_id in {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC", "PSF-2.0", "0BSD", "Unlicense", "CC0-1.0", "CC-BY-4.0", "ODC-BY-1.0", "MPL-2.0", "LGPL-2.1-only", "LGPL-3.0-only", "CC-BY-SA-4.0", "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only", "CC-BY-NC-4.0", "CC-BY-NC-SA-4.0"}
            else {"license": {"name": prof.name if prof.spdx_id != "UNKNOWN" else asset.raw_license}}
        )

        comp: dict[str, Any] = {
            "type": _map_component_type(asset.asset_type),
            "bom-ref": bom_ref,
            "name": asset.name,
            "version": asset.version or "unspecified",
            "licenses": [lic_entry],
            "properties": [
                {"name": "ai-sbom:asset-type", "value": asset.asset_type.value},
                {"name": "ai-sbom:license-category", "value": asset.license_category.value},
                {"name": "ai-sbom:source-file", "value": asset.source_file},
                {"name": "ai-sbom:discovery-method", "value": asset.discovery_method},
            ],
        }
        if asset.purl:
            comp["purl"] = asset.purl
        if asset.homepage:
            comp["externalReferences"] = [{"type": "website", "url": asset.homepage}]

        if asset.asset_type == AssetType.HF_MODEL:
            comp["modelCard"] = {
                "modelParameters": {"approach": {"type": "supervised"}},
                "quantitativeAnalysis": {},
                "considerations": {
                    "useCases": ["Detected automatically via static/remote AI-SBOM inspection."],
                    "technicalLimitations": [prof.notes] if prof.notes else [],
                },
            }
        elif asset.asset_type == AssetType.HF_DATASET:
            comp["data"] = [
                {
                    "type": "dataset",
                    "name": asset.name,
                    "classification": "public" if not asset.gated else "gated",
                }
            ]

        components.append(comp)

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "ai-sbom-gate",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": report.target,
                "licenses": [{"license": {"name": report.declared_project_license}}],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": root_ref,
                "dependsOn": dep_refs,
            }
        ],
    }


def render_cyclonedx_mlbom(report: ComplianceReport) -> str:
    """Serialize a CycloneDX 1.6 ML-BOM report to formatted JSON."""
    return json.dumps(build_cyclonedx_mlbom(report), indent=2, ensure_ascii=False)
