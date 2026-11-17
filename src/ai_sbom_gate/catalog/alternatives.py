"""Actionable permissive-license remediation recommendations for high-risk AI assets."""

from __future__ import annotations

from ai_sbom_gate.catalog.known_assets import normalize_pkg_key
from ai_sbom_gate.models import AssetType, LicenseCategory

_DIRECT_ALTERNATIVES: dict[str, list[str]] = {
    "pymupdf": ["pypdfium2 (Apache-2.0 / BSD-3-Clause)", "pypdf (BSD-3-Clause)", "pdfplumber (MIT)"],
    "fitz": ["pypdfium2 (Apache-2.0 / BSD-3-Clause)", "pypdf (BSD-3-Clause)"],
    "ultralytics": ["onnxruntime (MIT) + Apache-2.0 RT-DETR weights", "opencv-python (MIT)"],
    "chardet": ["charset-normalizer (MIT)"],
    "mysql-connector-python": ["PyMySQL (MIT)"],
    "psycopg2": ["Evaluate LGPL-3.0 dynamic linking compliance or use commercial driver"],
    "psycopg": ["Evaluate LGPL-3.0 compliance obligations"],
    "ffmpeg-static": ["Use system LGPL-built FFmpeg binary via subprocess without static bundling"],
    "black-forest-labs/flux.1-dev": ["black-forest-labs/FLUX.1-schnell (Apache-2.0)"],
    "stabilityai/stable-diffusion-3-medium": ["black-forest-labs/FLUX.1-schnell (Apache-2.0)"],
    "qwen/qwen-7b-chat": ["Qwen/Qwen2.5-7B-Instruct (Apache-2.0)"],
    "qwen/qwen2.5-72b-instruct": ["Qwen/Qwen2.5-32B-Instruct (Apache-2.0)"],
    "meta-llama/llama-3.1-8b-instruct": ["Qwen/Qwen2.5-7B-Instruct (Apache-2.0)", "microsoft/Phi-3.5-mini-instruct (MIT)"],
    "meta-llama/llama-3.2-1b-instruct": ["Qwen/Qwen2.5-1.5B-Instruct (Apache-2.0)"],
    "google/gemma-2-9b-it": ["Qwen/Qwen2.5-7B-Instruct (Apache-2.0)", "microsoft/Phi-3.5-mini-instruct (MIT)"],
    "tatsu-lab/alpaca": ["yahma/alpaca-cleaned (CC-BY-4.0)", "HuggingFaceTB/smoltalk (Apache-2.0)"],
    "lmsys/lmsys-chat-1m": ["HuggingFaceTB/smoltalk (Apache-2.0)"],
}


def get_alternatives(asset_name: str, asset_type: AssetType, category: LicenseCategory) -> list[str]:
    """Return concrete permissive alternatives when available."""
    key = normalize_pkg_key(asset_name) if asset_type == AssetType.PYTHON_PACKAGE else asset_name.strip().lower()
    if key in _DIRECT_ALTERNATIVES:
        return list(_DIRECT_ALTERNATIVES[key])

    if category == LicenseCategory.NON_COMMERCIAL:
        if asset_type == AssetType.HF_MODEL:
            return ["Replace with an Apache-2.0 or MIT licensed model (e.g., Qwen2.5-7B-Instruct, FLUX.1-schnell)."]
        if asset_type == AssetType.HF_DATASET:
            return ["Replace with a CC-BY-4.0, ODC-BY-1.0, or Apache-2.0 dataset (e.g., FineWeb, SmolTalk)."]
    if category == LicenseCategory.STRONG_COPYLEFT:
        return ["Replace with a permissive (MIT / Apache-2.0 / BSD) package or isolate behind a separate commercial license."]
    return []
