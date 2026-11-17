"""Optional live metadata inspector for Hugging Face Hub and PyPI JSON APIs."""

from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any, Callable

from ai_sbom_gate.catalog.spdx_licenses import normalize_license_id, resolve_license_profile
from ai_sbom_gate.models import AIAsset, AssetType

try:
    import certifi  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    certifi = None  # type: ignore[assignment]


def _default_fetch_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    ctx = ssl.create_default_context(cafile=certifi.where()) if certifi is not None else ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "ai-sbom-gate/0.1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


class RemoteInspector:
    """Enriches discovered AIAssets with live PyPI / Hugging Face Hub license metadata."""

    def __init__(
        self,
        fetch_json: Callable[[str, float], dict[str, Any]] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.fetch_json = fetch_json or _default_fetch_json
        self.timeout = timeout
        self._cache: dict[str, dict[str, Any] | None] = {}

    def _cached_get(self, url: str) -> dict[str, Any] | None:
        if url in self._cache:
            return self._cache[url]
        try:
            data = self.fetch_json(url, self.timeout)
        except Exception:
            data = None
        self._cache[url] = data
        return data

    def enrich_asset(self, asset: AIAsset) -> AIAsset:
        """Query remote registry when asset license is unknown or needs live gated/tag inspection."""
        if asset.asset_type == AssetType.PYTHON_PACKAGE and asset.normalized_license == "UNKNOWN":
            data = self._cached_get(f"https://pypi.org/pypi/{asset.name}/json")
            if isinstance(data, dict):
                info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
                raw_lic = self._extract_pypi_license(info)
                if raw_lic != "UNKNOWN":
                    prof = resolve_license_profile(raw_lic)
                    asset.raw_license = raw_lic
                    asset.normalized_license = prof.spdx_id
                    asset.license_category = prof.category
                if not asset.version and isinstance(info.get("version"), str):
                    asset.version = info["version"]

        elif asset.asset_type in {AssetType.HF_MODEL, AssetType.HF_DATASET}:
            kind_path = "datasets" if asset.asset_type == AssetType.HF_DATASET else "models"
            data = self._cached_get(f"https://huggingface.co/api/{kind_path}/{asset.name}")
            if isinstance(data, dict):
                raw_lic, gated, extra = self._extract_hf_license(data)
                if gated:
                    asset.gated = True
                if extra:
                    asset.extra_terms.extend(t for t in extra if t not in asset.extra_terms)
                if raw_lic != "UNKNOWN":
                    prof = resolve_license_profile(raw_lic)
                    asset.raw_license = raw_lic
                    asset.normalized_license = prof.spdx_id
                    asset.license_category = prof.category
        return asset

    @staticmethod
    def _extract_pypi_license(info: dict[str, Any]) -> str:
        lic_expr = info.get("license_expression")
        if isinstance(lic_expr, str) and lic_expr.strip():
            return lic_expr.strip()
        lic = info.get("license")
        if isinstance(lic, str) and lic.strip() and lic.strip().upper() != "UNKNOWN":
            first_line = lic.strip().splitlines()[0][:120]
            if normalize_license_id(first_line) != "UNKNOWN":
                return first_line
        classifiers = info.get("classifiers")
        if isinstance(classifiers, list):
            for cls in classifiers:
                if isinstance(cls, str) and cls.startswith("License :: OSI Approved :: "):
                    return cls.split("::")[-1].strip()
        return "UNKNOWN"

    @staticmethod
    def _extract_hf_license(data: dict[str, Any]) -> tuple[str, bool, list[str]]:
        gated = bool(data.get("gated", False))
        extra: list[str] = []
        card = data.get("cardData") if isinstance(data.get("cardData"), dict) else {}
        lic = card.get("license")
        if isinstance(lic, list) and lic:
            lic = lic[0]
        if isinstance(lic, str) and lic.strip():
            lic_str = lic.strip()
            if lic_str.lower() == "other":
                lic_name = str(card.get("license_name", "")).strip()
                if lic_name:
                    extra.append(f"Custom HF license_name: {lic_name}")
                    return lic_name, gated, extra
            if normalize_license_id(lic_str) != "UNKNOWN":
                return lic_str, gated, extra
            extra.append(f"Raw HF card license: {lic_str}")

        tags = data.get("tags")
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("license:"):
                    val = tag.split("license:", 1)[1].strip()
                    if val.lower() != "other":
                        return val, gated, extra
        return "UNKNOWN", gated, extra
