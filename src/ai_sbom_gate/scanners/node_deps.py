"""Node.js / npm dependency scanner (package.json and package-lock.json)."""

from __future__ import annotations

import json
from pathlib import Path

from ai_sbom_gate.catalog.known_assets import lookup_known_asset
from ai_sbom_gate.catalog.spdx_licenses import resolve_license_profile
from ai_sbom_gate.models import AIAsset, AssetType

_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "dist", "build"})


def _should_skip(path: Path, root: Path, excludes: list[str]) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts
    if any(p in _SKIP_DIRS for p in rel_parts):
        return True
    rel_posix = "/".join(rel_parts)
    for exc in excludes:
        norm = exc.strip().strip("/")
        if norm and (rel_posix == norm or rel_posix.startswith(norm + "/") or norm in rel_parts):
            return True
    return False


def _build_node_asset(
    name: str,
    version: str,
    raw_license: str,
    source_file: str,
    discovery_method: str,
) -> AIAsset:
    lic = raw_license
    homepage = f"https://www.npmjs.com/package/{name}"
    if not lic or lic == "UNKNOWN":
        known = lookup_known_asset(name, AssetType.NODE_PACKAGE)
        if known is not None:
            lic = known.license_id
            homepage = known.homepage
    profile = resolve_license_profile(lic)
    purl_ver = f"@{version}" if version else ""
    return AIAsset(
        name=name,
        asset_type=AssetType.NODE_PACKAGE,
        version=version,
        raw_license=lic or "UNKNOWN",
        normalized_license=profile.spdx_id,
        license_category=profile.category,
        source_file=source_file,
        line_number=1,
        discovery_method=discovery_method,
        purl=f"pkg:npm/{name}{purl_ver}",
        homepage=homepage,
    )


def scan_node_dependencies(root: Path, excludes: list[str] | None = None) -> list[AIAsset]:
    """Scan package.json and package-lock.json files under `root`."""
    ex = excludes or []
    assets: list[AIAsset] = []
    seen: set[tuple[str, str]] = set()

    for path in sorted(root.rglob("*")):
        if not path.is_file() or _should_skip(path, root, ex):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

        if path.name == "package.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = data.get(section)
                if not isinstance(deps, dict):
                    continue
                for pkg_name, ver_spec in deps.items():
                    key = (pkg_name.lower(), rel)
                    if key in seen:
                        continue
                    seen.add(key)
                    ver = str(ver_spec).lstrip("^~>=< ")
                    assets.append(
                        _build_node_asset(pkg_name, ver, "UNKNOWN", rel, f"package.json[{section}]")
                    )

        elif path.name == "package-lock.json":
            try:
                lock = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            packages = lock.get("packages") if isinstance(lock, dict) else None
            if isinstance(packages, dict):
                for pkg_path, meta in packages.items():
                    if not pkg_path or not isinstance(meta, dict):
                        continue
                    pkg_name = pkg_path.split("node_modules/")[-1]
                    if not pkg_name:
                        continue
                    key = (pkg_name.lower(), rel)
                    if key in seen:
                        continue
                    seen.add(key)
                    raw_lic = str(meta.get("license", "UNKNOWN"))
                    ver = str(meta.get("version", ""))
                    assets.append(
                        _build_node_asset(pkg_name, ver, raw_lic, rel, "package-lock.json")
                    )

    return assets
