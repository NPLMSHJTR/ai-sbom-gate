"""Python dependency & license metadata scanner (pyproject.toml, requirements.txt, uv.lock, poetry.lock)."""

from __future__ import annotations

import importlib.metadata as importlib_meta
import re
from pathlib import Path
from typing import Any

from ai_sbom_gate.catalog.known_assets import lookup_known_asset, normalize_pkg_key
from ai_sbom_gate.catalog.spdx_licenses import normalize_license_id, resolve_license_profile
from ai_sbom_gate.models import AIAsset, AssetType

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(.*)$")
_VERSION_PIN_RE = re.compile(r"==\s*([A-Za-z0-9._+-]+)")

_SKIP_DIRS = frozenset({".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"})


def _should_skip(path: Path, root: Path, excludes: list[str]) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        rel_parts = path.parts
    if any(part in _SKIP_DIRS for part in rel_parts):
        return True
    rel_posix = "/".join(rel_parts)
    for exc in excludes:
        norm = exc.strip().strip("/")
        if norm and (rel_posix == norm or rel_posix.startswith(norm + "/") or norm in rel_parts):
            return True
    return False


def _load_toml(path: Path) -> dict[str, Any]:
    raw_bytes = path.read_bytes()
    if tomllib is not None:
        return tomllib.loads(raw_bytes.decode("utf-8"))
    # Minimal fallback parser for simple key=value and array blocks on Python 3.10 without tomli
    return _minimal_toml_fallback(raw_bytes.decode("utf-8", errors="replace"))


def _minimal_toml_fallback(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    section_path: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].split("#", 1)[0].strip()
        i += 1
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            inner = line.strip("[]").strip()
            section_path = [p.strip().strip('"').strip("'") for p in inner.split(".")]
            cur = data
            for p in section_path:
                cur = cur.setdefault(p, {})
            continue
        if "=" in line:
            k, v = [x.strip() for x in line.split("=", 1)]
            k = k.strip('"').strip("'")
            while v.startswith("[") and not v.endswith("]") and i < len(lines):
                nxt = lines[i].split("#", 1)[0].strip()
                v += " " + nxt
                i += 1
            cur = data
            for p in section_path:
                cur = cur.setdefault(p, {})
            if v.startswith("[") and v.endswith("]"):
                items = [x.strip().strip('"').strip("'") for x in v[1:-1].split(",") if x.strip()]
                cur[k] = items
            else:
                cur[k] = v.strip('"').strip("'")
    return data


def _extract_pkg_name_and_version(spec: str) -> tuple[str, str] | None:
    no_comment = spec.split("#", 1)[0].strip()
    if not no_comment or no_comment.startswith(("-", "--", "git+", "http://", "https://")):
        return None
    no_marker = no_comment.split(";", 1)[0].strip()
    m = _REQ_NAME_RE.match(no_marker)
    if not m:
        return None
    name = m.group(1)
    rest = m.group(2)
    vm = _VERSION_PIN_RE.search(rest)
    version = vm.group(1) if vm else ""
    return name, version


def _lookup_installed_license(pkg_name: str) -> tuple[str, str]:
    """Query local Python environment metadata for an installed distribution's license."""
    for candidate in (pkg_name, normalize_pkg_key(pkg_name), pkg_name.replace("-", "_")):
        try:
            dist = importlib_meta.distribution(candidate)
        except importlib_meta.PackageNotFoundError:
            continue
        meta = dist.metadata
        lic_expr = meta.get("License-Expression")
        if lic_expr and str(lic_expr).strip() and str(lic_expr).strip().upper() != "UNKNOWN":
            return str(lic_expr).strip(), dist.version
        lic = meta.get("License")
        if lic and str(lic).strip() and str(lic).strip().upper() != "UNKNOWN":
            first_line = str(lic).strip().splitlines()[0][:120]
            if normalize_license_id(first_line) != "UNKNOWN":
                return first_line, dist.version
        classifiers = meta.get_all("Classifier") or []
        for cls in classifiers:
            if cls.startswith("License :: OSI Approved :: "):
                return cls.split("::")[-1].strip(), dist.version
    return "UNKNOWN", ""


def _build_python_asset(
    name: str,
    version: str,
    source_file: str,
    line_number: int,
    discovery_method: str,
) -> AIAsset:
    known = lookup_known_asset(name, AssetType.PYTHON_PACKAGE)
    raw_lic = "UNKNOWN"
    homepage = ""
    if known is not None:
        raw_lic = known.license_id
        homepage = known.homepage
    else:
        inst_lic, inst_ver = _lookup_installed_license(name)
        if inst_lic != "UNKNOWN":
            raw_lic = inst_lic
        if not version and inst_ver:
            version = inst_ver

    profile = resolve_license_profile(raw_lic)
    purl_ver = f"@{version}" if version else ""
    return AIAsset(
        name=name,
        asset_type=AssetType.PYTHON_PACKAGE,
        version=version,
        raw_license=raw_lic,
        normalized_license=profile.spdx_id,
        license_category=profile.category,
        source_file=source_file,
        line_number=line_number,
        discovery_method=discovery_method,
        purl=f"pkg:pypi/{normalize_pkg_key(name)}{purl_ver}",
        homepage=homepage or f"https://pypi.org/project/{normalize_pkg_key(name)}/",
    )


def detect_declared_project_license(root: Path) -> str:
    """Detect the target repository's own declared license from pyproject.toml, package.json, or LICENSE."""
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            data = _load_toml(pyproject)
            proj = data.get("project", {})
            if isinstance(proj, dict):
                lic = proj.get("license")
                if isinstance(lic, str) and lic.strip():
                    return normalize_license_id(lic)
                if isinstance(lic, dict):
                    if "text" in lic:
                        return normalize_license_id(str(lic["text"]))
            poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
            if isinstance(poetry, dict) and isinstance(poetry.get("license"), str):
                return normalize_license_id(poetry["license"])
        except Exception:
            pass

    for lic_name in ("LICENSE", "LICENSE.md", "LICENSE.txt"):
        lic_file = root / lic_name
        if lic_file.is_file():
            head = lic_file.read_text(encoding="utf-8", errors="ignore")[:800]
            if "Apache License" in head and "Version 2.0" in head:
                return "Apache-2.0"
            if "MIT License" in head or "Permission is hereby granted, free of charge" in head:
                return "MIT"
            if "GNU AFFERO GENERAL PUBLIC LICENSE" in head.upper():
                return "AGPL-3.0-only"
            if "GNU GENERAL PUBLIC LICENSE" in head.upper():
                return "GPL-3.0-only"
            if "Redistribution and use in source and binary forms" in head:
                return "BSD-3-Clause"
    return "UNDECLARED"


def scan_python_dependencies(root: Path, excludes: list[str] | None = None) -> list[AIAsset]:
    """Scan Python manifests and lockfiles under `root` for package dependencies."""
    ex = excludes or []
    assets: list[AIAsset] = []
    seen_keys: set[tuple[str, str]] = set()

    def add_asset(asset: AIAsset) -> None:
        key = (normalize_pkg_key(asset.name), asset.source_file)
        if key not in seen_keys:
            seen_keys.add(key)
            assets.append(asset)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or _should_skip(path, root, ex):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

        if path.name == "pyproject.toml":
            try:
                data = _load_toml(path)
            except Exception:
                continue
            proj = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
            deps = proj.get("dependencies", [])
            if isinstance(deps, list):
                for spec in deps:
                    if isinstance(spec, str):
                        parsed = _extract_pkg_name_and_version(spec)
                        if parsed:
                            add_asset(_build_python_asset(parsed[0], parsed[1], rel, 1, "pyproject.toml"))
            opt_deps = proj.get("optional-dependencies", {})
            if isinstance(opt_deps, dict):
                for group_name, group_list in opt_deps.items():
                    if isinstance(group_list, list):
                        for spec in group_list:
                            if isinstance(spec, str):
                                parsed = _extract_pkg_name_and_version(spec)
                                if parsed:
                                    add_asset(
                                        _build_python_asset(
                                            parsed[0], parsed[1], rel, 1, f"pyproject.toml[optional:{group_name}]"
                                        )
                                    )
            poetry_deps = (
                data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                if isinstance(data.get("tool"), dict)
                else {}
            )
            if isinstance(poetry_deps, dict):
                for pkg_name, val in poetry_deps.items():
                    if pkg_name.lower() == "python":
                        continue
                    ver = val.strip("^~=") if isinstance(val, str) else ""
                    add_asset(_build_python_asset(pkg_name, ver, rel, 1, "pyproject.toml[poetry]"))

        elif path.name.startswith("requirements") and path.suffix == ".txt":
            for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                parsed = _extract_pkg_name_and_version(line)
                if parsed:
                    add_asset(_build_python_asset(parsed[0], parsed[1], rel, lineno, "requirements.txt"))

        elif path.name in {"uv.lock", "poetry.lock"}:
            try:
                lock_data = _load_toml(path)
                pkgs = lock_data.get("package", [])
                if isinstance(pkgs, list):
                    for pkg in pkgs:
                        if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                            add_asset(
                                _build_python_asset(
                                    pkg["name"], str(pkg.get("version", "")), rel, 1, path.name
                                )
                            )
            except Exception:
                pass

    return assets
