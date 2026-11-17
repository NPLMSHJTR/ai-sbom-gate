"""Python AST and YAML/JSON config scanner for Hugging Face models and datasets."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from ai_sbom_gate.catalog.known_assets import lookup_known_asset
from ai_sbom_gate.catalog.spdx_licenses import resolve_license_profile
from ai_sbom_gate.models import AIAsset, AssetType

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

_SKIP_DIRS = frozenset({".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"})

_MODEL_CALL_NAMES = frozenset(
    {
        "from_pretrained",
        "pipeline",
        "hf_hub_download",
        "snapshot_download",
    }
)
_DATASET_CALL_NAMES = frozenset(
    {
        "load_dataset",
        "load_dataset_builder",
    }
)
_CONFIG_MODEL_KEYS = frozenset(
    {"model", "model_id", "model_name", "hf_model", "pretrained_model_name_or_path", "base_model"}
)
_CONFIG_DATASET_KEYS = frozenset({"dataset", "dataset_id", "dataset_name", "hf_dataset"})

_KNOWN_SHORT_DATASETS = frozenset({"squad", "glue", "imdb", "mnist", "cifar10"})
_YAML_KV_RE = re.compile(r'^\s*([A-Za-z0-9_.-]+)\s*:\s*["\']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)["\']?\s*$')


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


def _looks_like_hf_repo_id(candidate: str, allow_short_dataset: bool = False) -> bool:
    s = candidate.strip()
    if not s or len(s) > 120:
        return False
    if s.startswith((".", "/", "~", "http://", "https://")) or "\\" in s:
        return False
    if "{" in s or "}" in s or " " in s:
        return False
    if "/" in s:
        parts = s.split("/")
        return len(parts) == 2 and all(bool(p) for p in parts)
    return allow_short_dataset and s.lower() in _KNOWN_SHORT_DATASETS


def _resolve_str_node(node: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    return None


def _get_call_name(func: ast.AST) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _build_hf_asset(
    repo_id: str,
    asset_type: AssetType,
    source_file: str,
    line_number: int,
    discovery_method: str,
) -> AIAsset:
    known = lookup_known_asset(repo_id, asset_type)
    raw_lic = known.license_id if known is not None else "UNKNOWN"
    gated = known.gated if known is not None else False
    homepage = (
        known.homepage
        if known is not None
        else (
            f"https://huggingface.co/datasets/{repo_id}"
            if asset_type == AssetType.HF_DATASET
            else f"https://huggingface.co/{repo_id}"
        )
    )
    profile = resolve_license_profile(raw_lic)
    return AIAsset(
        name=repo_id,
        asset_type=asset_type,
        version="main",
        raw_license=raw_lic,
        normalized_license=profile.spdx_id,
        license_category=profile.category,
        source_file=source_file,
        line_number=line_number,
        discovery_method=discovery_method,
        purl=f"pkg:huggingface/{repo_id}",
        homepage=homepage,
        gated=gated,
    )


def _scan_python_ast(path: Path, rel_path: str) -> list[AIAsset]:
    source = path.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=rel_path)
    except SyntaxError:
        return []

    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                constants[node.targets[0].id] = node.value.value

    found: list[AIAsset] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _get_call_name(node.func)
        if call_name not in _MODEL_CALL_NAMES and call_name not in _DATASET_CALL_NAMES:
            continue

        kw_map: dict[str, ast.AST] = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        lineno = getattr(node, "lineno", 1)

        if call_name in _DATASET_CALL_NAMES:
            arg_node = kw_map.get("path") or (node.args[0] if node.args else None)
            if arg_node is not None:
                val = _resolve_str_node(arg_node, constants)
                if val and _looks_like_hf_repo_id(val, allow_short_dataset=True):
                    found.append(
                        _build_hf_asset(val, AssetType.HF_DATASET, rel_path, lineno, f"ast:{call_name}")
                    )
            continue

        if call_name == "pipeline":
            model_node = kw_map.get("model") or (node.args[1] if len(node.args) >= 2 else None)
            if model_node is not None:
                val = _resolve_str_node(model_node, constants)
                if val and _looks_like_hf_repo_id(val):
                    found.append(
                        _build_hf_asset(val, AssetType.HF_MODEL, rel_path, lineno, "ast:pipeline")
                    )
            continue

        # from_pretrained / hf_hub_download / snapshot_download
        repo_node = (
            kw_map.get("pretrained_model_name_or_path")
            or kw_map.get("repo_id")
            or (node.args[0] if node.args else None)
        )
        if repo_node is None:
            continue
        repo_val = _resolve_str_node(repo_node, constants)
        if not repo_val or not _looks_like_hf_repo_id(repo_val):
            continue

        asset_type = AssetType.HF_MODEL
        if "repo_type" in kw_map:
            rt_val = _resolve_str_node(kw_map["repo_type"], constants)
            if rt_val and rt_val.strip().lower() == "dataset":
                asset_type = AssetType.HF_DATASET

        found.append(_build_hf_asset(repo_val, asset_type, rel_path, lineno, f"ast:{call_name}"))

    return found


def _scan_config_obj(obj: Any, rel_path: str, out: list[AIAsset], depth: int = 0) -> None:
    if depth > 10:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).strip().lower()
            if isinstance(v, str):
                if kl in _CONFIG_MODEL_KEYS and _looks_like_hf_repo_id(v):
                    out.append(_build_hf_asset(v, AssetType.HF_MODEL, rel_path, 1, f"config:{k}"))
                elif kl in _CONFIG_DATASET_KEYS and _looks_like_hf_repo_id(v, allow_short_dataset=True):
                    out.append(_build_hf_asset(v, AssetType.HF_DATASET, rel_path, 1, f"config:{k}"))
            else:
                _scan_config_obj(v, rel_path, out, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _scan_config_obj(item, rel_path, out, depth + 1)


def scan_code_assets(root: Path, excludes: list[str] | None = None) -> list[AIAsset]:
    """Discover Hugging Face model and dataset references in Python source and config files."""
    ex = excludes or []
    assets: list[AIAsset] = []
    seen: set[tuple[str, AssetType, str]] = set()

    def add_unique(item: AIAsset) -> None:
        key = (item.name.lower(), item.asset_type, item.source_file)
        if key not in seen:
            seen.add(key)
            assets.append(item)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or _should_skip(path, root, ex):
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

        if path.suffix == ".py":
            for item in _scan_python_ast(path, rel):
                add_unique(item)
        elif path.suffix in {".yaml", ".yml"}:
            raw_text = path.read_text(encoding="utf-8", errors="replace")
            if yaml is not None:
                try:
                    parsed = yaml.safe_load(raw_text)
                    tmp: list[AIAsset] = []
                    _scan_config_obj(parsed, rel, tmp)
                    for item in tmp:
                        add_unique(item)
                    continue
                except Exception:
                    pass
            for lineno, line in enumerate(raw_text.splitlines(), 1):
                m = _YAML_KV_RE.match(line)
                if m:
                    k, v = m.group(1).lower(), m.group(2)
                    if k in _CONFIG_MODEL_KEYS:
                        add_unique(_build_hf_asset(v, AssetType.HF_MODEL, rel, lineno, f"yaml:{k}"))
                    elif k in _CONFIG_DATASET_KEYS:
                        add_unique(_build_hf_asset(v, AssetType.HF_DATASET, rel, lineno, f"yaml:{k}"))
        elif path.suffix == ".json" and path.name not in {"package.json", "package-lock.json"}:
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
                tmp = []
                _scan_config_obj(parsed, rel, tmp)
                for item in tmp:
                    add_unique(item)
            except Exception:
                pass

    return assets
