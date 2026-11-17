"""Unit tests for Python and Node.js dependency manifest & lockfile scanners."""

from __future__ import annotations

import json
from pathlib import Path

from ai_sbom_gate.models import AssetType
from ai_sbom_gate.scanners.node_deps import scan_node_dependencies
from ai_sbom_gate.scanners.python_deps import detect_declared_project_license, scan_python_dependencies


def test_python_pyproject_requirements_and_uv_lock_parsing(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample-ai"
version = "0.1.0"
license = { text = "Apache-2.0" }
dependencies = [
    "fastapi>=0.110.0",
    "pydantic[email]==2.7.1",
]
""",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "# comment line\nPyMuPDF==1.24.0\n-r dev.txt\nchardet>=5.0 ; python_version >= '3.10'\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "onnxruntime"
version = "1.18.0"
""",
        encoding="utf-8",
    )

    assert detect_declared_project_license(tmp_path) == "Apache-2.0"
    assets = scan_python_dependencies(tmp_path)
    names = {a.name: a for a in assets}
    assert "fastapi" in names and names["fastapi"].normalized_license == "MIT"
    assert "pydantic" in names and names["pydantic"].version == "2.7.1"
    assert "PyMuPDF" in names and names["PyMuPDF"].normalized_license == "AGPL-3.0-only"
    assert "chardet" in names and names["chardet"].normalized_license == "LGPL-2.1-only"
    assert "onnxruntime" in names and names["onnxruntime"].normalized_license == "MIT"


def test_node_package_json_and_lockfile_parsing(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "web-ai-app",
                "dependencies": {
                    "@huggingface/transformers": "^3.0.0",
                    "ffmpeg-static": "^5.2.0",
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "web-ai-app"},
                    "node_modules/zod": {"version": "3.23.0", "license": "MIT"},
                },
            }
        ),
        encoding="utf-8",
    )

    assets = scan_node_dependencies(tmp_path)
    by_name = {a.name: a for a in assets}
    assert by_name["@huggingface/transformers"].asset_type == AssetType.NODE_PACKAGE
    assert by_name["@huggingface/transformers"].normalized_license == "Apache-2.0"
    assert by_name["ffmpeg-static"].normalized_license == "GPL-3.0-only"
    assert by_name["zod"].normalized_license == "MIT"
