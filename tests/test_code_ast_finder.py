"""Unit tests for Python AST and config-based Hugging Face model/dataset discovery."""

from __future__ import annotations

import json
from pathlib import Path

from ai_sbom_gate.models import AssetType
from ai_sbom_gate.scanners.code_ast_finder import scan_code_assets


def test_ast_discovers_models_datasets_and_constants(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        """
BASE_LLM = "Qwen/Qwen2.5-7B-Instruct"

def setup():
    m1 = AutoModelForCausalLM.from_pretrained(BASE_LLM)
    m2 = DiffusionPipeline.from_pretrained(pretrained_model_name_or_path="black-forest-labs/FLUX.1-dev")
    p = pipeline("automatic-speech-recognition", model="openai/whisper-base")
    f = hf_hub_download(repo_id="HuggingFaceFW/fineweb", filename="README.md", repo_type="dataset")
    ds1 = load_dataset("tatsu-lab/alpaca", split="train")
    ds2 = load_dataset(path="squad")
    local_ignored = AutoModel.from_pretrained("./local_weights")
    return m1, m2, p, f, ds1, ds2, local_ignored
""",
        encoding="utf-8",
    )
    (tmp_path / "config.yaml").write_text(
        "model_id: google/gemma-2-9b-it\nhf_dataset: lmsys/lmsys-chat-1m\n",
        encoding="utf-8",
    )
    (tmp_path / "manifest.json").write_text(
        json.dumps({"model": "BAAI/bge-large-en-v1.5"}),
        encoding="utf-8",
    )

    assets = scan_code_assets(tmp_path)
    found = {(a.name, a.asset_type): a for a in assets}

    assert ("Qwen/Qwen2.5-7B-Instruct", AssetType.HF_MODEL) in found
    assert ("black-forest-labs/FLUX.1-dev", AssetType.HF_MODEL) in found
    assert ("openai/whisper-base", AssetType.HF_MODEL) in found
    assert ("google/gemma-2-9b-it", AssetType.HF_MODEL) in found
    assert ("BAAI/bge-large-en-v1.5", AssetType.HF_MODEL) in found

    assert ("HuggingFaceFW/fineweb", AssetType.HF_DATASET) in found
    assert ("tatsu-lab/alpaca", AssetType.HF_DATASET) in found
    assert ("squad", AssetType.HF_DATASET) in found
    assert ("lmsys/lmsys-chat-1m", AssetType.HF_DATASET) in found

    # Local paths must NOT be misidentified as HF models
    assert all("./local_weights" not in a.name for a in assets)
