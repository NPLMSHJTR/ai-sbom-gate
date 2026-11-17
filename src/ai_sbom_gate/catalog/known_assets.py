"""Built-in offline knowledge base of popular Python/Node packages, HF models, and HF datasets."""

from __future__ import annotations

from dataclasses import dataclass

from ai_sbom_gate.models import AssetType


@dataclass(frozen=True)
class KnownAssetEntry:
    canonical_name: str
    asset_type: AssetType
    license_id: str
    homepage: str = ""
    gated: bool = False


_KNOWN_PYTHON: dict[str, tuple[str, str]] = {
    "pymupdf": ("AGPL-3.0-only", "https://pypi.org/project/PyMuPDF/"),
    "fitz": ("AGPL-3.0-only", "https://pypi.org/project/PyMuPDF/"),
    "ultralytics": ("AGPL-3.0-only", "https://pypi.org/project/ultralytics/"),
    "chardet": ("LGPL-2.1-only", "https://pypi.org/project/chardet/"),
    "charset-normalizer": ("MIT", "https://pypi.org/project/charset-normalizer/"),
    "pypdfium2": ("Apache-2.0", "https://pypi.org/project/pypdfium2/"),
    "pypdf": ("BSD-3-Clause", "https://pypi.org/project/pypdf/"),
    "pdfplumber": ("MIT", "https://pypi.org/project/pdfplumber/"),
    "onnxruntime": ("MIT", "https://pypi.org/project/onnxruntime/"),
    "onnxruntime-gpu": ("MIT", "https://pypi.org/project/onnxruntime-gpu/"),
    "torch": ("BSD-3-Clause", "https://pypi.org/project/torch/"),
    "transformers": ("Apache-2.0", "https://pypi.org/project/transformers/"),
    "diffusers": ("Apache-2.0", "https://pypi.org/project/diffusers/"),
    "datasets": ("Apache-2.0", "https://pypi.org/project/datasets/"),
    "huggingface-hub": ("Apache-2.0", "https://pypi.org/project/huggingface-hub/"),
    "accelerate": ("Apache-2.0", "https://pypi.org/project/accelerate/"),
    "safetensors": ("Apache-2.0", "https://pypi.org/project/safetensors/"),
    "tokenizers": ("Apache-2.0", "https://pypi.org/project/tokenizers/"),
    "gradio": ("Apache-2.0", "https://pypi.org/project/gradio/"),
    "fastapi": ("MIT", "https://pypi.org/project/fastapi/"),
    "uvicorn": ("BSD-3-Clause", "https://pypi.org/project/uvicorn/"),
    "pydantic": ("MIT", "https://pypi.org/project/pydantic/"),
    "requests": ("Apache-2.0", "https://pypi.org/project/requests/"),
    "httpx": ("BSD-3-Clause", "https://pypi.org/project/httpx/"),
    "numpy": ("BSD-3-Clause", "https://pypi.org/project/numpy/"),
    "scipy": ("BSD-3-Clause", "https://pypi.org/project/scipy/"),
    "scikit-learn": ("BSD-3-Clause", "https://pypi.org/project/scikit-learn/"),
    "pandas": ("BSD-3-Clause", "https://pypi.org/project/pandas/"),
    "pillow": ("MIT", "https://pypi.org/project/pillow/"),
    "opencv-python": ("MIT", "https://pypi.org/project/opencv-python/"),
    "pyyaml": ("MIT", "https://pypi.org/project/PyYAML/"),
    "pytest": ("MIT", "https://pypi.org/project/pytest/"),
    "openai": ("Apache-2.0", "https://pypi.org/project/openai/"),
    "anthropic": ("MIT", "https://pypi.org/project/anthropic/"),
    "langchain": ("MIT", "https://pypi.org/project/langchain/"),
    "tiktoken": ("MIT", "https://pypi.org/project/tiktoken/"),
    "faiss-cpu": ("MIT", "https://pypi.org/project/faiss-cpu/"),
    "chromadb": ("Apache-2.0", "https://pypi.org/project/chromadb/"),
    "qdrant-client": ("Apache-2.0", "https://pypi.org/project/qdrant-client/"),
    "mysql-connector-python": ("GPL-2.0-only", "https://pypi.org/project/mysql-connector-python/"),
    "pymysql": ("MIT", "https://pypi.org/project/PyMySQL/"),
    "psycopg2": ("LGPL-3.0-only", "https://pypi.org/project/psycopg2/"),
    "psycopg": ("LGPL-3.0-only", "https://pypi.org/project/psycopg/"),
    "certifi": ("MPL-2.0", "https://pypi.org/project/certifi/"),
    "rich": ("MIT", "https://pypi.org/project/rich/"),
    "typer": ("MIT", "https://pypi.org/project/typer/"),
    "click": ("BSD-3-Clause", "https://pypi.org/project/click/"),
    "mcp": ("MIT", "https://pypi.org/project/mcp/"),
    "mcp-guard": ("Apache-2.0", "https://github.com/NPLMSHJTR/mcp-guard"),
}

_KNOWN_NODE: dict[str, tuple[str, str]] = {
    "@huggingface/transformers": ("Apache-2.0", "https://www.npmjs.com/package/@huggingface/transformers"),
    "openai": ("Apache-2.0", "https://www.npmjs.com/package/openai"),
    "@anthropic-ai/sdk": ("MIT", "https://www.npmjs.com/package/@anthropic-ai/sdk"),
    "langchain": ("MIT", "https://www.npmjs.com/package/langchain"),
    "zod": ("MIT", "https://www.npmjs.com/package/zod"),
    "react": ("MIT", "https://www.npmjs.com/package/react"),
    "next": ("MIT", "https://www.npmjs.com/package/next"),
    "express": ("MIT", "https://www.npmjs.com/package/express"),
    "axios": ("MIT", "https://www.npmjs.com/package/axios"),
    "typescript": ("Apache-2.0", "https://www.npmjs.com/package/typescript"),
    "ffmpeg-static": ("GPL-3.0-only", "https://www.npmjs.com/package/ffmpeg-static"),
}

_KNOWN_HF_MODELS: dict[str, tuple[str, bool]] = {
    "black-forest-labs/flux.1-dev": ("FLUX-1-dev-Non-Commercial", True),
    "black-forest-labs/flux.1-schnell": ("Apache-2.0", False),
    "meta-llama/llama-3.1-8b-instruct": ("Llama-3.1-Community", True),
    "meta-llama/llama-3.1-70b-instruct": ("Llama-3.1-Community", True),
    "meta-llama/llama-3.2-1b-instruct": ("Llama-3.2-Community", True),
    "meta-llama/llama-3.2-3b-instruct": ("Llama-3.2-Community", True),
    "google/gemma-2-9b-it": ("Gemma-Terms", True),
    "google/gemma-2-2b-it": ("Gemma-Terms", True),
    "qwen/qwen2.5-7b-instruct": ("Apache-2.0", False),
    "qwen/qwen2.5-1.5b-instruct": ("Apache-2.0", False),
    "qwen/qwen2.5-72b-instruct": ("Qwen-Research", False),
    "qwen/qwen-7b-chat": ("Qwen-Research", False),
    "microsoft/phi-3.5-mini-instruct": ("MIT", False),
    "openai/whisper-base": ("MIT", False),
    "openai/whisper-large-v3": ("MIT", False),
    "usefulsensors/moonshine-tiny": ("MIT", False),
    "baai/bge-large-en-v1.5": ("MIT", False),
    "baai/bge-small-en-v1.5": ("MIT", False),
    "sentence-transformers/all-minilm-l6-v2": ("Apache-2.0", False),
    "stabilityai/stable-diffusion-3-medium": ("Stability-AI-Community", True),
    "runwayml/stable-diffusion-v1-5": ("OpenRAIL-M", False),
    "deepseek-ai/deepseek-r1": ("MIT", False),
    "deepseek-ai/deepseek-v3": ("MIT", False),
}

_KNOWN_HF_DATASETS: dict[str, tuple[str, bool]] = {
    "tatsu-lab/alpaca": ("CC-BY-NC-4.0", False),
    "lmsys/lmsys-chat-1m": ("LMSYS-Non-Commercial", True),
    "huggingfacefw/fineweb": ("ODC-BY-1.0", False),
    "huggingfacetb/smoltalk": ("Apache-2.0", False),
    "openai/gsm8k": ("MIT", False),
    "rajpurkar/squad": ("CC-BY-SA-4.0", False),
    "squad": ("CC-BY-SA-4.0", False),
    "allenai/c4": ("ODC-BY-1.0", False),
    "yahma/alpaca-cleaned": ("CC-BY-4.0", False),
    "jtrshm/mcp-guard-bench": ("CC-BY-4.0", False),
}


def normalize_pkg_key(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def lookup_known_asset(name: str, asset_type: AssetType) -> KnownAssetEntry | None:
    """Look up offline license metadata for a Python/Node package or Hugging Face repo."""
    raw = name.strip()
    lower = raw.lower()
    if asset_type == AssetType.PYTHON_PACKAGE:
        key = normalize_pkg_key(raw)
        if key in _KNOWN_PYTHON:
            lic, url = _KNOWN_PYTHON[key]
            return KnownAssetEntry(raw, asset_type, lic, homepage=url)
    elif asset_type == AssetType.NODE_PACKAGE:
        if lower in _KNOWN_NODE:
            lic, url = _KNOWN_NODE[lower]
            return KnownAssetEntry(raw, asset_type, lic, homepage=url)
    elif asset_type == AssetType.HF_MODEL:
        if lower in _KNOWN_HF_MODELS:
            lic, gated = _KNOWN_HF_MODELS[lower]
            return KnownAssetEntry(raw, asset_type, lic, homepage=f"https://huggingface.co/{raw}", gated=gated)
    elif asset_type == AssetType.HF_DATASET:
        if lower in _KNOWN_HF_DATASETS:
            lic, gated = _KNOWN_HF_DATASETS[lower]
            return KnownAssetEntry(
                raw, asset_type, lic, homepage=f"https://huggingface.co/datasets/{raw}", gated=gated
            )
    return None
