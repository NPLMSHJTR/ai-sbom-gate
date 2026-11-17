"""Intentionally non-compliant AI application fixture for demonstrating ai-sbom-gate detection."""

from __future__ import annotations

IMAGE_GEN_MODEL = "black-forest-labs/FLUX.1-dev"


class AutoModelForCausalLM:
    @staticmethod
    def from_pretrained(model_id: str) -> str:
        return model_id


class DiffusionPipeline:
    @staticmethod
    def from_pretrained(model_id: str) -> str:
        return model_id


def load_dataset(path: str) -> str:
    return path


def run_demo() -> tuple[str, str, str]:
    llm = AutoModelForCausalLM.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
    img = DiffusionPipeline.from_pretrained(IMAGE_GEN_MODEL)
    ds = load_dataset("tatsu-lab/alpaca")
    return llm, img, ds
