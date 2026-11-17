"""Reference commercial-safe RAG application using permissive packages, models, and datasets."""

from __future__ import annotations

EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
CHAT_MODEL = "Qwen/Qwen2.5-7B-Instruct"


class AutoModel:
    @staticmethod
    def from_pretrained(model_id: str) -> str:
        return model_id


class AutoModelForCausalLM:
    @staticmethod
    def from_pretrained(model_id: str) -> str:
        return model_id


def load_dataset(path: str) -> str:
    return path


def build_pipeline() -> dict[str, str]:
    embedder = AutoModel.from_pretrained(EMBEDDING_MODEL)
    llm = AutoModelForCausalLM.from_pretrained(CHAT_MODEL)
    dataset = load_dataset("HuggingFaceTB/smoltalk")
    return {
        "embedder": embedder,
        "llm": llm,
        "dataset": dataset,
    }
