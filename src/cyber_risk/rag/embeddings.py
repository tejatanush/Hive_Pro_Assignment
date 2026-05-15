from __future__ import annotations

import hashlib
import logging
import os
from functools import lru_cache

import numpy as np

logger = logging.getLogger(__name__)

# Avoid optional TensorFlow/Keras import paths in some conda stacks.
os.environ.setdefault("TRANSFORMERS_NO_TF", "1")
os.environ.setdefault("USE_TF", "0")
# Public models must not use stale/expired HF tokens saved on the machine.
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")


class HashingEmbedder:
    """Deterministic local fallback when sentence-transformers cannot load."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    def get_sentence_embedding_dimension(self) -> int:
        return self.dim

    def encode(
        self,
        texts: list[str],
        batch_size: int = 32,
        show_progress_bar: bool = False,
        convert_to_numpy: bool = True,
        normalize_embeddings: bool = True,
    ):
        del batch_size, show_progress_bar, convert_to_numpy
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, text in enumerate(texts):
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            seed = int.from_bytes(digest[:8], "big")
            rng = np.random.default_rng(seed)
            vec = rng.standard_normal(self.dim).astype(np.float32)
            if normalize_embeddings:
                norm = np.linalg.norm(vec)
                if norm > 0:
                    vec /= norm
            out[i] = vec
        return out


def _use_hashing_backend() -> bool:
    return os.getenv("EMBEDDING_BACKEND", "").strip().lower() in {"hashing", "hash", "local"}


def _load_sentence_transformer(model_name: str):
    from sentence_transformers import SentenceTransformer

    # token=False → anonymous download for public models (avoids expired HF_TOKEN).
    try:
        return SentenceTransformer(model_name, token=False)
    except TypeError:
        return SentenceTransformer(model_name)


@lru_cache(maxsize=2)
def get_embedding_model(model_name: str):
    if _use_hashing_backend():
        logger.info("EMBEDDING_BACKEND=hashing — using HashingEmbedder (dim=384)")
        return HashingEmbedder(dim=384)

    try:
        model = _load_sentence_transformer(model_name)
        logger.info("Loaded embedding model %s", model_name)
        return model
    except ImportError as e:
        logger.warning("sentence-transformers not installed (%s); using HashingEmbedder", e)
    except OSError as e:
        logger.warning(
            "Could not load HuggingFace model %s (%s). "
            "Fix: run `huggingface-cli logout` or set EMBEDDING_BACKEND=hashing. "
            "Using HashingEmbedder.",
            model_name,
            e,
        )
    except Exception as e:  # pragma: no cover - HF hub / network errors
        logger.warning(
            "Embedding model load failed (%s). Using HashingEmbedder. "
            "For production quality, fix HF auth or pre-cache the model.",
            e,
        )
    return HashingEmbedder(dim=384)


def embed_texts(model_name: str, texts: list[str], batch_size: int = 32):
    model = get_embedding_model(model_name)
    return model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=len(texts) > 256,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )
