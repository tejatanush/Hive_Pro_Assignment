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


class HashingEmbedder:
    """Deterministic local fallback when sentence-transformers is unavailable."""

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

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


@lru_cache(maxsize=2)
def get_embedding_model(model_name: str):
    try:
        from sentence_transformers import SentenceTransformer
    except Exception as e:  # pragma: no cover - environment-specific
        logger.warning(
            "sentence-transformers unavailable (%s); using HashingEmbedder fallback",
            e,
        )
        return HashingEmbedder(dim=384)
    logger.info("Loading embedding model %s", model_name)
    return SentenceTransformer(model_name)


def embed_texts(model_name: str, texts: list[str], batch_size: int = 32):
    model = get_embedding_model(model_name)
    return model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=len(texts) > 256,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )
