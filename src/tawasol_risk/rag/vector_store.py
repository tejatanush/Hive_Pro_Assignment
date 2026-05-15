from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from tawasol_risk.config.settings import Settings, get_settings
from tawasol_risk.rag.embeddings import embed_texts
from tawasol_risk.rag.nist_oscal import NistControlChunk

logger = logging.getLogger(__name__)


@dataclass
class SearchHit:
    control_id: str
    title: str
    text: str
    score: float


class VectorIndex(Protocol):
    def search(self, query: str, top_k: int, allowed_prefixes: list[str] | None) -> list[SearchHit]: ...


class LocalNumpyIndex:
    """Disk-backed cosine similarity index (no Pinecone required)."""

    def __init__(self, vectors: np.ndarray, meta: list[dict[str, Any]], model_name: str) -> None:
        self._vectors = vectors.astype(np.float32, copy=False)
        self._meta = meta
        self._model_name = model_name

    @classmethod
    def load(cls, settings: Settings) -> LocalNumpyIndex:
        proc = settings.resolved_processed_dir()
        npz_path = proc / settings.local_vector_index_filename
        meta_path = proc / settings.local_vector_meta_filename
        if not npz_path.exists() or not meta_path.exists():
            raise FileNotFoundError(
                "Local vector index missing. Run: python scripts/ingest_nist_vectors.py"
            )
        z = np.load(str(npz_path))
        vectors = z["vectors"]
        payload = json.loads(meta_path.read_text(encoding="utf-8"))
        model_name = str(payload.get("model_name") or settings.embedding_model)
        meta = list(payload.get("items") or [])
        return cls(vectors=vectors, meta=meta, model_name=model_name)

    def search(self, query: str, top_k: int, allowed_prefixes: list[str] | None) -> list[SearchHit]:
        q = embed_texts(self._model_name, [query])[0].astype(np.float32)
        sims = self._vectors @ q  # cosine because normalized
        order = np.argsort(-sims)
        hits: list[SearchHit] = []
        for idx in order.tolist():
            m = self._meta[idx]
            cid: str = m["control_id"]
            if allowed_prefixes:
                stem = cid.split("(")[0].upper()
                if not any(stem.startswith(p.upper()) for p in allowed_prefixes):
                    continue
            hits.append(
                SearchHit(
                    control_id=cid,
                    title=m["title"],
                    text=m["text"],
                    score=float(sims[idx]),
                )
            )
            if len(hits) >= top_k:
                break
        return hits


def build_local_index(chunks: list[NistControlChunk], model_name: str, settings: Settings) -> None:
    texts = [f"{c.control_id} {c.title}\n{c.text}" for c in chunks]
    vectors = embed_texts(model_name, texts, batch_size=16)
    payload = {
        "model_name": model_name,
        "items": [{"control_id": c.control_id, "title": c.title, "text": c.text} for c in chunks],
    }
    proc = settings.resolved_processed_dir()
    npz_path = proc / settings.local_vector_index_filename
    meta_path = proc / settings.local_vector_meta_filename
    np.savez_compressed(str(npz_path), vectors=np.asarray(vectors, dtype=np.float32))
    meta_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    logger.info("Wrote local index to %s", npz_path)


class PineconeIndex:
    """Optional Pinecone serverless index."""

    def __init__(self, api_key: str, index_name: str, model_name: str) -> None:
        from pinecone import Pinecone

        self._index = Pinecone(api_key=api_key).Index(index_name)
        self._model_name = model_name

    def search(self, query: str, top_k: int, allowed_prefixes: list[str] | None) -> list[SearchHit]:
        qv = embed_texts(self._model_name, [query])[0].tolist()
        # Pinecone filter: control_id starts with SI-2 etc. is awkward; over-fetch then filter.
        res = self._index.query(vector=qv, top_k=max(top_k * 8, top_k), include_metadata=True)
        hits: list[SearchHit] = []
        for m in res.matches or []:
            meta = m.metadata or {}
            cid = str(meta.get("control_id", ""))
            if allowed_prefixes:
                stem = cid.split("(")[0].upper()
                if not any(stem.startswith(p.upper()) for p in allowed_prefixes):
                    continue
            hits.append(
                SearchHit(
                    control_id=cid,
                    title=str(meta.get("title", "")),
                    text=str(meta.get("text", "")),
                    score=float(m.score or 0.0),
                )
            )
            if len(hits) >= top_k:
                break
        return hits


def load_vector_index(settings: Settings | None = None) -> VectorIndex:
    s = settings or get_settings()
    if s.pinecone_api_key and s.pinecone_index_name:
        try:
            return PineconeIndex(s.pinecone_api_key, s.pinecone_index_name, s.embedding_model)
        except Exception as e:  # pragma: no cover
            logger.warning("Pinecone unavailable (%s); falling back to local index", e)
    return LocalNumpyIndex.load(s)


def upsert_pinecone(chunks: list[NistControlChunk], model_name: str, settings: Settings) -> None:
    from pinecone import Pinecone, ServerlessSpec

    if not settings.pinecone_api_key or not settings.pinecone_index_name:
        raise RuntimeError("PINECONE_API_KEY and PINECONE_INDEX_NAME are required for Pinecone upsert")

    pc = Pinecone(api_key=settings.pinecone_api_key)
    name = settings.pinecone_index_name

    from tawasol_risk.rag.embeddings import get_embedding_model

    model = get_embedding_model(model_name)
    dim = int(getattr(model, "get_sentence_embedding_dimension", lambda: 384)())

    existing_names: set[str] = set()
    try:
        lst = pc.list_indexes()
        # pinecone client versions differ: list[str] vs objects
        if hasattr(lst, "names"):
            existing_names = set(lst.names())
        else:
            for item in lst:  # type: ignore[assignment]
                if isinstance(item, str):
                    existing_names.add(item)
                else:
                    existing_names.add(getattr(item, "name", str(item)))
    except Exception:  # pragma: no cover
        existing_names = set()

    if name not in existing_names:
        pc.create_index(
            name=name,
            dimension=dim,
            metric="cosine",
            spec=ServerlessSpec(cloud=settings.pinecone_cloud, region=settings.pinecone_region),
        )
    index = pc.Index(name)
    texts = [f"{c.control_id} {c.title}\n{c.text}" for c in chunks]
    vectors = embed_texts(model_name, texts, batch_size=16)
    batch: list[dict[str, Any]] = []
    for i, (c, vec) in enumerate(zip(chunks, vectors, strict=True)):
        batch.append(
            {
                "id": c.control_id.replace("(", "_").replace(")", "_").lower(),
                "values": vec.astype(float).tolist(),
                "metadata": {
                    "control_id": c.control_id,
                    "title": c.title[:512],
                    "text": c.text[:3500],
                },
            }
        )
        if len(batch) >= 100:
            index.upsert(vectors=batch)
            batch.clear()
    if batch:
        index.upsert(vectors=batch)
    logger.info("Upserted %d NIST chunks into Pinecone index %s", len(chunks), name)
