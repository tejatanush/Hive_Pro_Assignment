from __future__ import annotations

import logging
from pathlib import Path

from cyber_risk.config.settings import Settings, get_settings
from cyber_risk.datasets.uploads import validate_pack_directory
from cyber_risk.rag.nist_oscal import download_nist_catalog, load_nist_chunks
from cyber_risk.rag.vector_store import build_local_index, upsert_pinecone
from cyber_risk.risk_engine.kev_service import download_kev_catalog

logger = logging.getLogger(__name__)

REQUIRED_CSV_NAMES = (
    "assets.csv",
    "vulnerabilities.csv",
    "threat_intelligence.csv",
    "business_services.csv",
    "remediation_guidance.csv",
)


def validate_data_pack(settings: Settings | None = None, pack_dir: Path | None = None) -> None:
    s = settings or get_settings()
    root = Path(pack_dir).resolve() if pack_dir is not None else s.resolved_data_dir()
    validate_pack_directory(root)


def ensure_kev_cache(settings: Settings | None = None, force: bool = False) -> Path:
    s = settings or get_settings()
    yaml_cfg = s.yaml_overlay()
    url = yaml_cfg.get("risk_engine", {}).get("kev_url")
    if url:
        return download_kev_catalog(url=url, settings=s, force=force)
    return download_kev_catalog(settings=s, force=force)


def ensure_nist_vector_index(settings: Settings | None = None, force_download: bool = False) -> None:
    s = settings or get_settings()
    if s.nist_rag_requires_pinecone():
        logger.info("NIST RAG pinned to Pinecone — skipping local npz index build")
        return
    if s.uses_pinecone():
        logger.info("Pinecone configured; skipping local index build")
        return
    if s.local_vector_index_ready() and not force_download:
        logger.info("Local NIST vector index already present")
        return
    download_nist_catalog(settings=s, force=force_download)
    chunks = load_nist_chunks(settings=s)
    build_local_index(chunks, s.embedding_model, s)
    logger.info("Built local NIST vector index (%d controls)", len(chunks))


def ensure_pinecone_index(settings: Settings | None = None, force_download: bool = False) -> None:
    s = settings or get_settings()
    if not s.uses_pinecone():
        if s.nist_rag_requires_pinecone():
            raise RuntimeError("PINECONE_API_KEY and PINECONE_INDEX_NAME required when local vector fallback is disabled")
        return
    download_nist_catalog(settings=s, force=force_download)
    chunks = load_nist_chunks(settings=s)
    upsert_pinecone(chunks, s.embedding_model, s)
    logger.info("Upserted %d NIST chunks into Pinecone index %s", len(chunks), s.pinecone_index_name)


def bootstrap_artifacts(
    settings: Settings | None = None,
    force: bool = False,
    *,
    pack_dir: Path | None = None,
) -> None:
    """Optional CSV validation; KEV sync; NIST catalog download (from YAML URL) → Pinecone or local index."""
    s = settings or get_settings()
    if not s.ignore_data_pack_for_ready_check:
        validate_data_pack(s, pack_dir)
    ensure_kev_cache(s, force=force)
    if s.uses_pinecone() or s.nist_rag_requires_pinecone():
        ensure_pinecone_index(s, force_download=force)
    ensure_nist_vector_index(s, force_download=force)


def readiness_status(settings: Settings | None = None) -> dict[str, bool | str]:
    s = settings or get_settings()
    if s.ignore_data_pack_for_ready_check:
        data_ok = True
    else:
        data_ok = all(p.exists() for p in s.required_data_files())
    kev_ok = s.kev_cache_ready()

    if s.nist_rag_requires_pinecone():
        vectors_ok = s.uses_pinecone()
        backend = "pinecone-required"
    else:
        vectors_ok = s.uses_pinecone() or s.local_vector_index_ready()
        backend = "pinecone" if s.uses_pinecone() else "local"

    ready = data_ok and kev_ok and vectors_ok
    return {
        "ready": ready,
        "data_pack": data_ok,
        "kev_cache": kev_ok,
        "vector_index": vectors_ok,
        "vector_backend": backend,
        "nist_catalog_source": "downloads from risk_engine.nist_catalog_url in configs/default.yaml → cached JSON → embedded into vector DB",
        "data_dir": str(s.resolved_data_dir()),
    }
