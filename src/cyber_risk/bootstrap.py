from __future__ import annotations

import logging
from pathlib import Path

from cyber_risk.config.settings import Settings, get_settings
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


def validate_data_pack(settings: Settings | None = None) -> None:
    s = settings or get_settings()
    missing = [p for p in s.required_data_files() if not p.exists()]
    if missing:
        names = ", ".join(p.name for p in missing)
        raise FileNotFoundError(
            f"Missing required data pack files under {s.resolved_data_dir()}: {names}"
        )


def ensure_kev_cache(settings: Settings | None = None, force: bool = False) -> Path:
    s = settings or get_settings()
    yaml_cfg = s.yaml_overlay()
    url = yaml_cfg.get("risk_engine", {}).get("kev_url")
    if url:
        return download_kev_catalog(url=url, settings=s, force=force)
    return download_kev_catalog(settings=s, force=force)


def ensure_nist_vector_index(settings: Settings | None = None, force_download: bool = False) -> None:
    s = settings or get_settings()
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
        return
    download_nist_catalog(settings=s, force=force_download)
    chunks = load_nist_chunks(settings=s)
    upsert_pinecone(chunks, s.embedding_model, s)
    logger.info("Upserted %d NIST chunks to Pinecone index %s", len(chunks), s.pinecone_index_name)


def bootstrap_artifacts(settings: Settings | None = None, force: bool = False) -> None:
    """Idempotent production bootstrap: validate CSV pack, KEV, NIST vectors."""
    s = settings or get_settings()
    validate_data_pack(s)
    ensure_kev_cache(s, force=force)
    if s.uses_pinecone():
        ensure_pinecone_index(s, force_download=force)
    else:
        ensure_nist_vector_index(s, force_download=force)


def readiness_status(settings: Settings | None = None) -> dict[str, bool | str]:
    s = settings or get_settings()
    data_ok = all(p.exists() for p in s.required_data_files())
    kev_ok = s.kev_cache_ready()
    vectors_ok = s.uses_pinecone() or s.local_vector_index_ready()
    ready = data_ok and kev_ok and vectors_ok
    return {
        "ready": ready,
        "data_pack": data_ok,
        "kev_cache": kev_ok,
        "vector_index": vectors_ok,
        "vector_backend": "pinecone" if s.uses_pinecone() else "local",
        "data_dir": str(s.resolved_data_dir()),
    }
