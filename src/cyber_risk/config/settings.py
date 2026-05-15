from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_project_root() -> Path:
    env = os.getenv("CYBER_RISK_PROJECT_ROOT") or os.getenv("TAWASOL_PROJECT_ROOT")
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[3]


def _load_yaml_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class Settings(BaseSettings):
    """Runtime configuration (environment variables + optional YAML overlay)."""

    model_config = SettingsConfigDict(
        env_prefix="CYBER_RISK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    project_root: Path = Field(default_factory=_default_project_root)
    data_dir: Path = Field(default=Path("data"))
    processed_dir: Path = Field(default=Path("data/processed"))
    config_path: Path = Field(default=Path("configs/default.yaml"))

    organization_name: str = Field(
        default="Organization",
        validation_alias=AliasChoices(
            "ORGANIZATION_NAME",
            "CYBER_RISK_ORGANIZATION_NAME",
            "TAWASOL_ORGANIZATION_NAME",
        ),
    )
    api_title: str = Field(default="Cyber Risk API")
    api_version: str = Field(default="1.0.0")
    log_level: str = Field(default="INFO")

    auto_bootstrap: bool = Field(
        default=False,
        description="Download KEV/NIST and build local index on API startup if artifacts are missing.",
        validation_alias=AliasChoices(
            "AUTO_BOOTSTRAP",
            "CYBER_RISK_AUTO_BOOTSTRAP",
        ),
    )

    kev_cache_filename: str = "kev_catalog.json"
    nist_catalog_filename: str = "nist_sp800_53_rev5_catalog.json"
    local_vector_index_filename: str = "nist_local_vectors.npz"
    local_vector_meta_filename: str = "nist_local_vectors.meta.json"

    pinecone_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("PINECONE_API_KEY", "CYBER_RISK_PINECONE_API_KEY"),
    )
    pinecone_index_name: str | None = Field(
        default="cyber-risk-nist",
        validation_alias=AliasChoices("PINECONE_INDEX_NAME", "CYBER_RISK_PINECONE_INDEX_NAME"),
    )
    pinecone_cloud: str = Field(
        default="aws",
        validation_alias=AliasChoices("PINECONE_CLOUD", "CYBER_RISK_PINECONE_CLOUD"),
    )
    pinecone_region: str = Field(
        default="us-east-1",
        validation_alias=AliasChoices("PINECONE_REGION", "CYBER_RISK_PINECONE_REGION"),
    )

    llm_provider: str = Field(
        default="none",
        validation_alias=AliasChoices("LLM_PROVIDER", "CYBER_RISK_LLM_PROVIDER"),
    )
    openai_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("OPENAI_API_KEY", "CYBER_RISK_OPENAI_API_KEY"),
    )
    groq_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GROQ_API_KEY", "CYBER_RISK_GROQ_API_KEY"),
    )
    groq_model: str = Field(
        default="llama-3.1-8b-instant",
        validation_alias=AliasChoices("GROQ_MODEL", "CYBER_RISK_GROQ_MODEL"),
    )

    embedding_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2",
        validation_alias=AliasChoices("EMBEDDING_MODEL", "CYBER_RISK_EMBEDDING_MODEL"),
    )

    #: When ``False``, NIST RAG **must** use Pinecone—no ``data/processed/*.npz`` fallback (recommended for production).
    allow_local_vector_fallback: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "ALLOW_LOCAL_VECTOR_FALLBACK",
            "CYBER_RISK_ALLOW_LOCAL_VECTOR_FALLBACK",
        ),
    )

    #: Skip checking that CSVs exist under ``data/`` before ``/ready`` (e.g. backend only accepts uploads).
    ignore_data_pack_for_ready_check: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "IGNORE_DATA_PACK_READY",
            "CYBER_RISK_IGNORE_DATA_PACK_READY",
        ),
    )

    def resolved_data_dir(self) -> Path:
        p = self.data_dir if self.data_dir.is_absolute() else self.project_root / self.data_dir
        return p.resolve()

    def resolved_processed_dir(self) -> Path:
        p = (
            self.processed_dir
            if self.processed_dir.is_absolute()
            else self.project_root / self.processed_dir
        )
        p.mkdir(parents=True, exist_ok=True)
        return p.resolve()

    def yaml_overlay(self) -> dict[str, Any]:
        cfg_path = (
            self.config_path if self.config_path.is_absolute() else self.project_root / self.config_path
        )
        return _load_yaml_config(cfg_path)

    def required_data_files(self) -> list[Path]:
        root = self.resolved_data_dir()
        return [
            root / "assets.csv",
            root / "vulnerabilities.csv",
            root / "threat_intelligence.csv",
            root / "business_services.csv",
            root / "remediation_guidance.csv",
        ]

    def local_vector_index_ready(self) -> bool:
        proc = self.resolved_processed_dir()
        return (
            (proc / self.local_vector_index_filename).exists()
            and (proc / self.local_vector_meta_filename).exists()
        )

    def kev_cache_ready(self) -> bool:
        return (self.resolved_processed_dir() / self.kev_cache_filename).exists()

    def uses_pinecone(self) -> bool:
        return bool(self.pinecone_api_key and self.pinecone_index_name)

    def nist_rag_requires_pinecone(self) -> bool:
        """If true, vector queries must go to Pinecone (no local npz index)."""
        return not self.allow_local_vector_fallback


@lru_cache
def get_settings() -> Settings:
    return Settings()
