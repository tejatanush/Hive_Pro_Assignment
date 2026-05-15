from __future__ import annotations

import logging
import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from cyber_risk.bootstrap import bootstrap_artifacts, readiness_status
from cyber_risk.config.settings import Settings, get_settings
from cyber_risk.datasets.uploads import validate_pack_directory
from cyber_risk.graph.workflow import run_langgraph_analysis

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


class RiskReportResponse(BaseModel):
    markdown: str
    risks: list[dict[str, Any]]


def _infra_ready(settings: Settings) -> dict[str, Any]:
    """KEV + vector backend (needed even when CSVs arrive via multipart)."""
    st = readiness_status(settings)
    infra_ok = bool(st.get("kev_cache")) and bool(st.get("vector_index"))
    return {**st, "infra_ready": infra_ok}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.getLogger().setLevel(settings.log_level.upper())
    if settings.auto_bootstrap:
        logger.info("AUTO_BOOTSTRAP enabled — syncing KEV / NIST cache and vector artifacts")
        bootstrap_artifacts(settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    yaml_cfg = settings.yaml_overlay()
    api_cfg = yaml_cfg.get("api", {})
    title = api_cfg.get("title") or settings.api_title
    version = api_cfg.get("version") or settings.api_version

    app = FastAPI(title=title, version=version, lifespan=lifespan)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, Any]:
        status = readiness_status(settings)
        if not status["ready"]:
            raise HTTPException(status_code=503, detail=status)
        return status

    @app.post("/v1/risk-report", response_model=RiskReportResponse)
    def risk_report(
        top_k: int | None = Query(
            default=None,
            ge=1,
            le=10,
            description="Number of top risks to return (1–10). Defaults to risk_engine.top_k in config.",
        ),
    ) -> RiskReportResponse:
        status = readiness_status(settings)
        if not status["ready"]:
            raise HTTPException(
                status_code=503,
                detail="Service not ready. Run bootstrap or set CYBER_RISK_AUTO_BOOTSTRAP=true.",
            )
        try:
            state = run_langgraph_analysis(settings, top_k=top_k)
        except FileNotFoundError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
        records = state.get("records") or []
        md = str(state.get("markdown") or "")
        return RiskReportResponse(markdown=md, risks=[r.model_dump(mode="json") for r in records])

    @app.get("/v1/risk-report.md", response_class=PlainTextResponse)
    def risk_report_md(
        top_k: int | None = Query(
            default=None,
            ge=1,
            le=10,
            description="Number of top risks to return (1–10).",
        ),
    ) -> str:
        status = readiness_status(settings)
        if not status["ready"]:
            raise HTTPException(status_code=503, detail=status)
        try:
            state = run_langgraph_analysis(settings, top_k=top_k)
        except FileNotFoundError as e:
            raise HTTPException(status_code=500, detail=str(e)) from e
        return str(state.get("markdown") or "")

    @app.post("/v1/risk-report/upload", response_model=RiskReportResponse)
    async def risk_report_upload(
        assets_csv: UploadFile = File(..., description="Filename should be assets.csv"),
        vulnerabilities_csv: UploadFile = File(...),
        threat_intelligence_csv: UploadFile = File(...),
        business_services_csv: UploadFile = File(...),
        remediation_guidance_csv: UploadFile = File(...),
        threat_report_md: UploadFile | None = File(None, description="Optional MDR-style markdown"),
        top_k: int | None = Query(
            default=None,
            ge=1,
            le=10,
            description="Defaults to configs/default.yaml risk_engine.top_k",
        ),
    ) -> RiskReportResponse:
        core = _infra_ready(settings)
        if not core["infra_ready"]:
            raise HTTPException(
                status_code=503,
                detail={"message": "KEV cache or vector index not ready.", "detail": core},
            )
        td = Path(tempfile.mkdtemp(prefix="api-pack-"))
        try:
            (td / "assets.csv").write_bytes(await assets_csv.read())
            (td / "vulnerabilities.csv").write_bytes(await vulnerabilities_csv.read())
            (td / "threat_intelligence.csv").write_bytes(await threat_intelligence_csv.read())
            (td / "business_services.csv").write_bytes(await business_services_csv.read())
            (td / "remediation_guidance.csv").write_bytes(await remediation_guidance_csv.read())
            if threat_report_md is not None:
                body = await threat_report_md.read()
                if body:
                    (td / "threat_report.md").write_bytes(body)
            validate_pack_directory(td)
            state = run_langgraph_analysis(settings, top_k=top_k, data_pack_dir=td)
            records = state.get("records") or []
            md = str(state.get("markdown") or "")
            return RiskReportResponse(markdown=md, risks=[r.model_dump(mode="json") for r in records])
        finally:
            shutil.rmtree(td, ignore_errors=True)

    return app


app = create_app()
