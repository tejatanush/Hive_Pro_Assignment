from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from cyber_risk.bootstrap import bootstrap_artifacts, readiness_status
from cyber_risk.config.settings import get_settings
from cyber_risk.graph.workflow import run_langgraph_analysis

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)


class RiskReportResponse(BaseModel):
    markdown: str
    risks: list[dict[str, Any]]


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.getLogger().setLevel(settings.log_level.upper())
    if settings.auto_bootstrap:
        logger.info("AUTO_BOOTSTRAP enabled — ensuring KEV and vector artifacts")
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

    return app


app = create_app()
