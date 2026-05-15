from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from tawasol_risk.config.settings import get_settings
from tawasol_risk.graph.workflow import run_langgraph_analysis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="TawasolPay Cyber Risk API", version="0.1.0")


class RiskReportResponse(BaseModel):
    markdown: str
    risks: list[dict[str, Any]]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/risk-report", response_model=RiskReportResponse)
def risk_report() -> RiskReportResponse:
    try:
        state = run_langgraph_analysis(get_settings())
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    records = state.get("records") or []
    md = str(state.get("markdown") or "")
    return RiskReportResponse(markdown=md, risks=[r.model_dump(mode="json") for r in records])


@app.get("/v1/risk-report.md", response_class=PlainTextResponse)
def risk_report_md() -> str:
    try:
        state = run_langgraph_analysis(get_settings())
    except FileNotFoundError as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
    return str(state.get("markdown") or "")
