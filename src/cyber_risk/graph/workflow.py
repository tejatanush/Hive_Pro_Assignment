from __future__ import annotations

import logging
from typing import Any, TypedDict, cast

from langgraph.graph import END, StateGraph

from cyber_risk.config.settings import Settings, get_settings
from cyber_risk.datasets.loaders import DataPack, load_data_pack
from cyber_risk.datasets.schemas import RiskRecord
from cyber_risk.rag.nist_retriever import excerpt, retrieve_nist_control
from cyber_risk.rag.vector_store import VectorIndex, load_vector_index
from cyber_risk.llm.groq_service import groq_api_key, polish_briefing_markdown
from cyber_risk.reporting.formatter import render_markdown_report
from cyber_risk.risk_engine.correlator import build_ranked_risks, risks_to_records
from cyber_risk.risk_engine.kev_service import KevCatalog, load_kev_catalog

logger = logging.getLogger(__name__)


class AnalysisState(TypedDict, total=False):
    settings: Settings
    yaml_cfg: dict[str, Any]
    top_k: int
    pack: DataPack
    kev: KevCatalog
    index: VectorIndex
    records: list[RiskRecord]
    markdown: str


def _settings(state: AnalysisState) -> Settings:
    return state.get("settings") or get_settings()


def node_load_pack(state: AnalysisState) -> AnalysisState:
    s = _settings(state)
    pack = load_data_pack(s)
    kev = load_kev_catalog(s)
    yaml_cfg = s.yaml_overlay()
    return {"pack": pack, "kev": kev, "yaml_cfg": yaml_cfg}


def node_load_index(state: AnalysisState) -> AnalysisState:
    s = _settings(state)
    return {"index": load_vector_index(s)}


def node_rank(state: AnalysisState) -> AnalysisState:
    pack = state["pack"]
    kev = state["kev"]
    yaml_cfg = state.get("yaml_cfg") or {}
    default_k = int(yaml_cfg.get("risk_engine", {}).get("top_k", 5))
    top_k = int(state["top_k"]) if state.get("top_k") is not None else default_k
    top_k = max(1, min(20, top_k))
    ranked = build_ranked_risks(pack, kev, top_k=top_k)
    return {"records": risks_to_records(ranked)}


def node_attach_nist(state: AnalysisState) -> AnalysisState:
    s = _settings(state)
    yaml_cfg = state.get("yaml_cfg") or {}
    prefs = cast(
        list[str],
        yaml_cfg.get("risk_engine", {}).get(
            "default_control_prefixes",
            ["SI-2", "RA-5", "IR-4", "AC-2", "SA-22", "SC-7", "CM-6"],
        ),
    )
    index = state["index"]
    updated: list[RiskRecord] = []
    for r in state["records"]:
        hit = retrieve_nist_control(r.vulnerability, r.asset, index, prefs, top_k=1)
        if hit is None:
            updated.append(r)
            continue
        updated.append(
            r.model_copy(
                update={
                    "nist_control_id": hit.control_id,
                    "nist_control_title": hit.title,
                    "nist_excerpt": excerpt(hit.text, limit=1400),
                }
            )
        )
    return {"records": updated}


def node_render(state: AnalysisState) -> AnalysisState:
    pack = state["pack"]
    s = _settings(state)
    md = render_markdown_report(
        state["records"],
        pack.threat_report_md,
        organization_name=s.organization_name,
    )
    return {"markdown": md}


def node_groq_polish(state: AnalysisState) -> AnalysisState:
    """Optional: rewrite briefing wording via Groq (llama-3.1-8b-instant by default)."""
    s = _settings(state)
    if s.llm_provider.strip().lower() != "groq":
        return {}
    if not groq_api_key(s):
        logger.warning("LLM_PROVIDER=groq but GROQ_API_KEY (or OPENAI_API_KEY) is unset; skipping polish")
        return {}
    try:
        polished = polish_briefing_markdown(state["markdown"], s)
        return {"markdown": polished}
    except Exception as e:
        logger.warning("Groq polish failed; returning deterministic markdown. %s", e)
        return {}


def build_analysis_graph() -> StateGraph:
    g = StateGraph(AnalysisState)
    g.add_node("load_pack", node_load_pack)
    g.add_node("load_index", node_load_index)
    g.add_node("rank", node_rank)
    g.add_node("nist", node_attach_nist)
    g.add_node("render", node_render)
    g.add_node("groq_polish", node_groq_polish)

    g.set_entry_point("load_pack")
    g.add_edge("load_pack", "load_index")
    g.add_edge("load_index", "rank")
    g.add_edge("rank", "nist")
    g.add_edge("nist", "render")
    g.add_edge("render", "groq_polish")
    g.add_edge("groq_polish", END)
    return g


def run_langgraph_analysis(settings: Settings | None = None, *, top_k: int | None = None) -> AnalysisState:
    graph = build_analysis_graph().compile()
    seed: AnalysisState = {}
    if settings is not None:
        seed["settings"] = settings
    if top_k is not None:
        seed["top_k"] = int(top_k)
    return graph.invoke(seed)
