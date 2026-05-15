from __future__ import annotations

import logging
from typing import Any, TypedDict, cast

from langgraph.graph import END, StateGraph

from tawasol_risk.config.settings import Settings, get_settings
from tawasol_risk.datasets.loaders import DataPack, load_data_pack
from tawasol_risk.datasets.schemas import RiskRecord
from tawasol_risk.rag.nist_retriever import excerpt, retrieve_nist_control
from tawasol_risk.rag.vector_store import VectorIndex, load_vector_index
from tawasol_risk.reporting.formatter import render_markdown_report
from tawasol_risk.risk_engine.correlator import build_ranked_risks, risks_to_records
from tawasol_risk.risk_engine.kev_service import KevCatalog, load_kev_catalog

logger = logging.getLogger(__name__)


class AnalysisState(TypedDict, total=False):
    settings: Settings
    yaml_cfg: dict[str, Any]
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
    top_k = int(yaml_cfg.get("risk_engine", {}).get("top_k", 5))
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
    md = render_markdown_report(state["records"], pack.threat_report_md)
    return {"markdown": md}


def build_analysis_graph() -> StateGraph:
    g = StateGraph(AnalysisState)
    g.add_node("load_pack", node_load_pack)
    g.add_node("load_index", node_load_index)
    g.add_node("rank", node_rank)
    g.add_node("nist", node_attach_nist)
    g.add_node("render", node_render)

    g.set_entry_point("load_pack")
    g.add_edge("load_pack", "load_index")
    g.add_edge("load_index", "rank")
    g.add_edge("rank", "nist")
    g.add_edge("nist", "render")
    g.add_edge("render", END)
    return g


def run_langgraph_analysis(settings: Settings | None = None) -> AnalysisState:
    graph = build_analysis_graph().compile()
    seed: AnalysisState = {}
    if settings is not None:
        seed["settings"] = settings
    return graph.invoke(seed)
