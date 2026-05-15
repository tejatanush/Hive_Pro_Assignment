from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cyber_risk.bootstrap import readiness_status  # noqa: E402
from cyber_risk.config.settings import get_settings  # noqa: E402
from cyber_risk.graph.workflow import run_langgraph_analysis  # noqa: E402


def _default_top_k(cfg: dict) -> int:
    try:
        k = int(cfg.get("risk_engine", {}).get("top_k", 5))
    except (TypeError, ValueError):
        k = 5
    return max(1, min(10, k))


def main() -> None:
    settings = get_settings()
    title = f"{settings.organization_name} — Cyber Risk Assistant"
    st.set_page_config(page_title=title, layout="wide")
    st.title(title)

    yaml_cfg = settings.yaml_overlay()
    default_k = _default_top_k(yaml_cfg)

    with st.sidebar:
        st.header("Analysis options")
        top_k = st.slider(
            "Number of risks to surface",
            min_value=1,
            max_value=10,
            value=default_k,
            help="How many ranked risks to include in this run.",
        )

    status = readiness_status(settings)
    if not status["ready"]:
        st.warning(
            "Service not ready. Run `python scripts/bootstrap.py` once, "
            "or set `CYBER_RISK_AUTO_BOOTSTRAP=true` on the API service.",
            icon="⚠️",
        )
        st.json(status)

    if st.button("Run analysis", type="primary"):
        with st.spinner("Running analysis pipeline…"):
            try:
                state = run_langgraph_analysis(settings, top_k=top_k)
            except FileNotFoundError as e:
                st.error(f"Missing prerequisites: {e}")
                return
            st.session_state["state"] = state

    state = st.session_state.get("state")
    if not state:
        st.info("Use the sidebar slider to choose how many risks to include, then click **Run analysis**.")
        return

    st.subheader("Risk briefing")
    st.markdown(state.get("markdown", ""))

    with st.expander("Structured JSON (API parity)"):
        st.json({"risks": [r.model_dump(mode="json") for r in state.get("records", [])]})


if __name__ == "__main__":
    main()
