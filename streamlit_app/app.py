from __future__ import annotations

import os
import sys
from pathlib import Path

import streamlit as st

# Ensure `src/` is importable when launching Streamlit from repo root.
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from tawasol_risk.config.settings import get_settings  # noqa: E402
from tawasol_risk.graph.workflow import run_langgraph_analysis  # noqa: E402


def main() -> None:
    st.set_page_config(page_title="TawasolPay Cyber Risk Assistant", layout="wide")
    st.title("TawasolPay — AI-assisted cyber risk prioritisation")
    st.caption(
        "Structured joins + CISA KEV + threat intel + **retrieved NIST SP 800-53 Rev.5 text** "
        "(embeddings). CSV remediation lines are hints only."
    )

    if st.button("Run analysis", type="primary"):
        with st.spinner("Running LangGraph pipeline (load → rank → NIST RAG → render)…"):
            try:
                state = run_langgraph_analysis(get_settings())
            except FileNotFoundError as e:
                st.error(
                    "Missing prerequisites. "
                    "Download KEV + NIST catalog and build the vector index:\n\n"
                    "`python scripts/download_kev.py`\n\n"
                    "`python scripts/ingest_nist_vectors.py`\n\n"
                    f"Details: {e}"
                )
                return
            st.session_state["state"] = state

    state = st.session_state.get("state")
    if not state:
        st.info('Click **Run analysis** to generate the board-ready briefing.')
        return

    st.subheader("Human-readable briefing")
    st.markdown(state.get("markdown", ""))

    with st.expander("Structured JSON (for debugging / API parity)"):
        st.json({"risks": [r.model_dump(mode="json") for r in state.get("records", [])]})


if __name__ == "__main__":
    main()
