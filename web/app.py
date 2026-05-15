from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cyber_risk.bootstrap import readiness_status  # noqa: E402
from cyber_risk.config.settings import get_settings  # noqa: E402
from cyber_risk.datasets.uploads import (  # noqa: E402
    REQUIRED_CSV_FILENAMES,
    cleanup_pack_directory,
    validate_pack_directory,
)
from cyber_risk.datasets.loaders import csv_row_counts_for_pack  # noqa: E402
from cyber_risk.graph.workflow import run_langgraph_analysis  # noqa: E402


def _default_top_k(cfg: dict) -> int:
    try:
        k = int(cfg.get("risk_engine", {}).get("top_k", 5))
    except (TypeError, ValueError):
        k = 5
    return max(1, min(10, k))


def _infra_only_ready(status: dict) -> bool:
    """Enough for uploads: KEV snapshot + vector index (no on-disk CSV pack)."""
    return bool(status.get("kev_cache")) and bool(status.get("vector_index"))


def _persist_upload_pack(csv_files: dict[str, Any], threat_md: Any | None) -> Path:
    td = Path(tempfile.mkdtemp(prefix="streamlit-pack-"))
    try:
        for name in REQUIRED_CSV_FILENAMES:
            uf = csv_files[name]
            if uf is None:
                raise ValueError(f"Missing file for {name}")
            (td / name).write_bytes(uf.getvalue())
        if threat_md is not None:
            (td / "threat_report.md").write_bytes(threat_md.getvalue())
        validate_pack_directory(td)
    except Exception:
        cleanup_pack_directory(td)
        raise
    return td


def main() -> None:
    settings = get_settings()
    title = f"{settings.organization_name} — Cyber Risk Assistant"
    st.set_page_config(page_title=title, layout="wide")
    st.title(title)

    yaml_cfg = settings.yaml_overlay()
    default_k = _default_top_k(yaml_cfg)
    status = readiness_status(settings)

    with st.sidebar:
        st.header("Analysis options")
        use_bundled = st.checkbox(
            "Use bundled `data/` directory (demo)",
            value=False,
            help="Loads CSVs + threat markdown from CYBER_RISK_DATA_DIR instead of uploads.",
        )
        if st.session_state.get("_bundled_mode") is not None and st.session_state.get("_bundled_mode") != use_bundled:
            st.session_state.pop("state", None)
            st.session_state.pop("last_top_k", None)
        st.session_state["_bundled_mode"] = use_bundled
        top_k = st.slider(
            "Number of risks to surface",
            min_value=1,
            max_value=10,
            value=default_k,
            help="How many ranked risks to include in this run.",
        )

    uploads_ok = use_bundled and status["ready"]
    infra_ok = _infra_only_ready(status)
    if use_bundled:
        if not uploads_ok:
            st.warning(
                "Bundled mode needs `data/` CSVs on disk, KEV cache, and a vector index. "
                "Run `python scripts/bootstrap.py` or set `CYBER_RISK_AUTO_BOOTSTRAP=true`.",
                icon="⚠️",
            )
            st.json(status)
    else:
        if not infra_ok:
            st.warning(
                "Upload mode still needs KEV + NIST vectors (Pinecone or local). "
                "Run bootstrap once or enable auto-bootstrap on the host.",
                icon="⚠️",
            )
            st.json(status)

    st.subheader("Data pack")
    if use_bundled:
        st.caption(f"Reading from `{settings.resolved_data_dir()}`.")
        csv_files = None
        threat_md = None
    else:
        st.caption(
            "Upload the five required CSVs (exact headers as in the assignment pack). "
            "Threat report markdown is optional but recommended."
        )
        csv_files = {}
        for name in REQUIRED_CSV_FILENAMES:
            csv_files[name] = st.file_uploader(
                name,
                type=["csv"],
                key=f"upl_{name}",
            )
        threat_md = st.file_uploader(
            "Threat report (.md, optional)",
            type=["md"],
            key="upl_threat",
        )

    run_disabled = (use_bundled and not uploads_ok) or ((not use_bundled) and not infra_ok)
    if st.button("Run analysis", type="primary", disabled=run_disabled):
        pack_dir: Path | None = None
        if use_bundled:
            st.session_state["_upload_csv_rows"] = None
        if not use_bundled:
            try:
                missing = [n for n in REQUIRED_CSV_FILENAMES if csv_files is None or csv_files[n] is None]
                if missing:
                    st.error(f"Upload every required CSV: {', '.join(missing)}")
                    return
                prev = st.session_state.get("pack_tmp")
                if prev:
                    cleanup_pack_directory(Path(prev))
                pack_dir = _persist_upload_pack(csv_files, threat_md)
                st.session_state["pack_tmp"] = str(pack_dir)
                try:
                    rc = csv_row_counts_for_pack(pack_dir)
                    st.session_state["_upload_csv_rows"] = rc
                except Exception:
                    st.session_state["_upload_csv_rows"] = None
            except (OSError, ValueError) as e:
                st.error(str(e))
                return

        with st.spinner("Running analysis pipeline…"):
            try:
                state = run_langgraph_analysis(
                    settings,
                    top_k=top_k,
                    data_pack_dir=pack_dir,
                )
            except FileNotFoundError as e:
                st.error(f"Missing prerequisites: {e}")
                return
            st.session_state["state"] = state
            st.session_state["last_top_k"] = top_k

    state = st.session_state.get("state")
    if not state:
        st.info(
            "Choose **bundled** or **upload** mode, then click **Run analysis**."
        )
        return

    n_rec = len(state.get("records") or [])
    last_k = st.session_state.get("last_top_k", top_k)
    st.caption(
        f"Last run: **top_k = {last_k}** → **{n_rec}** risk(s) in this briefing. "
        "(Count is capped by open vulnerabilities that successfully join to an asset in `assets.csv`; "
        "the JSON expander lists the same records as the markdown.)"
    )
    ur = st.session_state.get("_upload_csv_rows")
    if isinstance(ur, dict) and ur:
        st.caption(
            "**Upload parse (data rows read per CSV):** "
            + " · ".join(f"`{fn}`: {n}" for fn, n in sorted(ur.items()))
            + ". If `vulnerabilities.csv` is far smaller than on disk, the file may have been saved with a BOM/Excel "
            "header issue—loader now strips UTF‑8 BOM; re-export UTF‑8 CSV if problems persist."
        )

    st.subheader("Risk briefing")
    st.markdown(state.get("markdown", ""))

    with st.expander("Structured JSON (API parity)"):
        st.json({"risks": [r.model_dump(mode="json") for r in state.get("records", [])]})


if __name__ == "__main__":
    main()
