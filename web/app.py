from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Any

import httpx
import streamlit as st

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cyber_risk.bootstrap import readiness_status  # noqa: E402
from cyber_risk.config.settings import get_settings  # noqa: E402
from cyber_risk.datasets.schemas import RiskRecord  # noqa: E402
from cyber_risk.datasets.uploads import (  # noqa: E402
    REQUIRED_CSV_FILENAMES,
    cleanup_pack_directory,
    find_threat_report_in_dir,
    validate_pack_directory,
)
from cyber_risk.datasets.loaders import csv_row_counts_for_pack  # noqa: E402
from cyber_risk.graph.workflow import run_langgraph_analysis  # noqa: E402

# Deployed FastAPI service (Render). Analysis for Streamlit Cloud uses this URL via HTTP.
BACKEND_API_BASE_URL = "https://hive-pro-assignment.onrender.com".rstrip("/")

# Multipart field names must match api/main.py UploadFile parameters.
_CSV_FORM_FIELDS: tuple[tuple[str, str], ...] = (
    ("assets.csv", "assets_csv"),
    ("vulnerabilities.csv", "vulnerabilities_csv"),
    ("threat_intelligence.csv", "threat_intelligence_csv"),
    ("business_services.csv", "business_services_csv"),
    ("remediation_guidance.csv", "remediation_guidance_csv"),
)


def backend_health_url() -> str:
    return f"{BACKEND_API_BASE_URL}/health"


def backend_openapi_url() -> str:
    return f"{BACKEND_API_BASE_URL}/docs"


def backend_ready_url() -> str:
    return f"{BACKEND_API_BASE_URL}/ready"


def _default_top_k(cfg: dict) -> int:
    try:
        k = int(cfg.get("risk_engine", {}).get("top_k", 5))
    except (TypeError, ValueError):
        k = 5
    return max(1, min(10, k))


def _infra_only_ready(status: dict) -> bool:
    """Enough for local uploads: KEV snapshot + vector index."""
    return bool(status.get("kev_cache")) and bool(status.get("vector_index"))


def _bundled_csvs_present(settings: Any) -> bool:
    root = settings.resolved_data_dir()
    return all((root / name).is_file() for name in REQUIRED_CSV_FILENAMES)


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


def _analysis_via_remote_api(pack_root: Path, top_k: int) -> dict[str, Any]:
    """POST pack to Render; returns AnalysisState-shaped dict."""
    url = f"{BACKEND_API_BASE_URL}/v1/risk-report/upload"
    files: dict[str, tuple[str, bytes, str]] = {}
    for fname, field in _CSV_FORM_FIELDS:
        data = (pack_root / fname).read_bytes()
        files[field] = (fname, data, "text/csv")
    threat_p = find_threat_report_in_dir(pack_root)
    if threat_p is not None and threat_p.is_file():
        files["threat_report_md"] = (threat_p.name, threat_p.read_bytes(), "text/markdown")

    try:
        with httpx.Client(timeout=httpx.Timeout(300.0, connect=30.0)) as client:
            r = client.post(url, params={"top_k": top_k}, files=files)
    except httpx.RequestError as e:
        raise RuntimeError(f"Could not reach API at {BACKEND_API_BASE_URL}: {e}") from e

    if r.status_code == 503:
        detail = r.text
        try:
            detail = str(r.json())
        except Exception:
            pass
        raise RuntimeError(
            f"API returned 503 (not ready). Ensure Render has KEV + vectors / auto-bootstrap. Detail: {detail}"
        )
    if r.status_code != 200:
        raise RuntimeError(f"API error {r.status_code}: {r.text[:2000]}")

    body = r.json()
    risks_raw = body.get("risks") or []
    records = [RiskRecord.model_validate(x) for x in risks_raw]
    return {"markdown": str(body.get("markdown") or ""), "records": records}


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
        st.caption("**Backend API** (`BACKEND_API_BASE_URL`)")
        st.code(BACKEND_API_BASE_URL, language="text")
        st.markdown(
            f"[Health]({backend_health_url()}) · [Ready]({backend_ready_url()}) · [`/docs`]({backend_openapi_url()})"
        )
        use_remote_backend = st.checkbox(
            "Run analysis on deployed API (Render)",
            value=True,
            help="Recommended for Streamlit Cloud: no local KEV/Pinecone needed here. "
            "Uncheck to run the graph inside this machine (needs bootstrap locally).",
        )
        use_bundled = st.checkbox(
            "Use bundled `data/` directory (demo)",
            value=False,
            help="Loads CSVs + threat markdown from CYBER_RISK_DATA_DIR instead of uploads.",
        )
        if st.session_state.get("_bundled_mode") is not None and st.session_state.get("_bundled_mode") != use_bundled:
            st.session_state.pop("state", None)
            st.session_state.pop("last_top_k", None)
        st.session_state["_bundled_mode"] = use_bundled
        if st.session_state.get("_remote_mode") is not None and st.session_state.get("_remote_mode") != use_remote_backend:
            st.session_state.pop("state", None)
            st.session_state.pop("last_top_k", None)
        st.session_state["_remote_mode"] = use_remote_backend

        top_k = st.slider(
            "Number of risks to surface",
            min_value=1,
            max_value=10,
            value=default_k,
            help="How many ranked risks to include in this run.",
        )

    uploads_ok = use_bundled and status["ready"]
    infra_ok = _infra_only_ready(status)

    if use_remote_backend:
        st.info(
            "**Analysis runs on Render** — this Streamlit host only uploads your CSV pack. "
            "You do **not** need KEV or vector files here; the API must be ready (see sidebar links).",
            icon="ℹ️",
        )
    elif use_bundled:
        if not uploads_ok:
            st.warning(
                "Bundled **local** mode needs `data/` CSVs on disk, KEV cache, and a vector index. "
                "Run `python scripts/bootstrap.py` or enable **Run analysis on deployed API**.",
                icon="⚠️",
            )
            st.json(status)
    else:
        if not infra_ok:
            st.warning(
                "Upload **local** mode needs KEV + NIST vectors on this machine. "
                "Enable **Run analysis on deployed API** for Streamlit Cloud, or run bootstrap locally.",
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

    if use_remote_backend:
        if use_bundled:
            run_disabled = not _bundled_csvs_present(settings)
        else:
            missing_upl = [
                n for n in REQUIRED_CSV_FILENAMES if csv_files is None or csv_files.get(n) is None
            ]
            run_disabled = len(missing_upl) > 0
    else:
        run_disabled = (use_bundled and not uploads_ok) or ((not use_bundled) and not infra_ok)

    if st.button("Run analysis", type="primary", disabled=run_disabled):
        pack_dir: Path | None = None
        try:
            if use_bundled:
                st.session_state["_upload_csv_rows"] = None
                root = settings.resolved_data_dir()
                validate_pack_directory(root)
                pack_dir = root
                if use_remote_backend:
                    try:
                        st.session_state["_upload_csv_rows"] = csv_row_counts_for_pack(root)
                    except Exception:
                        st.session_state["_upload_csv_rows"] = None
            else:
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

            assert pack_dir is not None

            with st.spinner(
                "Calling deployed API…" if use_remote_backend else "Running analysis pipeline…"
            ):
                if use_remote_backend:
                    try:
                        state = _analysis_via_remote_api(pack_dir, top_k)
                    except RuntimeError as e:
                        st.error(str(e))
                        return
                else:
                    try:
                        state = run_langgraph_analysis(
                            settings,
                            top_k=top_k,
                            data_pack_dir=None if use_bundled else pack_dir,
                        )
                    except FileNotFoundError as e:
                        st.error(f"Missing prerequisites: {e}")
                        return
                st.session_state["state"] = state
                st.session_state["last_top_k"] = top_k
        except FileNotFoundError as e:
            st.error(str(e))
            return

    state = st.session_state.get("state")
    if not state:
        hint = ""
        if use_remote_backend and run_disabled:
            if use_bundled:
                hint = " Bundled CSVs are missing under `data/` in this deployment."
            else:
                hint = " Upload all five CSV files above."
        st.info(
            "Choose options in the sidebar, then click **Run analysis**." + hint
        )
        return

    n_rec = len(state.get("records") or [])
    last_k = st.session_state.get("last_top_k", top_k)
    mode_lbl = "API (Render)" if use_remote_backend else "local pipeline"
    st.caption(
        f"Last run ({mode_lbl}): **top_k = {last_k}** → **{n_rec}** risk(s). "
        "(Capped by open vulnerabilities that join to an asset in `assets.csv`.)"
    )
    ur = st.session_state.get("_upload_csv_rows")
    if isinstance(ur, dict) and ur:
        st.caption(
            "**Pack row counts:** "
            + " · ".join(f"`{fn}`: {n}" for fn, n in sorted(ur.items()))
        )

    st.subheader("Risk briefing")
    st.markdown(state.get("markdown", ""))

    with st.expander("Structured JSON (API parity)"):
        st.json({"risks": [r.model_dump(mode="json") for r in state.get("records", [])]})


if __name__ == "__main__":
    main()
