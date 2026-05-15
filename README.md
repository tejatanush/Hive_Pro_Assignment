# Cyber Risk Assistant

**Live UI (Streamlit Cloud):** [hiveproassignment](https://hiveproassignment-79rctevrgjctndhmwdx7kk.streamlit.app/)

**Live API (Render):** [hive-pro-assignment](https://hive-pro-assignment.onrender.com/) — OpenAPI at `/docs`, `/health`, `/ready`, `POST /v1/risk-report`, `POST /v1/risk-report/upload`.

Production-oriented API and UI for **prioritised cyber risk analysis**: ingest organization-specific CSV packs (from disk **or uploads**), cross-check **CISA KEV**, correlate **threat intelligence**, rank top risks (beyond CVSS-only), and retrieve **NIST SP 800-53 Rev. 5** remediation text via embeddings stored in a **vector database** (local `*.npz` in dev or **mandatory Pinecone** when `ALLOW_LOCAL_VECTOR_FALLBACK=false`).

Input data paths are **not hardcoded** in the app logic: uploads go to a temp folder per run; the NIST catalog is downloaded from `risk_engine.nist_catalog_url` in `configs/default.yaml` into `nist_sp800_53_rev5_catalog.json`, then chunked and embedded—not pasted as static strings.

For **hosted UI/API without CSVs baked into the image**, set **`CYBER_RISK_IGNORE_DATA_PACK_READY=true`** so `/ready` only checks **KEV + vector backend** while clients supply files via multipart or Streamlit uploads.

## Architecture

| Layer | Technology | Role |
|-------|------------|------|
| Structured data | CSV joins + scoring | Assets, vulns, TI, business services (filesystem or uploads) |
| Reference feeds | CISA KEV JSON | Active exploitation / ransomware flags |
| RAG | NIST OSCAL + embeddings | Authoritative control text |
| Vector store | **Local** (dev) or **Pinecone** (prod) | NIST semantic search |
| LLM (optional) | Groq `llama-3.1-8b-instant` | Polish briefing wording only |
| API | FastAPI | `/v1/risk-report`, `/v1/risk-report/upload`, `/ready` |
| UI | Streamlit (`web/`) | Human-readable briefing |

## Repository layout

```text
api/                 # FastAPI application
web/                 # Streamlit UI
configs/             # YAML defaults
data/                # Default disk pack (`CYBER_RISK_DATA_DIR`) when not using uploads
data/processed/      # Generated KEV + NIST + vector index (gitignored)
scripts/             # bootstrap, download_kev, ingest_nist_vectors
src/cyber_risk/      # Core library
```

---

## Part A — Local setup (do this first)

### 1. Clone, venv, install

```powershell
cd c:\Users\tejat\Desktop\Hiver
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
pip install -e .
```

Use a **dedicated venv** (avoid global conda) for reliable `sentence-transformers`.

### 2. Configure environment

```powershell
copy .env.example .env
```

Edit `.env`:

```text
ORGANIZATION_NAME=Your Company Name
GROQ_API_KEY=gsk_...
LLM_PROVIDER=groq
GROQ_MODEL=llama-3.1-8b-instant
```

For **local only**, leave `PINECONE_API_KEY` empty.

### 3. Place your data pack (or use uploads)

For **disk** workflows, required files in `data/`:

- `assets.csv`
- `vulnerabilities.csv`
- `threat_intelligence.csv`
- `business_services.csv`
- `remediation_guidance.csv`
- `synthetic_threat_report.md` (or any `*threat_report*.md` — optional but recommended)

**Alternatively:** Streamlit defaults to **upload** mode (five CSVs + optional `.md`). The API exposes **`POST /v1/risk-report/upload`** with the same files as multipart fields—no copying into `data/` required.

### 4. One-time bootstrap (required)

```powershell
python scripts\bootstrap.py
```

This downloads CISA KEV + NIST catalog and builds `data/processed/nist_local_vectors.npz`.

Verify readiness (recommended after **`pip install -e .`**):

```powershell
python -c "from cyber_risk.bootstrap import readiness_status; print(readiness_status())"
```

If you see `ModuleNotFoundError: No module named 'cyber_risk'`, run:

```powershell
$env:PYTHONPATH="src"
python -c "from cyber_risk.bootstrap import readiness_status; print(readiness_status())"
```

Expect `"ready": true`.

### 5. Run locally

**API**

```powershell
uvicorn api.main:app --reload --port 8000
```

**Checks**

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
curl -X POST http://127.0.0.1:8000/v1/risk-report
```

**Multipart upload (parity with deployed Render)**

Form field names match OpenAPI (`assets_csv`, `vulnerabilities_csv`, …). Optional `threat_report_md`:

```powershell
curl -X POST "http://127.0.0.1:8000/v1/risk-report/upload?top_k=5" `
  -F "assets_csv=@data/assets.csv" `
  -F "vulnerabilities_csv=@data/vulnerabilities.csv" `
  -F "threat_intelligence_csv=@data/threat_intelligence.csv" `
  -F "business_services_csv=@data/business_services.csv" `
  -F "remediation_guidance_csv=@data/remediation_guidance.csv" `
  -F "threat_report_md=@data/synthetic_threat_report.md"
```

Uses **KEV + vector backend** only; pair with **`CYBER_RISK_IGNORE_DATA_PACK_READY=true`** when the server has no bundled `data/*.csv`.

**UI** (second terminal — upload mode is default; enable “bundled” only if you rely on `data/`)

```powershell
streamlit run web\app.py
```

The repo includes `.streamlit/config.toml` with **file watching disabled**, so Streamlit does not traverse `transformers` and spam the console with optional `torchvision` / vision-model import errors on Windows.

**API — limit number of risks**

```powershell
curl -X POST "http://127.0.0.1:8000/v1/risk-report?top_k=3"
curl "http://127.0.0.1:8000/v1/risk-report.md?top_k=5"
```

(Query `top_k` is optional; omit it to use `configs/default.yaml` → `risk_engine.top_k`.)

---

## Part B — Production / cloud

### Deployed stack (this submission)

| Surface | URL | Notes |
|---------|-----|--------|
| UI | [Streamlit Cloud](https://hiveproassignment-79rctevrgjctndhmwdx7kk.streamlit.app/) | Upload CSVs + optional threat `.md`; needs KEV + vectors on the host or remote API wiring. |
| API | [Render](https://hive-pro-assignment.onrender.com/) | Set `PINECONE_*`, `ALLOW_LOCAL_VECTOR_FALLBACK=false` (recommended), `IGNORE_DATA_PACK_READY=true` if no baked-in `data/`, `CYBER_RISK_AUTO_BOOTSTRAP=true` for first boot. |

### Railway (alternative)

The repo still includes `Dockerfile` / `railway.toml` if you prefer Railway over Render.

### Docker (local prod-like)

```powershell
docker compose up --build
```

API: `http://localhost:8000` · UI: `http://localhost:8501`

---

## Do you need a vector database?

| Environment | Vector store | Action |
|-------------|--------------|--------|
| **Local dev** | Files in `data/processed/` | `python scripts/bootstrap.py` |
| **Cloud prod (Render, etc.)** | **Pinecone** (recommended) | Set `PINECONE_*`, `ALLOW_LOCAL_VECTOR_FALLBACK=false`, `bootstrap.py --pinecone` or `AUTO_BOOTSTRAP` |
| **Cloud prod (simple)** | Local index + `AUTO_BOOTSTRAP` | Slower; rebuilds on each fresh volume |

Ranking does **not** require Pinecone. Only **NIST RAG** needs a vector index (local or Pinecone).

---

## Environment reference

| Variable | Purpose |
|----------|---------|
| `ORGANIZATION_NAME` | Report title / UI branding |
| `CYBER_RISK_DATA_DIR` | Input CSV directory (default `data`) |
| `CYBER_RISK_AUTO_BOOTSTRAP` | `true` = download KEV/NIST on API start if missing |
| `ALLOW_LOCAL_VECTOR_FALLBACK` | `false` = NIST RAG **must** use Pinecone (no local `*.npz`) |
| `IGNORE_DATA_PACK_READY` | `true` = `/ready` skips on-disk CSV check (upload-only hosts) |
| `GROQ_API_KEY` / `LLM_PROVIDER=groq` | Optional briefing polish |
| `PINECONE_API_KEY` / `PINECONE_INDEX_NAME` | Production vector store for NIST chunks |

---

## Assignment submission checklist (DELIVERABLES §4)

| Requirement | How this repo meets it |
|-------------|------------------------|
| **Public URL** | **API:** [hive-pro-assignment.onrender.com](https://hive-pro-assignment.onrender.com/) (`/docs`, `/ready`, `POST /v1/risk-report`, `/v1/risk-report/upload`). **UI:** [Streamlit Cloud demo](https://hiveproassignment-79rctevrgjctndhmwdx7kk.streamlit.app/). |
| **Ingest data pack** | Five CSVs + optional markdown: read from **`CYBER_RISK_DATA_DIR`**, or supplied via Streamlit uploads (temp dir passed to the graph) or **`POST /v1/risk-report/upload`**. Bootstrap syncs **CISA KEV** + **NIST OSCAL** into the vector store (`scripts/bootstrap.py` or `CYBER_RISK_AUTO_BOOTSTRAP`). |
| **NIST SP 800-53 not hardcoded** | Controls are parsed from official Rev. 5 OSCAL JSON, embedded, retrieved per risk (`cyber_risk.rag.*`), and shown as `nist_control_id` + `nist_excerpt`. |
| **Top-5 + evidence + remediation** | Defaults to **five** risks via `risk_engine.top_k: 5` in `configs/default.yaml`. Omit `top_k` on `POST /v1/risk-report` or send `top_k=5`. Each entry includes scorer rationale, TI, KEV, CSV hint, and NIST excerpt. |
| **GitHub + README** | Repo + §Part A for local setup. |

---

## Supporting question 1 — The data split

**What we embed and why:** We embed text chunks from the **NIST SP 800-53 Rev. 5 OSCAL catalog** (downloaded via `risk_engine.nist_catalog_url` in YAML, cached as JSON, never inlined as prose in code). Vector search selects control narratives that fit heterogeneous CVE/asset context without hand-writing mapping tables.

**What we query as structured records and why:** **Assets, vulnerabilities, threat intelligence, business services, remediation hints, and CISA KEV** stay as keyed rows (CSV joins + CVE lookups). Prioritisation depends on crisp categorical signals—internet exposure, KEV membership, TI matches—that must remain auditable and stable, not similarity‑weighted guesses.

---

## Supporting question 2 — Three ways it fails (and mitigations)

1. **If a CVE appears in `vulnerabilities.csv` but that CVE is absent from our downloaded KEV snapshot** (delayed feed, typo, stale cache), the model will treat it as *not currently KEV-listed* even if defenders know it as actively exploited—and it will omit the ransomware-campaign uplift. **Mitigations already or partially in place:** date-versioned `kev_catalog.json`, explicit `"on_kev": false/true` surfaced in briefing text, repeatable `scripts/bootstrap.py` refresh. **Stretch:** TTL alerts when KEV file age exceeds N days.

2. **Semantic NIST retrieval can return a plausible-but-wrong control** when wording overlaps AC/SI/IR families similarly. Users may see remediation prose that misses the strongest control—without knowing it unless they sanity-check IDs. **Mitigations:** constrain candidate prefixes by heuristic family gates, persist `nist_control_id` + verbatim excerpt alongside score, `/ready` only guarantees index presence—not retrieval correctness.

3. **Threat intel only joins when `threat_intelligence.matched_cve_or_control` exactly equals vulnerability `cve`**. Campaign noise with different IDs, synonyms, or non-CVE tags still leaves “no TI match” messaging which can understate topical threat chatter. **Mitigations:** explicit narrative when zero TI rows matched; roadmap for normalization or secondary/vendor keys.

**(Optional)** With **`LLM_PROVIDER=groq`**, polish step could subtly rephrase headings—use `none` when evaluators grade textual parity.

---

## Supporting question 3 — One improvement

If I had one more engineering day on this branch, **I’d invest in a deterministic regression harness** (golden fixtures asserting rank order for synthetic pairs, invariant checks JSON→markdown numerics parity, labelled NIST-recall probes). Ranking heuristics and embedding stacks are both easy to regress silently when dependencies drift; freezing expectations in CI buys far more evaluator confidence than any extra UI polish at this maturity level.
