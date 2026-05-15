from __future__ import annotations

import re

from tawasol_risk.datasets.schemas import AssetRow, VulnRow
from tawasol_risk.rag.vector_store import SearchHit, VectorIndex


def suggest_control_prefixes(vuln: VulnRow, asset: AssetRow, defaults: list[str]) -> list[str]:
    blob = " ".join(
        [
            vuln.vulnerability_name or "",
            vuln.affected_component or "",
            asset.vendor_product or "",
            asset.asset_type or "",
        ]
    ).lower()
    picks: list[str] = list(defaults)
    if any(k in blob for k in ("end of life", "eol", "unsupported", "windows server 2012")):
        picks = ["SA-22", *defaults]
    if any(k in blob for k in ("monitor", "scan", "vulnerability", "assess")):
        picks = ["RA-5", *defaults]
    if any(k in blob for k in ("incident", "handling", "response")):
        picks = ["IR-4", *defaults]
    if any(k in blob for k in ("account", "credential", "mfa", "authentication", "password")):
        picks = ["AC-2", *defaults]
    if any(k in blob for k in ("boundary", "firewall", "segment", "vpn", "network")):
        picks = ["SC-7", *defaults]
    # De-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for p in picks:
        stem = p.strip().upper()
        if stem not in seen:
            seen.add(stem)
            out.append(stem)
    return out[:8]


def retrieve_nist_control(
    vuln: VulnRow,
    asset: AssetRow,
    index: VectorIndex,
    default_prefixes: list[str],
    top_k: int = 1,
) -> SearchHit | None:
    prefixes = suggest_control_prefixes(vuln, asset, default_prefixes)
    query = (
        f"NIST SP 800-53 security control guidance for flaw remediation and risk response.\n"
        f"Asset type: {asset.asset_type}. Exposure: {asset.internet_exposed}. "
        f"Vulnerability: {vuln.vulnerability_name}. CVE: {vuln.cve}. Component: {vuln.affected_component}."
    )
    hits = index.search(query, top_k=top_k, allowed_prefixes=prefixes)
    if not hits:
        hits = index.search(query, top_k=top_k, allowed_prefixes=None)
    return hits[0] if hits else None


def excerpt(text: str, limit: int = 1200) -> str:
    t = re.sub(r"\s+", " ", text).strip()
    return t if len(t) <= limit else t[: limit - 3] + "..."
