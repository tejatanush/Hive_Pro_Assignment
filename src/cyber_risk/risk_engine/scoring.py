from __future__ import annotations

import math

from cyber_risk.datasets.schemas import (
    AssetRow,
    BusinessServiceRow,
    RemediationHintRow,
    ThreatIntelRow,
    VulnRow,
)
from cyber_risk.risk_engine.kev_service import KevEntry


def _crit_mult(criticality: str) -> float:
    c = (criticality or "").strip().lower()
    return {"critical": 1.35, "high": 1.2, "medium": 1.08, "low": 1.0}.get(c, 1.05)


def _revenue_mult(impact: str | None) -> float:
    if not impact:
        return 1.05
    m = impact.strip().lower()
    return {"critical": 1.25, "high": 1.15, "medium": 1.08, "low": 1.02}.get(m, 1.05)


def _risk_appetite_mult(appetite: str | None) -> float:
    """Lower stated appetite => higher multiplier (less room for failure)."""
    if not appetite:
        return 1.05
    a = appetite.strip().lower()
    return {
        "very low": 1.22,
        "low": 1.12,
        "medium": 1.05,
        "high": 0.98,
    }.get(a, 1.05)


def _intel_boost(intel: list[ThreatIntelRow]) -> tuple[float, dict[str, float]]:
    """Aggregate TI signals for a vulnerability (matched on CVE / synthetic IDs)."""
    if not intel:
        return 1.0, {"intel_records": 0.0}
    best = 1.0
    for row in intel:
        conf = (row.confidence or "").strip().lower()
        mat = (row.exploit_maturity or "").strip().lower()
        rw = (row.ransomware_association or "").strip().lower() in {"yes", "y", "true"}
        conf_m = {"high": 1.12, "medium": 1.06, "low": 1.02}.get(conf, 1.04)
        mat_m = {
            "weaponized": 1.18,
            "active exploitation": 1.16,
            "proof of concept": 1.07,
            "commodity exploit": 1.1,
        }.get(mat, 1.04)
        rw_m = 1.12 if rw else 1.0
        combined = conf_m * mat_m * rw_m
        best = max(best, combined)
    return best, {"intel_records": float(len(intel)), "intel_best_factor": best}


def composite_risk_score(
    vuln: VulnRow,
    asset: AssetRow,
    service: BusinessServiceRow | None,
    intel: list[ThreatIntelRow],
    kev: KevEntry | None,
) -> tuple[float, dict[str, float]]:
    """
    Risk score: CVSS is a base scale factor, but exposure, exploitability, TI, and
    business/control context materially change prioritisation (per assignment).
    """
    cvss = float(vuln.cvss or 0.0)
    base = max(cvss, 0.1)

    exposure = (vuln.asset_exposure or asset.internet_exposed or "").strip().lower()
    if exposure in {"internet", "yes"}:
        exposure_m = 1.45
    else:
        exposure_m = 1.0

    exploit_csv = (vuln.exploit_available or "").strip().lower() in {"yes", "y", "true"}
    exploit_m = 1.25 if exploit_csv else 1.0

    kev_m = 1.0
    kev_rw_m = 1.0
    if kev is not None:
        kev_m = 1.35
        kr = (kev.known_ransomware_campaign_use or "").strip().lower()
        if kr in {"known", "yes", "true", "y"}:
            kev_rw_m = 1.28

    intel_m, intel_parts = _intel_boost(intel)

    crit_m = _crit_mult(asset.criticality)
    svc_m = 1.0
    if service is not None:
        svc_m = _revenue_mult(service.revenue_impact) * _risk_appetite_mult(service.risk_appetite)

    edr = (asset.edr_installed or "").strip().lower()
    customer = (service.customer_facing if service else "No").strip().lower() == "yes"
    control_gap_m = 1.0
    if edr in {"no", "n", "false"} and exposure in {"internet", "yes"}:
        control_gap_m *= 1.12
    if customer and exposure in {"internet", "yes"}:
        control_gap_m *= 1.06

    days = float(vuln.days_open or 0)
    staleness_m = 1.0 + min(0.12, math.log1p(max(days, 0.0)) / 40.0)

    score = (
        base
        * exposure_m
        * exploit_m
        * kev_m
        * kev_rw_m
        * intel_m
        * crit_m
        * svc_m
        * control_gap_m
        * staleness_m
    )

    breakdown: dict[str, float] = {
        "cvss": cvss,
        "exposure_m": exposure_m,
        "exploit_m": exploit_m,
        "kev_m": kev_m,
        "kev_ransomware_m": kev_rw_m,
        "intel_m": intel_m,
        "criticality_m": crit_m,
        "service_m": svc_m,
        "control_gap_m": control_gap_m,
        "staleness_m": staleness_m,
        **intel_parts,
    }
    return float(score), breakdown


def match_threat_intel(vuln: VulnRow, intel_rows: list[ThreatIntelRow]) -> list[ThreatIntelRow]:
    cve = (vuln.cve or "").strip().upper()
    out: list[ThreatIntelRow] = []
    for row in intel_rows:
        token = (row.matched_cve_or_control or "").strip().upper()
        if not token:
            continue
        if token == cve:
            out.append(row)
    return out


def pick_remediation_hint(vuln: VulnRow, hints: list[RemediationHintRow]) -> RemediationHintRow | None:
    if not hints:
        return None
    """Fuzzy match remediation_guidance.csv by vulnerability name keywords (hint only)."""
    name = (vuln.vulnerability_name or "").lower()
    best = None
    best_score = -1.0
    for h in hints:
        ft = (h.finding_type or "").lower()
        score = 0.0
        for tok in name.replace(",", " ").split():
            if len(tok) < 4:
                continue
            if tok in ft:
                score += 1.0
        if score > best_score:
            best_score = score
            best = h
    return best
