from __future__ import annotations

import re

from cyber_risk.datasets.schemas import RiskRecord


def sanitize_threat_report_markdown(raw: str) -> str:
    """
    Strip hiring-assessment / synthetic disclaimers from ingested MDR text for production-style output.
    """
    if not raw.strip():
        return raw
    cleaned = raw.strip()
    cleaned = re.sub(
        r"(?i).*SYNTHETIC DATA FOR HIRING ASSESSMENT ONLY.*\n?",
        "",
        cleaned,
    )
    lines_out: list[str] = []
    for line in cleaned.splitlines():
        low = line.lower()
        if "synthetic data for hiring assessment" in low:
            continue
        if "generated for hiring assessment" in low:
            continue
        if "fictional" in low and "do not use for operational security" in low:
            continue
        if "do not use for operational security decisions" in low and "synthetic" in low:
            continue
        lines_out.append(line)
    return "\n".join(lines_out).strip()


def render_markdown_report(
    records: list[RiskRecord],
    threat_report_md: str,
    organization_name: str = "Organization",
) -> str:
    threat_block = sanitize_threat_report_markdown(threat_report_md)
    lines: list[str] = []
    lines.append(f"# {organization_name} — Prioritised Cyber Risk Briefing")
    lines.append("")
    lines.append("## MDR advisory context (ingested)")
    lines.append("")
    if threat_block:
        lines.append(threat_block)
    else:
        lines.append("_No threat intelligence report found in the data pack._")
    lines.append("")
    n = len(records)
    lines.append(f"## Top {n} risk{'s' if n != 1 else ''} (ranked)")
    lines.append("")
    for r in records:
        lines.append(f"### {r.rank}. {r.asset.asset_name} — {r.vulnerability.vulnerability_name}")
        lines.append("")
        lines.append(f"- **CVE / finding:** {r.vulnerability.cve}")
        lines.append(f"- **Severity / CVSS:** {r.vulnerability.severity} / {r.vulnerability.cvss}")
        lines.append(
            f"- **Exposure:** asset internet exposed = {r.asset.internet_exposed}; "
            f"recorded exposure = {r.vulnerability.asset_exposure or 'n/a'}"
        )
        lines.append(
            f"- **Business service:** {r.business_service.business_service if r.business_service else 'unmapped'}"
        )
        lines.append(f"- **Composite score:** {r.composite_score:.2f}")
        lines.append("")
        lines.append("**Why this ranks here**")
        lines.append("")
        lines.append(r.rationale_sentence)
        lines.append("")
        if r.threat_intel:
            lines.append("**Matched threat intelligence**")
            lines.append("")
            for ti in r.threat_intel[:3]:
                lines.append(
                    f"- **{ti.intel_id}** — {ti.threat_actor} / {ti.campaign_name} "
                    f"({ti.confidence}, exploit maturity: {ti.exploit_maturity}, ransomware: {ti.ransomware_association})"
                )
                lines.append(f"  - {ti.summary}")
            lines.append("")
        lines.append("**CISA KEV context**")
        lines.append("")
        if r.kev.get("on_kev"):
            lines.append(
                f"- On KEV: yes — ransomware campaign field: {r.kev.get('known_ransomware_campaign_use')}; "
                f"date added: {r.kev.get('date_added')}"
            )
            lines.append(f"- Required action (catalog): {r.kev.get('required_action')}")
        else:
            lines.append("- On KEV: **no** (this does not mean safe — it means not present in the downloaded KEV snapshot).")
        lines.append("")
        lines.append("**Operational remediation hint (CSV starter only)**")
        lines.append("")
        if r.remediation_hint:
            lines.append(f"- _Hint type:_ {r.remediation_hint.finding_type}")
            lines.append(f"- _Hint:_ {r.remediation_hint.recommended_action}")
        else:
            lines.append("- _No close match in remediation_guidance.csv._")
        lines.append("")
        lines.append("**Authoritative remediation guidance (NIST SP 800-53 Rev. 5, retrieved)**")
        lines.append("")
        if r.nist_control_id and r.nist_excerpt:
            lines.append(f"- **Control:** {r.nist_control_id} — {r.nist_control_title or ''}".strip())
            lines.append("")
            lines.append("```")
            lines.append(r.nist_excerpt.strip())
            lines.append("```")
        else:
            lines.append(
                "_NIST control text not available yet. Run `python scripts/bootstrap.py` "
                "(or ingest) after configuring your vector index._"
            )
        lines.append("")
        lines.append("**Score factor breakdown (transparent weights)**")
        lines.append("")
        items = [f"{k}={v:.3f}" for k, v in sorted(r.score_breakdown.items(), key=lambda kv: -abs(kv[1]))][:12]
        lines.append("- " + ", ".join(items))
        lines.append("")
        lines.append("---")
        lines.append("")
    lines.append("## Analyst notes")
    lines.append("")
    lines.append(
        "- CVSS alone does not drive the rank ordering; internet exposure, exploit signals, KEV ransomware flags, "
        "threat-intel matches, business criticality, and compensating-control gaps are multiplicative factors."
    )
    lines.append("")
    return "\n".join(lines).strip() + "\n"
