from __future__ import annotations

from collections import defaultdict

from tawasol_risk.config.settings import Settings, get_settings
from tawasol_risk.datasets.loaders import DataPack, load_data_pack
from tawasol_risk.datasets.schemas import (
    AssetRow,
    BusinessServiceRow,
    RemediationHintRow,
    RiskRecord,
    ThreatIntelRow,
    VulnRow,
)
from tawasol_risk.risk_engine.kev_service import KevCatalog, kev_to_public_dict, load_kev_catalog
from tawasol_risk.risk_engine.scoring import composite_risk_score, match_threat_intel, pick_remediation_hint


def _asset_index(assets: list[AssetRow]) -> dict[str, AssetRow]:
    return {a.asset_id: a for a in assets}


def _service_index(services: list[BusinessServiceRow]) -> dict[str, BusinessServiceRow]:
    return {s.business_service: s for s in services}


def _rationale_sentence(
    rank: int,
    vuln: VulnRow,
    asset: AssetRow,
    service: BusinessServiceRow | None,
    intel: list[ThreatIntelRow],
    kev_public: dict,
) -> str:
    exposure = "internet-exposed" if (asset.internet_exposed or "").lower() == "yes" else "internal"
    svc = service.business_service if service else "an unmapped business service"
    ti = "active matching threat intelligence" if intel else "no direct CVE-matched threat intel row"
    kev_txt = (
        "listed on the CISA KEV catalog with ransomware campaign history"
        if kev_public.get("on_kev") and kev_public.get("ransomware_flag")
        else (
            "listed on the CISA KEV catalog"
            if kev_public.get("on_kev")
            else "not currently listed on the CISA KEV catalog"
        )
    )
    edr = "EDR is absent" if (asset.edr_installed or "").lower() == "no" else "EDR is present"
    exploit = (
        "exploit code or exploitation is reported as available"
        if (vuln.exploit_available or "").lower() == "yes"
        else "no reported exploit availability in the inventory"
    )
    return (
        f"Rank {rank} prioritises {asset.asset_name} ({asset.asset_type}) because it is {exposure}, "
        f"supports the '{svc}' service, carries {asset.criticality} criticality, and has "
        f"{vuln.vulnerability_name} ({vuln.cve}) with CVSS {vuln.cvss:.1f}. The record shows {exploit}, "
        f"{ti}, and the CVE is {kev_txt}. {edr}."
    )


def build_ranked_risks(
    pack: DataPack,
    kev: KevCatalog,
    top_k: int = 5,
) -> list[
    tuple[
        float,
        dict,
        VulnRow,
        AssetRow,
        BusinessServiceRow | None,
        list[ThreatIntelRow],
        dict,
        RemediationHintRow | None,
    ]
]:
    assets = _asset_index(pack.assets)
    services = _service_index(pack.business_services)
    intel_by_cve: dict[str, list] = defaultdict(list)
    for row in pack.threat_intel:
        intel_by_cve[(row.matched_cve_or_control or "").strip().upper()].append(row)

    ranked: list[
        tuple[
            float,
            dict,
            VulnRow,
            AssetRow,
            BusinessServiceRow | None,
            list[ThreatIntelRow],
            dict,
            RemediationHintRow | None,
        ]
    ] = []
    for vuln in pack.vulnerabilities:
        if (vuln.status or "").lower() not in {"", "open"}:
            continue
        asset = assets.get(vuln.asset_id)
        if asset is None:
            continue
        svc = services.get(asset.business_service)
        intel = intel_by_cve.get((vuln.cve or "").strip().upper(), [])
        ke_row = kev.lookup(vuln.cve)
        score, breakdown = composite_risk_score(vuln, asset, svc, intel, ke_row)
        hint = pick_remediation_hint(vuln, pack.remediation_hints)
        ranked.append(
            (
                score,
                breakdown,
                vuln,
                asset,
                svc,
                intel,
                kev_to_public_dict(ke_row),
                hint,
            )
        )

    ranked.sort(key=lambda x: x[0], reverse=True)
    return ranked[:top_k]


def risks_to_records(
    ranked: list[
        tuple[
            float,
            dict,
            VulnRow,
            AssetRow,
            BusinessServiceRow | None,
            list[ThreatIntelRow],
            dict,
            RemediationHintRow | None,
        ]
    ],
) -> list[RiskRecord]:
    out: list[RiskRecord] = []
    for i, (score, breakdown, vuln, asset, svc, intel, kev_pub, hint) in enumerate(ranked, start=1):
        out.append(
            RiskRecord(
                rank=i,
                composite_score=score,
                score_breakdown=breakdown,
                asset=asset,
                vulnerability=vuln,
                business_service=svc,
                threat_intel=intel,
                kev=kev_pub,
                remediation_hint=hint,
                rationale_sentence=_rationale_sentence(i, vuln, asset, svc, intel, kev_pub),
                nist_control_id=None,
                nist_control_title=None,
                nist_excerpt=None,
            )
        )
    return out


def run_structured_ranking(settings: Settings | None = None, top_k: int = 5) -> list[RiskRecord]:
    s = settings or get_settings()
    pack = load_data_pack(s)
    kev = load_kev_catalog(s)
    ranked = build_ranked_risks(pack, kev, top_k=top_k)
    return risks_to_records(ranked)
