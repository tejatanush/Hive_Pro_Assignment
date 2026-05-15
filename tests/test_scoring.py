from __future__ import annotations

from tawasol_risk.datasets.schemas import AssetRow, BusinessServiceRow, ThreatIntelRow, VulnRow
from tawasol_risk.risk_engine.kev_service import KevEntry
from tawasol_risk.risk_engine.scoring import composite_risk_score


def _v(**kwargs) -> VulnRow:
    base = dict(
        vuln_id="V",
        asset_id="A",
        vulnerability_name="Test vuln",
        cve="CVE-2024-0001",
        severity="High",
        cvss=10.0,
        exploit_available="No",
        patch_available="Yes",
        days_open=1,
        asset_exposure="Internal",
        auth_required="Yes",
        status="Open",
        affected_component="os",
    )
    base.update(kwargs)
    return VulnRow.model_validate(base)


def _a(**kwargs) -> AssetRow:
    base = dict(
        asset_id="A",
        asset_name="srv",
        asset_type="Server",
        environment="Production",
        owner_team="t",
        business_service="SVC",
        internet_exposed="No",
        criticality="High",
        data_classification="Internal",
        edr_installed="Yes",
        last_seen_days=1,
        location="UAE",
        vendor_product="linux",
    )
    base.update(kwargs)
    return AssetRow.model_validate(base)


def _svc() -> BusinessServiceRow:
    return BusinessServiceRow.model_validate(
        {
            "business_service": "SVC",
            "business_owner": "o",
            "business_impact": "x",
            "customer_facing": "No",
            "compliance_scope": "SOC 2",
            "revenue_impact": "Medium",
            "rto_hours": 24,
            "depends_on": "",
            "risk_appetite": "Medium",
        }
    )


def test_internal_cvss10_lower_than_internet_cvss8_with_exploit_signals() -> None:
    internal_high = composite_risk_score(
        _v(cvss=10.0, exploit_available="No", asset_exposure="Internal"),
        _a(internet_exposed="No"),
        _svc(),
        [],
        None,
    )[0]

    internet_med = composite_risk_score(
        _v(cvss=8.0, exploit_available="Yes", asset_exposure="Internet"),
        _a(internet_exposed="Yes", edr_installed="No"),
        _svc(),
        [
            ThreatIntelRow.model_validate(
                {
                    "intel_id": "TI",
                    "threat_actor": "A",
                    "campaign_name": "C",
                    "target_sector": "Fin",
                    "target_region": "ME",
                    "matched_cve_or_control": "CVE-2024-0001",
                    "exploit_maturity": "Weaponized",
                    "active_last_seen": "2026-04-22",
                    "ransomware_association": "Yes",
                    "confidence": "High",
                    "summary": "s",
                }
            )
        ],
        KevEntry(
            cve_id="CVE-2024-0001",
            vendor_project=None,
            product=None,
            vulnerability_name=None,
            date_added=None,
            required_action=None,
            known_ransomware_campaign_use="Known",
            raw={},
        ),
    )[0]

    assert internet_med > internal_high
