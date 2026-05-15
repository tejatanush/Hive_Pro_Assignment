from __future__ import annotations

from pydantic import BaseModel, Field


class AssetRow(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    environment: str
    owner_team: str | None = None
    business_service: str
    internet_exposed: str
    criticality: str
    data_classification: str
    edr_installed: str
    last_seen_days: int | None = None
    location: str | None = None
    vendor_product: str | None = None


class VulnRow(BaseModel):
    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str
    severity: str
    cvss: float
    exploit_available: str
    patch_available: str
    days_open: int | None = None
    asset_exposure: str | None = None
    auth_required: str | None = None
    status: str | None = None
    affected_component: str | None = None


class ThreatIntelRow(BaseModel):
    intel_id: str
    threat_actor: str
    campaign_name: str
    target_sector: str
    target_region: str
    matched_cve_or_control: str
    exploit_maturity: str
    active_last_seen: str | None = None
    ransomware_association: str
    confidence: str
    summary: str


class BusinessServiceRow(BaseModel):
    business_service: str
    business_owner: str
    business_impact: str
    customer_facing: str
    compliance_scope: str | None = None
    revenue_impact: str
    rto_hours: int | None = None
    depends_on: str | None = None
    risk_appetite: str | None = None


class RemediationHintRow(BaseModel):
    finding_type: str
    recommended_action: str
    priority_hint: str
    validation_evidence: str


class RiskRecord(BaseModel):
    """Structured top risk for API / UI."""

    rank: int
    composite_score: float
    score_breakdown: dict[str, float]
    asset: AssetRow
    vulnerability: VulnRow
    business_service: BusinessServiceRow | None = None
    threat_intel: list[ThreatIntelRow] = Field(default_factory=list)
    kev: dict[str, str | bool | None] = Field(default_factory=dict)
    remediation_hint: RemediationHintRow | None = None
    rationale_sentence: str
    nist_control_id: str | None = None
    nist_control_title: str | None = None
    nist_excerpt: str | None = None
