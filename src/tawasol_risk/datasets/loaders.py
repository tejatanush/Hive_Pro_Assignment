from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from tawasol_risk.config.settings import Settings, get_settings
from tawasol_risk.datasets.schemas import (
    AssetRow,
    BusinessServiceRow,
    RemediationHintRow,
    ThreatIntelRow,
    VulnRow,
)


@dataclass
class DataPack:
    assets: list[AssetRow]
    vulnerabilities: list[VulnRow]
    threat_intel: list[ThreatIntelRow]
    business_services: list[BusinessServiceRow]
    remediation_hints: list[RemediationHintRow]
    threat_report_md: str


def _read_csv(path: Path, model: type) -> list:
    if not path.exists():
        raise FileNotFoundError(f"Missing dataset file: {path}")
    # Preserve literal "None" in compliance_scope etc. (pandas treats it as NA by default).
    df = pd.read_csv(path, keep_default_na=False)
    records: list = []
    for row in df.to_dict(orient="records"):
        cleaned = {k: (None if v == "" else v) for k, v in row.items()}
        records.append(model.model_validate(cleaned))
    return records


def load_threat_report(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def load_data_pack(settings: Settings | None = None) -> DataPack:
    s = settings or get_settings()
    root = s.resolved_data_dir()
    assets = _read_csv(root / "assets.csv", AssetRow)
    vulns = _read_csv(root / "vulnerabilities.csv", VulnRow)
    intel = _read_csv(root / "threat_intelligence.csv", ThreatIntelRow)
    services = _read_csv(root / "business_services.csv", BusinessServiceRow)
    hints = _read_csv(root / "remediation_guidance.csv", RemediationHintRow)
    report = load_threat_report(root / "synthetic_threat_report.md")
    return DataPack(
        assets=assets,
        vulnerabilities=vulns,
        threat_intel=intel,
        business_services=services,
        remediation_hints=hints,
        threat_report_md=report,
    )
