from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from cyber_risk.config.settings import Settings, get_settings
from cyber_risk.datasets.schemas import (
    AssetRow,
    BusinessServiceRow,
    RemediationHintRow,
    ThreatIntelRow,
    VulnRow,
)
from cyber_risk.datasets.uploads import (
    REQUIRED_CSV_FILENAMES,
    find_threat_report_in_dir,
    validate_pack_directory,
)

# Streamlit / browser uploads are often saved as UTF-8 with BOM; Excel may add stray spaces in headers.
_CSV_READ_KWARGS: dict = {"keep_default_na": False, "encoding": "utf-8-sig"}


def _normalize_column(name: object) -> str:
    s = name if isinstance(name, str) else str(name)
    return s.strip().removeprefix("\ufeff").strip()


def _load_dataframe(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, **_CSV_READ_KWARGS)
    df.columns = [_normalize_column(c) for c in df.columns]
    return df


def csv_row_counts_for_pack(root: Path) -> dict[str, int]:
    """Fast row counts (same reader as load) for UI diagnostics after upload."""
    validate_pack_directory(root)
    return {name: len(_load_dataframe(root / name)) for name in REQUIRED_CSV_FILENAMES}


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
    df = _load_dataframe(path)
    records: list = []
    for row in df.to_dict(orient="records"):
        cleaned = {k: (None if v == "" else v) for k, v in row.items()}
        records.append(model.model_validate(cleaned))
    return records


def load_threat_report(dir_path: Path) -> str:
    direct = find_threat_report_in_dir(dir_path)
    if direct and direct.is_file():
        return direct.read_text(encoding="utf-8-sig")
    return ""


def load_data_pack(
    settings: Settings | None = None,
    *,
    data_pack_dir: Path | None = None,
) -> DataPack:
    """Load pack from ``data_pack_dir`` or default ``CYBER_RISK_DATA_DIR`` / ``data``."""
    s = settings or get_settings()
    root = Path(data_pack_dir).resolve() if data_pack_dir is not None else s.resolved_data_dir()
    validate_pack_directory(root)
    assets = _read_csv(root / "assets.csv", AssetRow)
    vulns = _read_csv(root / "vulnerabilities.csv", VulnRow)
    intel = _read_csv(root / "threat_intelligence.csv", ThreatIntelRow)
    services = _read_csv(root / "business_services.csv", BusinessServiceRow)
    hints = _read_csv(root / "remediation_guidance.csv", RemediationHintRow)
    report = load_threat_report(root)
    return DataPack(
        assets=assets,
        vulnerabilities=vulns,
        threat_intel=intel,
        business_services=services,
        remediation_hints=hints,
        threat_report_md=report,
    )
