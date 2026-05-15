from __future__ import annotations

import shutil
from pathlib import Path

REQUIRED_CSV_FILENAMES = (
    "assets.csv",
    "vulnerabilities.csv",
    "threat_intelligence.csv",
    "business_services.csv",
    "remediation_guidance.csv",
)

THREAT_REPORT_CANDIDATES = (
    "threat_report.md",
    "synthetic_threat_report.md",
    "mdr_advisory.md",
)


def find_threat_report_in_dir(root: Path) -> Path | None:
    for name in THREAT_REPORT_CANDIDATES:
        p = root / name
        if p.is_file():
            return p
    for p in sorted(root.glob("*.md")):
        if p.is_file():
            return p
    return None


def validate_pack_directory(root: Path) -> None:
    missing = [n for n in REQUIRED_CSV_FILENAMES if not (root / n).is_file()]
    if missing:
        raise FileNotFoundError(f"Missing required CSV(s) in folder: {', '.join(missing)}")


def cleanup_pack_directory(path: Path | None) -> None:
    if path is None or not path.is_dir():
        return
    shutil.rmtree(path, ignore_errors=True)
