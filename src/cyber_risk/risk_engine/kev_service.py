from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from cyber_risk.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KevEntry:
    cve_id: str
    vendor_project: str | None
    product: str | None
    vulnerability_name: str | None
    date_added: str | None
    required_action: str | None
    known_ransomware_campaign_use: str | None
    raw: dict[str, Any]


class KevCatalog:
    def __init__(self, entries: dict[str, KevEntry]) -> None:
        self._by_cve = entries

    def lookup(self, cve: str) -> KevEntry | None:
        return self._by_cve.get(cve.strip().upper())

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> KevCatalog:
        rows = payload.get("vulnerabilities") or payload.get("data") or []
        out: dict[str, KevEntry] = {}
        for row in rows:
            cid = (row.get("cveID") or row.get("cve_id") or "").strip().upper()
            if not cid:
                continue
            out[cid] = KevEntry(
                cve_id=cid,
                vendor_project=row.get("vendorProjectProduct"),
                product=row.get("product"),
                vulnerability_name=row.get("vulnerabilityName"),
                date_added=row.get("dateAdded"),
                required_action=row.get("requiredAction"),
                known_ransomware_campaign_use=row.get("knownRansomwareCampaignUse"),
                raw=row,
            )
        return cls(out)


def kev_cache_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return s.resolved_processed_dir() / s.kev_cache_filename


def download_kev_catalog(
    url: str = DEFAULT_KEV_URL,
    settings: Settings | None = None,
    force: bool = False,
) -> Path:
    """Download CISA KEV to processed cache and return path."""
    s = settings or get_settings()
    path = kev_cache_path(s)
    if path.exists() and not force:
        return path
    logger.info("Downloading CISA KEV from %s", url)
    with httpx.Client(timeout=120.0) as client:
        r = client.get(url)
        r.raise_for_status()
        path.write_bytes(r.content)
    return path


def load_kev_catalog(settings: Settings | None = None) -> KevCatalog:
    path = kev_cache_path(settings or get_settings())
    if not path.exists():
        download_kev_catalog(settings=settings)
    data = json.loads(path.read_text(encoding="utf-8"))
    return KevCatalog.from_json(data)


def kev_to_public_dict(entry: KevEntry | None) -> dict[str, str | bool | None]:
    if entry is None:
        return {"on_kev": False}
    kr = (entry.known_ransomware_campaign_use or "").strip().lower()
    ransomware = kr in {"known", "yes", "true", "y"}
    return {
        "on_kev": True,
        "cve_id": entry.cve_id,
        "date_added": entry.date_added,
        "required_action": entry.required_action,
        "known_ransomware_campaign_use": entry.known_ransomware_campaign_use,
        "ransomware_flag": ransomware,
    }
