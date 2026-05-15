from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import httpx

from cyber_risk.config.settings import Settings, get_settings

logger = logging.getLogger(__name__)

DEFAULT_NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)


@dataclass
class NistControlChunk:
    control_id: str
    title: str
    text: str


def _collect_prose(parts: Iterable[dict[str, Any]] | None, buf: list[str]) -> None:
    if not parts:
        return
    for p in parts:
        prose = p.get("prose")
        if prose and isinstance(prose, str):
            buf.append(prose.strip())
        nested = p.get("parts")
        if nested:
            _collect_prose(nested, buf)


def _normalize_control_id(raw_id: str) -> str:
    rid = raw_id.strip()
    m = re.match(r"^([a-z]{2})-(\d+)(?:\((\d+)\))?$", rid, flags=re.I)
    if not m:
        return rid.upper()
    fam, num, sub = m.group(1).upper(), m.group(2), m.group(3)
    if sub:
        return f"{fam}-{int(num)}({int(sub)})"
    return f"{fam}-{int(num)}"


def flatten_control(control: dict[str, Any]) -> NistControlChunk | None:
    cid = control.get("id")
    title = control.get("title")
    if not cid or not title:
        return None
    buf: list[str] = []
    _collect_prose(control.get("parts"), buf)
    text = "\n".join(buf).strip()
    if not text:
        text = str(title)
    norm = _normalize_control_id(str(cid))
    return NistControlChunk(control_id=norm, title=str(title), text=text[:12000])


def walk_nested_controls(control: dict[str, Any], out: list[NistControlChunk]) -> None:
    ch = flatten_control(control)
    if ch:
        out.append(ch)
    for child in control.get("controls") or []:
        walk_nested_controls(child, out)


def catalog_to_chunks(catalog: dict[str, Any]) -> list[NistControlChunk]:
    cat = catalog.get("catalog") or catalog
    groups = cat.get("groups") or []
    out: list[NistControlChunk] = []
    for g in groups:
        for c in g.get("controls") or []:
            walk_nested_controls(c, out)
    # De-dupe by control_id keeping longest text
    best: dict[str, NistControlChunk] = {}
    for ch in out:
        prev = best.get(ch.control_id)
        if prev is None or len(ch.text) > len(prev.text):
            best[ch.control_id] = ch
    return list(best.values())


def nist_catalog_cache_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return s.resolved_processed_dir() / s.nist_catalog_filename


def download_nist_catalog(
    url: str = DEFAULT_NIST_URL,
    settings: Settings | None = None,
    force: bool = False,
) -> Path:
    s = settings or get_settings()
    path = nist_catalog_cache_path(s)
    if path.exists() and not force:
        return path
    logger.info("Downloading NIST SP 800-53 Rev.5 OSCAL catalog from %s", url)
    with httpx.Client(timeout=300.0) as client:
        r = client.get(url)
        r.raise_for_status()
        path.write_bytes(r.content)
    return path


def load_nist_chunks(settings: Settings | None = None) -> list[NistControlChunk]:
    path = nist_catalog_cache_path(settings or get_settings())
    if not path.exists():
        download_nist_catalog(settings=settings)
    catalog = json.loads(path.read_text(encoding="utf-8"))
    return catalog_to_chunks(catalog)
