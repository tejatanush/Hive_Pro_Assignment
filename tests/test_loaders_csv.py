from __future__ import annotations

from pathlib import Path

import pandas as pd

from cyber_risk.datasets.loaders import _load_dataframe, _normalize_column


def test_normalize_column_strips_bom_and_whitespace() -> None:
    assert _normalize_column("  \ufeffasset_id  ") == "asset_id"


def test_load_dataframe_strips_utf8_bom_from_file(tmp_path: Path) -> None:
    p = tmp_path / "t.csv"
    p.write_bytes(b"\xef\xbb\xbfcol_a,col_b\n1,2\n3,4\n")
    df = _load_dataframe(p)
    assert list(df.columns) == ["col_a", "col_b"]
    assert len(df) == 2


def test_plain_utf8_without_bom_still_works(tmp_path: Path) -> None:
    p = tmp_path / "t.csv"
    p.write_text("x,y\na,b\n", encoding="utf-8")
    df = _load_dataframe(p)
    assert list(df.columns) == ["x", "y"]


def test_bom_first_header_matches_pandas_utf8_sig(tmp_path: Path) -> None:
    """Regression: uploaded UTF-8 BOM files must not leave \\ufeff on the first header."""
    p = tmp_path / "t.csv"
    p.write_bytes(b"\xef\xbb\xbfk1,k2\nv,v\n")
    good = _load_dataframe(p)
    assert list(good.columns) == ["k1", "k2"]
    assert not any("\ufeff" in str(c) for c in good.columns)
