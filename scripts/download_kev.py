from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
sys.path.insert(0, str(_SRC))

from tawasol_risk.config.settings import get_settings  # noqa: E402
from tawasol_risk.risk_engine.kev_service import download_kev_catalog  # noqa: E402


def main() -> None:
    path = download_kev_catalog(settings=get_settings(), force=False)
    print(f"Wrote CISA KEV cache to: {path}")


if __name__ == "__main__":
    main()
