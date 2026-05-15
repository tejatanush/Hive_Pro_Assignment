from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
sys.path.insert(0, str(_SRC))

from cyber_risk.bootstrap import bootstrap_artifacts, readiness_status  # noqa: E402
from cyber_risk.config.settings import get_settings  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap KEV cache and NIST vector index")
    parser.add_argument("--force", action="store_true", help="Re-download feeds and rebuild index")
    parser.add_argument("--pinecone", action="store_true", help="Upsert to Pinecone (requires PINECONE_API_KEY)")
    args = parser.parse_args()

    settings = get_settings()
    if args.pinecone:
        if not settings.pinecone_api_key:
            raise SystemExit("PINECONE_API_KEY is required when using --pinecone")
        from cyber_risk.bootstrap import ensure_kev_cache, ensure_pinecone_index, validate_data_pack

        validate_data_pack(settings)
        ensure_kev_cache(settings, force=args.force)
        ensure_pinecone_index(settings, force_download=args.force)
    else:
        bootstrap_artifacts(settings, force=args.force)
    status = readiness_status(settings)
    print("Readiness:", status)


if __name__ == "__main__":
    main()
