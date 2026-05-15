from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
sys.path.insert(0, str(_SRC))

from cyber_risk.config.settings import get_settings  # noqa: E402
from cyber_risk.rag.nist_oscal import download_nist_catalog, load_nist_chunks  # noqa: E402
from cyber_risk.rag.vector_store import build_local_index, upsert_pinecone  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Chunk + embed NIST SP 800-53 Rev.5 OSCAL catalog")
    parser.add_argument("--pinecone", action="store_true", help="Upsert into Pinecone instead of local npz")
    parser.add_argument("--force-download", action="store_true", help="Re-download the OSCAL JSON")
    args = parser.parse_args()

    settings = get_settings()
    download_nist_catalog(settings=settings, force=args.force_download)
    chunks = load_nist_chunks(settings=settings)
    print(f"Parsed {len(chunks)} NIST control chunks")

    if args.pinecone or os.getenv("PINECONE_FORCE_UPSERT") == "1":
        upsert_pinecone(chunks, settings.embedding_model, settings)
        print("Pinecone upsert complete")
        return

    build_local_index(chunks, settings.embedding_model, settings)
    print("Local vector index build complete")


if __name__ == "__main__":
    main()
