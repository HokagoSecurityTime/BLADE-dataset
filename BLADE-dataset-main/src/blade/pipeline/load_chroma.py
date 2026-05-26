"""bola_dataset.json → ChromaDB 적재.

source 라벨로 컬렉션(bola_cve / bola_standards / bola_patterns) 라우팅.
임베딩은 nomic-embed-text (Ollama).
"""

from __future__ import annotations

from pathlib import Path

from blade import config
from blade.schema import Record, load_records
from blade.utils import chroma_client, ollama_client


def run(*, dataset_path: Path | None = None, batch_pause: float = 0.0) -> dict[str, int]:
    dataset_path = dataset_path or config.DATASET_PATH

    print("=== load_chroma ===")
    print(f"  dataset:    {dataset_path}")
    print(f"  chroma:     {config.CHROMA_PATH}")
    print(f"  embed:      {config.EMBED_MODEL}")
    print(f"  collections: {list(config.ALL_COLLECTIONS)}")

    if not ollama_client.is_alive():
        raise RuntimeError(
            "Ollama is not reachable. Start `ollama serve` and `ollama pull nomic-embed-text`."
        )

    records: list[Record] = load_records(dataset_path)
    print(f"  loaded {len(records)} records")

    client = chroma_client.get_client()
    collections = chroma_client.get_all_collections(client)

    success = skipped = failed = 0
    per_collection: dict[str, int] = {n: 0 for n in collections}

    for idx, rec in enumerate(records, 1):
        col_name = chroma_client.collection_for_source(rec.metadata.source)
        col = collections[col_name]

        existing = col.get(ids=[rec.id])
        if existing.get("ids"):
            skipped += 1
            continue

        embedding = ollama_client.embed(rec.document)
        if embedding is None:
            failed += 1
            print(f"  [{idx}] {rec.id}: embed failed")
            continue

        try:
            col.add(
                ids=[rec.id],
                embeddings=[embedding],
                documents=[rec.document],
                metadatas=[rec.metadata.to_chroma_dict()],
            )
            success += 1
            per_collection[col_name] += 1
        except Exception as exc:
            failed += 1
            print(f"  [{idx}] {rec.id}: add failed: {exc}")

    print(f"\n  success={success}  skipped={skipped}  failed={failed}")
    print("  per-collection:")
    for name, col in collections.items():
        print(f"    {name:<20} count={col.count()}")
    return per_collection


if __name__ == "__main__":
    run()
