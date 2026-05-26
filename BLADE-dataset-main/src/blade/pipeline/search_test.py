"""ChromaDB 검색 sanity check."""

from __future__ import annotations

from blade import config
from blade.utils import chroma_client, ollama_client


TEST_QUERIES = [
    "API endpoint allows users to access another user's order by changing orderId in URL",
    "User can view other tenant's data by modifying organization ID",
    "Missing authorization check on DELETE endpoint allows deleting other users resources",
    "GET /api/orders/{orderId} user ownership path parameter jwt",
    "UUID resource endpoint missing authorization check",
]


def run(n_results: int = 3) -> None:
    print("=== search_test ===")
    if not ollama_client.is_alive():
        raise RuntimeError("Ollama is not reachable")

    client = chroma_client.get_client()
    collections = chroma_client.get_all_collections(client)
    total = sum(c.count() for c in collections.values())
    print(f"  total docs across {len(collections)} collections: {total}")
    if total == 0:
        print("  [warn] no documents — run pipeline.load_chroma first")
        return

    for q in TEST_QUERIES:
        print("=" * 80)
        print(f"query: {q}")
        emb = ollama_client.embed(q)
        if emb is None:
            print("  [warn] embed failed")
            continue
        results = chroma_client.query_all(client, query_embedding=emb, n_results=n_results)
        for i, r in enumerate(results, 1):
            md = r["metadata"]
            print(f"  [{i}] {r['id']}  ({r['collection']}, dist={r['distance']:.4f})")
            print(f"      pattern: {md.get('bola_pattern', '-')}  policy_hint: {md.get('policy_template_hint', '-')}")
            print(f"      severity: {md.get('severity', '-')} ({md.get('cvss_score', 0)})")


if __name__ == "__main__":
    run()
