"""OAS 엔드포인트 → ChromaDB 의 BOLA 패턴 검색.

A 트랙 `retrieve_patterns.py` 를 통합 스키마에 맞춰 재작성:
- 임베딩: sentence-transformers MiniLM → Ollama nomic-embed-text
- 컬렉션: 단일 `blade_cve_kb` → 가이드 §4-5 의 3-컬렉션 병렬 검색
- metadata 키: attack_pattern → bola_pattern, recommended_policy → policy_template_hint
"""

from __future__ import annotations

from typing import Any

from blade.schema import K
from blade.utils import chroma_client, ollama_client


def _build_query(endpoint: dict[str, Any]) -> str:
    schema_str = ""
    for model_name, fields in endpoint.get("schema", {}).items():
        field_list = ", ".join(f"{k}({v})" for k, v in fields.items())
        schema_str += f"{model_name}({field_list})"

    return (
        f"{endpoint['method']} {endpoint['path']}\n"
        f"Description: {endpoint.get('description', '')}\n"
        f"Schema: {schema_str}\n"
        f"JWT fields: {', '.join(endpoint.get('jwt_fields', []))}\n"
        f"Need object-level authorization policy"
    ).strip()


def retrieve_patterns(endpoint: dict[str, Any], n_results: int = 5) -> list[dict[str, Any]]:
    """엔드포인트와 유사한 BOLA 사례를 검색해 정책 생성용 컨텍스트로 반환."""
    query = _build_query(endpoint)
    embedding = ollama_client.embed(query)
    if embedding is None:
        return []

    client = chroma_client.get_client()
    results = chroma_client.query_all(
        client,
        query_embedding=embedding,
        n_results=n_results,
    )

    out: list[dict[str, Any]] = []
    for r in results:
        md = r["metadata"]
        out.append(
            {
                "cve_id": md.get(K.CVE_ID, "") or md.get(K.SOURCE_ID, ""),
                "bola_pattern": md.get(K.BOLA_PATTERN, ""),
                "policy_template_hint": md.get(K.POLICY_TEMPLATE_HINT, ""),
                "severity": md.get(K.SEVERITY, ""),
                "cvss_score": md.get(K.CVSS_SCORE, 0.0),
                "rule_type": md.get(K.RULE_TYPE, ""),
                "ownership_type": md.get(K.OWNERSHIP_TYPE, ""),
                "distance": r["distance"],
                "collection": r["collection"],
                "document": r["document"],
            }
        )
    return out


if __name__ == "__main__":
    test_endpoints = [
        {
            "method": "GET", "path": "/api/orders/{orderId}",
            "description": "주문 상세 조회", "jwt_fields": ["sub", "role"],
            "schema": {"Order": {"id": "string", "userId": "string"}}
        },
        {
            "method": "GET", "path": "/api/tenants/{tenantId}/projects",
            "description": "테넌트의 프로젝트 목록", "jwt_fields": ["sub", "tenant_id"],
            "schema": {"Project": {"id": "string", "tenantId": "string"}}
        },
    ]
    for ep in test_endpoints:
        print("=" * 60)
        print(f"{ep['method']} {ep['path']}")
        for p in retrieve_patterns(ep):
            print(f"  [{p['cve_id']}] {p['bola_pattern']} → {p['policy_template_hint']} "
                  f"(d={p['distance']:.4f}, {p['collection']})")
