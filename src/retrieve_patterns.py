import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import chromadb
from chromadb.utils import embedding_functions
from policy_templates import POLICY_TEMPLATES

CHROMA_PATH = "chroma_db"
COLLECTION_NAME = "blade_cve_kb"

def get_collection():
    client = chromadb.PersistentClient(path=CHROMA_PATH)
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    return client.get_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn
    )

def retrieve_patterns(endpoint: dict, n_results: int = 5) -> list:
    collection = get_collection()

    schema_str = ""
    for model_name, fields in endpoint.get("schema", {}).items():
        field_list = ", ".join(f"{k}({v})" for k, v in fields.items())
        schema_str += f"{model_name}({field_list})"

    query = f"""
    {endpoint['method']} {endpoint['path']}
    Description: {endpoint.get('description', '')}
    Schema: {schema_str}
    JWT fields: {', '.join(endpoint.get('jwt_fields', []))}
    Need object-level authorization policy
    """.strip()

    result = collection.query(
        query_texts=[query],
        n_results=n_results,
    )

    patterns = []
    for i in range(len(result["ids"][0])):
        patterns.append({
            "cve_id": result["metadatas"][0][i]["cve_id"],
            "attack_pattern": result["metadatas"][0][i]["attack_pattern"],
            "recommended_policy": result["metadatas"][0][i]["recommended_policy"],
            "severity": result["metadatas"][0][i]["severity"],
            "distance": result["distances"][0][i],
            "document": result["documents"][0][i],
        })

    return patterns


if __name__ == "__main__":
    test_endpoints = [
        {
            "method": "GET",
            "path": "/api/orders/{orderId}",
            "description": "주문 상세 조회",
            "jwt_fields": ["sub", "role"],
            "schema": {"Order": {"id": "string", "userId": "string", "totalPrice": "number"}}
        },
        {
            "method": "DELETE",
            "path": "/api/posts/{postId}",
            "description": "게시글 삭제",
            "jwt_fields": ["sub", "role"],
            "schema": {"Post": {"id": "string", "authorId": "string", "content": "string"}}
        },
        {
            "method": "GET",
            "path": "/api/users/{userId}",
            "description": "사용자 프로필 조회",
            "jwt_fields": ["sub"],
            "schema": {"User": {"id": "string", "email": "string", "name": "string"}}
        },
        {
            "method": "GET",
            "path": "/api/tenants/{tenantId}/projects",
            "description": "테넌트의 프로젝트 목록",
            "jwt_fields": ["sub", "tenant_id"],
            "schema": {"Project": {"id": "string", "tenantId": "string", "name": "string"}}
        },
        {
            "method": "POST",
            "path": "/api/projects/{projectId}/members",
            "description": "프로젝트 멤버 추가",
            "jwt_fields": ["sub", "role"],
            "schema": {"Project": {"id": "string", "ownerId": "string", "memberIds": "array"}}
        },
    ]

    for ep in test_endpoints:
        print("=" * 60)
        print(f"{ep['method']} {ep['path']}")
        patterns = retrieve_patterns(ep)
        for p in patterns:
            print(f"  [{p['cve_id']}] {p['attack_pattern']} → {p['recommended_policy']} (거리: {p['distance']:.4f})")
        print()