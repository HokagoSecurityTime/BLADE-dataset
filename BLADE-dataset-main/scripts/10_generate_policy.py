"""테스트 OAS 엔드포인트에 대해 BLADE 정책 YAML 생성."""

import yaml

import _bootstrap  # noqa: F401

from blade import config
from blade.policy import generate, validate


TEST_ENDPOINTS = [
    {
        "method": "GET",
        "path": "/api/orders/{orderId}",
        "description": "주문 상세 조회",
        "jwt_fields": ["sub", "role"],
        "schema": {"Order": {"id": "string", "userId": "string", "totalPrice": "number"}},
    },
    {
        "method": "DELETE",
        "path": "/api/posts/{postId}",
        "description": "게시글 삭제",
        "jwt_fields": ["sub", "role"],
        "schema": {"Post": {"id": "string", "authorId": "string", "content": "string"}},
    },
    {
        "method": "GET",
        "path": "/api/tenants/{tenantId}/projects",
        "description": "테넌트의 프로젝트 목록",
        "jwt_fields": ["sub", "tenant_id"],
        "schema": {"Project": {"id": "string", "tenantId": "string", "name": "string"}},
    },
]


def main() -> None:
    config.POLICIES_DIR.mkdir(parents=True, exist_ok=True)
    for ep in TEST_ENDPOINTS:
        print("=" * 60)
        print(f"{ep['method']} {ep['path']}")
        policy = generate.generate_policy(ep)
        if not policy:
            print("  생성 실패")
            continue
        print(yaml.dump(policy, allow_unicode=True, default_flow_style=False))
        validate.validate_and_save(policy)


if __name__ == "__main__":
    main()
