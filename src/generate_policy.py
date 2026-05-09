import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import json
import yaml
import requests
from policy_templates import POLICY_TEMPLATES
from retrieve_patterns import retrieve_patterns

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5:7b"

def build_prompt(endpoint: dict, patterns: list) -> str:
    template_str = ""
    for name, info in POLICY_TEMPLATES.items():
        template_str += f"- {name}: {info['description']} (예: {info['example']})\n"

    pattern_str = ""
    for i, p in enumerate(patterns[:3]):
        pattern_str += f"""[{i+1}] CVE: {p['cve_id']} | 심각도: {p['severity']}
     공격 패턴: {p['attack_pattern']}
     추천 정책: {p['recommended_policy']}
     내용: {p['document'][:300]}

"""

    schema_str = json.dumps(endpoint.get("schema", {}), ensure_ascii=False)

    prompt = f"""You are an API access control policy generator for BLADE security system.

TASK:
Generate a YAML policy draft for the given API endpoint to prevent BOLA attacks.

RULES:
- Select ONLY ONE template from the allowed list
- Do NOT invent DB fields or JWT fields that don't exist in the schema
- If unsure, choose manual_review_required
- Set mode to "alert" always
- Output YAML only, no explanation, no markdown fences

[Endpoint]
method: {endpoint['method']}
path: {endpoint['path']}
description: {endpoint.get('description', '')}
jwt_fields: {endpoint.get('jwt_fields', [])}
schema: {schema_str}

[Allowed policy templates]
{template_str}

[Retrieved CVE patterns - use as reference]
{pattern_str}

[Output schema - fill all fields]
policyId: (snake_case, method + path 기반)
method:
path:
mode: alert
resource:
  type:
  idFrom:
subject:
  idFrom:
rule:
  template:
  relation:
  lookup:
    table:
    key: id
    keyFrom:
    ownerField:
confidence:
reason:
"""
    return prompt


def generate_policy(endpoint: dict) -> dict | None:
    patterns = retrieve_patterns(endpoint, n_results=5)
    prompt = build_prompt(endpoint, patterns)

    try:
        print(f"  LLM 호출 중... (30초~2분 소요)")
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "top_p": 0.9,
                }
            },
            timeout=120
        )

        if response.status_code != 200:
            print(f"ollama 오류: {response.status_code}")
            print(f"에러 내용: {response.text}")
            return None

        raw_output = response.json().get("response", "")

        # yaml 펜스 제거
        clean = raw_output.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        clean = clean.strip()

        policy = yaml.safe_load(clean)
        return policy

    except Exception as e:
        print(f"정책 생성 실패: {e}")
        return None


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
    ]

    for ep in test_endpoints:
        print("=" * 60)
        print(f"{ep['method']} {ep['path']}")
        policy = generate_policy(ep)
        if policy:
            print(yaml.dump(policy, allow_unicode=True, default_flow_style=False))
        else:
            print("생성 실패")
        print()