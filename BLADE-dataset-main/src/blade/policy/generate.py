"""LLM 기반 BLADE 정책 YAML 생성.

A 트랙 `generate_policy.py` 를 새 스키마/클라이언트로 리팩토링.
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from blade import config
from blade.policy.retrieve import retrieve_patterns
from blade.policy.templates import POLICY_TEMPLATES
from blade.utils import ollama_client


def _build_prompt(endpoint: dict[str, Any], patterns: list[dict[str, Any]]) -> str:
    template_str = "".join(
        f"- {name}: {info['description']} (예: {info['example']})\n"
        for name, info in POLICY_TEMPLATES.items()
    )
    pattern_str = ""
    for i, p in enumerate(patterns[:3]):
        pattern_str += (
            f"[{i+1}] CVE: {p.get('cve_id', '')} | severity: {p.get('severity', '')}\n"
            f"     BOLA pattern: {p.get('bola_pattern', '')}\n"
            f"     policy hint: {p.get('policy_template_hint', '')}\n"
            f"     content: {p.get('document', '')[:300]}\n\n"
        )
    schema_str = json.dumps(endpoint.get("schema", {}), ensure_ascii=False)

    return f"""You are an API access control policy generator for BLADE security system.

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


def generate_policy(endpoint: dict[str, Any]) -> dict[str, Any] | None:
    patterns = retrieve_patterns(endpoint, n_results=5)
    prompt = _build_prompt(endpoint, patterns)

    print(f"  LLM 호출 중... ({config.POLICY_MODEL})")
    try:
        raw = ollama_client.generate(
            prompt,
            model=config.POLICY_MODEL,
            temperature=0.1,
            num_predict=1024,
            options={"top_p": 0.9},
        )
    except ollama_client.OllamaError as exc:
        print(f"  정책 생성 실패: {exc}")
        return None

    clean = raw.strip()
    if clean.startswith("```"):
        clean = "\n".join(clean.split("\n")[1:])
    if clean.endswith("```"):
        clean = "\n".join(clean.split("\n")[:-1])
    clean = clean.strip()

    try:
        return yaml.safe_load(clean)
    except Exception as exc:
        print(f"  YAML 파싱 실패: {exc}")
        return None


if __name__ == "__main__":
    test_endpoints = [
        {
            "method": "GET", "path": "/api/orders/{orderId}",
            "description": "주문 상세 조회", "jwt_fields": ["sub", "role"],
            "schema": {"Order": {"id": "string", "userId": "string", "totalPrice": "number"}}
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
