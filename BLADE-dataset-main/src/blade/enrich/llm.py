"""LLM 기반 enrichment (B 트랙 채택).

규칙 기반 분류가 confidence < 2 인 항목을 llama3.2:3b 로 분류.
"""

from __future__ import annotations

from typing import Any

from blade import config
from blade.utils import ollama_client

ENRICHMENT_PROMPT = """You are a security analyst. Given the vulnerability description below, classify it as a BOLA/IDOR pattern and respond with ONLY a single JSON object (no prose, no markdown fence).

Description:
{description}

CWE: {cwe_id}
Severity: {severity}

Required JSON fields:
- endpoint_pattern: vulnerable endpoint pattern, e.g. "GET /users/{{id}}"; use "unknown" if not inferrable
- id_type: one of path_param | query_param | body_param | unknown
- ownership_check_missing: one of path | query | body | unknown
- attack_method: one of id_enumeration | id_substitution | parameter_tampering | mass_assignment
- bola_pattern: one of integer_id_enumeration | nested_resource_idor | mass_assignment | filter_param_bypass | batch_unvalidated | admin_path_exposure | uuid_idor
- rule_based_detectable: true or false
- inference_required: true or false
- reason: one short sentence (English) justifying the classification

Return JSON only.
"""


_VALID_BOLA = {
    "integer_id_enumeration", "nested_resource_idor", "mass_assignment",
    "filter_param_bypass", "batch_unvalidated", "admin_path_exposure", "uuid_idor",
}
_VALID_ID_TYPE = {"path_param", "query_param", "body_param", "unknown"}
_VALID_OWNERSHIP = {"path", "query", "body", "unknown"}
_VALID_ATTACK = {"id_enumeration", "id_substitution", "parameter_tampering", "mass_assignment"}


def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes"}
    return False


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    bola = str(raw.get("bola_pattern", "nested_resource_idor")).lower()
    if bola not in _VALID_BOLA:
        bola = "nested_resource_idor"

    id_type = str(raw.get("id_type", "unknown")).lower()
    if id_type not in _VALID_ID_TYPE:
        id_type = "unknown"

    ownership = str(raw.get("ownership_check_missing", "unknown")).lower()
    if ownership not in _VALID_OWNERSHIP:
        ownership = "unknown"

    attack = str(raw.get("attack_method", "id_substitution")).lower()
    if attack not in _VALID_ATTACK:
        attack = "id_substitution"

    return {
        "endpoint_pattern": str(raw.get("endpoint_pattern", "unknown")) or "unknown",
        "id_type": id_type,
        "ownership_check_missing": ownership,
        "attack_method": attack,
        "bola_pattern": bola,
        "rule_based_detectable": _coerce_bool(raw.get("rule_based_detectable", False)),
        "inference_required": _coerce_bool(raw.get("inference_required", True)),
        "reason": str(raw.get("reason", "")).strip()[:300],
        "enrichment_method": "llm",
    }


def warmup() -> bool:
    """LLM 모델 사전 로드. 도달 가능하면 True."""
    print(f"  warming up enrichment LLM ({config.ENRICHMENT_MODEL})...")
    return ollama_client.warmup(model=config.ENRICHMENT_MODEL)


def classify(item: dict[str, Any]) -> dict[str, Any] | None:
    """item → enrichment dict (LLM). 실패 시 None."""
    prompt = ENRICHMENT_PROMPT.format(
        description=item.get("description") or item.get("title") or "",
        cwe_id=item.get("cwe_id") or "unknown",
        severity=item.get("severity") or "unknown",
    )
    try:
        response = ollama_client.generate(
            prompt,
            model=config.ENRICHMENT_MODEL,
            temperature=0.0,
            num_predict=256,
        )
    except ollama_client.OllamaError as exc:
        print(f"  [warn] LLM call failed for {item.get('id')}: {exc}")
        return None

    parsed = ollama_client.parse_first_json(response)
    if parsed is None:
        print(f"  [warn] LLM returned non-JSON for {item.get('id')}")
        return None
    return _normalize(parsed)
