"""정책 YAML 검증 — A 트랙 그대로 (config 경로만 갱신)."""

from __future__ import annotations

from pathlib import Path

import yaml

from blade import config
from blade.policy.templates import POLICY_TEMPLATES

REQUIRED_FIELDS = ["policyId", "method", "path", "mode", "resource", "subject", "rule", "confidence", "reason"]
REQUIRED_RULE_FIELDS = ["template", "relation", "lookup"]
REQUIRED_LOOKUP_FIELDS = ["table", "key", "keyFrom", "ownerField"]
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
VALID_MODES = {"alert", "block"}


def validate_policy(policy: dict) -> tuple[bool, list[str]]:
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in policy:
            errors.append(f"필수 필드 누락: {field}")
    if errors:
        return False, errors

    if str(policy["method"]).upper() not in VALID_METHODS:
        errors.append(f"유효하지 않은 method: {policy['method']}")
    if policy["mode"] not in VALID_MODES:
        errors.append(f"유효하지 않은 mode: {policy['mode']}")

    rule = policy.get("rule", {}) or {}
    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            errors.append(f"rule 필드 누락: rule.{field}")
    if "template" in rule and rule["template"] not in POLICY_TEMPLATES:
        errors.append(f"유효하지 않은 template: {rule['template']}")

    if rule.get("template") != "manual_review_required":
        lookup = rule.get("lookup", {}) or {}
        for field in REQUIRED_LOOKUP_FIELDS:
            if field not in lookup:
                errors.append(f"lookup 필드 누락: rule.lookup.{field}")

    confidence = policy.get("confidence")
    if confidence is not None:
        try:
            c = float(confidence)
            if not (0.0 <= c <= 1.0):
                errors.append(f"confidence 범위 오류: {confidence}")
        except (ValueError, TypeError):
            errors.append(f"confidence 가 숫자가 아님: {confidence}")

    res_id = (policy.get("resource", {}) or {}).get("idFrom", "")
    if res_id and "." not in res_id:
        errors.append(f"resource.idFrom 형식 오류: '{res_id}' (예: path.orderId)")

    sub_id = (policy.get("subject", {}) or {}).get("idFrom", "")
    if sub_id and not sub_id.startswith("jwt."):
        errors.append(f"subject.idFrom 은 jwt. 로 시작해야 함: '{sub_id}'")

    return len(errors) == 0, errors


def validate_and_save(policy: dict, output_dir: Path | None = None) -> bool:
    output_dir = output_dir or config.POLICIES_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    valid, errors = validate_policy(policy)
    if valid:
        policy_id = policy.get("policyId", "unknown")
        path = output_dir / f"{policy_id}.yaml"
        with path.open("w", encoding="utf-8") as f:
            yaml.dump(policy, f, allow_unicode=True, default_flow_style=False)
        print(f"정책 저장 완료: {path}")
        return True
    print("정책 검증 실패:")
    for e in errors:
        print(f"   - {e}")
    return False


if __name__ == "__main__":
    if not config.POLICIES_DIR.exists():
        print(f"{config.POLICIES_DIR} 폴더가 없음. generate.py 먼저 실행")
    else:
        for path in sorted(config.POLICIES_DIR.glob("*.yaml")):
            print(f"\n검증 중: {path.name}")
            with path.open("r", encoding="utf-8") as f:
                policy = yaml.safe_load(f)
            valid, errors = validate_policy(policy)
            print("  OK" if valid else f"  errors: {errors}")
