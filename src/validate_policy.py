import yaml
from pathlib import Path
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from policy_templates import POLICY_TEMPLATES

REQUIRED_FIELDS = ["policyId", "method", "path", "mode", "resource", "subject", "rule", "confidence", "reason"]
REQUIRED_RULE_FIELDS = ["template", "relation", "lookup"]
REQUIRED_LOOKUP_FIELDS = ["table", "key", "keyFrom", "ownerField"]
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
VALID_MODES = {"alert", "block"}

def validate_policy(policy: dict) -> tuple:
    errors = []

    for field in REQUIRED_FIELDS:
        if field not in policy:
            errors.append(f"필수 필드 누락: {field}")

    if errors:
        return False, errors

    if policy["method"].upper() not in VALID_METHODS:
        errors.append(f"유효하지 않은 method: {policy['method']}")

    if policy["mode"] not in VALID_MODES:
        errors.append(f"유효하지 않은 mode: {policy['mode']}")

    rule = policy.get("rule", {})
    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            errors.append(f"rule 필드 누락: rule.{field}")

    if "template" in rule:
        if rule["template"] not in POLICY_TEMPLATES:
            errors.append(f"유효하지 않은 template: {rule['template']}")

    if rule.get("template") != "manual_review_required":
        lookup = rule.get("lookup", {})
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
            errors.append(f"confidence가 숫자가 아님: {confidence}")

    resource_id_from = policy.get("resource", {}).get("idFrom", "")
    if resource_id_from and "." not in resource_id_from:
        errors.append(f"resource.idFrom 형식 오류: '{resource_id_from}' (예: path.orderId)")

    subject_id_from = policy.get("subject", {}).get("idFrom", "")
    if subject_id_from and not subject_id_from.startswith("jwt."):
        errors.append(f"subject.idFrom은 jwt.로 시작해야 함: '{subject_id_from}'")

    return len(errors) == 0, errors


def validate_and_save(policy: dict, output_dir: str = "data/policies") -> bool:
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    valid, errors = validate_policy(policy)

    if valid:
        policy_id = policy.get("policyId", "unknown")
        output_path = Path(output_dir) / f"{policy_id}.yaml"
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(policy, f, allow_unicode=True, default_flow_style=False)
        print(f"정책 저장 완료: {output_path}")
        return True
    else:
        print(f"정책 검증 실패:")
        for err in errors:
            print(f"   - {err}")
        return False


if __name__ == "__main__":
    # 08에서 생성된 정책 파일들 전부 검증
    policy_dir = Path("data/policies")

    if not policy_dir.exists():
        print("data/policies 폴더가 없어. 08_generate_policy.py 먼저 실행해봐")
    else:
        yaml_files = list(policy_dir.glob("*.yaml"))
        if not yaml_files:
            print("검증할 정책 파일이 없어")
        else:
            for yaml_file in yaml_files:
                print(f"\n검증 중: {yaml_file.name}")
                with open(yaml_file, "r", encoding="utf-8") as f:
                    policy = yaml.safe_load(f)
                validate_policy(policy)