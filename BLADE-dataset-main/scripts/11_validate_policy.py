"""data/policies/*.yaml 일괄 검증."""

import yaml

import _bootstrap  # noqa: F401

from blade import config
from blade.policy.validate import validate_policy


def main() -> int:
    if not config.POLICIES_DIR.exists():
        print(f"{config.POLICIES_DIR} 없음 — 10_generate_policy.py 먼저 실행")
        return 1
    files = sorted(config.POLICIES_DIR.glob("*.yaml"))
    if not files:
        print("검증할 정책 파일이 없음")
        return 1
    fail = 0
    for path in files:
        with path.open("r", encoding="utf-8") as f:
            policy = yaml.safe_load(f)
        valid, errors = validate_policy(policy)
        print(f"\n{path.name}: {'OK' if valid else 'FAIL'}")
        for e in errors:
            print(f"  - {e}")
        if not valid:
            fail += 1
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
