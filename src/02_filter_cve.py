import json
from pathlib import Path

RAW_PATH = Path("data/raw/nvd_cves_raw.json")
OUT_PATH = Path("data/processed/filtered_access_control_cves.json")
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

# BOLA/접근통제 관련 CWE 목록
RELATED_CWE = {
    "CWE-639",  # Authorization Bypass Through User-Controlled Key
    "CWE-862",  # Missing Authorization
    "CWE-863",  # Incorrect Authorization
    "CWE-284",  # Improper Access Control
    "CWE-285",  # Improper Authorization
}

KEYWORDS = [
    "authorization",
    "access control",
    "idor",
    "object level",
    "broken object",
    "bypass",
    "privilege",
    "tenant",
    "owner",
    "unauthorized",
]

def get_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""

def get_cwes(cve):
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                cwes.append(value)
    return cwes

def is_related(cve):
    description = get_description(cve).lower()
    cwes = set(get_cwes(cve))

    keyword_match = any(k in description for k in KEYWORDS)
    cwe_match = bool(cwes & RELATED_CWE)

    return keyword_match or cwe_match

def main():
    with open(RAW_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)

    filtered = []
    for item in items:
        cve = item["cve"]
        if is_related(cve):
            filtered.append(item)

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(filtered, f, ensure_ascii=False, indent=2)

    print(f"전체 CVE: {len(items)}개")
    print(f"필터링 후: {len(filtered)}개")
    print(f"저장 완료: {OUT_PATH}")

if __name__ == "__main__":
    main()