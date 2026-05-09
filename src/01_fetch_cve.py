import os
import json
import nvdlib
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

API_KEY = os.getenv("NVD_API_KEY", "") or None  # 빈 문자열이면 None으로

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)

KEYWORD_CONFIG = {
    "Broken Object Level Authorization": 500,
    "BOLA": 500,
    "IDOR": 500,
    "authorization bypass": 300,
    "improper authorization": 300,
    "access control": 300,
}

def fetch_cves_by_keyword(keyword: str, limit: int):
    print(f"[수집 중] keyword='{keyword}' (최대 {limit}개)")

    try:
        results = nvdlib.searchCVE(
            keywordSearch=keyword,
            limit=limit,
            key=API_KEY,
            delay=1 if API_KEY else 7,
        )
        print(f"  → {len(results)}개 수집됨")
        return results

    except Exception as e:
        print(f"  → 실패: {e}")
        return []

def cve_to_dict(r):
    """nvdlib 객체를 JSON 저장 가능한 dict로 변환"""

    # 설명 추출
    descriptions = []
    for d in getattr(r, "descriptions", []):
        descriptions.append({"lang": d.lang, "value": d.value})

    # CWE 추출
    weaknesses = []
    for w in getattr(r, "weaknesses", []):
        descs = []
        for d in getattr(w, "description", []):
            descs.append({"value": d.value})
        weaknesses.append({"description": descs})

    # CVSS 추출
    metrics = {}
    if hasattr(r, "v31score") and r.v31score:
        metrics["cvssMetricV31"] = [{
            "cvssData": {
                "baseScore": r.v31score,
                "baseSeverity": getattr(r, "v31severity", ""),
            }
        }]
    elif hasattr(r, "v30score") and r.v30score:
        metrics["cvssMetricV30"] = [{
            "cvssData": {
                "baseScore": r.v30score,
                "baseSeverity": getattr(r, "v30severity", ""),
            }
        }]

    return {
        "cve": {
            "id": r.id,
            "published": str(getattr(r, "published", "")),
            "lastModified": str(getattr(r, "lastModified", "")),
            "descriptions": descriptions,
            "weaknesses": weaknesses,
            "metrics": metrics,
        }
    }

def main():
    merged = {}

    for keyword, limit in KEYWORD_CONFIG.items():
        results = fetch_cves_by_keyword(keyword, limit)

        for r in results:
            if r.id not in merged:
                merged[r.id] = cve_to_dict(r)

        print(f"현재까지 고유 CVE: {len(merged)}개\n")

    output_path = RAW_DIR / "nvd_cves_raw.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(list(merged.values()), f, ensure_ascii=False, indent=2)

    print(f"저장 완료: {output_path}")
    print(f"총 고유 CVE 개수: {len(merged)}")

if __name__ == "__main__":
    main()