import json
from pathlib import Path

IN_PATH = Path("data/processed/filtered_access_control_cves.json")
OUT_PATH = Path("data/processed/chroma_documents.json")

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

def get_cvss(cve):
    metrics = cve.get("metrics", {})

    if "cvssMetricV31" in metrics:
        m = metrics["cvssMetricV31"][0]
        return {
            "score": m["cvssData"].get("baseScore"),
            "severity": m["cvssData"].get("baseSeverity"),
        }
    if "cvssMetricV30" in metrics:
        m = metrics["cvssMetricV30"][0]
        return {
            "score": m["cvssData"].get("baseScore"),
            "severity": m["cvssData"].get("baseSeverity"),
        }

    return {"score": None, "severity": None}

def classify_pattern(description: str, cwes: list):
    text = description.lower()
    cwe_set = set(cwes)

    # 단순 if-else 대신 점수 기반으로 분류
    scores = {
        "tenant_boundary_bypass": 0,
        "role_bypass": 0,
        "id_tampering": 0,
        "ownership_check_missing": 0,
    }

    # 텍스트 기반 점수
    for kw in ["tenant", "organization", "workspace", "multi-tenant"]:
        if kw in text:
            scores["tenant_boundary_bypass"] += 2

    for kw in ["privilege escalation", "admin", "role", "permission"]:
        if kw in text:
            scores["role_bypass"] += 2

    for kw in ["idor", "insecure direct object", "object level", "bola"]:
        if kw in text:
            scores["id_tampering"] += 3
    if " id " in text or "identifier" in text:
        scores["id_tampering"] += 1

    # CWE 기반 점수 (텍스트보다 신뢰도 높으므로 가중치 높게)
    if "CWE-639" in cwe_set:
        scores["id_tampering"] += 3
    if "CWE-862" in cwe_set or "CWE-863" in cwe_set:
        scores["ownership_check_missing"] += 3
    if "CWE-284" in cwe_set or "CWE-285" in cwe_set:
        scores["role_bypass"] += 2

    best = max(scores, key=scores.get)

    if scores[best] == 0:
        return "access_control_general", "manual_review_required"

    policy_map = {
        "tenant_boundary_bypass": "tenant_match",
        "role_bypass": "role_required",
        "id_tampering": "owner_match",
        "ownership_check_missing": "owner_match",
    }

    return best, policy_map[best]

def build_document(cve):
    cve_id = cve.get("id")
    description = get_description(cve)
    cwes = get_cwes(cve)
    cvss = get_cvss(cve)

    attack_pattern, recommended_policy = classify_pattern(description, cwes)

    document = f"""
CVE ID: {cve_id}

This vulnerability is related to API or application access control.

Original description:
{description}

Weakness classification:
{", ".join(cwes) if cwes else "unknown"}

Interpreted attack pattern:
{attack_pattern}

Recommended BLADE policy template:
{recommended_policy}

Security meaning:
An authenticated user may access or modify a resource without proper object-level authorization.
The defense should verify the relationship between the requester and the target resource.

Recommended validation:
- Identify subject from JWT claims (sub, user_id, role, tenant_id)
- Extract target object identifier from path, query, or request body
- Query ownership or permission relation store
- Allow only if required relation is satisfied
""".strip()

    metadata = {
        "cve_id": cve_id,
        "published": cve.get("published", ""),
        "lastModified": cve.get("lastModified", ""),
        "cwes": ", ".join(cwes),
        "attack_pattern": attack_pattern,
        "recommended_policy": recommended_policy,
        # None이면 0.0으로 저장 (ChromaDB는 None 불가)
        "cvss_score": float(cvss["score"]) if cvss["score"] is not None else 0.0,
        "cvss_available": str(cvss["score"] is not None),
        "severity": cvss["severity"] if cvss["severity"] else "UNKNOWN",
        "source": "NVD",
    }

    return {
        "id": cve_id,
        "document": document,
        "metadata": metadata,
    }

def main():
    with open(IN_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)

    docs = []
    for item in items:
        cve = item["cve"]
        docs.append(build_document(cve))

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(docs, f, ensure_ascii=False, indent=2)

    print(f"문서 변환 완료: {OUT_PATH}")
    print(f"총 문서 개수: {len(docs)}")

    # 패턴 분포 확인
    from collections import Counter
    patterns = Counter(d["metadata"]["attack_pattern"] for d in docs)
    print("\n패턴 분포:")
    for pattern, count in patterns.most_common():
        print(f"  {pattern}: {count}개")

if __name__ == "__main__":
    main()