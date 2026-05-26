"""규칙 기반 enrichment.

3 트랙 통합:
- B `cve_fetcher.rule_based_classify` → bola_pattern (가이드 7 종) 분류
- C `enrich_nvd.infer_*` → ownership_type / attack_method / domain / business_logic_complexity
- A `03_build_documents.classify_pattern` → policy_template_hint (정책 템플릿 매핑)

raw item + 분류 결과를 합쳐 enriched dict 를 반환한다.
"""

from __future__ import annotations

import re
from typing import Any

# --- 정규식 ------------------------------------------------------------

_METHOD_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s,'\"`)>\]]+)", re.I
)
_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(/[a-z0-9_\-]+(?:/[\w\-{}]+){1,5})", re.I)
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)


# --- C 트랙 도메인/리소스 ---------------------------------------------

_DOMAIN_HINTS = {
    "ecommerce": ["cart", "order", "payment", "invoice", "product", "shop"],
    "healthcare": ["patient", "medical", "health", "doctor", "clinical"],
    "banking": ["bank", "account", "transfer", "transaction", "finance"],
    "hr": ["employee", "salary", "payroll", "staff"],
    "saas": ["tenant", "organization", "subscription", "workspace"],
    "social": ["post", "comment", "friend", "profile", "message"],
}


def infer_domain(text: str) -> str:
    t = text.lower()
    for domain, keywords in _DOMAIN_HINTS.items():
        if any(k in t for k in keywords):
            return domain
    return "generic"


# --- endpoint / id ----------------------------------------------------


def detect_endpoint(text: str) -> str:
    m = _METHOD_PATH_RE.search(text)
    if m:
        return f"{m.group(1).upper()} {m.group(2).rstrip('.,);')}"
    m2 = _PATH_RE.search(text)
    if m2:
        return f"GET {m2.group(1).rstrip('.,);')}"
    return ""


def detect_http_method(desc: str) -> str:
    d = desc.lower()
    methods: list[str] = []
    if any(w in d for w in ["view", "read", "access", "disclose", "retrieve", "get ", "list", "expose", "leak"]):
        methods.append("GET")
    if any(w in d for w in ["modif", "edit", "update", "change", "alter", "set "]):
        methods.append("PUT")
    if any(w in d for w in ["delete", "remov"]):
        methods.append("DELETE")
    if any(w in d for w in ["creat", "submit", "add ", "upload", "post "]):
        methods.append("POST")
    return "/".join(dict.fromkeys(methods)) if methods else "GET"


def detect_id_type(text: str) -> str:
    d = text.lower()
    if any(w in d for w in ["query param", "query string", "?id=", "?pid=", "?user_id="]):
        return "query_param"
    if any(w in d for w in ["post body", "request body", "form data", "json body", "body param"]):
        return "body_param"
    return "path_param"


def detect_id_format(text: str) -> str:
    d = text.lower()
    if "uuid" in d or "guid" in d or _UUID_RE.search(text):
        return "uuid"
    if any(w in d for w in ["sequential", "integer id", "numeric id", "incremental", "auto-increment", "guessable"]):
        return "integer_sequential"
    if any(w in d for w in ["username", "email", "slug", "name-based"]):
        return "string_slug"
    return ""


# --- C 트랙 ownership / attack_method (5+3 종) ------------------------


def infer_ownership_type(desc: str, cwe: str = "") -> str:
    d = desc.lower()
    if any(w in d for w in ["admin", "role", "privilege", "permission level", "rbac"]):
        return "role_based"
    if any(w in d for w in ["organization", "tenant", "company", "department", "group member", "org member"]):
        return "hierarchical"
    if any(w in d for w in ["sender", "recipient", "shared with", "delegat"]):
        return "delegated"
    if any(w in d for w in ["context", "workflow", "draft", "published"]):
        return "contextual"
    return "direct"


def infer_attack_method(desc: str) -> str:
    d = desc.lower()
    if any(w in d for w in ["enumerat", "brute force", "sequential", "iterate", "increment"]):
        return "id_enumeration"
    if any(w in d for w in ["tamper", "forge", "craft", "manipulat", "alter", "modif"]):
        return "parameter_tampering"
    if "mass assignment" in d or "mass-assignment" in d:
        return "mass_assignment"
    return "id_substitution"


def infer_rule_type(cwe: str, ownership_type: str) -> str:
    cwes = set(cwe.upper().split("|"))
    if "CWE-284" in cwes or "CWE-863" in cwes:
        return "block_path"
    if ownership_type == "role_based":
        return "block_path"
    return "jwt_ownership"


def infer_complexity(ownership_type: str, severity_score: float) -> int:
    base = {
        "direct": 2, "delegated": 3, "contextual": 3,
        "role_based": 4, "hierarchical": 4,
    }.get(ownership_type, 3)
    if severity_score >= 9.0:
        base = min(base + 1, 5)
    return base


# --- B 트랙 bola_pattern (가이드 7 종) ---------------------------------


def detect_bola_pattern(
    description: str,
    title: str = "",
    *,
    id_format: str = "",
) -> tuple[str, str, int]:
    """Returns (bola_pattern, reason, confidence_0_to_3).

    confidence < 2 면 호출 측이 LLM 으로 위임할지 판단.
    """
    text = f"{description} {title}".lower()
    if not text.strip():
        return "", "", 0

    if "mass assignment" in text or "mass-assignment" in text:
        return "mass_assignment", "Description mentions mass assignment", 3
    if re.search(r"\badmin(\s+(panel|endpoint|path|interface|api))?\b", text) and (
        "/admin" in text or "expose" in text or "unauthorized" in text or "without auth" in text
    ):
        return "admin_path_exposure", "Admin endpoint exposed without proper auth", 3
    if re.search(r"\b(batch|bulk)\b", text) and (
        "idor" in text or "object" in text or "validation" in text or "any user" in text
    ):
        return "batch_unvalidated", "Batch/bulk endpoint without per-item ownership check", 2
    if "filter" in text and re.search(r"\b(param|parameter|query|bypass)\b", text):
        return "filter_param_bypass", "Filter/query parameter can be bypassed", 2
    if id_format == "uuid" and ("idor" in text or "direct object" in text or "any user" in text):
        return "uuid_idor", "IDOR via UUID identifier", 2
    if id_format == "integer_sequential" and re.search(
        r"\b(enumerat|incremental|sequential|guess|brute)", text
    ):
        return "integer_id_enumeration", "Sequential integer IDs allow enumeration", 3
    if any(k in text for k in ["broken object level authorization", "insecure direct object reference", "idor", "bola"]):
        if id_format == "integer_sequential":
            return "integer_id_enumeration", "BOLA/IDOR with integer identifier", 2
        return "nested_resource_idor", "IDOR/BOLA keyword present without specific identifier type", 1
    return "", "", 0


# --- A 트랙 policy_template_hint -------------------------------------


def suggest_policy_template(description: str, cwes: str) -> str:
    """A 의 점수 기반 4-카테고리 분류 → 정책 템플릿 6 종으로 매핑."""
    text = description.lower()
    cwe_set = set(cwes.upper().split("|"))

    scores = {
        "tenant_match": 0,
        "role_required": 0,
        "owner_match": 0,
    }
    for kw in ["tenant", "organization", "workspace", "multi-tenant"]:
        if kw in text:
            scores["tenant_match"] += 2
    for kw in ["privilege escalation", "admin", "role", "permission"]:
        if kw in text:
            scores["role_required"] += 2
    for kw in ["idor", "insecure direct object", "object level", "bola"]:
        if kw in text:
            scores["owner_match"] += 3
    if " id " in text or "identifier" in text:
        scores["owner_match"] += 1

    if "CWE-639" in cwe_set:
        scores["owner_match"] += 3
    if "CWE-862" in cwe_set or "CWE-863" in cwe_set:
        scores["owner_match"] += 3
    if "CWE-284" in cwe_set or "CWE-285" in cwe_set:
        scores["role_required"] += 2

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return "manual_review_required"
    return best


# --- 통합 ---------------------------------------------------------------


def classify(item: dict[str, Any]) -> dict[str, Any] | None:
    """raw item → enrichment dict.

    confidence 가 낮으면 None 을 반환해 LLM 으로 위임. _preclassified 가 붙어있으면
    그 결과를 그대로 신뢰하고 부족한 필드만 규칙으로 보강한다.
    """
    description = (item.get("description") or "").strip()
    title = (item.get("title") or "").strip()
    cwe = item.get("cwe_id") or ""
    severity_score = float(item.get("cvss_score") or 0.0)

    pre = item.get("_preclassified") or {}

    text = f"{description} {title}"
    endpoint = pre.get("endpoint_pattern") or detect_endpoint(text)
    method = detect_http_method(description) if not pre.get("endpoint_pattern") else (endpoint.split()[0] if endpoint and " " in endpoint else "")
    id_type = pre.get("id_type") or detect_id_type(description)
    id_format = pre.get("id_format") or detect_id_format(description)
    ownership_type = pre.get("ownership_type") or infer_ownership_type(description, cwe)
    attack_method = pre.get("attack_method") or infer_attack_method(description)
    rule_type = pre.get("rule_type") or infer_rule_type(cwe, ownership_type)
    domain = pre.get("domain") or infer_domain(text)
    complexity = pre.get("business_logic_complexity") or infer_complexity(ownership_type, severity_score)
    owasp = pre.get("owasp_mapping") or "API1:2023"
    policy_hint = suggest_policy_template(description, cwe)

    bola_pattern = pre.get("bola_pattern") or ""
    reason = pre.get("reason") or ""
    confidence = 3 if pre else 0

    if not bola_pattern:
        bp, rsn, conf = detect_bola_pattern(description, title, id_format=id_format)
        if bp:
            bola_pattern = bp
            reason = rsn
            confidence = conf

    if confidence < 2 and not pre:
        # 호출 측이 LLM 위임 결정
        return None

    rule_based = bool(pre.get("rule_based_detectable")) if pre else (
        rule_type == "jwt_ownership" and id_type == "path_param" and ownership_type == "direct"
    )
    inference_required = bool(pre.get("inference_required", not rule_based))

    return {
        "endpoint_pattern": endpoint,
        "http_method": method,
        "id_type": id_type,
        "id_format": id_format,
        "ownership_type": ownership_type,
        "ownership_check_missing": pre.get("ownership_check_missing") or "",
        "attack_method": attack_method,
        "bola_pattern": bola_pattern,
        "rule_type": rule_type,
        "rule_based_detectable": rule_based,
        "inference_required": inference_required,
        "business_logic_complexity": complexity,
        "domain": domain,
        "owasp_mapping": owasp,
        "policy_template_hint": policy_hint,
        "reason": reason,
        "enrichment_method": "preclassified" if pre else "rule",
    }
