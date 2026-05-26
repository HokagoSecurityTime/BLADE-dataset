"""OWASP API Security Top 10 - API1:2023 BOLA 정의 문서 fetcher."""

from __future__ import annotations

from typing import Any

from blade.sources._http import safe_get

OWASP_API_BASE = (
    "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/"
)

OWASP_API_DOCS = [
    (
        "owasp-api1-2023",
        "OWASP API1:2023 - Broken Object Level Authorization",
        "0xa1-broken-object-level-authorization.md",
        "nested_resource_idor",
    ),
]


def fetch() -> list[dict[str, Any]]:
    print("[OWASP API] ...")
    collected: list[dict[str, Any]] = []
    for doc_id, title, fname, default_pattern in OWASP_API_DOCS:
        url = OWASP_API_BASE + fname
        resp = safe_get(url, timeout=30)
        if resp is None:
            continue
        text = (resp.text or "").strip()
        if not text:
            continue
        collected.append(
            {
                "id": doc_id,
                "source": "owasp_api",
                "cve_id": "",
                "title": title,
                "description": text,
                "cwe_id": "CWE-639",
                "severity": "",
                "cvss_score": 0.0,
                "attack_vector": "NETWORK",
                "url": url,
                "updated_at": "",
                "_preclassified": {
                    "endpoint_pattern": "unknown",
                    "id_type": "unknown",
                    "ownership_check_missing": "path",
                    "attack_method": "idor",
                    "bola_pattern": default_pattern,
                    "rule_based_detectable": True,
                    "inference_required": False,
                    "reason": "OWASP API1:2023 canonical BOLA definition document",
                },
            }
        )
    print(f"[OWASP API] -> {len(collected)}")
    return collected
