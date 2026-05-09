"""OWASP WSTG Authorization Testing (ATHZ-01~04) fetcher."""

from __future__ import annotations

from typing import Any

from blade.sources._http import safe_get

WSTG_BASE = (
    "https://raw.githubusercontent.com/OWASP/wstg/master/document/"
    "4-Web_Application_Security_Testing/05-Authorization_Testing/"
)

WSTG_DOCS = [
    ("wstg-ATHZ-01", "WSTG-ATHZ-01: Testing Directory Traversal File Include",
     "01-Testing_Directory_Traversal_File_Include.md", "filter_param_bypass"),
    ("wstg-ATHZ-02", "WSTG-ATHZ-02: Testing for Bypassing Authorization Schema",
     "02-Testing_for_Bypassing_Authorization_Schema.md", "admin_path_exposure"),
    ("wstg-ATHZ-03", "WSTG-ATHZ-03: Testing for Privilege Escalation",
     "03-Testing_for_Privilege_Escalation.md", "mass_assignment"),
    ("wstg-ATHZ-04", "WSTG-ATHZ-04: Testing for Insecure Direct Object References",
     "04-Testing_for_Insecure_Direct_Object_References.md", "nested_resource_idor"),
]


def fetch() -> list[dict[str, Any]]:
    print("[OWASP WSTG] ...")
    collected: list[dict[str, Any]] = []
    for doc_id, title, fname, default_pattern in WSTG_DOCS:
        url = WSTG_BASE + fname
        resp = safe_get(url, timeout=30)
        if resp is None:
            continue
        text = (resp.text or "").strip()
        if not text:
            continue
        collected.append(
            {
                "id": doc_id,
                "source": "wstg",
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
                    "reason": f"OWASP WSTG authorization testing reference: {title}",
                },
            }
        )
    print(f"[OWASP WSTG] -> {len(collected)}")
    return collected
