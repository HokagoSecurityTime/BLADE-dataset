"""CAPEC: BOLA 와 직접 관련된 공격 패턴 (정적 큐레이션).

MITRE 가 깔끔한 per-entry API 를 제공하지 않아 정적으로 큐레이션한다.
"""

from __future__ import annotations

from typing import Any

CAPEC_ENTRIES = [
    {
        "capec_id": "CAPEC-1",
        "name": "Accessing Functionality Not Properly Constrained by ACLs",
        "description": (
            "An attacker exploits a weakness in access control to gain access to functionality "
            "that should be restricted. ACLs may be unconfigured, misconfigured, or use overly "
            "permissive defaults, allowing unauthorized callers to invoke privileged operations."
        ),
        "bola_pattern": "admin_path_exposure",
    },
    {
        "capec_id": "CAPEC-39",
        "name": "Manipulating Opaque Client-based Data Tokens",
        "description": (
            "The adversary modifies client-side identifiers (URL parameters, hidden fields, "
            "cookies) that the server trusts as opaque, in order to access another user's data. "
            "The classic IDOR pattern: change /orders/1001 to /orders/1002."
        ),
        "bola_pattern": "integer_id_enumeration",
    },
    {
        "capec_id": "CAPEC-58",
        "name": "Restful Privilege Elevation",
        "description": (
            "An attacker invokes RESTful methods (PUT, DELETE, PATCH) that the application did "
            "not expect to be exposed, or accesses object IDs that belong to other users, due "
            "to missing per-method per-object authorization checks."
        ),
        "bola_pattern": "nested_resource_idor",
    },
    {
        "capec_id": "CAPEC-122",
        "name": "Privilege Abuse",
        "description": (
            "A legitimate user uses a granted privilege to perform an unintended action that the "
            "authorization model didn't anticipate, e.g., a regular user calling an admin-only "
            "endpoint that wasn't gated, or escalating their own role via mass-assignment."
        ),
        "bola_pattern": "mass_assignment",
    },
    {
        "capec_id": "CAPEC-180",
        "name": "Exploiting Incorrectly Configured Access Control Security Levels",
        "description": (
            "An attacker takes advantage of incorrectly configured access control to read or "
            "modify resources owned by other users. Caused by missing ownership predicate "
            "(e.g., WHERE owner_id = ?) in the authorization layer."
        ),
        "bola_pattern": "nested_resource_idor",
    },
]


def fetch() -> list[dict[str, Any]]:
    print("[CAPEC] static curation ...")
    collected: list[dict[str, Any]] = []
    for entry in CAPEC_ENTRIES:
        capec_id = entry["capec_id"]
        num = capec_id.split("-", 1)[1]
        collected.append(
            {
                "id": f"capec-{capec_id}",
                "source": "capec",
                "cve_id": "",
                "title": f"{capec_id}: {entry['name']}",
                "description": entry["description"],
                "cwe_id": "CWE-639",
                "severity": "",
                "cvss_score": 0.0,
                "attack_vector": "NETWORK",
                "url": f"https://capec.mitre.org/data/definitions/{num}.html",
                "updated_at": "",
                "_preclassified": {
                    "endpoint_pattern": "unknown",
                    "id_type": "unknown",
                    "ownership_check_missing": "path",
                    "attack_method": "idor",
                    "bola_pattern": entry["bola_pattern"],
                    "rule_based_detectable": True,
                    "inference_required": False,
                    "reason": f"CAPEC reference: {entry['name']}",
                },
            }
        )
    print(f"[CAPEC] -> {len(collected)}")
    return collected
