"""CISA KEV (Known Exploited Vulnerabilities) fetcher."""

from __future__ import annotations

from typing import Any

from blade.sources._http import safe_get

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def fetch() -> list[dict[str, Any]]:
    print("[CISA KEV] ...")
    resp = safe_get(CISA_KEV_URL, timeout=60)
    if resp is None:
        return []
    try:
        data = resp.json()
    except Exception as exc:
        print(f"  [warn] CISA JSON parse failed: {exc}")
        return []

    collected: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", []) or []:
        try:
            short = (v.get("shortDescription") or "").lower()
            if "object" not in short and "authorization" not in short:
                continue
            cve_id = v.get("cveID") or ""
            if not cve_id:
                continue
            collected.append(
                {
                    "id": f"cisa-{cve_id}",
                    "source": "cisa",
                    "cve_id": cve_id,
                    "title": v.get("vulnerabilityName", ""),
                    "description": v.get("shortDescription", ""),
                    "cwe_id": "",
                    "severity": "",
                    "cvss_score": 0.0,
                    "attack_vector": "",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "updated_at": v.get("dateAdded", ""),
                }
            )
        except Exception as exc:
            print(f"  [warn] cisa entry skipped: {exc}")
    print(f"[CISA KEV] -> {len(collected)}")
    return collected
