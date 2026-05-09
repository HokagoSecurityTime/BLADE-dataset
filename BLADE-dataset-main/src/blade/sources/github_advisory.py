"""GitHub Advisory Database (CWE-639) fetcher."""

from __future__ import annotations

import os
import re
from typing import Any

from blade import config
from blade.sources._http import safe_get

GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


def fetch(token: str | None = None) -> list[dict[str, Any]]:
    print("[GitHub Advisories] CWE-639 ...")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = token or config.GITHUB_TOKEN or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        print("  [info] GITHUB_TOKEN not set — unauthenticated rate limit")

    collected: list[dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        params = {"cwes": "CWE-639", "per_page": per_page, "page": page}
        resp = safe_get(GITHUB_ADVISORY_URL, params=params, headers=headers, timeout=30)
        if resp is None:
            break
        try:
            items = resp.json()
        except Exception as exc:
            print(f"  [warn] github JSON parse failed: {exc}")
            break
        if not isinstance(items, list) or not items:
            break

        for adv in items:
            try:
                ghsa_id = adv.get("ghsa_id")
                if not ghsa_id:
                    continue
                cvss = adv.get("cvss") if isinstance(adv.get("cvss"), dict) else {}
                cvss_score = cvss.get("score") or 0.0
                attack_vector = ""
                vector = (cvss or {}).get("vector_string") or ""
                m = re.search(r"AV:([NALP])", vector)
                if m:
                    attack_vector = {
                        "N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"
                    }.get(m.group(1), "")
                cwes = adv.get("cwes") or []
                cwe_id = cwes[0].get("cwe_id") if (cwes and isinstance(cwes, list)) else "CWE-639"

                collected.append(
                    {
                        "id": f"github-{ghsa_id}",
                        "source": "github",
                        "cve_id": adv.get("cve_id") or "",
                        "title": adv.get("summary", "") or "",
                        "description": adv.get("description", "") or adv.get("summary", ""),
                        "cwe_id": cwe_id or "CWE-639",
                        "severity": (adv.get("severity") or "").upper(),
                        "cvss_score": float(cvss_score) if cvss_score else 0.0,
                        "attack_vector": attack_vector,
                        "url": adv.get("html_url", ""),
                        "updated_at": adv.get("updated_at", ""),
                    }
                )
            except Exception as exc:
                print(f"  [warn] github advisory skipped: {exc}")

        print(f"  page {page}: cumulative {len(collected)}")
        if len(items) < per_page:
            break
        page += 1

    print(f"[GitHub Advisories] -> {len(collected)}")
    return collected
