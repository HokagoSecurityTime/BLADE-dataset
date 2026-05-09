"""NVD CVE fetcher.

C 트랙(`nvd_bulk_collector.py`) 의 CWE 기반 대량 수집을 base 로 채택.
A 트랙(`01_fetch_cve.py`) 의 키워드 검색을 옵션 모드로 통합.
B 트랙(`cve_fetcher.fetch_nvd`) 의 None-safe 추출 헬퍼를 흡수.
"""

from __future__ import annotations

import time
from typing import Any

from blade import config
from blade.sources._http import safe_get

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_CWES = ["CWE-639", "CWE-862", "CWE-284", "CWE-285", "CWE-863"]
DEFAULT_KEYWORDS = [
    "broken object level authorization",
    "insecure direct object reference IDOR",
    "object level authorization API",
]

RESULTS_PER_PAGE = 100
SLEEP_AUTHENTICATED = 0.7
SLEEP_UNAUTHENTICATED = 6.5


# --- raw 추출 헬퍼 (B 의 None-safe 패턴 채택) -----------------------------


def _description(cve: dict) -> str:
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return (d.get("value") or "").strip()
    return ""


def _cwes(cve: dict) -> list[str]:
    out: list[str] = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                out.append(v)
    # dedupe, preserve order
    seen: set[str] = set()
    uniq: list[str] = []
    for c in out:
        if c not in seen:
            seen.add(c)
            uniq.append(c)
    return uniq


def _cvss(cve: dict) -> tuple[float, str, str]:
    """(score, severity, attack_vector). 없으면 (0.0, '', '')."""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        cdata = items[0].get("cvssData", {}) or {}
        score = cdata.get("baseScore") or 0.0
        sev = cdata.get("baseSeverity") or items[0].get("baseSeverity") or ""
        av = cdata.get("attackVector", "")
        try:
            return float(score), sev, av
        except (TypeError, ValueError):
            return 0.0, sev, av
    return 0.0, "", ""


def _to_raw(cve: dict) -> dict[str, Any] | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    cwes = _cwes(cve)
    score, sev, av = _cvss(cve)
    return {
        "id": f"nvd-{cve_id}",
        "source": "nvd",
        "cve_id": cve_id,
        "title": cve_id,
        "description": _description(cve),
        "cwe_id": "|".join(cwes),
        "severity": sev,
        "cvss_score": score,
        "attack_vector": av,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "updated_at": cve.get("lastModified", ""),
    }


# --- 페이지 수집 --------------------------------------------------------


def _headers(api_key: str | None) -> dict[str, str]:
    return {"apiKey": api_key} if api_key else {}


def _fetch_page(params: dict[str, Any], api_key: str | None) -> dict | None:
    resp = safe_get(
        NVD_URL,
        params=params,
        headers=_headers(api_key),
        timeout=60,
        retries=5,
        backoff=10.0,
    )
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception as exc:
        print(f"  [warn] NVD JSON parse failed: {exc}")
        return None


def _paginate(
    base_params: dict[str, Any],
    api_key: str | None,
    *,
    label: str,
) -> list[dict]:
    sleep = SLEEP_AUTHENTICATED if api_key else SLEEP_UNAUTHENTICATED
    items: list[dict] = []
    start = 0
    while True:
        params = {**base_params, "resultsPerPage": RESULTS_PER_PAGE, "startIndex": start}
        data = _fetch_page(params, api_key)
        if not data:
            break
        page = data.get("vulnerabilities", []) or []
        total = data.get("totalResults", 0)
        items.extend(page)
        print(f"    {label} progress: {min(start + RESULTS_PER_PAGE, total)}/{total}")
        if not page or start + RESULTS_PER_PAGE >= total:
            break
        start += RESULTS_PER_PAGE
        time.sleep(sleep)
    return items


# --- public ------------------------------------------------------------


def fetch_by_cwe(
    cwes: list[str] | None = None,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """CWE ID 별로 수집 (C 트랙). 양 위주 — BOLA 5 종 CWE 기본."""
    cwes = cwes or DEFAULT_CWES
    api_key = api_key or config.NVD_API_KEY
    print(f"[NVD/CWE] {cwes}  api_key={'yes' if api_key else 'no'}")

    seen: dict[str, dict] = {}
    for cwe in cwes:
        print(f"  - cweId: {cwe}")
        page_items = _paginate({"cweId": cwe}, api_key, label=cwe)
        for entry in page_items:
            cve = entry.get("cve", {}) or {}
            cve_id = cve.get("id")
            if cve_id and cve_id not in seen:
                seen[cve_id] = cve

    raws: list[dict] = []
    for cve in seen.values():
        r = _to_raw(cve)
        if r:
            raws.append(r)
    print(f"[NVD/CWE] -> {len(raws)} unique CVEs")
    return raws


def fetch_by_keyword(
    keywords: list[str] | None = None,
    api_key: str | None = None,
) -> list[dict[str, Any]]:
    """키워드 기반 수집 (A 트랙). 자연어 매칭 — recall 보강용."""
    keywords = keywords or DEFAULT_KEYWORDS
    api_key = api_key or config.NVD_API_KEY
    print(f"[NVD/keyword] {keywords}  api_key={'yes' if api_key else 'no'}")

    seen: dict[str, dict] = {}
    for kw in keywords:
        print(f"  - keyword: {kw!r}")
        page_items = _paginate({"keywordSearch": kw}, api_key, label=kw)
        for entry in page_items:
            cve = entry.get("cve", {}) or {}
            cve_id = cve.get("id")
            if cve_id and cve_id not in seen:
                seen[cve_id] = cve

    raws: list[dict] = []
    for cve in seen.values():
        r = _to_raw(cve)
        if r:
            raws.append(r)
    print(f"[NVD/keyword] -> {len(raws)} unique CVEs")
    return raws


def fetch(
    *,
    mode: str = "cwe",
    api_key: str | None = None,
    cwes: list[str] | None = None,
    keywords: list[str] | None = None,
) -> list[dict[str, Any]]:
    """통합 진입점. mode = 'cwe' | 'keyword' | 'both'."""
    if mode == "cwe":
        return fetch_by_cwe(cwes=cwes, api_key=api_key)
    if mode == "keyword":
        return fetch_by_keyword(keywords=keywords, api_key=api_key)
    if mode == "both":
        a = fetch_by_cwe(cwes=cwes, api_key=api_key)
        b = fetch_by_keyword(keywords=keywords, api_key=api_key)
        seen = {x["id"] for x in a}
        return a + [x for x in b if x["id"] not in seen]
    raise ValueError(f"unknown NVD fetch mode: {mode!r}")
