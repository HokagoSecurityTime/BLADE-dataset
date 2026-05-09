"""BOLA/IDOR 데이터 수집 + LLM enrichment 파이프라인.

여러 소스에서 BOLA/IDOR 관련 취약점/지식 문서를 수집하고,
규칙 기반으로 1차 분류 → 모호한 항목만 llama3.2:3b 로 enrichment 후
dataset/bola_dataset.json 으로 가이드 §3 스키마({id, document, metadata})로 저장한다.

소스:
    1. NVD API
    2. HackerOne 공개 리포트 (스크래핑)
    3. GitHub Advisory Database
    4. CISA KEV
    5. OWASP API Security (API1:2023 BOLA 정의 문서)
    6. OWASP WSTG ATHZ-01~04 (Authorization Testing 가이드)
    7. CAPEC (큐레이션된 공격 패턴 정의)
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# --- 상수 -----------------------------------------------------------------

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HACKERONE_URL = "https://hackerone.com/hacktivity"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
OWASP_API_BASE = (
    "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/"
)
WSTG_BASE = (
    "https://raw.githubusercontent.com/OWASP/wstg/master/document/"
    "4-Web_Application_Security_Testing/05-Authorization_Testing/"
)
OLLAMA_GENERATE_URL = "http://localhost:11434/api/generate"
LLM_MODEL = "llama3.2:3b"
LLM_TIMEOUT = 300  # seconds — 첫 로드 + 긴 description 대비
LLM_KEEP_ALIVE = "10m"  # 모델을 메모리에 유지해 재로딩 비용 제거

NVD_KEYWORDS = [
    "broken object level authorization",
    "insecure direct object reference IDOR",
]

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "bola_dataset.json"

ENRICHMENT_PROMPT = """You are a security analyst. Given the vulnerability description below, classify it as a BOLA/IDOR pattern and respond with ONLY a single JSON object (no prose, no markdown fence).

Description:
{description}

CWE: {cwe_id}
Severity: {severity}

Required JSON fields:
- endpoint_pattern: vulnerable endpoint pattern, e.g. "GET /users/{{id}}"; use "unknown" if not inferrable
- id_type: one of integer | uuid | slug | unknown
- ownership_check_missing: one of path | query | body | unknown
- attack_method: one of enumeration | idor | mass_assignment | filter_bypass | batch | admin_exposure
- bola_pattern: one of integer_id_enumeration | nested_resource_idor | mass_assignment | filter_param_bypass | batch_unvalidated | admin_path_exposure | uuid_idor
- rule_based_detectable: true or false
- inference_required: true or false
- reason: one short sentence (English) justifying the classification

Return JSON only.
"""


# --- HTTP 헬퍼 -------------------------------------------------------------


def _safe_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> requests.Response | None:
    """예외를 흡수하는 GET 래퍼."""
    try:
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        r.raise_for_status()
        return r
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] GET {url} failed: {exc}")
        return None


# --- NVD --------------------------------------------------------------------


def fetch_nvd(api_key: str | None = None) -> list[dict[str, Any]]:
    """NVD API 에서 BOLA/IDOR 관련 CVE 수집."""
    print("[1/7] Fetching NVD ...")
    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key
    sleep_sec = 0.6 if not api_key else 0.0

    collected: list[dict[str, Any]] = []
    seen_cve: set[str] = set()

    for keyword in NVD_KEYWORDS:
        print(f"  - keyword: {keyword!r}")
        start_index = 0
        results_per_page = 100
        while True:
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
            }
            resp = _safe_get(NVD_URL, params=params, headers=headers, timeout=60)
            if resp is None:
                break
            try:
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                print(f"    [warn] NVD JSON parse failed: {exc}")
                break

            vulns = data.get("vulnerabilities", []) or []
            if not vulns:
                break

            for entry in vulns:
                try:
                    cve = entry.get("cve", {}) or {}
                    cve_id = cve.get("id")
                    if not cve_id or cve_id in seen_cve:
                        continue
                    seen_cve.add(cve_id)

                    descriptions = cve.get("descriptions", []) or []
                    description = next(
                        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                        "",
                    )

                    weaknesses = cve.get("weaknesses", []) or []
                    cwe_id = ""
                    for w in weaknesses:
                        for d in w.get("description", []) or []:
                            v = d.get("value", "")
                            if v.startswith("CWE-"):
                                cwe_id = v
                                break
                        if cwe_id:
                            break

                    metrics = cve.get("metrics", {}) or {}
                    cvss_score: float | None = None
                    severity = ""
                    attack_vector = ""
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        items = metrics.get(key) or []
                        if not items:
                            continue
                        cdata = items[0].get("cvssData", {}) or {}
                        cvss_score = cdata.get("baseScore")
                        severity = (
                            cdata.get("baseSeverity")
                            or items[0].get("baseSeverity")
                            or ""
                        )
                        attack_vector = cdata.get("attackVector", "")
                        break

                    collected.append(
                        {
                            "id": f"nvd-{cve_id}",
                            "source": "nvd",
                            "cve_id": cve_id,
                            "title": cve_id,
                            "description": description,
                            "cwe_id": cwe_id,
                            "severity": severity,
                            "cvss_score": cvss_score,
                            "attack_vector": attack_vector,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "updated_at": cve.get("lastModified", ""),
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    print(f"    [warn] NVD entry skipped: {exc}")
                    continue

            total_results = data.get("totalResults", 0)
            start_index += results_per_page
            print(
                f"    progress: {min(start_index, total_results)}/{total_results}"
            )
            if start_index >= total_results:
                break
            if sleep_sec:
                time.sleep(sleep_sec)

        if sleep_sec:
            time.sleep(sleep_sec)

    print(f"  -> NVD collected: {len(collected)}")
    return collected


# --- HackerOne --------------------------------------------------------------


def _build_chrome_driver() -> webdriver.Chrome:
    """헤드리스 Chrome 드라이버 생성 (Selenium Manager 가 chromedriver 자동 해결)."""
    opts = ChromeOptions()
    opts.add_argument("--headless=new")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1920,1080")
    opts.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    )
    opts.add_experimental_option("excludeSwitches", ["enable-automation"])
    opts.add_experimental_option("useAutomationExtension", False)
    return webdriver.Chrome(options=opts)


def fetch_hackerone(
    max_scrolls: int = 15, scroll_pause: float = 2.0, wait_seconds: int = 20
) -> list[dict[str, Any]]:
    """HackerOne hacktivity 를 Selenium 으로 스크래핑.

    페이지가 React 로 렌더링돼서 requests + BS4 로는 빈 결과가 나오므로
    headless Chrome 으로 JS 실행 후 무한스크롤하며 리포트 카드를 수집한다.
    """
    print("[2/7] Fetching HackerOne (Selenium) ...")
    target = f"{HACKERONE_URL}?querystring=IDOR&disclosed=true"

    driver: webdriver.Chrome | None = None
    try:
        driver = _build_chrome_driver()
    except WebDriverException as exc:
        print(f"  [warn] Chrome driver init failed: {exc}")
        print("  -> HackerOne collected: 0")
        return []

    collected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    try:
        print(f"  GET {target}")
        driver.get(target)

        try:
            WebDriverWait(driver, wait_seconds).until(
                EC.presence_of_element_located(
                    (By.CSS_SELECTOR, "a[href*='/reports/']")
                )
            )
        except TimeoutException:
            print("  [warn] hacktivity report links did not appear in time")

        # 무한스크롤로 더 많은 카드 로드
        last_count = 0
        for i in range(max_scrolls):
            driver.execute_script(
                "window.scrollTo(0, document.body.scrollHeight);"
            )
            time.sleep(scroll_pause)
            anchors = driver.find_elements(
                By.CSS_SELECTOR, "a[href*='/reports/']"
            )
            count = len(anchors)
            print(f"  scroll {i + 1}/{max_scrolls}: {count} report anchors")
            if count == last_count:
                break
            last_count = count

        html = driver.page_source
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] Selenium scrape error: {exc}")
        html = ""
    finally:
        try:
            driver.quit()
        except Exception:  # noqa: BLE001
            pass

    if not html:
        print("  -> HackerOne collected: 0")
        return []

    soup = BeautifulSoup(html, "html.parser")
    for link in soup.select("a[href*='/reports/']"):
        try:
            href = link.get("href") or ""
            m = re.search(r"/reports/(\d+)", href)
            if not m:
                continue
            report_id = m.group(1)
            if report_id in seen_ids:
                continue
            seen_ids.add(report_id)

            title = (link.get_text(strip=True) or "").strip()
            if not title:
                continue

            url = href if href.startswith("http") else f"https://hackerone.com{href}"

            # severity 는 카드 내부 어딘가의 'severity' 클래스 element 에서 추출 시도
            severity = ""
            container = link.find_parent(["article", "li", "div"]) or link
            sev_tag = container.find(class_=re.compile("severity", re.I))
            if sev_tag is not None:
                severity = sev_tag.get_text(strip=True)

            collected.append(
                {
                    "id": f"hackerone-{report_id}",
                    "source": "hackerone",
                    "cve_id": "",
                    "title": title,
                    "description": title,
                    "cwe_id": "CWE-639",
                    "severity": severity,
                    "cvss_score": None,
                    "attack_vector": "NETWORK",
                    "url": url,
                    "updated_at": "",
                }
            )
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] hackerone entry skipped: {exc}")
            continue

    print(f"  -> HackerOne collected: {len(collected)}")
    return collected


# --- GitHub Advisory --------------------------------------------------------


def fetch_github_advisories(token: str | None = None) -> list[dict[str, Any]]:
    """GitHub Advisory Database 에서 CWE-639 advisories 수집."""
    print("[3/7] Fetching GitHub Advisories (CWE-639) ...")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = token or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    else:
        print("  [info] GITHUB_TOKEN not set — using unauthenticated rate limit")

    collected: list[dict[str, Any]] = []
    page = 1
    per_page = 100

    while True:
        params = {"cwes": "CWE-639", "per_page": per_page, "page": page}
        resp = _safe_get(GITHUB_ADVISORY_URL, params=params, headers=headers, timeout=30)
        if resp is None:
            break
        try:
            items = resp.json()
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] GitHub JSON parse failed: {exc}")
            break

        if not isinstance(items, list) or not items:
            break

        for adv in items:
            try:
                ghsa_id = adv.get("ghsa_id")
                if not ghsa_id:
                    continue
                cve_id = adv.get("cve_id") or ""
                title = adv.get("summary", "") or ""
                description = adv.get("description", "") or title
                severity = (adv.get("severity") or "").upper()
                cvss = (adv.get("cvss") or {}) if isinstance(adv.get("cvss"), dict) else {}
                cvss_score = cvss.get("score")
                attack_vector = ""
                vector = cvss.get("vector_string") or ""
                m = re.search(r"AV:([NALP])", vector)
                if m:
                    attack_vector = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}.get(
                        m.group(1), ""
                    )

                cwes = adv.get("cwes") or []
                cwe_id = ""
                if cwes and isinstance(cwes, list):
                    cwe_id = cwes[0].get("cwe_id") or "CWE-639"
                else:
                    cwe_id = "CWE-639"

                collected.append(
                    {
                        "id": f"github-{ghsa_id}",
                        "source": "github",
                        "cve_id": cve_id,
                        "title": title,
                        "description": description,
                        "cwe_id": cwe_id,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "attack_vector": attack_vector,
                        "url": adv.get("html_url", ""),
                        "updated_at": adv.get("updated_at", ""),
                    }
                )
            except Exception as exc:  # noqa: BLE001
                print(f"  [warn] github advisory skipped: {exc}")
                continue

        print(f"  page {page}: cumulative {len(collected)}")
        if len(items) < per_page:
            break
        page += 1

    print(f"  -> GitHub collected: {len(collected)}")
    return collected


# --- CISA KEV ---------------------------------------------------------------


def fetch_cisa_kev() -> list[dict[str, Any]]:
    """CISA KEV 에서 'object'/'authorization' 키워드 매칭만 필터링."""
    print("[4/7] Fetching CISA KEV ...")
    resp = _safe_get(CISA_KEV_URL, timeout=60)
    if resp is None:
        print("  -> CISA collected: 0")
        return []
    try:
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] CISA JSON parse failed: {exc}")
        return []

    collected: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", []) or []:
        try:
            short_desc = (v.get("shortDescription") or "").lower()
            if "object" not in short_desc and "authorization" not in short_desc:
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
                    "cvss_score": None,
                    "attack_vector": "",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "updated_at": v.get("dateAdded", ""),
                }
            )
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] cisa entry skipped: {exc}")
            continue

    print(f"  -> CISA collected: {len(collected)}")
    return collected


# --- OWASP API Security -----------------------------------------------------

# 가이드 §1: API1:2023 BOLA 공식 정의/패턴 문서
OWASP_API_DOCS = [
    (
        "owasp-api1-2023",
        "OWASP API1:2023 - Broken Object Level Authorization",
        "0xa1-broken-object-level-authorization.md",
        "nested_resource_idor",
    ),
]


def fetch_owasp_api_security() -> list[dict[str, Any]]:
    """OWASP API Security Top 10 의 BOLA 정의 문서 수집."""
    print("[5/7] Fetching OWASP API Security ...")
    collected: list[dict[str, Any]] = []
    for doc_id, title, fname, default_pattern in OWASP_API_DOCS:
        url = OWASP_API_BASE + fname
        resp = _safe_get(url, timeout=30)
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
                "cvss_score": None,
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
    print(f"  -> OWASP API collected: {len(collected)}")
    return collected


# --- OWASP WSTG ATHZ --------------------------------------------------------

# 가이드 §1: WSTG-ATHZ-01~04 (Authorization Testing 가이드)
WSTG_DOCS = [
    (
        "wstg-ATHZ-01",
        "WSTG-ATHZ-01: Testing Directory Traversal File Include",
        "01-Testing_Directory_Traversal_File_Include.md",
        "filter_param_bypass",
    ),
    (
        "wstg-ATHZ-02",
        "WSTG-ATHZ-02: Testing for Bypassing Authorization Schema",
        "02-Testing_for_Bypassing_Authorization_Schema.md",
        "admin_path_exposure",
    ),
    (
        "wstg-ATHZ-03",
        "WSTG-ATHZ-03: Testing for Privilege Escalation",
        "03-Testing_for_Privilege_Escalation.md",
        "mass_assignment",
    ),
    (
        "wstg-ATHZ-04",
        "WSTG-ATHZ-04: Testing for Insecure Direct Object References",
        "04-Testing_for_Insecure_Direct_Object_References.md",
        "nested_resource_idor",
    ),
]


def fetch_wstg() -> list[dict[str, Any]]:
    """OWASP WSTG Authorization Testing 문서 (ATHZ-01~04) 수집."""
    print("[6/7] Fetching OWASP WSTG ATHZ ...")
    collected: list[dict[str, Any]] = []
    for doc_id, title, fname, default_pattern in WSTG_DOCS:
        url = WSTG_BASE + fname
        resp = _safe_get(url, timeout=30)
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
                "cvss_score": None,
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
    print(f"  -> WSTG collected: {len(collected)}")
    return collected


# --- CAPEC ------------------------------------------------------------------

# 가이드 §1: CAPEC 공격 패턴 분류. MITRE 가 깔끔한 per-entry API 를 제공하지
# 않아 BOLA 와 직접 관련된 항목을 큐레이션해 정적으로 포함한다.
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


def fetch_capec() -> list[dict[str, Any]]:
    """CAPEC: BOLA 와 직접 관련된 공격 패턴 정의 (정적 큐레이션)."""
    print("[7/7] Loading CAPEC entries ...")
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
                "cvss_score": None,
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
    print(f"  -> CAPEC collected: {len(collected)}")
    return collected


# --- LLM enrichment ---------------------------------------------------------


_VALID_ID_TYPE = {"integer", "uuid", "slug", "unknown"}
_VALID_OWNERSHIP = {"path", "query", "body", "unknown"}
_VALID_ATTACK = {
    "enumeration",
    "idor",
    "mass_assignment",
    "filter_bypass",
    "batch",
    "admin_exposure",
}
_VALID_PATTERN = {
    "integer_id_enumeration",
    "nested_resource_idor",
    "mass_assignment",
    "filter_param_bypass",
    "batch_unvalidated",
    "admin_path_exposure",
    "uuid_idor",
}


def _coerce_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "1", "yes"}
    return False


def _normalize_enrichment(raw: dict[str, Any]) -> dict[str, Any]:
    id_type = str(raw.get("id_type", "unknown")).lower()
    if id_type not in _VALID_ID_TYPE:
        id_type = "unknown"

    ownership = str(raw.get("ownership_check_missing", "unknown")).lower()
    if ownership not in _VALID_OWNERSHIP:
        ownership = "unknown"

    attack = str(raw.get("attack_method", "idor")).lower()
    if attack not in _VALID_ATTACK:
        attack = "idor"

    pattern = str(raw.get("bola_pattern", "nested_resource_idor")).lower()
    if pattern not in _VALID_PATTERN:
        pattern = "nested_resource_idor"

    return {
        "endpoint_pattern": str(raw.get("endpoint_pattern", "unknown")) or "unknown",
        "id_type": id_type,
        "ownership_check_missing": ownership,
        "attack_method": attack,
        "bola_pattern": pattern,
        "rule_based_detectable": _coerce_bool(raw.get("rule_based_detectable", False)),
        "inference_required": _coerce_bool(raw.get("inference_required", True)),
        "reason": str(raw.get("reason", "")).strip()[:300],
    }


def _parse_llm_json(text: str) -> dict[str, Any] | None:
    """LLM 응답에서 첫 번째 JSON 객체를 추출해 파싱."""
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        candidate = fenced.group(1)
    else:
        m = re.search(r"\{.*\}", text, re.S)
        candidate = m.group(0) if m else None
    if not candidate:
        return None
    try:
        return json.loads(candidate)
    except Exception:  # noqa: BLE001
        return None


def enrich_with_llm(item: dict[str, Any]) -> dict[str, Any] | None:
    """단일 항목을 LLM 으로 enrichment."""
    prompt = ENRICHMENT_PROMPT.format(
        description=item.get("description") or item.get("title") or "",
        cwe_id=item.get("cwe_id") or "unknown",
        severity=item.get("severity") or "unknown",
    )
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": LLM_KEEP_ALIVE,
        "options": {"temperature": 0.0, "num_predict": 256},
    }
    try:
        resp = requests.post(OLLAMA_GENERATE_URL, json=payload, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        print(f"  [warn] LLM call failed for {item.get('id')}: {exc}")
        return None

    parsed = _parse_llm_json(data.get("response", ""))
    if parsed is None:
        print(f"  [warn] LLM returned non-JSON for {item.get('id')}")
        return None
    return _normalize_enrichment(parsed)


def warmup_llm() -> bool:
    """모델을 미리 로드해 첫 호출 지연을 제거. 도달 가능하면 True."""
    print(f"  warming up LLM ({LLM_MODEL}) ... ", end="", flush=True)
    try:
        resp = requests.post(
            OLLAMA_GENERATE_URL,
            json={
                "model": LLM_MODEL,
                "prompt": "ok",
                "stream": False,
                "keep_alive": LLM_KEEP_ALIVE,
                "options": {"num_predict": 1},
            },
            timeout=LLM_TIMEOUT,
        )
        resp.raise_for_status()
        print("ready")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"failed: {exc}")
        return False


# --- 규칙 기반 사전 분류 ----------------------------------------------------

# description 에서 메서드 + 경로 추출 (예: "GET /api/v1/users/{id}")
_METHOD_PATH_RE = re.compile(
    r"\b(GET|POST|PUT|DELETE|PATCH)\s+(/[^\s,'\"`)>\]]+)", re.I
)
# 경로만 단독으로 (메서드 없이)
_PATH_RE = re.compile(r"(?<![A-Za-z0-9])(/[a-z0-9_\-]+(?:/[\w\-{}]+){1,5})", re.I)
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)


def _detect_endpoint(description: str) -> str:
    m = _METHOD_PATH_RE.search(description)
    if m:
        return f"{m.group(1).upper()} {m.group(2).rstrip('.,);')}"
    m2 = _PATH_RE.search(description)
    if m2:
        return f"GET {m2.group(1).rstrip('.,);')}"
    return "unknown"


def _detect_id_type(text: str) -> str:
    if "uuid" in text or "guid" in text or _UUID_RE.search(text):
        return "uuid"
    if "slug" in text:
        return "slug"
    if re.search(r"\b(numeric|integer|sequential|incremental)\s+id\b", text):
        return "integer"
    if re.search(r"/\{id\}|/\d{2,}\b", text):
        return "integer"
    return "unknown"


def rule_based_classify(item: dict[str, Any]) -> dict[str, Any] | None:
    """description 키워드만으로 분류 가능한 항목은 LLM 없이 채워서 반환.

    확신할 수 있을 때만 결과를 돌려주고, 그렇지 않으면 None 을 반환해 LLM 으로 넘긴다.
    """
    description = (item.get("description") or "").strip()
    title = (item.get("title") or "").strip()
    text = f"{description} {title}".lower()
    if not text.strip():
        return None

    endpoint = _detect_endpoint(description or title)
    id_type = _detect_id_type(text)

    # 패턴별 키워드 점수
    pattern: str | None = None
    attack: str | None = None
    confidence = 0
    reason = ""

    if "mass assignment" in text or "mass-assignment" in text:
        pattern, attack = "mass_assignment", "mass_assignment"
        confidence = 3
        reason = "Description mentions mass assignment"
    elif re.search(r"\badmin(\s+(panel|endpoint|path|interface|api))?\b", text) and (
        "/admin" in text or "expose" in text or "unauthorized" in text or "without auth" in text
    ):
        pattern, attack = "admin_path_exposure", "admin_exposure"
        confidence = 3
        reason = "Admin endpoint exposed without proper auth"
    elif re.search(r"\b(batch|bulk)\b", text) and (
        "idor" in text or "object" in text or "validation" in text or "any user" in text
    ):
        pattern, attack = "batch_unvalidated", "batch"
        confidence = 2
        reason = "Batch/bulk endpoint without per-item ownership check"
    elif "filter" in text and re.search(r"\b(param|parameter|query|bypass)\b", text):
        pattern, attack = "filter_param_bypass", "filter_bypass"
        confidence = 2
        reason = "Filter/query parameter can be bypassed to access others' data"
    elif id_type == "uuid" and ("idor" in text or "direct object" in text or "any user" in text):
        pattern, attack = "uuid_idor", "idor"
        confidence = 2
        reason = "IDOR via UUID identifier"
    elif id_type == "integer" and re.search(
        r"\b(enumerat|incremental|sequential|guess|brute)", text
    ):
        pattern, attack = "integer_id_enumeration", "enumeration"
        confidence = 3
        reason = "Sequential integer IDs allow enumeration"
    elif (
        "broken object level authorization" in text
        or "insecure direct object reference" in text
        or "idor" in text
        or "bola" in text
    ) and id_type == "integer":
        pattern, attack = "integer_id_enumeration", "enumeration"
        confidence = 2
        reason = "BOLA/IDOR with integer identifier"
    elif (
        "broken object level authorization" in text
        or "insecure direct object reference" in text
        or "idor" in text
        or "bola" in text
    ):
        # 키워드는 있지만 id_type 불명 → 신뢰도 낮음
        pattern, attack = "nested_resource_idor", "idor"
        confidence = 1
        reason = "IDOR/BOLA keyword present without specific identifier type"

    # ownership 위치 추론
    if "query" in text and "param" in text:
        ownership = "query"
    elif re.search(r"\b(request body|json body|payload|post body)\b", text):
        ownership = "body"
    elif endpoint != "unknown" or "/{id}" in text or "path parameter" in text:
        ownership = "path"
    else:
        ownership = "unknown"

    # 신뢰도 2 이상만 규칙 기반으로 확정. 그 미만이면 LLM 위임.
    if pattern is None or confidence < 2:
        return None

    return {
        "endpoint_pattern": endpoint,
        "id_type": id_type,
        "ownership_check_missing": ownership,
        "attack_method": attack or "idor",
        "bola_pattern": pattern,
        "rule_based_detectable": True,
        "inference_required": False,
        "reason": reason,
    }


# --- 파이프라인 -------------------------------------------------------------


def _dedupe(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """source+id 조합으로 중복 제거 (id 자체에 source prefix 가 이미 포함됨)."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for it in items:
        key = it.get("id", "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def _to_record(item: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """flat raw + enrichment → 가이드 §3 스키마 {id, document, metadata}.

    document 는 임베딩 대상 텍스트, metadata 는 ChromaDB 필터링용 scalar 모음.
    """
    description = item.get("description") or item.get("title") or ""
    cwe_id = item.get("cwe_id") or ""
    bola_pattern = extra.get("bola_pattern") or ""
    document = (
        f"{item.get('id', '')}: {description} "
        f"CWE: {cwe_id} Pattern: {bola_pattern}"
    )
    metadata = {
        "source": item.get("source", ""),
        "cve_id": item.get("cve_id", "") or "",
        "cwe_id": cwe_id,
        "severity": item.get("severity", "") or "",
        "cvss_score": item.get("cvss_score"),
        "attack_vector": item.get("attack_vector", "") or "",
        "title": item.get("title", "") or "",
        "url": item.get("url", "") or "",
        "updated_at": item.get("updated_at", "") or "",
        "endpoint_pattern": extra.get("endpoint_pattern", "") or "",
        "id_type": extra.get("id_type", "") or "",
        "ownership_check_missing": extra.get("ownership_check_missing", "") or "",
        "attack_method": extra.get("attack_method", "") or "",
        "bola_pattern": bola_pattern,
        "rule_based_detectable": bool(extra.get("rule_based_detectable", False)),
        "inference_required": bool(extra.get("inference_required", True)),
        "reason": extra.get("reason", "") or "",
    }
    return {"id": item["id"], "document": document, "metadata": metadata}


def run(
    nvd_api_key: str | None = None,
    github_token: str | None = None,
    output_path: Path = OUTPUT_PATH,
) -> list[dict[str, Any]]:
    """전체 수집 + enrichment 파이프라인 실행."""
    print("=== BOLA/IDOR dataset pipeline ===")

    raw: list[dict[str, Any]] = []
    for fetcher in (
        lambda: fetch_nvd(nvd_api_key),
        fetch_hackerone,
        lambda: fetch_github_advisories(github_token),
        fetch_cisa_kev,
        fetch_owasp_api_security,
        fetch_wstg,
        fetch_capec,
    ):
        try:
            raw.extend(fetcher())
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] source fetch failed, skipping: {exc}")

    print(f"\nTotal raw items: {len(raw)}")
    deduped = _dedupe(raw)
    print(f"After dedupe (source+id): {len(deduped)}")

    print(f"\n=== Enriching (rules + {LLM_MODEL}) ===")
    llm_alive = warmup_llm()
    if not llm_alive:
        print("  [warn] LLM unreachable — items needing inference will be skipped")

    records: list[dict[str, Any]] = []
    pre_count = 0
    rule_count = 0
    llm_count = 0
    skipped = 0
    for idx, item in enumerate(deduped, 1):
        prefix = f"  [{idx}/{len(deduped)}] {item['id']}"
        try:
            # 정의/지식 문서는 fetcher 단에서 _preclassified 를 미리 채워둠
            preclass = item.pop("_preclassified", None)
            if preclass is not None:
                extra = preclass
                pre_count += 1
                print(f"{prefix} -> preclassified ({extra['bola_pattern']})")
            else:
                extra = rule_based_classify(item)
                if extra is not None:
                    rule_count += 1
                    print(f"{prefix} -> rule ({extra['bola_pattern']})")
                elif llm_alive:
                    extra = enrich_with_llm(item)
                    if extra is None:
                        skipped += 1
                        continue
                    llm_count += 1
                    print(f"{prefix} -> llm ({extra['bola_pattern']})")
                else:
                    skipped += 1
                    print(f"{prefix} -> skipped (LLM unavailable, no rule match)")
                    continue
            records.append(_to_record(item, extra))
        except Exception as exc:  # noqa: BLE001
            skipped += 1
            print(f"  [warn] enrichment skipped for {item.get('id')}: {exc}")
            continue

    print(
        f"\nEnrichment summary: pre={pre_count}, rule={rule_count}, "
        f"llm={llm_count}, skipped={skipped}"
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
    print(f"\nSaved {len(records)} records -> {output_path}")
    return records


if __name__ == "__main__":
    run(
        nvd_api_key=os.environ.get("NVD_API_KEY"),
        github_token=os.environ.get("GITHUB_TOKEN"),
    )
