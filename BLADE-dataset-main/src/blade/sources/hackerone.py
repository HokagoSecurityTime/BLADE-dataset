"""HackerOne hacktivity 스크래퍼.

페이지가 React 로 렌더링돼서 requests + BS4 만으로는 빈 결과가 나옴.
헤드리스 Chrome (Selenium) 으로 JS 실행 후 무한스크롤하며 리포트 카드 수집.
B 트랙 `cve_fetcher.fetch_hackerone` 을 그대로 분리.
"""

from __future__ import annotations

import re
import time
from typing import Any

from blade.sources._http import safe_get  # noqa: F401  (간접 사용)

HACKERONE_URL = "https://hackerone.com/hacktivity"


def _build_chrome_driver():
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions

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


def fetch(
    max_scrolls: int = 15,
    scroll_pause: float = 2.0,
    wait_seconds: int = 20,
) -> list[dict[str, Any]]:
    """HackerOne hacktivity 검색 결과를 스크래핑."""
    print("[HackerOne] selenium scrape ...")
    try:
        from selenium.common.exceptions import TimeoutException, WebDriverException
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait
        from bs4 import BeautifulSoup
    except ImportError as exc:
        print(f"  [warn] selenium/bs4 not installed: {exc}")
        return []

    target = f"{HACKERONE_URL}?querystring=IDOR&disclosed=true"

    try:
        driver = _build_chrome_driver()
    except Exception as exc:
        print(f"  [warn] Chrome driver init failed: {exc}")
        return []

    seen_ids: set[str] = set()
    collected: list[dict[str, Any]] = []

    try:
        print(f"  GET {target}")
        driver.get(target)
        try:
            WebDriverWait(driver, wait_seconds).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "a[href*='/reports/']"))
            )
        except TimeoutException:
            print("  [warn] hacktivity report links did not appear in time")

        last_count = 0
        for i in range(max_scrolls):
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(scroll_pause)
            anchors = driver.find_elements(By.CSS_SELECTOR, "a[href*='/reports/']")
            count = len(anchors)
            print(f"  scroll {i + 1}/{max_scrolls}: {count} report anchors")
            if count == last_count:
                break
            last_count = count

        html = driver.page_source
    except Exception as exc:
        print(f"  [warn] selenium scrape error: {exc}")
        html = ""
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    if not html:
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
                    "cvss_score": 0.0,
                    "attack_vector": "NETWORK",
                    "url": url,
                    "updated_at": "",
                }
            )
        except Exception as exc:
            print(f"  [warn] hackerone entry skipped: {exc}")
    print(f"[HackerOne] -> {len(collected)}")
    return collected
