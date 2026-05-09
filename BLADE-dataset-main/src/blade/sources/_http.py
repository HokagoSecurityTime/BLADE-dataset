"""공통 HTTP 헬퍼 — 예외 흡수 + 짧은 retry."""

from __future__ import annotations

import time
from typing import Any

import requests


def safe_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    retries: int = 3,
    backoff: float = 5.0,
) -> requests.Response | None:
    """예외/4xx/5xx 흡수. None 반환 시 호출 측이 skip 결정."""
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=timeout)
            if r.status_code == 429:
                wait = backoff * (attempt + 1) * 6
                print(f"  [429] {url} — sleeping {wait}s")
                time.sleep(wait)
                continue
            r.raise_for_status()
            return r
        except Exception as exc:
            last_exc = exc
            if attempt + 1 < retries:
                time.sleep(backoff * (attempt + 1))
    print(f"  [warn] GET {url} failed after {retries} attempts: {last_exc}")
    return None
