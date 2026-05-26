"""팀 Google 스프레드시트 (500+ CVE) → raw items.

C 트랙 `sheets_importer.py` 의 CSV 다운로드 + 한글 헤더 정규화 로직 보존.
시트 ID 는 config.GOOGLE_SHEETS_ID (env BLADE_SHEETS_ID 로 오버라이드).
"""

from __future__ import annotations

import csv
import io
import re
import sys
from pathlib import Path
from typing import Any

import requests

from blade import config

HEADER_MAP = {
    "CVE ID": "cve_id",
    "cve id": "cve_id",
    "취약 엔드포인트 패턴": "endpoint_pattern",
    "ID 유형": "id_type",
    "소유권 검증 누락 위치": "ownership_check_missing",
    "공격 방식": "attack_method",
    "OWASP 매핑": "owasp_mapping",
    "탐지 가능 여부": "rule_based_detectable",
    "LLM 추론 필요 여부": "inference_required",
    "설명": "description",
    "CWE": "cwe_id",
    # English fall-backs
    "cve_id": "cve_id",
    "endpoint_pattern": "endpoint_pattern",
    "description": "description",
    "cwe": "cwe_id",
    "cwe_mapping": "cwe_id",
    "owasp": "owasp_mapping",
}


def _normalise_header(h: str) -> str:
    s = h.strip()
    return HEADER_MAP.get(s, s.lower().replace(" ", "_"))


def _is_na(v: str) -> bool:
    return not v or v.strip().upper() in ("N/A", "NA", "-", "")


def _download_csv(sheet_id: str) -> str:
    url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid=0"
    print(f"  GET {url}")
    r = requests.get(url, timeout=30, allow_redirects=True)
    if r.status_code != 200:
        print(f"  [error] HTTP {r.status_code} — sheet must be 'Anyone with link → Viewer'")
        sys.exit(1)
    return r.text


def fetch(
    sheet_id: str | None = None,
    local_csv: str | Path | None = None,
) -> list[dict[str, Any]]:
    print("[Google Sheets] ...")
    if local_csv:
        raw = Path(local_csv).read_text(encoding="utf-8-sig")
    else:
        raw = _download_csv(sheet_id or config.GOOGLE_SHEETS_ID)

    reader = csv.DictReader(io.StringIO(raw))
    items: list[dict[str, Any]] = []
    skipped = 0

    for row in reader:
        norm = {_normalise_header(k): (v or "").strip() for k, v in row.items()}
        cve_id = norm.get("cve_id", "").strip()
        if not cve_id or not re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
            skipped += 1
            continue
        owasp = norm.get("owasp_mapping", "API1:2023") or "API1:2023"
        if _is_na(owasp):
            owasp = "API1:2023"

        items.append(
            {
                "id": f"sheets-{cve_id}",
                "source": "sheets",
                "cve_id": cve_id,
                "title": cve_id,
                "description": norm.get("description", ""),
                "cwe_id": norm.get("cwe_id", "") or "",
                "severity": "",
                "cvss_score": 0.0,
                "attack_vector": "",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "updated_at": "",
                # 시트가 직접 채운 필드는 _preclassified 로 보존
                "_preclassified": {
                    "endpoint_pattern": "" if _is_na(norm.get("endpoint_pattern", "")) else norm["endpoint_pattern"],
                    "id_type": "" if _is_na(norm.get("id_type", "")) else norm["id_type"],
                    "ownership_check_missing": "" if _is_na(norm.get("ownership_check_missing", "")) else norm["ownership_check_missing"],
                    "attack_method": "" if _is_na(norm.get("attack_method", "")) else norm["attack_method"],
                    "bola_pattern": "",
                    "rule_based_detectable": str(norm.get("rule_based_detectable", "")).lower() in ("true", "1", "yes"),
                    "inference_required": str(norm.get("inference_required", "")).lower() in ("true", "1", "yes"),
                    "owasp_mapping": owasp,
                    "reason": "google sheets manual curation",
                },
            }
        )

    print(f"[Google Sheets] -> {len(items)} valid CVE rows  ({skipped} skipped)")
    return items
