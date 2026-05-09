"""중앙 설정 — 경로, 모델, 컬렉션 이름.

CWD 의존을 제거하기 위해 모든 경로는 repo root 기준 절대 경로로 계산한다.
환경 변수로 일부 항목(CHROMA_PATH, OLLAMA_URL, NVD/GitHub 토큰)을 오버라이드할 수 있다.
"""

from __future__ import annotations

import os
from pathlib import Path

# --- 경로 ---------------------------------------------------------------

# repo root: src/blade/config.py → parents[2]
REPO_ROOT: Path = Path(__file__).resolve().parents[2]

DATA_DIR: Path = REPO_ROOT / "data"
RAW_DIR: Path = DATA_DIR / "raw"
PROCESSED_DIR: Path = DATA_DIR / "processed"
POLICIES_DIR: Path = DATA_DIR / "policies"

LEGACY_DIR: Path = REPO_ROOT / "legacy"

DATASET_PATH: Path = PROCESSED_DIR / "bola_dataset.json"

CHROMA_PATH: Path = Path(os.environ.get("CHROMA_PATH", REPO_ROOT / "chroma_db"))


# --- ChromaDB 컬렉션 ---------------------------------------------------
# 가이드 §4-5 의 source_type 기반 분할 전략

COLLECTION_CVE = "bola_cve"
COLLECTION_STANDARDS = "bola_standards"   # cwe / capec / owasp / wstg
COLLECTION_PATTERNS = "bola_patterns"     # business_logic / hackerone / github

ALL_COLLECTIONS = (COLLECTION_CVE, COLLECTION_STANDARDS, COLLECTION_PATTERNS)

# source → collection 라우팅
SOURCE_TO_COLLECTION = {
    "nvd": COLLECTION_CVE,
    "cisa": COLLECTION_CVE,
    "sheets": COLLECTION_CVE,
    "cwe": COLLECTION_STANDARDS,
    "capec": COLLECTION_STANDARDS,
    "owasp_api": COLLECTION_STANDARDS,
    "wstg": COLLECTION_STANDARDS,
    "hackerone": COLLECTION_PATTERNS,
    "github": COLLECTION_PATTERNS,
    "business_logic": COLLECTION_PATTERNS,
}

# source_type 라벨 (스키마용)
SOURCE_TO_TYPE = {
    "nvd": "cve",
    "cisa": "cve",
    "sheets": "cve",
    "cwe": "standard",
    "capec": "standard",
    "owasp_api": "standard",
    "wstg": "standard",
    "hackerone": "report",
    "github": "report",
    "business_logic": "pattern",
}


# --- Ollama / 모델 ------------------------------------------------------

OLLAMA_BASE_URL: str = os.environ.get("OLLAMA_URL", "http://localhost:11434")
OLLAMA_GENERATE_URL: str = f"{OLLAMA_BASE_URL}/api/generate"
OLLAMA_EMBED_URL: str = f"{OLLAMA_BASE_URL}/api/embeddings"
OLLAMA_TAGS_URL: str = f"{OLLAMA_BASE_URL}/api/tags"

EMBED_MODEL: str = os.environ.get("BLADE_EMBED_MODEL", "nomic-embed-text")
EMBED_DIM: int = 768  # nomic-embed-text

ENRICHMENT_MODEL: str = os.environ.get("BLADE_ENRICH_MODEL", "llama3.2:3b")
POLICY_MODEL: str = os.environ.get("BLADE_POLICY_MODEL", "qwen2.5:7b")


# --- 외부 API 토큰 (env에서 읽음, 없으면 None) -------------------------

NVD_API_KEY: str | None = os.environ.get("NVD_API_KEY") or None
GITHUB_TOKEN: str | None = os.environ.get("GITHUB_TOKEN") or None

GOOGLE_SHEETS_ID: str = os.environ.get(
    "BLADE_SHEETS_ID",
    "1R2aoTQrz_ByQ5CABeZLJrWvQZg5kSu-30tVbVWxmSQU",
)


# --- raw 파일 표준 위치 -------------------------------------------------

RAW_NVD = RAW_DIR / "nvd_cves.json"
RAW_HACKERONE = RAW_DIR / "hackerone_reports.json"
RAW_GITHUB = RAW_DIR / "github_advisories.json"
RAW_CISA = RAW_DIR / "cisa_kev.json"
RAW_OWASP_API = RAW_DIR / "owasp_api.json"
RAW_WSTG = RAW_DIR / "owasp_wstg.json"
RAW_CAPEC = RAW_DIR / "capec_curated.json"
RAW_SHEETS = RAW_DIR / "google_sheets.json"
RAW_STANDARDS_SEED = RAW_DIR / "standards_seed.csv"
