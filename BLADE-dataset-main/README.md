# BLADE — BOLA 탐지 RAG 데이터셋 & 정책 생성 툴킷

BOLA(Broken Object Level Authorization) 취약점 탐지를 위한 LLM RAG 학습용 데이터셋과,
OAS 엔드포인트로부터 BLADE 정책 YAML 을 생성하는 도구 모음.

---

## 빠른 시작

```bash
# 1) 의존성
pip install -r requirements.txt

# 2) Ollama 데몬 + 모델
ollama serve &
ollama pull nomic-embed-text llama3.2:3b qwen2.5:7b

# 3) 환경 변수 (선택)
cp .env.example .env
# 편집 — NVD_API_KEY 가 있으면 NVD 수집이 10배 빠름

# 4) 통합 데이터셋은 이미 data/processed/bola_dataset.json 에 마이그레이션돼 있음 (7,501 records).
#    ChromaDB 적재만 하면 곧장 사용 가능:
PYTHONPATH=src python scripts/00_check_ollama.py
PYTHONPATH=src python scripts/03_load_chroma.py
PYTHONPATH=src python scripts/04_test_search.py
```

Windows PowerShell:

```powershell
$env:PYTHONPATH = "$PWD\src"
python scripts\00_check_ollama.py
python scripts\03_load_chroma.py
python scripts\04_test_search.py
```

---

## 워크플로우

| 단계 | 스크립트 | 입력 | 출력 |
|---|---|---|---|
| 0 | `scripts/00_check_ollama.py` | — | Ollama/모델 헬스체크 |
| 1 | `scripts/01_fetch_all.py` | 외부 API/스크래퍼 | `data/raw/<source>.json` |
| 2 | `scripts/02_build_dataset.py` | `data/raw/*.json` | `data/processed/bola_dataset.json` |
| 3 | `scripts/03_load_chroma.py` | `bola_dataset.json` | `chroma_db/` (3 collections) |
| 4 | `scripts/04_test_search.py` | `chroma_db/` | retrieval sanity check |
| 10 | `scripts/10_generate_policy.py` | OAS 엔드포인트 | `data/policies/*.yaml` |
| 11 | `scripts/11_validate_policy.py` | `data/policies/*.yaml` | 검증 결과 |

옵션 플래그:

```bash
# fetch 일부만
python scripts/01_fetch_all.py --only nvd capec
python scripts/01_fetch_all.py --skip hackerone

# LLM 없이 enrichment (rule-based 만)
python scripts/02_build_dataset.py --no-llm
```

---

## 프로젝트 구조

```
BLADE-DATASET-MAIN/
├── data/
│   ├── raw/                    # 원본 수집 (source별 JSON)
│   ├── processed/
│   │   └── bola_dataset.json   # ★ 통합 데이터셋 (7,501 records)
│   └── policies/               # 생성된 정책 YAML
│
├── src/blade/                  # 패키지
│   ├── config.py               # 경로/모델/컬렉션 상수
│   ├── schema.py               # Record/Metadata dataclass + 키 상수
│   ├── sources/                # 소스별 fetcher (NVD, HackerOne, GitHub, CISA, OWASP, WSTG, CAPEC, Sheets)
│   ├── enrich/                 # 규칙 분류 + LLM 분류
│   ├── pipeline/               # fetch → build → load → search
│   ├── policy/                 # retrieve → generate → validate
│   └── utils/                  # ollama_client, chroma_client
│
├── scripts/                    # 사용자 실행 진입점 (얇은 래퍼)
├── tools/
│   └── migrate_legacy.py       # legacy/ → 새 스키마 일회성 변환기
├── docs/                       # 가이드 문서 (DB_Guide, dataset_guide, nvd_raw_guide)
├── legacy/                     # 통합 전 원본 (gitignore)
├── INTEGRATION_PLAN.md         # 설계 결정 기록
└── INTEGRATION_REPORT.md       # 통합 작업 보고서
```

---

## 데이터셋 스키마

`data/processed/bola_dataset.json` — 단일 정합 형식.

```json
{
  "id": "nvd-CVE-2022-34770",
  "document": "source: nvd  source_id: nvd-CVE-2022-34770\nendpoint: GET /api/...\n...",
  "metadata": {
    "source": "nvd|cisa|hackerone|github|owasp_api|wstg|capec|sheets|cwe|business_logic",
    "source_type": "cve|standard|report|pattern",
    "source_id": "nvd-CVE-2022-34770",
    "cve_id": "CVE-2022-34770",
    "cwe_id": "CWE-639",
    "severity": "MEDIUM",
    "cvss_score": 4.6,
    "bola_pattern": "nested_resource_idor",
    "endpoint_pattern": "/api/users/{userId}",
    "http_method": "GET",
    "id_type": "path_param",
    "ownership_type": "direct",
    "attack_method": "id_substitution",
    "rule_type": "jwt_ownership",
    "domain": "ecommerce",
    "policy_template_hint": "owner_match",
    "enrichment_method": "preclassified|rule|llm|legacy"
    // ... (총 25개 필드)
  }
}
```

전체 필드 정의는 [`src/blade/schema.py`](src/blade/schema.py) 참고.

---

## ChromaDB 컬렉션 구조

가이드 §4-5 의 source_type 기반 분할.

| 컬렉션 | 담당 source | 용도 |
|---|---|---|
| `bola_cve` | nvd, cisa, sheets | 실제 CVE 사례 |
| `bola_standards` | cwe, capec, owasp_api, wstg | 표준/정의 문서 |
| `bola_patterns` | hackerone, github, business_logic | 실전 패턴/리포트 |

검색 시 3개를 병렬 query 하고 거리 기준으로 머지 (`utils/chroma_client.query_all`).

---

## 더 읽을 거리

- [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md) — 통합 설계 결정 8 개 + 마이그레이션 리스크
- [INTEGRATION_REPORT.md](INTEGRATION_REPORT.md) — 실제로 무엇이 어떻게 통합됐는지 (모듈 매핑, 데이터 카운트, 손실/주의사항)
- [docs/dataset_guide.md](docs/dataset_guide.md) — 가이드 §3 스키마 / §4 청크 설계 원본
- [docs/DB_Guide.md](docs/DB_Guide.md) — RAG 지식 베이스 구축 가이드
- [docs/nvd_raw_guide.md](docs/nvd_raw_guide.md) — NVD 대량 수집 사양

---

## 라이선스 / 협업

3 명이 각자 구축한 트랙(A/B/C)을 단일 코드베이스로 병합한 결과물입니다.
원본 코드는 `legacy/` 에 보존돼 있어 누구의 어느 코드가 어디로 갔는지
[INTEGRATION_REPORT.md](INTEGRATION_REPORT.md) 의 매핑 표에서 추적 가능합니다.
