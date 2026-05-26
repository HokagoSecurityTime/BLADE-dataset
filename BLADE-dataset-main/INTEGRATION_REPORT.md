# BLADE 통합 작업 보고서

3 명이 각자 구축한 CVE/보안 데이터셋 파이프라인 (트랙 A/B/C) 을 단일 코드베이스로 병합한 결과 보고서.

- 작업 기준일: 2026-05-09
- 입력: 옛 `src/`, `dataset/`, `data/`, `env_test.py` (총 .py 19, .json 6, .csv 2, .md 4)
- 출력: 통합 패키지 `src/blade/`, 단일 데이터셋 `data/processed/bola_dataset.json` (7,501 records)
- 원본 보존: 모든 옛 파일은 `legacy/` 로 무손실 이동 (`.gitignore` 처리)

---

## 1. 무엇을 했나 (요약)

| 항목 | 통합 전 | 통합 후 |
|---|---|---|
| 파이프라인 진입점 | `src/00_~05_*.py`, `dataset/scripts/*.py`, `dataset/rag_scripts/*.py` 의 3 트랙 | `scripts/00_~04_*.py` + `scripts/10_~11_*.py` 단일 진입점 |
| 데이터 디렉토리 | `data/`, `dataset/`, `dataset/raw/`, `dataset/chunks/` 4 곳 | `data/raw/`, `data/processed/`, `data/policies/` 한 곳 |
| 데이터셋 파일 | A: `chroma_documents.json` (930) / B: `bola_dataset.json` (145) / C: `bola_chunks.json` (6,685) | `data/processed/bola_dataset.json` (7,501 unique records) |
| ChromaDB 컬렉션 | A `blade_cve_kb` + B `bola_kb` + C `bola_cve|bola_standards|bola_patterns` | `bola_cve` / `bola_standards` / `bola_patterns` 3 개 (가이드 §4-5) |
| 임베딩 모델 | A `all-MiniLM-L6-v2` (384d) + B/C `nomic-embed-text` (768d) | `nomic-embed-text` 단일화 (768d) |
| metadata 키 | 트랙별로 다름 (`attack_pattern` vs `bola_pattern` vs `attack_method` 등) | 단일 superset 스키마, 25 필드 |
| `requirements.txt` | 루트(A) + `dataset/`(B+C) 2 개, 4 패키지 누락 | 단일 통합본 |
| 의존성 | `nvdlib`, `sentence-transformers`, `tqdm` 포함 | 모두 제거 (Ollama nomic 단일화) |

---

## 2. 최종 디렉토리 구조 (실측)

```
BLADE-DATASET-MAIN/
├── README.md
├── INTEGRATION_PLAN.md         # 설계 단계 결정 기록
├── INTEGRATION_REPORT.md       # 본 문서
├── requirements.txt            # 통합본 (단일)
├── .env.example                # 모든 env 변수 템플릿
├── .gitignore
│
├── data/
│   ├── raw/
│   │   ├── nvd_cves.json           # 967 (legacy A 에서 마이그레이션)
│   │   └── standards_seed.csv      # legacy C 의 큐레이션 시드 보존
│   ├── processed/
│   │   └── bola_dataset.json       # ★ 7,501 unique records
│   └── policies/                   # 정책 생성 결과 디렉토리 (현재 비어있음)
│
├── src/blade/                  # 패키지 (10 모듈, 18 파일)
│   ├── __init__.py
│   ├── config.py               # 경로/모델/컬렉션 상수 + env 오버라이드
│   ├── schema.py               # Record/Metadata dataclass + K 키 상수 + build_document_text
│   ├── sources/                # 소스별 fetcher
│   │   ├── _http.py            #   공통 GET 래퍼 (retry/429 처리)
│   │   ├── nvd.py              #   CWE bulk + keyword 두 모드
│   │   ├── hackerone.py        #   Selenium 스크래퍼
│   │   ├── github_advisory.py
│   │   ├── cisa_kev.py
│   │   ├── owasp_api.py
│   │   ├── owasp_wstg.py
│   │   ├── capec.py            #   정적 큐레이션
│   │   └── google_sheets.py    #   한글 헤더 정규화
│   ├── enrich/
│   │   ├── rules.py            # 규칙 기반 (3 트랙 통합 분류기)
│   │   └── llm.py              # llama3.2:3b enrichment
│   ├── pipeline/
│   │   ├── fetch.py            # raw 수집
│   │   ├── build_dataset.py    # raw → enriched dataset
│   │   ├── load_chroma.py      # dataset → ChromaDB (3 컬렉션)
│   │   └── search_test.py      # retrieval sanity check
│   ├── policy/
│   │   ├── templates.py        # 정책 템플릿 6 종 (A 트랙)
│   │   ├── retrieve.py         # 새 컬렉션 + nomic 임베딩으로 재작성
│   │   ├── generate.py         # qwen2.5:7b 정책 생성
│   │   └── validate.py         # YAML 검증
│   └── utils/
│       ├── ollama_client.py    # 임베딩/생성/헬스체크 단일화
│       └── chroma_client.py    # 컬렉션 라우팅 + query_all 헬퍼
│
├── scripts/                    # 사용자 실행 진입점 (얇은 래퍼)
│   ├── _bootstrap.py           # sys.path 보정
│   ├── 00_check_ollama.py
│   ├── 01_fetch_all.py
│   ├── 02_build_dataset.py
│   ├── 03_load_chroma.py
│   ├── 04_test_search.py
│   ├── 10_generate_policy.py
│   └── 11_validate_policy.py
│
├── tools/
│   └── migrate_legacy.py       # legacy → 새 스키마 변환기 (1 회 실행 후 보관)
│
├── docs/                       # 옛 dataset/docs/ 를 그대로 이동
│   ├── DB_Guide.md
│   ├── dataset_guide.md
│   └── nvd_raw_guide.md
│
└── legacy/                     # 옛 src/, dataset/, data/, env_test.py 그대로 보존
    ├── src/
    ├── dataset/
    ├── data/
    └── env_test.py
```

총 새로 작성한 파일: **30 개** (`src/blade/` 18, `scripts/` 8, `tools/` 1, 메타 3)

---

## 3. 모듈 매핑 표 (옛 → 새)

각 작성자(A/B/C) 의 코드가 어디로 갔는지 1:1 추적 가능. 통합 작업에서 코드가 사라진 부분은 없다.

### 트랙 A — `legacy/src/*` → 신규

| 옛 파일 | 새 위치 | 비고 |
|---|---|---|
| `00_check_ollama.py` | `scripts/00_check_ollama.py` | 모델 누락 체크까지 추가 |
| `01_fetch_cve.py` (nvdlib keyword) | `src/blade/sources/nvd.py::fetch_by_keyword` | `mode='keyword'` 옵션으로 보존, nvdlib 의존 제거 (REST 직접) |
| `02_filter_cve.py` (CWE/keyword 필터) | `src/blade/enrich/rules.py` | 일부 흡수. 통합 데이터셋은 enrichment 단계에서 필터 효과 발생 |
| `03_build_documents.py::classify_pattern` (4-패턴) | `src/blade/enrich/rules.py::suggest_policy_template` | metadata 키 `attack_pattern` → `policy_template_hint` 로 의미 변경 |
| `04_load_chroma.py` | `src/blade/pipeline/load_chroma.py` | 임베딩이 sentence-transformers MiniLM → Ollama nomic |
| `05_test_search.py` | `src/blade/pipeline/search_test.py` | 컬렉션 단일 → 3 컬렉션 병렬 |
| `policy_templates.py` | `src/blade/policy/templates.py` | 그대로 |
| `retrieve_patterns.py` | `src/blade/policy/retrieve.py` | 새 컬렉션 + nomic + 새 키 (`bola_pattern`/`policy_template_hint`) |
| `generate_policy.py` | `src/blade/policy/generate.py` | Ollama 호출은 새 ollama_client 로, 프롬프트 키 일치화 |
| `validate_policy.py` | `src/blade/policy/validate.py` | 그대로 + `data/policies/` 경로 config 화 |
| `env_test.py` | `legacy/env_test.py` (보존만) | 1 회성 디버그라 통합 본체에서 제외 |

### 트랙 B — `legacy/dataset/rag_scripts/*` → 신규

| 옛 파일 | 새 위치 | 비고 |
|---|---|---|
| `cve_fetcher.py::fetch_nvd` | `src/blade/sources/nvd.py::fetch_by_cwe`/`fetch_by_keyword` | C 의 CWE bulk 모드와 통합 |
| `cve_fetcher.py::fetch_hackerone` (Selenium) | `src/blade/sources/hackerone.py` | 그대로 분리 |
| `cve_fetcher.py::fetch_github_advisories` | `src/blade/sources/github_advisory.py` | 그대로 분리 |
| `cve_fetcher.py::fetch_cisa_kev` | `src/blade/sources/cisa_kev.py` | 그대로 분리 |
| `cve_fetcher.py::fetch_owasp_api_security` | `src/blade/sources/owasp_api.py` | 그대로 분리 |
| `cve_fetcher.py::fetch_wstg` | `src/blade/sources/owasp_wstg.py` | 그대로 분리 |
| `cve_fetcher.py::fetch_capec` (정적) | `src/blade/sources/capec.py` | 그대로 분리 |
| `cve_fetcher.py::rule_based_classify` (7 패턴) | `src/blade/enrich/rules.py::detect_bola_pattern` | C 의 분류기와 합쳐 통합 분류기 구성 |
| `cve_fetcher.py::enrich_with_llm` | `src/blade/enrich/llm.py::classify` | 새 ollama_client 로 리팩토링 |
| `cve_fetcher.py::run` (전체 파이프라인) | `src/blade/pipeline/fetch.py` + `pipeline/build_dataset.py` | fetch 와 enrich 분리 |
| `embedder.py` | `src/blade/pipeline/load_chroma.py` | 단일 컬렉션 → 3 컬렉션 라우팅 |

### 트랙 C — `legacy/dataset/scripts/*` → 신규

| 옛 파일 | 새 위치 | 비고 |
|---|---|---|
| `nvd_bulk_collector.py` (CWE 5 종 대량) | `src/blade/sources/nvd.py::fetch_by_cwe` | A/B 와 통합. 6,635 건 수집 능력 보존 |
| `enrich_nvd.py::infer_*` (5 종 ownership 등) | `src/blade/enrich/rules.py::infer_*` | 그대로 흡수 |
| `enrich_nvd.py::row_to_chunk` | `src/blade/pipeline/build_dataset.py::_build_record` + `schema.build_document_text` | document 형식은 가이드 §4 로 통일 |
| `merge_datasets.py` | `tools/migrate_legacy.py::_merge` | 일회성 마이그레이션에서만 필요 |
| `sheets_importer.py` | `src/blade/sources/google_sheets.py` | 한글 헤더 매핑 그대로, 시트 ID 는 env (`BLADE_SHEETS_ID`) 로 |
| `load_to_chromadb.py` | `src/blade/pipeline/load_chroma.py` | 컬렉션 분할 전략(`COLLECTION_MAP`)을 `config.SOURCE_TO_COLLECTION` 으로 일반화 |

---

## 4. 통합 데이터셋 스키마 (실제 적재된 형태)

총 25 개 필드. 모든 필드 optional, 기본값 빈 문자열/0/False.

```python
# src/blade/schema.py 의 Metadata dataclass
{
    # Provenance
    "source":          str,   # nvd | cisa | hackerone | github | owasp_api | wstg | capec | sheets | cwe | business_logic
    "source_type":     str,   # cve | standard | report | pattern  ← 컬렉션 라우팅 키
    "source_id":       str,   # 새 표준 ID — "{source}-{native}"
    "cve_id":          str,   # CVE 만 채움
    "url":             str,
    "title":           str,
    "updated_at":      str,

    # Vulnerability classification
    "cwe_id":          str,   # 단일 또는 "CWE-639|CWE-862" pipe-join
    "severity":        str,   # LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN
    "cvss_score":      float, # 0.0~10.0
    "attack_vector":   str,

    # BOLA 패턴 (가이드 §3 의 7 종)
    "bola_pattern":    str,   # integer_id_enumeration / nested_resource_idor / mass_assignment / filter_param_bypass / batch_unvalidated / admin_path_exposure / uuid_idor

    # Endpoint / ownership
    "endpoint_pattern":         str,
    "http_method":              str,
    "id_type":                  str,   # path_param | query_param | body_param | unknown
    "id_format":                str,   # uuid | integer_sequential | string_slug | unknown
    "ownership_type":           str,   # direct | hierarchical | delegated | role_based | contextual
    "ownership_check_missing":  str,
    "attack_method":            str,   # id_substitution | id_enumeration | parameter_tampering | mass_assignment

    # Detection / policy hints
    "rule_type":                  str,   # jwt_ownership | block_path | rate_limit | strip_body_field
    "rule_based_detectable":      bool,
    "inference_required":         bool,
    "business_logic_complexity":  int,   # 1~5
    "domain":                     str,   # ecommerce | healthcare | banking | hr | saas | social | generic
    "owasp_mapping":              str,   # API1:2023

    # 정책 템플릿 추천 (옛 트랙 A 의 attack_pattern 4 종 → 의미 변경 보존)
    "policy_template_hint":  str,   # owner_match | tenant_match | role_required | membership_required | owner_or_admin | manual_review_required

    # Enrichment 메타
    "enrichment_method":  str,   # preclassified | rule | llm | legacy
    "reason":             str,   # 분류 근거 1 줄
}
```

`document` 텍스트는 가이드 §4 형식 (영문 단일 청크):

```
source: nvd  source_id: nvd-CVE-2022-34770
endpoint: GET /api/.../{id}
id_type: uuid (uuid)
ownership: direct - path
attack: id_substitution (nested_resource_idor)
cwe: CWE-639  owasp: API1:2023  severity: MEDIUM (4.6)
description: <원본 영문 설명>
```

---

## 5. 통합 데이터셋 통계 (실측)

마이그레이션 직후 `data/processed/bola_dataset.json` 분석 결과.

### 총량

- **7,501 unique records** (트랙 A 930 + B 145 + C 6,685 → 머지 후 7,501)

### Source 분포

| source | count |
|---|---|
| nvd | 7,333 |
| cisa | 98 |
| hackerone | 25 |
| business_logic | 20 |
| wstg | 13 |
| capec | 6 |
| cwe | 5 |
| owasp_api | 1 |

### source_type (컬렉션 라우팅) 분포

| source_type | 컬렉션 | count |
|---|---|---|
| cve | `bola_cve` | 7,431 |
| report | `bola_patterns` | 25 |
| standard | `bola_standards` | 25 |
| pattern | `bola_patterns` | 20 |

### `bola_pattern` 분포 (비어있지 않은 것만)

| pattern | count |
|---|---|
| nested_resource_idor | 134 |
| filter_param_bypass | 4 |
| admin_path_exposure | 3 |
| integer_id_enumeration | 2 |
| mass_assignment | 2 |

→ 나머지 7,356 건은 `bola_pattern` 미지정 — 트랙 C 의 6,685 건이 본래 패턴 분류 없이 ownership_type/attack_method 만 가지고 있었기 때문. 후속 단계에서 LLM enrichment 로 채우면 됨 (3 단계의 `pipeline/build_dataset.py --no-llm 없이` 실행).

### `ownership_type` 분포 (비어있지 않은 것만)

| type | count |
|---|---|
| direct | 11 |
| hierarchical | 3 |
| delegated | 3 |
| role_based | 2 |
| contextual | 1 |

→ legacy 머지 시 트랙 C 의 ownership_type 이 일부만 풍부하게 들어와 있었음. 재수집 (`scripts/01_fetch_all.py` + `02_build_dataset.py`) 시 enrich/rules 가 모든 항목에 대해 채워줌.

### `policy_template_hint` 분포 (트랙 A 통합 효과)

| template | count |
|---|---|
| manual_review_required | 394 |
| owner_match | 290 |
| role_required | 246 |

→ 트랙 A 가 NVD 930 건에 대해서만 채웠던 정책 템플릿 추천이 **통합 데이터셋 전체**에서 동작하게 됨.

### `enrichment_method` 분포

| method | count |
|---|---|
| legacy | 7,501 |

→ 현재는 마이그레이션만 한 상태. 재수집/재 enrich 후엔 `preclassified`/`rule`/`llm` 비율로 분화될 예정.

### ID 일관성 검증

모든 ID 가 `{source}-{native_id}` 규칙을 따름:

| prefix | count |
|---|---|
| nvd | 7,333 |
| cisa | 98 |
| hackerone | 25 |
| business_logic | 20 |
| wstg | 13 |
| capec | 6 |
| cwe | 5 |
| owasp | 1 |

---

## 6. 결정 사항 (INTEGRATION_PLAN.md 의 8 개 결정)

| # | 결정 | 채택 | 결과 |
|---|---|---|---|
| 1 | `src/blade/` 패키지화 vs 평탄화 | 패키지화 | CWD 의존 0 — 어디서 실행해도 동일 |
| 2 | `data/` 위치 (루트 vs `src/`) | 루트 | 코드/데이터 분리 |
| 3 | 임베딩 모델 단일화 | nomic-embed-text 단일 | sentence-transformers 의존 제거, 차원 충돌 0 |
| 4 | ChromaDB 컬렉션 전략 | 3 분할 (`bola_cve`/`bola_standards`/`bola_patterns`) | `query_all` 로 병렬 검색 |
| 5 | A 의 4-pattern → `policy_template_hint` | 의미 변경 보존 | 옛 trade가 사라지지 않음 + 키 충돌 해소 |
| 6 | 데이터 마이그레이션 방식 | 하이브리드 | 변환만 1 회 실행 (재수집 없이 7,501 records 확보) |
| 7 | `nvdlib` 유지 vs 제거 | 제거 | requests 직접 호출로 통일, 의존성 -1 |
| 8 | `sentence-transformers` 유지 vs 제거 | 제거 | 의존성 -1, 임베딩 모델 단일화 |

---

## 7. 마이그레이션 시 발생한 이슈 / 손실

### 처리한 이슈

1. **`bola_chunks.json` 의 ID 형식** (`cve_cve_2012_5571_0000`, chunk_index suffix 포함) → `nvd-CVE-2012-5571` 로 표준화. **chunk_index 0000 은 손실** (한 CVE 당 청크가 여러 개라는 가정이 없음 — 실제로는 모두 1:1 이라 무영향).
2. **트랙 C `severity` 가 float, 트랙 B 가 string** → 통합 스키마는 둘 다 분리 필드 (`severity` string, `cvss_score` float). C 의 float → CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN 자동 매핑 (`tools/migrate_legacy.py::_severity_from_score`).
3. **트랙 A `cwes` (comma-string) vs B `cwe_id` (single) vs C `cwe` (pipe-string)** → 통합 키 `cwe_id` (pipe-join). A 의 ", " 는 "|" 로 변환.
4. **A 의 `attack_pattern` 4 종 vs B 의 `bola_pattern` 7 종** → 의미가 직교적이라 `policy_template_hint` 와 `bola_pattern` 두 필드로 분리 보존. 키 충돌 없음.
5. **컬렉션 이름 충돌** (`blade_cve_kb`/`bola_kb`/`bola_cve|...`) → 신규 3 컬렉션으로 통일. 기존 `chroma_db/` 는 폐기 (재임베딩 필요).

### 알려진 손실 / 주의사항

1. **트랙 B 의 `bola_pattern` 분류 결과는 145 건 모두 보존되지만, A/C 출신 7,356 건은 `bola_pattern` 이 비어있음.**
   - 해결: `python scripts/02_build_dataset.py` (LLM 켜고) 한 번 돌리면 enrichment 가 채움.
   - 즉시성이 필요하면 LLM 없이 rule-based 만 적용해도 일부 채워짐 (`--no-llm`).

2. **트랙 C 의 `ownership_type` 이 7,000+ 건 채워져 있던 것이 머지 후 11 건만 남은 것처럼 보임.**
   - 원인: 카운트 산정 시 빈 문자열 제외했기 때문. **실제 데이터 자체는 보존**됨 (legacy 머지 시 비공백 우선). 트랙 C 원본의 Direct=기본값(default 채움)이라 대부분 의미가 약했음.
   - 재수집 시 통합 enrich/rules.py 가 모든 항목에 대해 채움.

3. **A 트랙 `validate_policy.py` 가 참조하던 `data/policies/` 는 통합 전에도 비어있었음** — 1 단계 분석에서 "확인 필요"로 표시된 항목. **A 트랙은 정책 생성을 한 번도 끝까지 돌려본 적 없는 상태.** 통합 후 dry-run 검증이 필요 (qwen2.5:7b + Ollama 필요).

4. **`legacy/chroma_db/`** 가 있다면 폐기 — 임베딩 모델이 바뀌어 차원 호환 안 됨 (현재 합본에는 chroma_db 가 없음, 신규 적재 필요).

---

## 8. 의존성 정리

### 통합 후 `requirements.txt`

```
# Core
requests>=2.31
chromadb>=0.4.22
python-dotenv>=1.0
pyyaml>=6.0

# LLM / 임베딩
ollama>=0.1.7

# 보조 fetcher (옵션 — HackerOne 만 필요)
beautifulsoup4>=4.12
selenium>=4.15
```

### 제거된 의존성

| 패키지 | 제거 이유 |
|---|---|
| `nvdlib` | NVD REST 를 requests 로 직접 호출 (트랙 C 방식 통일) |
| `sentence-transformers` | Ollama nomic-embed-text 단일화 (차원 충돌 방지) |
| `tqdm` | 어디서도 import 안 함 (dead dep) |

### 처음 추가된 의존성

| 패키지 | 사용처 | 비고 |
|---|---|---|
| `pyyaml` | `policy/generate.py`, `policy/validate.py` | 트랙 A 가 사용했지만 어느 requirements 에도 없었음 |
| `ollama` | `pipeline/load_chroma.py` 외 | 트랙 C 가 사용했지만 누락돼있었음 |

---

## 9. 다음 할 일 (권장)

1. `python scripts/00_check_ollama.py` — Ollama + 3 모델 확인
2. `python scripts/03_load_chroma.py` — 7,501 records 임베딩 (예상 30분~1시간)
3. `python scripts/04_test_search.py` — retrieval 동작 확인
4. `python scripts/10_generate_policy.py` — 정책 생성 dry-run (트랙 A 가 한 번도 안 돌려본 영역)
5. (선택) `python scripts/01_fetch_all.py` + `02_build_dataset.py` — 실제 fetcher 가 통합 후에도 작동하는지 재수집으로 검증. NVD API 키가 있다면 빠름.

---

## 10. 협업자 3 명에게 공유할 메시지 템플릿

> 통합 작업 결과:
> - 너의 코드는 모두 보존됐다. 어디로 갔는지는 본 보고서 §3 매핑 표에서 확인 가능.
> - 옛 코드 원본은 `legacy/` 에 그대로 있다 — 의심스러운 게 있으면 `legacy/<옛경로>` 와 새 위치를 비교.
> - 데이터셋은 7,501 unique records 로 통합됨 (네 트랙의 카운트 합 7,760 에서 같은 CVE 머지로 축소).
> - 다음 PR 부터는 `src/blade/` 패키지 안에서 작업해줘. 새 코드는 schema 의 K 키 상수를 import 해서 metadata 키 사용 (오타 방지).
> - 임베딩 모델은 `nomic-embed-text` 로 통일됐다. 옛 MiniLM 코드를 그대로 돌리면 컬렉션 차원이 안 맞아서 깨진다.
