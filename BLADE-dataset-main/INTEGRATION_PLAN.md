# 2단계: 통합 설계 제안

3명이 각자 구축한 CVE/보안 데이터셋 파이프라인 (트랙 A/B/C)을 단일 코드베이스로 병합하기 위한 설계안.
1단계 전수 분석 결과를 바탕으로 작성. 결정이 필요한 분기점은 ⚠️ 표시.

---

## A. 통합 후 디렉토리 구조 (제안)

```
BLADE-DATASET-MAIN/
├── README.md                       # 새로 작성 (현재는 1줄)
├── requirements.txt                # 통합본 (단일)
├── .env.example                    # NVD_API_KEY, GITHUB_TOKEN, CHROMA_PATH 등
├── .gitignore
│
├── data/                           # ← dataset/ + data/ 통합. 데이터만 보관
│   ├── raw/
│   │   ├── nvd_cves.json           #  A의 nvd_cves_raw.json + C의 nvd_raw.csv 통합본
│   │   ├── nvd_cves.csv            #  CSV export (선택)
│   │   ├── hackerone_reports.json  #  B 트랙 보존
│   │   ├── github_advisories.json  #  B 트랙 보존
│   │   ├── cisa_kev.json           #  B 트랙 보존
│   │   ├── owasp_wstg.json         #  B 트랙 보존
│   │   ├── capec_curated.json      #  B 트랙 보존
│   │   └── standards_seed.csv      #  C의 bola_dataset.csv (CWE/CAPEC/WSTG 큐레이션 시드)
│   │
│   ├── processed/
│   │   └── bola_dataset.json       # ★ 통합 데이터셋 (단일 정합 스키마)
│   │
│   └── policies/                   # A 트랙 generate_policy 출력 (현재 미존재)
│
├── src/blade/                      # 모듈화. CWD 의존 제거
│   ├── __init__.py
│   ├── config.py                   # 경로/모델/컬렉션 이름 한 곳에 모음
│   ├── schema.py                   # 통합 스키마 정의 + Record dataclass
│   │
│   ├── sources/                    # 데이터 소스별 fetcher (역할 = "외부에서 raw 가져오기")
│   │   ├── nvd.py                  # A `01_fetch_cve` + B `fetch_nvd` + C `nvd_bulk_collector` 통합
│   │   ├── hackerone.py            # B에서 추출
│   │   ├── github_advisory.py      # B에서 추출
│   │   ├── cisa_kev.py             # B에서 추출
│   │   ├── owasp_api.py            # B에서 추출
│   │   ├── owasp_wstg.py           # B에서 추출
│   │   ├── capec.py                # B에서 추출
│   │   └── google_sheets.py        # C `sheets_importer`
│   │
│   ├── enrich/                     # raw → enriched record 변환
│   │   ├── rules.py                # A `classify_pattern` + B `rule_based_classify` + C `enrich_nvd.infer_*` 통합
│   │   └── llm.py                  # B `enrich_with_llm` (Ollama llama3.2 호출)
│   │
│   ├── pipeline/                   # 단계별 실행 진입점
│   │   ├── fetch.py                # 모든 소스 → data/raw/*.json
│   │   ├── build_dataset.py        # raw → enrich → data/processed/bola_dataset.json
│   │   ├── load_chroma.py          # bola_dataset.json → ChromaDB
│   │   └── search_test.py          # 검색 테스트 (현 05_test_search 자리)
│   │
│   ├── policy/                     # A 트랙 정책 생성 RAG
│   │   ├── templates.py            # A `policy_templates`
│   │   ├── retrieve.py             # A `retrieve_patterns`
│   │   ├── generate.py             # A `generate_policy`
│   │   └── validate.py             # A `validate_policy`
│   │
│   └── utils/
│       ├── ollama_client.py        # 임베딩/생성 Ollama 호출 단일화
│       └── chroma_client.py        # ChromaDB 클라이언트/컬렉션 헬퍼
│
├── scripts/                        # 사용자가 실제 실행하는 CLI 진입점 (얇은 래퍼)
│   ├── 00_check_ollama.py          # A에서 그대로
│   ├── 01_fetch_all.py             # → src/blade/pipeline/fetch.py
│   ├── 02_build_dataset.py         # → src/blade/pipeline/build_dataset.py
│   ├── 03_load_chroma.py           # → src/blade/pipeline/load_chroma.py
│   ├── 04_test_search.py           # → src/blade/pipeline/search_test.py
│   ├── 10_generate_policy.py       # → src/blade/policy/generate.py
│   └── 11_validate_policy.py       # → src/blade/policy/validate.py
│
├── docs/                           # dataset/docs/ 이동
│   ├── README.md
│   ├── DB_Guide.md
│   ├── dataset_guide.md
│   └── nvd_raw_guide.md
│
├── tests/                          # 새로 (선택)
│
├── chroma_db/                      # gitignore (런타임 산출물)
│
└── legacy/                         # 원본 보존 (안전망)
    ├── src/                        # 옛 src/* 전체
    ├── dataset/                    # 옛 dataset/* 전체 (raw/chunks/scripts/rag_scripts 포함)
    ├── data/                       # 옛 data/* 전체
    └── env_test.py
```

⚠️ **결정 포인트 1**: `src/blade/` 패키지화 vs 그냥 `src/` 평탄화
- 추천: 패키지화. CWD 의존 제거되고 import 경로가 안정됨.
- 대안: 평탄화. 학습 비용 적음. 그러나 셋 다 같은 폴더에 던져넣으면 다시 카오스.

⚠️ **결정 포인트 2**: `data/` 위치를 루트로 vs `src/blade/data/`로
- 추천: 루트. 데이터는 코드와 별개 자산.

---

## B. 중복 함수/모듈 통합 — base 선정

| 기능 | base 선정 | 보존할 가치 | 폐기 |
|---|---|---|---|
| **NVD fetch** | C `nvd_bulk_collector` (CWE 기반, 양·재시도·rate-limit 가장 견고) | A의 `nvdlib` keyword 모드를 옵션 플래그로 통합, B의 페이지네이션 로직은 코드 중복 | A `01_fetch_cve` (nvdlib 의존 제거) |
| **CWE/desc/CVSS 추출 헬퍼** | B `cve_fetcher`의 인라인 (가장 방어적, None-safety) | C `nvd_bulk_collector._severity/_description/_cwe_list`를 함수로 빼서 재사용 | A의 같은 헬퍼 |
| **HackerOne / GitHub / CISA / OWASP / WSTG / CAPEC** | B `cve_fetcher` (유일한 구현, source별로 파일 분할만) | — | — |
| **Google Sheets 임포트** | C `sheets_importer` (유일) | — | — |
| **enrichment (rule-based)** | C `enrich_nvd.infer_*` (가장 결정론적, ownership 5종 분류 풍부) + B `rule_based_classify` (가이드 7-pattern 직결) **둘 다 유지** | A `classify_pattern` (4-pattern) → 통합 스키마의 `policy_template_hint` 필드로 보존 | — |
| **enrichment (LLM)** | B `enrich_with_llm` (구조화 프롬프트, fallback 견고) | — | — |
| **Ollama 호출** | 새로 `utils/ollama_client.py`로 묶기 | A/B/C 셋 다 `requests.post` 직접 호출 → 한 곳에서 timeout/retry 통합 | 직접 `requests` 호출 3곳 |
| **ChromaDB 적재** | C `load_to_chromadb` (source_type별 컬렉션 분할 전략, 가이드 §4-5와 일치) | B `embedder`의 metadata sanitization 로직 흡수 | A `04_load_chroma` (단일 컬렉션, MiniLM 의존) |
| **임베딩** | `nomic-embed-text` (Ollama, 768d) — 가이드 권장 모델 | — | A의 `all-MiniLM-L6-v2` 폐기 (차원 불일치, 한 DB에 공존 불가) |
| **검색/RAG** | A `retrieve_patterns` (정책 생성에 직결되는 유일한 구현) | 임베딩 함수만 nomic으로 교체 | — |
| **정책 생성/검증** | A `generate_policy` + `validate_policy` (유일) | Ollama 호출만 새 client로 | — |

⚠️ **결정 포인트 3**: 임베딩 모델 단일화
- 추천: `nomic-embed-text` (Ollama, 768d) 단일화. A 트랙도 같은 컬렉션에서 retrieve 가능해짐.
- 비용: A를 돌려본 사람은 sentence-transformers 환경이 갖춰져 있음 → Ollama + nomic 모델 풀이 추가로 필요해짐.
- 대안: 컬렉션 자체를 분리해 두 모델 공존 (`blade_cve_kb` MiniLM + `bola_*` nomic) — 통합 의미가 반감됨. 비추.

⚠️ **결정 포인트 4**: ChromaDB 컬렉션 전략
- 추천: C의 3-컬렉션 분할 (`bola_cve` / `bola_standards` / `bola_patterns`) — 가이드 §4-5와 일치, source_type 라우팅 단순.
- 대안: 단일 컬렉션 + metadata 필터. 검색 단순하지만 컬렉션 분할 검색의 신호 격리 효과 잃음.

---

## C. 데이터셋 통합 스키마 (초안)

세 트랙의 metadata를 superset으로 합치되, 가이드 §3을 베이스로. **모든 필드는 optional 허용 + 기본값으로 빈 문자열 / None / 0.0**.

```python
# src/blade/schema.py
@dataclass
class Record:
    id: str                  # 규칙: "{source}-{native_id}" 예: "nvd-CVE-2022-34770", "hackerone-12345"
    document: str            # ChromaDB 임베딩 대상 텍스트 (가이드 §4 형식)
    metadata: Metadata

@dataclass
class Metadata:
    # === Provenance (가이드 §3) ===
    source: str              # nvd | hackerone | github | cisa | owasp_api | wstg | capec | sheets | cwe
    source_type: str         # cve | standard | report | pattern   ← 컬렉션 라우팅 키
    cve_id: str = ""
    url: str = ""
    title: str = ""
    updated_at: str = ""

    # === Vulnerability classification (NVD 공식) ===
    cwe_id: str = ""         # 단일 (B 스타일). 복수 CWE는 "|" join
    severity: str = ""       # LOW/MEDIUM/HIGH/CRITICAL/UNKNOWN  ← string으로 통일
    cvss_score: float = 0.0  # ← float 분리 (C는 둘이 합쳐있던 것을 분리)
    attack_vector: str = ""

    # === BOLA 패턴 분류 (가이드 7-pattern, B에서 채움) ===
    bola_pattern: str = ""           # integer_id_enumeration | nested_resource_idor | ... (가이드 §3)

    # === Endpoint/ownership (C+B 풍부 필드) ===
    endpoint_pattern: str = ""
    http_method: str = ""
    id_type: str = ""                # path_param | query_param | body_param | unknown
    id_format: str = ""              # uuid | integer_sequential | string_slug | unknown
    ownership_type: str = ""         # direct | hierarchical | delegated | role_based | contextual (C)
    ownership_check_missing: str = "" # 어디서 검증이 빠졌는지 (B+C 텍스트)
    attack_method: str = ""          # id_substitution | id_enumeration | parameter_tampering | mass_assignment | ... (C+B 합집합)

    # === Detection/policy hints ===
    rule_type: str = ""              # jwt_ownership | block_path | rate_limit | strip_body_field (가이드 §4 표)
    rule_based_detectable: bool = False
    inference_required: bool = True
    business_logic_complexity: int = 0  # 1~5 (C, 가이드 §3 정의)
    domain: str = ""                 # ecommerce | finance | sns | enterprise | file | generic
    owasp_mapping: str = ""          # API1:2023

    # === A 트랙 정책 hint 보존 ===
    policy_template_hint: str = ""   # owner_match | tenant_match | role_required | ... (A `recommended_policy`)

    # === Enrichment 메타 ===
    enrichment_method: str = ""      # preclassified | rule | llm
    reason: str = ""                 # enrichment 근거 1줄
```

**document 텍스트 형식** (가이드 §4 따라 영어 통일):

```
source: {source}  source_id: {cve_id|id}
endpoint: {http_method} {endpoint_pattern}
id_type: {id_type} ({id_format})
ownership: {ownership_type} — {ownership_check_missing}
attack: {attack_method} ({bola_pattern})
cwe: {cwe_id}  owasp: {owasp_mapping}  severity: {severity} ({cvss_score})
description: {description}
```

⚠️ **결정 포인트 5**: 키 이름 충돌 해소 (B와 C가 다른 이름으로 같은 의미를 씀)
- B `cwe_id` ↔ C `cwe` → **`cwe_id`로 통일** (가이드 표기)
- B `cve_id` (separate) vs C `source_id` (CVE면 CVE-..., CWE면 CWE-...) → **둘 다 보존** (`source_id` = "{source}-{native}", `cve_id`는 CVE만 채움)
- A `attack_pattern` (4종 자체 분류) → **`policy_template_hint`로 의미 변경해 보존** (혼동 방지)
- B `bola_pattern` (7종) = 가이드 표준 → **이 이름 유지**
- C `attack_method` (3종) → **유지** (B와 의미가 미묘히 다른 직교 분류)

⚠️ **결정 포인트 6**: 기존 데이터 마이그레이션 정책
- 옵션 A — **재생성**: 기존 JSON/CSV 다 버리고 통합 fetcher 한 번 돌려서 처음부터. 깔끔하지만 NVD API rate limit으로 시간 소요.
- 옵션 B — **변환만**: 기존 3종 데이터를 새 스키마로 변환 스크립트 한 번 돌리고 끝. 빠르지만 fetcher 코드 통합 결과의 검증이 안 됨.
- 옵션 C(추천) — **하이브리드**: 일단 변환 스크립트로 통합 데이터셋 만들고, 추후 fetcher가 안정되면 재수집.

---

## D. 통합 `requirements.txt` (초안)

```
# Core
requests>=2.31
chromadb>=0.4.22
python-dotenv>=1.0
pyyaml>=6.0

# Data sources
nvdlib>=0.7              # A 트랙 keyword fetch 옵션 보존 시
beautifulsoup4>=4.12     # B HackerOne 보조 파싱
selenium>=4.15           # B HackerOne (Chrome 필요 — README에 명시)

# Embedding / LLM
ollama>=0.1.7            # C `load_to_chromadb` 직접 호출 + 새 ollama_client에서 사용

# (제거)
# tqdm                   ← 어디서도 import 안 함
# sentence-transformers  ← MiniLM 폐기 → 제거. 단, 폐쇄망 fallback 필요하면 유지.
```

⚠️ **결정 포인트 7**: `nvdlib` 유지 vs 제거
- 유지: A의 keyword 검색을 그대로 살릴 수 있음
- 제거: NVD REST를 `requests`로 직접 호출하는 C 방식으로 통일 (의존성 1개 줄임)

⚠️ **결정 포인트 8**: `sentence-transformers` 유지 vs 제거
- 추천 제거 (Ollama 단일화)
- 유지: Ollama가 안 떠있을 때 폐쇄망 fallback 가능

---

## E. 마이그레이션 리스크

| # | 리스크 | 가능성 | 영향 | 완화책 |
|---|---|---|---|---|
| 1 | **임베딩 모델 변경 → 기존 ChromaDB 폐기 필요** | 확실 | 중 (재임베딩 시간) | `legacy/chroma_db/` 백업 후 새 디렉토리에 재생성. 6,685건 × Ollama 임베딩은 30분~1시간. |
| 2 | **컬렉션 이름 충돌** (`blade_cve_kb`/`bola_kb`/`bola_cve`) | 확실 | 중 | 새 이름 3종(`bola_cve`/`bola_standards`/`bola_patterns`)으로 통일하고, A 트랙 retrieve도 이쪽에서 검색하게 변경 |
| 3 | **CVE 중복 ID 충돌** (A: `CVE-2022-34770`, B: `nvd-CVE-2022-34770`, C: `cve_cve_2022_34770_0000`) | 확실 | 높음 | `id` 규칙을 `{source}-{native_id}`로 통일. C 데이터는 `cve_cve_..._0000` → `nvd-CVE-...`로 변환. **인덱스 suffix 손실** 됨에 유의 |
| 4 | **6,635건 NVD ↔ 145건 BOLA 데이터 중복** | 확실 | 중 | C가 NVD를 CWE 기반으로 양적으로 수집, B는 키워드+멀티소스로 질적 수집. 같은 CVE는 source가 같으면 dedupe(id), 다른 source면(예: nvd vs cisa) 둘 다 보존 |
| 5 | **A 트랙 `retrieve_patterns` 메타데이터 키 변경** (`attack_pattern`/`recommended_policy` → `bola_pattern`/`policy_template_hint`) | 확실 | 중 | retrieve/generate 코드의 키 참조 11곳 일괄 수정 필요. 스키마 정의를 `schema.py`에서 import해서 키 상수화 |
| 6 | **Selenium/Chrome 의존이 트랙 A 사용자 환경에 추가됨** | 중 | 낮 | requirements를 `core` / `optional-fetch` 두 그룹으로 분리. HackerOne fetch는 optional |
| 7 | **`data/policies/` 디렉토리 미존재 → A 정책 생성 한 번도 안 돌아간 상태** (1단계 분석에서 "확인 필요"로 남김) | — | — | 통합 후 한번은 dry-run으로 generate_policy 검증 필요 |
| 8 | **`dataset/raw/bola_dataset.csv`의 출처 불명** (어떤 코드도 안 읽음) | — | — | `data/raw/standards_seed.csv`로 보존 + docs에 "수동 큐레이션 시드"라고 명시 |
| 9 | **Google Sheets 시트 ID가 코드에 하드코딩됨** | 낮 | 중 (시트 권한 변경 시 깨짐) | env로 빼기 (`BLADE_SHEETS_ID`) |
| 10 | **import 경로 깨짐** (3명이 각자 `sys.path.append` + 상대경로 혼용) | 확실 | 중 | `src/blade/` 패키지로 정리하면 `pip install -e .` (또는 PYTHONPATH=src) 단일 진입점 |
| 11 | **legacy/ 보존이 git 추적/사이즈 문제** | 중 | 낮 | legacy/는 `.gitignore`에 넣고 로컬에만 보존하거나, 별도 브랜치(`legacy-backup`)로 보관 — 팀과 합의 필요 |
| 12 | **3명의 작성자 중 한 명이 자기 코드가 사라진 줄 알고 PR 거부** | 중 | 높음 | legacy/ 백업 + 통합 PR 본문에 "어느 코드가 어디로 갔는지" 매핑 표 첨부. 3명에게 분석 보고서 공유 후 합의 |

---

## F. 통합 실행 순서 (3단계 진행 시 권장 청크)

쪼개서 진행하면 중간 검증이 쉽다.

1. **세이프티 백업**: `legacy/` 만들고 기존 `src/`, `dataset/`, `data/`, `env_test.py` 통째로 이동 (삭제 안 함)
2. **데이터 폴더 통합**: `data/raw/`, `data/processed/` 새 구조로 옮기기 (스키마 변환은 아직 안 함)
3. **스키마 통합 변환기 작성**: `tools/migrate_legacy.py` 한 번 돌려서 기존 3종 → `data/processed/bola_dataset.json` 단일 정합 파일 생성. **재수집 없이 스키마만**.
4. **`src/blade/` 패키지 골격 + 핵심 모듈 작성**: schema, config, ollama_client, chroma_client, sources/nvd.py 등 — 기존 코드를 모듈로 옮기고 import 경로만 정리
5. **CLI 래퍼 (`scripts/0X_*.py`) 추가**: 사용자 인터페이스는 기존 `00_~05_` 패턴 유지
6. **requirements 통합 + README 갱신**
7. **검증**: 각 단계마다 카운트/스키마 sanity check, ChromaDB 재적재, retrieve test 1회씩

---

## 결정해야 할 항목 요약 (8개)

| # | 결정 | 추천 |
|---|---|---|
| 1 | `src/blade/` 패키지화 vs 평탄화 | 패키지화 |
| 2 | `data/`를 루트 vs `src/blade/data/` | 루트 |
| 3 | 임베딩 모델 (Ollama nomic 단일화 vs 분리 공존) | nomic 단일화 |
| 4 | ChromaDB 컬렉션 (3개 분할 vs 단일+필터) | 3개 분할 (가이드 §4-5) |
| 5 | A 트랙 `attack_pattern`(4종) → `policy_template_hint`로 의미 변경 보존 | 보존 |
| 6 | 기존 데이터 처리 (재생성 vs 변환 vs 하이브리드) | 하이브리드 |
| 7 | `nvdlib` 유지 vs 제거 | 제거 (의존성 줄이기) |
| 8 | `sentence-transformers` 유지 vs 제거 | 제거 (Ollama 단일화) |
