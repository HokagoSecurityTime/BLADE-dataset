# B·C 완료 보고

## 최신 상태 — 에이전트 직접 라벨링 D 완료

사용자 요청에 따라 유료 API 대신 대화형 에이전트가 2,027건을 직접 검토했다. 사용량 제한으로 중단된 구간은 저장된 개별 판단에서 재개했다. 이번 에이전트 실행의 외부 라벨링 API 호출은 0회다. 아래의 기존 API 잔액 부족 기록은 이전 실행 이력이다.

| label | 건수 |
|---|---:|
| public | 9 |
| role_required | 9 |
| membership_required | 3 |
| tenant_match | 0 |
| owner_match | 0 |
| owner_or_admin | 0 |
| manual_review_required | 2,006 |

- 결과: `datasets/blade/processed/apisguru_agent_labeled.jsonl` — 2,027건, ID 누락·중복 0, 7종 외 라벨 0.
- low_conf: **2,011건(99.21%)**. label_error: **0건**. 보류 판단은 처리 실패가 아니며, 오류 0이 라벨 정확성을 뜻하지 않는다.
- 검수표: `training/data/review_sample.md` **41건**. public 9 + role 9 + membership 3 전부와 manual 무작위 20건(seed42). 0건인 세 라벨은 샘플 생성 불가. 마지막 '검수' 열에 수정 라벨을 적는다.
- 출처: model_id=`codex-agent-unreported`, meta.label_source=`interactive_codex_agent`. 정확한 기반 모델·설정은 노출되지 않아 API 모델명으로 가장하지 않았다. v2.1은 검토 지침으로 사용했으며 API 프롬프트의 동일 재현 실행은 아니다. confidence는 보정되지 않은 주관적 판단이다.
- 코드 검증: 전체 **231 passed, 1 skipped, 3 warnings**. 세 묶음 각각의 배정 ID 및 출력 스키마 검증 후 입력 순서로 합병했다. 원본 필드·meta는 유지하고 라벨 및 출처 필드만 추가했다.

**이 결과는 지금 상태로 7종 분류기 학습에 사용할 수 없다.** 보류 비율이 98.96%이며 객체 정책 세 클래스가 비어 있다. 후보의 ERD는 API 응답에서 만든 추정 스키마이고, OAS 상세 description은 보존되지 않았으며 컨트롤러 신호도 없다. 소유자 컬럼처럼 보이는 이름만으로 실제 조회 관계를 발명하지 않도록 한 v2.1 기준 때문에 대부분 보류됐다. 공개/역할/구독 21건도 사람 검수가 필요하다.

다음은 사람 검수와 근거 보강이다. 원천 OAS의 상세 인가 설명을 보존하고, 확인 가능한 DB 조회 관계나 컨트롤러 증거가 있는 서비스를 추가해야 한다. 별도 사용자 검수 전 train/val 분할·학습은 수행하지 않는다. 상세 출처·해시·한계는 `training/data/AGENT_LABEL_REPORT.md`와 `agent_label_report.json`을 참조한다.

---

## 2026-10-19 D 실행 시도 — API 크레딧 부족으로 중단

사용자 승인 후 OpenAI gpt-4o-mini / v2.1 / concurrency=4로 실제 실행을 시작했다. API 진단 응답은 HTTP 429, error.type=insufficient_quota, error.code=credit_balance_exhausted였다. 일시적 rate limit이 아니므로 반복 요청을 중단했다.

- 저장된 라벨: **0건**. 첫 100건 체크포인트 이전 중단되어 partial JSONL은 생성되지 않았다. manifest만 남아 있으며 실행 중인 프로세스가 없음을 확인한 뒤 stale lock을 제거했다.
- 원본 및 filtered 데이터는 변경하지 않았다. 검수표·라벨 분포는 아직 생성할 수 없다.
- quota exhausted를 감지하면 즉시 종료하도록 보완했다. 일반 429는 기존 지수 백오프를 유지한다. 관련 테스트 11개 통과.
- API 계정/프로젝트의 크레딧을 충전하거나 사용 가능한 API 키를 `.env`에 설정한 후 재개할 수 있다. ChatGPT 구독과 별개인 해당 API 계정의 상태를 확인해야 한다. 현재 요청 시도 수는 계측하지 않아 정확한 숫자를 보고하지 않는다.
- 사용자의 D 실행 승인은 유지된다. 충전 완료를 알려주면 동일 입력으로 다시 실행하고 완료 후 라벨별 검수표를 만든다.

재개 명령(PowerShell):

```powershell
$env:TIKTOKEN_CACHE_DIR='C:\BLADE\.cache\tiktoken'
.\.python\python.exe -m training.data.label --execute --provider openai --model gpt-4o-mini --concurrency 4
```

---

## 2026-10-19 추가: v2.1 프롬프트 보완

아래 기존 C 결과는 v2.0 기록이다. **현재 라벨러 기본값은 v2.1**이며 `prompts/v2.0.md`는 수정하지 않았다. 런타임 기본값은 v2.0으로 유지한다.

- 라벨러가 OAS의 effective security 원문, scope 목록, 익명 인증 대안 여부를 공용 프롬프트에 전달한다. 원본 추출기는 operation/global 적용 후 값만 저장하므로 상속 출처는 복원하거나 추측하지 않는다.
- security 누락은 unknown이며 public의 근거가 아니다. 빈 배열/빈 요구사항 객체도 객체 인가가 불필요하다는 증거는 아니다. 배열의 OR 및 객체 내부 AND 의미를 유지한다.
- admin/write/manage scope만으로 역할·관리자 우회·소유권을 판단하지 않는다. 인증만 확인되고 7종 정책 근거가 부족하면 manual_review_required로 처리한다.
- ERD가 API 응답에서 추정한 정보임을 명시하고 PK/FK·조회 키·소유권의 발명을 금지한다.
- 런타임에서도 v2.1 선택과 classify(..., security_context=...)로 같은 템플릿을 사용할 수 있다. 기존 Endpoint 파서는 security를 자동 전달하지 않으므로 호출자가 제공하지 않으면 unknown이다.

소켓 연결을 차단한 dry-run 재계산(API 호출 0회):

| 지표 | v2.1 |
|---|---:|
| 표본 평균 입력 | 1,586.48토큰 |
| 표본 최대 / 전체 최대 | 1,890 / 2,412토큰 |
| 8,000 초과 | 0건 |
| 예상 총 토큰(출력 건당 150 포함) | **3,519,845** |
| truncate 적용 시 총 토큰 | **3,519,845** |
| 예상 시간(건당 3초, 동시 4개 가정) | 약 25분 20초 |

v2.0 추정 대비 약 29.9% 증가. 단가 미입력으로 금액은 미산정. 실제 모델 분류 품질은 아직 측정하지 않았으며 D는 실행하지 않았다. 토큰 상세는 `label_dry_run.json`, 이전 v2.0 값은 `label_dry_run_normal.json`에 보존한다.

---

B 결과: `datasets/blade/processed/apisguru_filtered.jsonl`, **2,027건 / 370 services**, seed 42.

| signal_class | has_security=false | has_security=true |
|---|---:|---:|
| owner | 169 | 258 |
| tenant | 49 | 111 |
| both | 88 | 154 |
| path_only | 112 | 286 |
| none | 350 | 450 |

| method | 건수 |
|---|---:|
| DELETE | 84 |
| GET | 1,304 |
| PATCH | 131 |
| POST | 290 |
| PUT | 218 |

- none 쿼터 조정 없음: security=true 450 / false 350. 두 none 그룹을 합쳐 service당 최대 4건, 상한 도달 121 services.
- 신호 그룹에는 service 상한을 추가하지 않음. 전체 service당 최대 15건, 15건인 service는 16개.
- 신호 그룹 1,243 + none 800 = 2,043건 선택 후 중복 16건 제거 → 2,027건. 입력 전체 중복 24건 중 나머지 8건은 선택 집합에 들어오지 않음. 선택된 중복은 입력 순서상 첫 건 유지.
- incomplete: 신호 그룹의 저정보 126건을 유지 대상으로 삼았고, 중복 제거 후 125건.

## C — API 호출 없는 토큰 계산

모델: **OpenAI gpt-4o-mini**. `--provider/--model` → `BLADE_LABEL_PROVIDER/BLADE_LABEL_MODEL` → 기본값 순서. 런타임 `BLADE_LLM_*` 설정과 분리하며 `.env`는 수정하지 않음. Qwen은 베이스라인·파인튜닝용이며 라벨 생성에 사용하지 않음.

`verification/phase3/dry_run_offline.py`로 소켓 연결을 차단한 상태에서 일반/`--truncate-erd` dry-run 각각 성공. 실제 라벨링 API 호출 **0회**, D 미실행.

| 지표 | 결과 |
|---|---:|
| signal_class별 표본 | 10건씩, 총 50건 |
| 표본 평균 입력 토큰 | 1,187.14 |
| 표본 최대 입력 토큰 | 1,497 |
| 전체 최대 입력 토큰 | 2,015 |
| 8,000 초과 | 0건 |
| 추정 입력: 평균 × 2,027, 올림 | 2,406,333 |
| 추정 출력: 150 × 2,027 | 304,050 |
| 추정 총 토큰 | **2,710,383** |
| truncate 적용 시 총 토큰 | **2,710,383** |
| 실제 절단 대상 | 0건 |
| 예상 시간: 3초 × 2,027 / 4 | **1,520.25초 ≈ 25분 20초** |

단가는 `training/configs/pricing.yaml`의 gpt-4o-mini / claude-sonnet-4-5 항목을 사용자가 입력하도록 비워뒀다. 금액은 아직 계산하지 않음. 시간에는 재시도·rate limit 지연이 포함되지 않으며 출력 150토큰은 추정 가정이다.

토큰은 tiktoken 0.14.0 / o200k_base로 시스템·사용자 본문을 센 값이며 API 메시지 포장 비용은 제외한다. 과금 토큰의 확정값이 아니다. [OpenAI 토큰 계산 문서](https://developers.openai.com/api/docs/guides/token-counting).
50건은 클래스 균등 표본이라 모집단 비율과 다르다. 추가로 전체 본문을 직접 합산한 입력은 2,396,833토큰이며 가정 출력 포함 2,700,883토큰이다.

## 공용 프롬프트와 실행 준비

- `prompts/v2.0.md`: SHA-256·스냅샷 일시 포함. 런타임 `prompt.py`와 라벨러가 같은 파일을 읽고, 향후 내용 변경은 v2.1 등 새 버전으로 한다. 패키지 및 Docker 복사 대상에 포함.
- 원본 프롬프트는 `verification/phase3/prompt_before_v2.py`에 보존. 7개 데모 엔드포인트와 controller/RAG 조합에서 조립된 UTF-8 바이트 동일성 검증.
- RAG/controller off, 원본의 ERD 컬럼 이름을 사용하되 없는 PK/FK는 추측하지 않음. A2 owner/tenant 후보는 휴리스틱 힌트다.
- **현재 런타임 Endpoint 템플릿은 OAS security를 전달하지 않는다.** v2.0 동일성을 유지했으므로 has_security/scopes는 데이터에 보존되지만 모델 입력에는 직접 포함되지 않는다. 이 신호가 필요한 public/role 분류에는 한계가 있다.
- `--truncate-erd`: 8,000 초과 건만 owner/tenant 후보 + id + 첫 30컬럼 합집합으로 전송. 저장되는 원본 ERD는 보존하며 실제 절단 시 meta.erd_truncated 표시.
- 향후 승인된 실행: 100건 단위 append·flush·fsync, 입력/모델/프롬프트 manifest 검증 후 재개, concurrency 기본 4, 최초 요청 + 재시도 3회, 429 지수 백오프. 중단 시 미커밋 최대 100건은 다시 요청될 수 있음. 손상된 체크포인트는 자동 삭제하지 않고 오류로 중단.
- 출력은 요청한 label/confidence/rationale/object_param/owner_lookup/model_id/prompt_version/labeled_at. confidence<0.6은 low_conf, 최종 실패는 label_error. 런타임의 confidence<0.7 라벨 자동 치환은 데이터 라벨에 적용하지 않음.
- 모델 역할 구분은 실제 저장소 규약 파일 `AGENT.md`의 Phase 3에 기록. 학습·분할 코드는 실행하지 않음.

검증: 전체 테스트 **222 passed, 1 skipped, 3 warnings**. 재시도·체크포인트 테스트는 모의 응답만 사용. D는 사용자 명시 승인 전 실행하지 않는다.
