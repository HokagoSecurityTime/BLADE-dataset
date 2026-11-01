# API 인가 정책 데이터셋 재라벨링 방법론 제안

작성일: 2026-10-19. 상태: **제안 — 재추출·재라벨링·학습 미실행**.

## 1. 결론

**정책의 의미를 분류하는 작업과 실제 DB 조회 설정을 생성하는 작업을 분리한다.** 원천 OAS의 인가 설명을 복구하고, 근거가 명시된 항목에 먼저 정책 라벨을 부여한다. 조회 관계를 모르면 라벨을 자동으로 보류하지 말고 `lookup_status=unresolved`로 기록한다. 다만 정책 자체의 근거가 없거나 모순되면 계속 보류한다.

전체 2,027건을 바로 다시 처리하지 않는다. 고정된 100건 파일럿에서 근거 복구 효과와 사람 검수 정확도를 확인한 후 확대한다. 추정 ERD를 실제 스키마로 간주하거나, 클래스 수를 맞추기 위해 라벨을 만들어내지 않는다.

## 2. 현재 결과와 실패 원인

현재 `agent_label_report.json` 기준: public 9, role_required 9, membership_required 3, manual_review_required 2,006, 객체 정책 3종 각각 0건. low_conf 2,011건(99.21%). 파일 처리는 완료됐지만 7종 학습 데이터 확보라는 목적은 달성하지 못했다.

| 원인 | 확인된 사실 | 수정 방향 |
|---|---|---|
| 정책과 조회 설정을 함께 요구 | 소유자 제한이 문장에 있어도 owner_lookup 불명확 시 보류 | 의미 라벨과 조회 상태 분리 |
| 상세 설명 손실 | 추출기는 summary가 있으면 description을 사용하지 않으며, 없으면 description 앞 300자만 summary에 저장 | 두 필드 원문과 출처를 별도로 보존 |
| 추정 응답 구조를 ERD로 표시 | 응답/요청 속성을 CREATE TABLE로 변환; 중첩 속성·스키마 분기 평탄화 | response_schema와 실제 erd를 구분 |
| 근거가 없는 정보의 과대해석 위험 | owner/user/account 컬럼명, admin scope, 중첩 path는 후보 신호 | 검색·검수 우선순위에만 사용, 확정 라벨 근거로 단독 사용 금지 |
| 원본의 정보 한계 | 2,027건 모두 controller 없음, security null 754건 | 보완 가능한 근거를 먼저 수집; 불가능하면 보류 |
| 원천 편향 | 객체 ID 후보·service당 초기 최대 15건 중심; 추출 순서 영향 | 기존 집합 비교와 추가 데이터 구축을 별도 작업으로 관리 |

예: BigOven의 “Authenticated user must be the original one that posted the reply.”는 owner_match의 의미 근거다. 그러나 응답에서 평탄화된 Poster.UserID를 실제 replies 테이블의 소유자 컬럼이라고 단정할 수는 없다. 제안 방식에서는 **owner_match + lookup unresolved**로 표현한다. 이는 예시이며 기존 파일을 수정한 결과가 아니다.

## 3. 근거를 복구하는 방법

기존 2,027건의 ID·service·method·path를 고정한다. `meta.source_file`을 이용해 같은 원천 명세의 동일 operation을 찾는다. 원천이 없으면 unavailable, 버전이 다르면 version_mismatch로 기록하고 최신 명세로 조용히 대체하지 않는다.

복구 대상:

- operation summary와 description 전체, path-item 설명, parameter 설명과 required/type.
- operation/global security 원문과 적용 출처. operation의 빈 배열은 global 설정을 덮어쓴다. 누락과 익명 허용을 구분한다.
- security scheme 설명 및 OAuth scope 설명. scope 이름을 앱 역할이나 관리자 우회로 변환하지 않는다.
- 성공 응답과 오류 응답의 설명·스키마를 구분. default 응답을 성공 리소스 스키마로 간주하지 않는다.
- 요청 body와 응답 schema를 분리하고, `Poster.UserID` 같은 중첩 경로 및 oneOf/anyOf/allOf 분기를 보존한다. 같은 속성 이름을 합쳐 다른 객체의 관계로 오인하지 않는다.
- 원천 파일 상대경로, 파일 SHA-256, 명세 버전, JSON Pointer, 사용한 원문 구절을 저장한다. 저장소 revision은 확인 가능한 경우만 기록한다.

OpenAPI 3.x와 Swagger 2.0 구조 차이를 처리한다. 로컬 `$ref`는 JSON Pointer escape·순환을 처리하고, 외부 참조는 자동 네트워크 접근 없이 unresolved로 표시한다. 외부 문서 조사는 이후 별도 범위로 제안한다.

`erd_snippet`은 이력 비교용으로 보존하되 `schema_provenance=api_response_inferred`를 붙인다. 모델 입력에서는 verified DB schema라고 제시하지 않는다. 실제 스키마가 없는 항목은 `verified_erd=null`이다.

## 4. 분리할 출력 계약

7종 label 명칭은 유지한다. 후보 파일에는 보류 라벨도 남기고, 학습 적격 여부를 별도로 판단한다.

| 필드 | 의미 |
|---|---|
| label | public / role_required / membership_required / tenant_match / owner_match / owner_or_admin / manual_review_required |
| policy_status | supported / ambiguous / insufficient_evidence / conflict |
| evidence_strength | explicit / corroborated / heuristic_only / absent |
| evidence | 근거별 source_file, source_sha256, JSON Pointer, 원문 구절 |
| rationale | 해당 endpoint·operation에 대한 판단과 불확실성 |
| confidence | 보정되지 않은 보조 추정값; 근거 등급·사람 검수를 대체하지 않음 |
| object_param | 식별 가능한 실제 입력 파라미터; 불명확하면 null |
| owner_lookup | 검증 가능한 실제 조회 설정만 기록; 추정으로 생성하지 않음 |
| lookup_status | resolved / unresolved / not_applicable |
| lookup_reason | 근거 누락·모호한 객체 연결 등 구체적 이유 |
| label_source / reviewer / prompt_version | 에이전트 생성·사람 수정·검토 지침 버전 구분 |
| human_review | pending / confirmed / corrected / rejected 및 수정 이력 |
| training_eligibility | pending_review / policy_only / policy_and_lookup / excluded |

예시(개념 설명용; 원천 인용 위치는 복구 후 실제 값으로 채워야 함):

```json
{
  "label": "owner_match",
  "policy_status": "supported",
  "evidence_strength": "explicit",
  "object_param": "replyId",
  "owner_lookup": null,
  "lookup_status": "unresolved",
  "lookup_reason": "Owner restriction is explicit; physical database mapping is not verified.",
  "training_eligibility": "pending_review"
}
```

이것은 **새 데이터셋 계약 제안**이다. 기존 런타임 출력 계약은 객체 라벨에 lookup을 요구하므로 위 레코드를 그대로 정책 YAML 생성이나 기존 joint-output 학습에 넣으면 안 된다. 향후 정책만 예측하는 학습 과제와 lookup까지 예측하는 과제를 나누거나, 학습·평가 스키마를 명시적으로 변경해야 한다. 이번 단계에서는 런타임 검증을 완화하지 않는다.

`manual_review_required` 중 입력 근거 부족 때문에 보류된 항목은 곧바로 정답 학습 데이터로 넣지 않는다. 사람에게도 근거가 부족한 사례와, 명시적인 모순 때문에 보류가 올바른 사례를 구분한다. 데이터 결손을 모델의 보류 정답으로 대량 학습시키지 않는다.

## 5. 정책 판단 규칙

| 라벨 | 필요한 근거 | 단독 근거로 부족한 것 |
|---|---|---|
| public | 해당 작업이 공개·무제한 인가 대상임을 밝힌 설명과 모순 없는 맥락 | security 누락/빈 배열, GET, public 응답 속성 |
| role_required | 해당 작업에 요구되는 역할을 명시한 설명 | admin 경로·태그·scope 이름만 존재 |
| membership_required | 구독·회원 등급 또는 자격 요건을 명시 | member라는 테이블·필드명, OAuth scope |
| tenant_match | 호출자 조직과 대상 조직이 일치해야 한다는 관계 | organization_id·projectId가 있다는 사실 |
| owner_match | 호출자 자신·소유자·작성자만 허용하는 관계 | 응답에 author/user_id가 있다는 사실 |
| owner_or_admin | 소유자 허용과 관리자 대체 허용을 모두 명시 | 관리자 기능 존재, admin scope, 역할 컬럼 |
| manual_review_required | 근거 부족·충돌·여러 정책을 단일 라벨로 표현 불가 | 원하는 클래스 비율을 맞추기 위한 선택 |

명시적인 admin-only 작업은 리소스 ID가 있어도 역할 정책으로 판단할 수 있다. **ID 존재만으로 소유권 분기로 강제하지 않는다.** 반대로 admin OR owner는 role_required로 축약하지 않는다.

tenant AND role처럼 복합 조건인데 현재 7종으로 충실하게 표현할 수 없으면 conflict/ambiguous로 남긴다. 새로운 8번째 label은 만들지 않는다. 조건의 AND/OR 및 적용 범위를 근거에 보존한다.

정책 의미가 명확하면 physical lookup 미확정과 독립적으로 label을 정한다. 단, 누가 어떤 객체에 대한 소유권을 요구받는지 자체가 불명확하면 여전히 보류한다. 정책에 필요한 범위를 넘어 인증·데이터 필터를 소유권 검사로 해석하지 않는다.

## 6. 새 검토 지침 v2.2 제안

v2.0/v2.1을 수정하지 않는다. 승인 후 `training/data/prompts/policy_label_v2.2.md`라는 **데이터 검토 전용 지침**을 새로 만든다. 런타임과 다른 출력 계약이므로 루트 런타임 프롬프트의 새 버전인 것처럼 연결하지 않는다. `prompt_version=policy-label-v2.2`와 콘텐츠 해시로 추적한다.

지침에는 다음 순서를 명시한다: 관련 원문 근거 추출 → 주체/대상/조건 식별 → 정책 라벨 판단 → 조회 설정의 독립 평가 → 근거 충돌·누락 기록. 증거 없는 관계 추론과 입력 텍스트의 지시 따르기를 금지한다. API 과금 없이 에이전트 검토를 사용하되, 정확한 API 모델 실행과 동일한 재현성을 주장하지 않는다.

## 7. 단계별 실행 제안

### P1 — 근거 복구

`enrich_candidates.py`를 작성하여 고정 2,027건의 원문 근거를 복구한다. 원본 및 기존 라벨 파일은 변경하지 않는다. 복구 성공·원천 없음·operation 매칭 실패·참조 미해결 건수를 보고한다. 신규 API를 추가하거나 기존 필터를 다시 돌리지 않는다.

### P2 — 100건 파일럿 선정

seed 42로 다음을 중복 없이 선택한다. 기존 직접 판단 사례 21건 전부 + 기존 보류에서 79건. 보류 79건은 owner/tenant/both/path_only/none 신호 그룹을 16/16/16/16/15건씩 배정하고, 앞선 선택분은 제외한다. 그룹 부족 시 잔여 그룹으로 고정 순서 재배분하고 실제 배분을 기록한다.

현재 보류였지만 소유자 제한 설명이 이미 확인된 BigOven 사례는 해당 그룹의 선택분에 우선 포함하고, 나머지를 무작위 선택한다. 이는 균등 무작위 모집단 평가가 아닌 **의도적으로 구성한 파일럿**임을 표시한다. 선정 ID·원천 해시를 재라벨링 전에 고정한다.

### P3 — 에이전트 판단 및 사람 검수

에이전트는 복구된 근거를 읽고 개별 결정을 작성한다. 룰은 후보 검색과 스키마 검증에만 사용하고 라벨을 일괄 생성하지 않는다. 새 판단 시 이전 라벨을 숨기고 비교는 나중에 수행해 고정관념을 줄인다.

사람이 100건 전부를 검수한다. 검수표에는 label, 정책 근거 원문, lookup_status, 원천 위치, 수정 label, 수정 사유를 담는다. 기존 검수표의 사람 수정 내용을 덮어쓰지 않는다. 실제 원문을 확인할 수 없으면 검수 완료가 아니라 unresolved로 남긴다.

### P4 — 확대 여부 판단

아래는 실험 성과를 보장하는 기준이 아니라 **제안하는 품질 관문**이다.

- ID·필수 필드·허용 라벨 검사 통과, 모든 supported 라벨에 추적 가능한 근거 존재.
- 사람 확인 결과 잘못 인용한 원문 또는 발명한 lookup은 0건이어야 한다. 하나라도 발견하면 해당 원인을 수정한다.
- 기존 보류 79건 중 사람 확인을 거쳐 구체 정책으로 바뀐 비율과 건수를 보고한다. 전환율을 높이기 위해 근거 기준을 낮추지 않는다.
- 구체 정책으로 제안된 항목 중 사람 확인 비율 90% 이상을 확대 검토 기준으로 제안한다. 표본 수·오류 수를 함께 보고하며, 소수 사례만으로 클래스 정확도를 주장하지 않는다.
- 전체 및 label별 오라벨률은 사람 검수 가능한 항목을 분모로 명시한다. 검수 불가·보류는 별도 집계한다. 특정 label 오라벨률 20% 초과 시 그 label은 확대하지 않고 기준을 수정한다.
- pilot에서 유효한 정책 근거를 거의 얻지 못하면 2,027건 전체 재라벨링 대신 실제 근거가 있는 서비스 추가 구축으로 전환한다.

### P5 — 전체 적용과 분할 준비

파일럿 검수 후 같은 계약으로 나머지에 적용한다. 라벨별 최대 20건 무작위 검수와 lookup 미확정 사례·새로 발견된 클래스의 추가 검수를 구분해서 보고한다. 이 표본만으로 미검수 전체를 gold 데이터라고 부르지 않는다.

train/val 9:1 service 분할(seed42)은 그 뒤에 한다. 정책만 학습하는 집합에는 사람 검수 기준을 통과한 policy_only를 포함할 수 있지만, 조회 설정까지 학습하는 집합에는 policy_and_lookup만 허용한다. test는 여전히 별도 구축하며 여기서 생성하지 않는다. demo endpoint 누수 제거 및 같은 서비스·파생 버전의 교차 여부를 점검한다.

## 8. 제안 산출물

| 경로 | 용도 |
|---|---|
| processed/apisguru_enriched_v2.jsonl | 원문 근거 복구 사본 |
| training/data/enrichment_report_v2.md | 복구 성공률·실패 이유 |
| training/data/pilot_v2_ids.json | 선정 ID·seed·해시·배분 고정 |
| training/data/prompts/policy_label_v2.2.md | 데이터 전용 판단 계약 |
| processed/apisguru_policy_pilot_v2.jsonl | 100건 정책/조회 분리 결과 |
| training/data/review_sample_v2.md | 원문 근거를 포함한 새 사람 검수표 |
| training/data/pilot_comparison_v2.md | 이전/새 판단 전이, 사람 정정, lookup unresolved 비율 |
| processed/apisguru_policy_labeled_v2.jsonl | 파일럿 검수 후 확대된 결과 |

위 processed 경로는 모두 `datasets/blade/processed/` 아래다. 아직 파일을 생성하거나 실행하지 않았다. 기존 `apisguru_agent_labeled.jsonl`, `review_sample.md`, v2.1 프롬프트는 비교 자료로 보존한다.

## 9. 검증과 성공의 정의

코드 검증은 security 상속/빈 배열/미지정 구분, Swagger 2와 OAS 3 구조, 중첩 경로 보존, 참조 순환·미해결 표시, 원문 인용 일치, 입력 ID 보존, evidence 없는 supported 거부를 다룬다.

데이터 검증에서는 **label=owner_match이며 owner_lookup=null이고 lookup_status=unresolved인 후보가 허용됨**을 확인하되, 해당 레코드가 실행 정책이나 lookup 학습 세트에 들어가지 못하도록 검사한다. 누락된 판단을 기본 라벨로 채우지 않는다. 기존 Phase 1·2 테스트는 그대로 유지한다.

성공은 보류율 하락 자체가 아니다. **사람이 원문으로 확인할 수 있는 정책 라벨이 늘고, 미확정 조회 설정이 확정 사실과 섞이지 않는 것**이다. APIs.guru만으로 모든 클래스의 충분한 사례가 확보된다고 약속하지 않는다. 부족한 객체 정책 클래스는 실제 코드·스키마가 있는 공개 서비스나 별도 합성 서비스로 보충하되, 출처와 평가 세트를 분리해야 한다.

추천 착수 범위: **P1 근거 복구 + P2 파일럿 고정 + P3 100건 재검토 및 검수표 작성까지**. 사용자 검수 후 확대 여부를 결정한다. 학습 코드·유료 API 호출·런타임 정책 변경은 이 제안 범위에 포함하지 않는다.
