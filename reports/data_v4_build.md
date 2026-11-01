# data-v4 학습 보강 + test_v31_supp 평가 추가분 구축 (2026-10-28, 검수 전 정지)

학습·동결은 하지 않았다. test_v30·data-v1~v3는 해시 확인 후 읽기만 했다(빌드 시작·끝 assert). 라벨 정의·AGENTS 규칙은 바꾸지 않았다.

## 1. 출처 결정

- **학습 출처 교체(사용자 결정 2026-10-27):** 지시서의 Mattermost(AGPL-3.0, api/ 명세 포함)와 Plane(AGPL-3.0)은 data-v3 1b의 rw_axum(AGPL) 제외와 같은 이유로 허용 라이선스 프로젝트로 바꿨다.
  - Mattermost → **Zulip 12.3** (Apache-2.0, 커밋 `b3198225`): OpenAPI 설명에 권한 문구가 있고, 채널 구독·관리자·작성자 또는 관리자 구조가 있다.
  - Plane → **Label Studio 1.23.2** (Apache-2.0, 커밋 `df96d791`): 조직 → 프로젝트 구조의 Django REST.
- **평가 추가분(test_v31_supp):** 지시서대로 5개.

| 프로젝트 | 버전·커밋 | 라이선스 | OAS |
|---|---|---|---|
| Chatwoot | v4.19.1 `caab07a8` | MIT (enterprise/ 제외, 읽지 않음) | swagger 63 + routes 생성 23 |
| Chamilo LMS | v2.0.0-RC.2 `296654b9` (RC.3 직전 태그) | GPL-3.0-or-later | API Platform 속성에서 생성 69 |
| Flowise (DocumentStore) | flowise@3.0.13 `f0c12941` | Apache-2.0 + enterprise/ 상용 라이선스 | swagger 26 + routes 생성 41 |
| cloud-security-multitenant-lab | main `a428c4f8` | 미선언 | Flask 라우트 생성 6 |
| Generic University | master `50dfa924` | 미선언 | Laravel 라우트 생성 35 |

**DocumentStore 출처 확인:** GHSA-3prp-9gf7-4rxx = FlowiseAI/Flowise, npm `flowise` ≤ 3.0.13 취약, 3.1.0 수정(CVE-2026-41277, CWE-284/639/915). DocumentStore 생성 API가 클라이언트가 보낸 id를 그대로 TypeORM `save()`에 넘겨 다른 워크스페이스의 스토어를 덮어쓴다(upsert → IDOR). 수정 커밋 `840d2ae1` "Prevent IDOR Takeover of DocumentStores (#5914)": DTO 필드 허용 목록과 `workspaceId`를 서버의 활성 워크스페이스로 강제. 입력은 3.0.13 코드, label은 수정이 보여 주는 의도된 정책이다.

**Chamilo advisory(입력 = RC.2 코드, label = 수정 커밋의 정책):** course_rel_users IDOR GHSA-x373-8j9j-g5pj(2a9f060·bd2ba34·c9c30cd), PUT /api/users/{id} roles 대량 할당 GHSA-7phx-w897-4c9x(d3b8838), 그 밖에 GHSA-fp2p·j2pr·27x6·ch7g·p2pv·2fr5·65wx·99q5·438r·8423 등. 취약 표시 36건(advisory 연결 26, 수정 커밋만 10). 상세는 data/raw_v4/chamilo/SOURCE.md.

## 2. 추출·중복 제거

| 프로젝트 | 용도 | 추출 | 레코드화 | 비고 |
|---|---|---:|---:|---|
| Zulip | train | 193 | 187 | 발췌가 잘려 권한 검사 줄이 빠진 2건 제외(PATCH /api/v1/realm, PATCH /api/v1/streams/{stream_id}), 파라미터 이름만 다른 같은 경로 4건 제외 |
| Label Studio | train | 253 | 253 | 저장소 백엔드 5종(S3·GCS·Azure·Redis·Local) 거의 같은 코드 → 선정 단계에서 그룹당 1건(76건 제외) |
| Chatwoot | test | 86 | 86 | |
| Chamilo | test | 69 | 69 | |
| Flowise | test | 67 | 67 | |
| multitenant lab | test | 6 | 6 | vulnerable 앱의 전체 라우트 |
| Generic University | test | 35 | 35 | |

- 중복 대조: (서비스명 정규화, method, 경로 정규화 — 소문자·파라미터 이름 제거·끝 슬래시 제거) 기준으로 APIs.guru 후보 원본(datasets/blade/raw/apisguru_candidates.jsonl, 424개 서비스), data-v1(train/val_v30), data-v2(train/val/pool), data-v3(train_v3a/b, val_v3), test_v30과 대조했다. **겹침 0건**(제외 목록 없음). APIs.guru 원본 디렉터리(openapi-directory)에도 zulip·chatwoot·flowise·label studio·chamilo 이름의 API는 없다.
- 학습·평가 프로젝트는 서로 겹치지 않는다. 학습 추출 에이전트는 평가 전용 프로젝트와 processed/ 아래 test 파일을 읽지 않았다.
- 입력 형식: 기존 oas_code 조건과 같다(prepare_lora_inputs.test_record — OAS operation + "핸들러 원문(근거)… FILE <경로>" + 코드 발췌, 발췌 최대 3,000자).

## 3. 학습용 라벨링 (gpt-4o-mini + 프롬프트 v3.0.1, oas_code)

- 440건, 출력 오류 0, 응답 449회, 입력 1,417,555(캐시 782,080)·출력 30,471 토큰, 추정 $0.17(청구서 아님). 입력은 SFT 입력과 같은 문자열.
- rationale 점검: 검수 메모·시트명·규칙 ID 0건, 파일 경로 인용 0건(자동 제거 장치는 있었으나 해당 없음). 모델이 반환한 label·confidence는 그대로 보존했다.

| 프로젝트 | public | role | membership | tenant | owner | owner_or_admin | manual | 합 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Zulip 라벨 | 22 | 52 | 3 | 0 | 43 | 14 | 53 | 187 |
| Label Studio 라벨 | 3 | 7 | 1 | 0 | 3 | 0 | 239 | 253 |
| **Zulip 선정** | 22 | 37 | 3 | 0 | 37 | 14 | 37 | **150** |
| **Label Studio 선정** | 3 | 7 | 1 | 0 | 3 | 0 | 14 | **28** |

- 선정 규칙: 프로젝트당 최대 150, 프로젝트 안에서 한 label 50% 이하, 목표 label 우선, seed 42. Label Studio는 manual 외 label이 14건뿐이라 50% 규칙 때문에 28건만 들어간다.
- **목표 미달:** 목표 label(membership·tenant·owner_or_admin) 선정 18건(membership 4, tenant 0, owner_or_admin 14). 원인은 라벨러다. gpt-4o-mini가 조직 범위 필터(Label Studio `active_organization`)와 채널 접근 함수(Zulip `access_stream_by_id`)를 "접근 조건 불확실"로 보고 보류했다(Label Studio 94% manual). 추출 단계 요약상 Label Studio는 조직 범위 195건, Zulip은 구독·멤버십 19건·소유자 또는 관리자 17건이었다.

## 4. 평가 추가분 초안 (전 건 사람 확정 대상)

초안은 추출 에이전트가 문서·코드·advisory·수정 커밋 근거로 쓴 것이며 train 라벨러(gpt-4o-mini)는 test에 쓰지 않았다.

| 프로젝트 | 건수 | 취약 | public | role | membership | tenant | owner | owner_or_admin | manual |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Chatwoot | 86 | 0 | 1 | 14 | 50 | 0 | 16 | 0 | 5 |
| Chamilo | 69 | 36 | 1 | 10 | 8 | 2 | 7 | 22 | 19 |
| Flowise | 67 | 37 | 0 | 5 | 3 | 54 | 1 | 1 | 3 |
| multitenant lab | 6 | 3 | 1 | 1 | 0 | 3 | 0 | 0 | 1 |
| Generic University | 35 | 28 | 0 | 21 | 0 | 0 | 7 | 0 | 7 |
| **합계** | **263** | 104 | 3 | 51 | **61** | **59** | 31 | **23** | 35 |

- 초안 기준으로 목표 label 3종 모두 20건 이상이다. 다만 한 label이 한 프로젝트에 몰려 있다(membership 50/61 Chatwoot, tenant 54/59 Flowise, owner_or_admin 22/23 Chamilo). confidence 0.6 미만 56건.
- **검수자가 일관되게 정해야 할 것:**
  1. Chatwoot `/accounts/{account_id}/...`: 경로가 대상 계정을 고르고 코드가 account_users 구성원 여부를 본다 → membership_required로 통일. tenant_match로 볼 거면 일괄 변경.
  2. Flowise: 요청이 워크스페이스를 지정하지 않고 서버가 활성 워크스페이스로 거른다 → tenant_match로 통일. 워크스페이스를 경로·본문으로 지정하고 구성원 여부를 보는 3건만 membership_required.
  3. Chatwoot 대화·받은편지함: 상담원은 받은편지함·팀 구성원이어야 하고 관리자는 우회 → membership_required(0.6~0.75) 또는 manual.
  4. Chamilo 보낸 사람/받는 사람·관계 양쪽 검사를 owner_or_admin으로 둔 건, 그룹 모더레이터를 role_required로 둔 건.
  5. Generic University에는 목표 label 구조가 없다. 소유 검사는 주석 처리된 트레이트에서 의도를 추정했다.
- **입력에 힌트가 남은 경우:** multitenant lab 원본 코드의 `[VULN-x]`·"No admin role check" 주석, Flowise·Chamilo 일부 주석은 규격대로 그대로 두었다(test_v30 취약 API도 같은 성격의 주석이 있다).
- **라이선스 주의:** Flowise 67건 중 56건의 코드 발췌에 `packages/server/src/enterprise/`(FlowiseAI 상용 라이선스, 개발·테스트 목적 복사는 허용, 공개 배포 금지) 코드가 들어 있다. test 전용이라 학습에는 쓰지 않지만, 이 파일을 공개 저장소에 올리면 배포가 된다. multitenant lab·Generic University는 라이선스 미선언.

## 5. data-v3.1b (data-v3b 학습 target의 검수 메타 문구 치환)

- scripts/build_data_v31.py. label·입력·순서 불변, LLM 없음. data-v3b 동결 파일은 해시 확인 후 읽기만 했다.
- 치환: `review_sheet_reviewed.xlsx sheet X:` 삭제, 검수 분류 태그(SELF·VIS·AUTH_ANY·CODE_SHORT·VIS+SELF data-scope) 삭제, 시트·번호·test 참조 문장(시트 A #22, 4번과 동일, test의 …와 같은 유형, 오라벨) 삭제, `파일.go:줄 match "코드"` → `핸들러 코드 "코드"`, 판단 문장의 규칙 ID(human_review_v2·_r3·_fix, R1_self_owner, R1_self_split, R4_noauth_public) → label별 기존 템플릿(예: "소유자 본인만 허용하는 조건이므로 owner_match").

| 파일 | 메타 문구 포함(전) | 치환 | 잔존(후) |
|---|---:|---:|---:|
| train SFT target (train_sft_v31b.jsonl, 786건) | 86 | 86 | **0** |
| train 레코드 rationale (train_v31b.jsonl) | 81 | 81 | 0 |
| val SFT target (val_sft_v31.jsonl, 126건) | 5 | 5 | 0 |
| val 레코드 rationale (val_v31.jsonl) | 5 | 5 | 0 |

- 잔존 0은 빌드 assert(메타 정규식 + 규칙 ID 판단 정규식). 변경 목록 datasets/blade/processed/rationale_meta_cleanup_v31.jsonl, 해시 training/lora/data_v31/data_v31_hashes.json. v3a는 지시 범위 밖이라 하지 않았다.

## 6. 산출물

| 파일 | 내용 |
|---|---|
| data/raw_v4/<project>/{candidates.jsonl, SOURCE.md} | 추출 원자료(7개 프로젝트), data/raw_v4/EXTRACTION_SPEC.md 추출 규격 |
| datasets/blade/processed/data_v4/candidates_train_v4.jsonl | train 후보 440 `291933c2…` |
| datasets/blade/processed/data_v4/train_v4_labeled_v301.jsonl | LLM 1차 라벨 440 `a400488a…` |
| datasets/blade/processed/data_v4/train_v4_selected.jsonl | 선정 178 `0b02589f…` |
| datasets/blade/processed/data_v4/test_v31_supp_candidates.jsonl | 평가 추가분 263(label 미확정) `09507f7e…` |
| review/v4_train_review.xlsx | 학습용 검수: 선정 178건의 label별 층화 20%(올림) 41건 + '선정 제외 manual 표본' 30건(Label Studio 20, Zulip 10) |
| review/test_v31_supp_review.xlsx | 평가 추가분 전 263건, 근거(문서·코드 줄·advisory·커밋)·GitHub 고정 링크·확정 label 열 |
| scripts/build_data_v4.py, scripts/build_data_v31.py | 빌드 스크립트 |

## 7. 다음 결정이 필요한 것

1. **학습용 라벨 방식.** LLM 1차 라벨로는 목표 label이 거의 안 나온다(선정 178건 중 18건). 검수 시트 결과(특히 '선정 제외 manual 표본')로 보류가 실제로 틀렸는지 확인한 뒤 고를 것: (a) 사람 검수 확대, (b) data-v3처럼 코드 검사 내용으로 규칙 라벨(근거 줄 기록), (c) 현 상태 유지.
2. test_v31_supp 확정 후 동결·평가 정의(eval-def v2에 보조 구간으로 추가할지).
3. Flowise enterprise 코드가 든 test 파일의 저장소 공개 범위.

## 8. 검수 반영·동결 (2026-10-28)

검수 파일: review/v4_train_review_reviewed.xlsx, review/test_v31_supp_review_reviewed.xlsx (검수자 Claude AI, 근거 열 기준). 검수 규약 G1~G8은 AGENTS.md 'data-v4 검수 규약'에 원문 그대로 옮겼다. 사용자 확인: 그룹 안 역할은 G3(role_required), Flowise 쿼리 모드별 2건은 manual.

**test_v31_supp 확정 222건**(제외 41건, 사유 test_v31_supp_excluded.jsonl). SHA `803d9149…`. 사람 표본 확인 시트 review/test_v31_supp_spotcheck.xlsx 32행(CHANGED 6 + label별 4, public은 2건뿐).

| label | 합 | Chatwoot | Chamilo | Flowise | multitenant lab | Generic University |
|---|---:|---:|---:|---:|---:|---:|
| public | 2 | 1 | 0 | 0 | 1 | 0 |
| role_required | 39 | 13 | 10 | 2 | 0 | 14 |
| membership_required | 55 | 50 | 4 | 1 | 0 | 0 |
| tenant_match | 55 | 0 | 0 | 52 | 3 | 0 |
| owner_match | 21 | 10 | 4 | 1 | 0 | 6 |
| owner_or_admin | 20 | 0 | 19 | 1 | 0 | 0 |
| manual_review_required | 30 | 5 | 21 | 3 | 0 | 1 |
| **합** | **222** | 79 | 58 | 60 | 4 | 21 |

**학습 규칙 라벨(training/data/rule_label_v4.py):** 검수 완료 71건과 비교 일치 69·불일치 0·규칙 미적용 2(97.2%, 미적용을 불일치로 셀 때). 첫 규칙은 59/4/8이었고 불일치를 규칙 수정으로 해소했다(/users/me 경로의 check_can_access_user는 본인 목록 대상 확인으로 간주, 채널 목록·구독 대상 채널 접근·조직 설정 의존 권한 → manual, 경로 조직 구성원 행 → membership 우선, 본문 storage id의 객체 검사 → tenant, 객체 없는 인증만 → manual). 440건 중 규칙 라벨 412, 미적용 28.

**선정·분리:** Zulip 150(role 38, owner 49, manual 49, owner_or_admin 8, public 6), Label Studio 66(tenant 33, manual 13, owner 10, public 5, membership 5). 핸들러 단위 그룹 분리로 추가분 train 194 / val 22. data-v4 SFT train 978(manual 13.6%), val 147, 4096 토큰 초과 3건 제외. 정합성 점검 전부 0. 사람 표본 검수 시트 review/v4_rule_label_sample.xlsx 63행(label별 최대 10).

**RunPod 번들:** data_v2·data_v3·data_v4·runpod, data_v4_hashes.json SHA `df24db70…`. 순서 v2 s43·s44 → v4 s42·43·44 → 기존 어댑터 eval-only(v2 s42, v3b ×3) → 베이스. 학습은 아직 실행하지 않았다.
