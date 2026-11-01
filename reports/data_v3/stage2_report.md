# data-v3 2단계 — data-v2 + 코드 쌍 병합, 합성 정답 문장 중립화, 쿼터 25%(v3a) / 10%(v3b) 동결

입력: train_v2 799 + 쿼터 pool_v2 22 + v3s1b train 109 / val_v2 98 + v3s1b val 28. data-v1·data-v2 해시 assert(시작·종료), test_v30·train_v2·val_v2 읽기만. 학습·API 호출 없음.

## 1. 합성 description 중립화

대상: 합성 레코드 189건(train 171, val 18). 합성 payload는 OAS description을 쓰지 않으므로 정답 문장이 모델 입력에 들어가는 경로는 핸들러 발췌(FastAPI `description=` 인자, `#`/`//`/`/** */` 주석, 독스트링)다. 정답 문장을 지우고, 빈 주석·빈 인자를 정리하고, fixture·변형 해설 주석("Deliberate fixture: …", "Variant: …")도 지웠다. 인증 위치 문장(구조 정보)은 남겼다. OAS operation description도 같은 기준으로 비웠다(모델 입력 아님). rationale(학습 target)은 바꾸지 않았다. test_v30 합성은 동결이라 그대로다.

| 지운 정답 문장 | 건수 |
|---|---:|
| Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. | 38 |
| The record owner or an administrator may read it. | 31 |
| Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. | 22 |
| Tenant and subscription are not checked. | 22 |
| Only administrators may read this operational resource. | 20 |
| Only the record owner may read it. | 20 |
| Caller and record must share a tenant. | 20 |
| Intentionally anonymous reference catalogue. | 16 |
| Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review. | 10 |
| Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | 6 |
| A premium plan is required. | 6 |

| 지운 해설 주석 | 건수 |
|---|---:|
| # Deliberate fixture: object authorization check omitted. | 26 |
| // Deliberate fixture: object authorization check omitted. | 24 |
| # Variant: object authorization check removed. | 11 |
| # Variant: authentication via dependency only; no authorization check. | 11 |
| // Variant: object authorization check removed. | 8 |
| // Variant: authentication via middleware only; no authorization check. | 4 |
| // Variant: authentication by @PreAuthorize only; no authorization check. | 4 |

코드가 바뀐 레코드 143 / 189 (나머지는 정답 문장이 OAS description·rationale에만 있었다). 전체 목록: `datasets/blade/processed/synthetic_neutralization_v3.jsonl`.

합성 변형 summary 끝의 변형 종류 접미사 삭제: 57건 (Authonly 19, Extauth 19, Extguard 19). 예: "Orbit Tickets Drafts Authonly" → "Orbit Tickets Drafts".

## 1b. label–rationale 정합성

점검: 구체 label인데 rationale(레코드 필드)에 보류 표현(no concrete label·pending review·manual·cannot determine·보류·단일 라벨로 표현되지 않음 등)이 있는 건 98건(train·val 합계, 쿼터 전). 학습 target(SFT)은 규칙 relabel 레코드에 템플릿 rationale을 쓰므로 target 수준 불일치는 1건이었다(Gitea 사람 검수 rationale의 "manual은 명백한 과보류" 문장). 재작성은 템플릿 규칙으로 했고(LLM 호출 없음) 레코드 rationale = 학습 target rationale이 되게 맞췄다. 재작성 후 남은 불일치 0(빌드 assert). 목록: `datasets/blade/processed/rationale_rewrites_v3.jsonl`.

| 규칙 | split | 재작성 | 학습 target 변경 |
|---|---|---:|---:|
| authonly_intended_policy | train | 19 | 19 |
| gitea_relabel_template | train | 80 | 0 |
| gitea_relabel_template | val | 5 | 0 |
| gitea_relabel_template_hold_stripped | train | 1 | 1 |
| v3_form_request_owner | train | 3 | 3 |
| v3_owner_compare | train | 21 | 21 |
| v3_owner_compare | val | 6 | 6 |
| v3_owner_filter | train | 3 | 3 |
| v3_owner_filter | val | 2 | 2 |
| v3_owner_filter_unless_admin | train | 3 | 3 |
| v3_owner_or_instance_admin | train | 1 | 1 |
| v3_owner_or_parent_owner | train | 2 | 2 |
| v3_owner_or_superuser | val | 3 | 3 |
| v3_role_annotation | train | 14 | 14 |
| v3_self_only | train | 8 | 8 |
| v3_self_or_admin | train | 7 | 7 |
| v3_self_or_superuser | val | 1 | 1 |
| v3_superuser_dependency | val | 6 | 6 |
| v3_variant_intended_policy | train | 47 | 47 |
| v3_variant_intended_policy | val | 10 | 10 |

| 규칙 | label | 이전(앞부분) | 이후 |
|---|---|---|---|
| authonly_intended_policy | owner_match | Authentication only; no requester-object relationship or role check is implemented, so no  | description: 경로·리소스 구조상 요청자 본인 객체. 코드에 검사는 없으나 의도된 정책은 owner_match |
| gitea_relabel_template | public | description: 비관리자 요청 시 sudo 시도만 403; 판단: 인증이 필요하나 특정 인가 조건이 명시되지 않아 보류 | description: chain ['sudo']: no authn/authz middleware; 판단: R4_noauth_public 기준으로 public |
| gitea_relabel_template_hold_stripped | public | description: 요청자가 sudo를 시도할 경우에만 403을 반환하며, 이는 인가 규칙이 아닌 미들웨어 설명; 판단: 접근 조건이 명확하지 않으므로 보류 | description: review_sheet_reviewed.xlsx sheet A: reqToken 없음(sudo만). 인스턴스 전역 설정 조회, 익명 접근 가능; 판단: human_review_v2 기준으로 p |
| v3_owner_or_parent_owner | owner_match |  | description: 핸들러 원문 — 요청자가 객체 또는 상위 객체(게시글)의 작성자일 때만 허용, 관리자 경로 없음; 판단: owner_match |
| v3_variant_intended_policy | owner_match |  | description: 검사 코드는 없으나 경로·리소스 의미상 게시글·댓글 작성자 본인만 수정·삭제하는 자원; 판단: 의도된 정책은 owner_match |
| v3_role_annotation | role_required |  | description: 핸들러 원문 — @PreAuthorize hasRole/hasAnyRole로 역할 검사; 판단: role_required |
| v3_owner_compare | owner_match |  | description: 핸들러 원문 — 요청자 id와 객체 소유자 id를 비교해 다르면 거부; 판단: owner_match |
| v3_owner_filter | owner_match |  | description: 핸들러 원문 — 객체 조회를 요청자 소유로 한정(작성자 = 현재 사용자); 판단: owner_match |
| v3_form_request_owner | owner_match |  | description: 핸들러 원문 — FormRequest::authorize가 객체 소유자와 요청자를 비교; 판단: owner_match |
| v3_self_or_admin | owner_or_admin |  | description: 핸들러 원문 — 요청자가 대상 사용자 본인이거나 인스턴스 관리자여야 함; 판단: owner_or_admin |
| v3_owner_or_instance_admin | owner_or_admin |  | description: 핸들러 원문 — 요청자가 객체 작성자이거나 인스턴스 관리자여야 함; 판단: owner_or_admin |
| v3_self_only | owner_match |  | description: 핸들러 원문 — 요청자가 대상 사용자 본인이어야 함(관리자 예외 없음); 판단: owner_match |
| v3_owner_filter_unless_admin | owner_or_admin |  | description: 핸들러 원문 — 관리자가 아니면 조회를 요청자 소유 객체로 한정; 판단: owner_or_admin |
| v3_superuser_dependency | role_required |  | description: 핸들러 원문 — 라우트 의존성 get_current_active_superuser로 슈퍼유저가 아니면 403; 판단: role_required |
| v3_self_or_superuser | owner_or_admin |  | description: 핸들러 원문 — 본인 사용자 레코드는 허용, 다른 사용자 레코드는 슈퍼유저만; 판단: owner_or_admin |
| v3_owner_or_superuser | owner_or_admin |  | description: 핸들러 원문 — 슈퍼유저는 통과, 그 외에는 요청자가 객체 소유자여야 함; 판단: owner_or_admin |

## 2. manual 쿼터

| 버전 | 목표식 | 구체 label | manual 목표 | manual 후보 | manual 유지 | pool | train | manual 비율 | 선택 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| v3a | concrete/3 | 708 | 236 | 222 | 222 | 0 | 930 | 23.9% | candidates 222 <= target 236: all kept |
| v3b | concrete/9 | 708 | 79 | 222 | 79 | 143 | 787 | 10.0% | 검수 우선 19, 출처별 {'apisguru': 31, 'synthetic': 11, 'gitea': 18} |

manual 후보 = train_v2 manual + pool_v2(data-v2 쿼터에서 빠졌던 Gitea manual). 코드 쌍(v3s1b)은 전부 구체 label이다.

## 3. 동결 결과

| label | train_v3a | train_v3b | val_v3 |
|---|---:|---:|---:|
| public | 46 | 46 | 10 |
| role_required | 186 | 186 | 34 |
| membership_required | 55 | 55 | 6 |
| tenant_match | 54 | 54 | 5 |
| owner_match | 318 | 318 | 30 |
| owner_or_admin | 49 | 49 | 8 |
| manual_review_required | 222 | 79 | 33 |
| 합계 | 930 | 787 | 126 |

| 출처 | train_v3a | train_v3b | val_v3 |
|---|---:|---:|---:|
| apisguru | 411 | 338 | 52 |
| gitea | 239 | 197 | 28 |
| synthetic | 171 | 143 | 18 |
| v3_pair | 109 | 109 | 28 |

조건별(코드 있음): train_v3a 519, train_v3b 449, val_v3 74. 코드 있는 레코드 manual 비율: v3a 22.7%, v3b 10.7% (참고 test_v30 코드 있음 5.7%).

## 4. 해시

| 파일 | SHA-256 |
|---|---:|
| train_v3a.jsonl | 1f5d1055ac3d8d407e555c774183acf4c52ceb03ea508391ee5d508484446e66 |
| train_v3b.jsonl | 723e3b3a784e624033379dce5e46b243c2c3444c34db7efb5032ea2436a696dd |
| val_v3.jsonl | 69536f8b10e99538673a1beaf96411aba2b18f341e04f9429f717d9d84cbc109 |
| train_v3a_manual_pool.jsonl | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| train_v3b_manual_pool.jsonl | b43ab0097e59adb9657a4d77d161185918681094e9cb6167f1f03ea1e16c01f3 |
| synthetic_neutralization_v3.jsonl | 91bb7aded5416dbd72b12de2690602f9ddcf5becc571fbc86dbfa8c2f6a86626 |
| rationale_rewrites_v3.jsonl | f1c52fe5a4469cb8dfb4040f0e3373a380ea5d31941b877afd317ae576f101af |
| test_v30.jsonl | 9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2 |
| policy_label_v3.0.1.md | d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef |
| pairs_train_v3s1b.jsonl | cc34308a149dee2d92998087002e6f63ab771d083cae07f5604d6828fdfab303 |
| pairs_val_v3s1b.jsonl | f1826e1c24957e42abbf4d60b6bc5aaeabbf99bd0b60893d1b9014bc8ccf7138 |

## 5. 한계

- v3a의 manual 후보가 목표보다 적어 manual 비율이 25%에 못 미친다(위 표).
- 합성 rationale(target)은 원래 description 문장을 그대로 담고 있다. 입력에서는 지웠지만 출력 문장으로는 남는다.
- 합성 변형의 경로(`/authonly/`·`/extauth/`·`/extguard/`)와 함수 이름에는 변형 종류가 그대로 남는다(summary 접미사만 지움). test_v30 합성은 동결이라 접미사도 그대로다.
- data-v3 코드 쌍의 한계(role_required 전부 Java, owner_or_admin은 Go·JS, val 작음, 라이선스 미선언 5개)는 reports/data_v3/stage1b_report.md 한계 절.
