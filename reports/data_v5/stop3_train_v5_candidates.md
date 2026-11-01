# 작업 C 정지 지점 3 — data-v5 학습 보강분 규칙 라벨·검수 시트 (2026-10-31)

C-3 병행 예외(정지 지점 1 사용자 결정)에 따라 test_v5 검수와 동시에 진행했다. 학습·동결은 하지 않았다. 기존 동결본은 해시 대조 후 읽기만 했고, test_v5 검수 시트·test 파일의 label은 읽지 않았다(test_v5 후보의 (서비스, method, 경로) 키만 겹침 검사에 사용).

## 1. 출처 프로젝트 (Rocket.Chat·Ghost·Umami·기존 test 출처·포크·AGPL 제외)

| 프로젝트 | 태그 · 커밋 | 라이선스 | 선정 이유 | 추출 | 규칙 라벨 | 제외 |
|---|---|---|---|---:|---:|---:|
| Dendrite (Matrix 홈서버, Go) | `v0.13.8` · `763c79f1` (matrix-org, Apache 시절 마지막 태그) | Apache-2.0 | 방 구성원 행(QueryMembershipForUser) + power level 역할 + 본인 계정 자원 | 136 | 129 | 7 |
| NodeBB (포럼, Node.js) | `v4.16.5` · `c3d8dc51` | GPL-3.0 | 채팅방 구성원(assert.room = 구성원 OR 관리자), 본인 OR 관리자·글로벌 모더레이터(isPrivilegedOrSelf 계열) | 146 | 139 | 7 |
| Taiga (프로젝트 관리, Django) | `6.10.2` · `4b023d84` | MPL-2.0 | 댓글·첨부 `IsProjectAdmin() \| CommentAndOriginalOwner()` 계열, 프로젝트 역할 권한 | 150 | 148 | 2 |
| 합 | | | | 432 | 416 | 16 |

- 중복 대조: (서비스 정규화, method, 경로 정규화) 키로 APIs.guru 후보·data-v1~v4·test_v30·test_v31_supp·test_v5 후보와 대조해 **겹침 0건**. 내부 중복 0, 형식 오류 0.
- 클론은 `datasets/blade/raw/opensource/`(git 미추적)에 얕게 받아 읽기만 했다. 원자료·추출 스크립트·인가 구조 요약: `data/raw_v5_train/<project>/{candidates.jsonl, SOURCE.md, extract_*.py}`.
- 각 후보의 `auth_checks`는 핸들러 체인에서 찾은 인가 검사를 종류(kind)·함수 이름·파일:줄·원문 줄로 기록한 것이다(추출 단계, LLM 미사용).

## 2. 규칙 (training/data/rule_label_v5.py, 검수 규약 G1~G7 + 정지 지점 1 통일 판단에서 도출)

| 규칙 ID | 조건(auth_checks kind 집합; auth_only는 무시) | label | 건수 |
|---|---|---|---:|
| G7_anonymous | anonymous만 | public | 28 |
| G6_auth_only | auth_only만(객체 관계·역할 검사 없음) | manual | 17 |
| G6_hold_* | visibility_branch / setting_dependent / compound_and 포함 | manual | 90 |
| G4_self_target / G4_owner_field | self_target 또는 owner_field만, 우회 없음 | owner_match | 75 |
| G5_owner_with_superuser_bypass | 소유자형 + 상위 권한 우회 항목(bypass=true, Taiga `enough_perms = IsSuperUser()`) | owner_or_admin | 13 |
| G5_owner_or_global_role | self_target + global_role이 명시적 OR(Dendrite admin whois) | owner_or_admin | 1 |
| G5_owner_or_privileged | 추출이 "본인/소유자 OR 권한 보유자"로 기록한 검사(isPrivilegedOrSelf, canEdit, `IsCommentProjectAdmin() \| IsCommentOwner()` 등) | owner_or_admin | 48 |
| G5_owner_or_room_role | 구성원 확인 뒤 객체 소유자 OR 방 power level(Dendrite redact·alias 삭제) | owner_or_admin | 3 |
| G2_membership_row | membership_row만(관리자 우회 포함) | membership_required | 13 |
| G2_membership_self_action | 구성원 확인 뒤 본인 행만 변경(leave·forget·typing·read_markers·chat state) — 정지 지점 1 통일 판단 "방 비구성원을 거부하면 membership" | membership_required | 6 |
| G3_group_role / G3_global_role | 그룹 안 역할(power level·방 소유자·프로젝트 관리자·역할 권한) 또는 전역 역할 | role_required | 122 |

- 제외 16건(라벨 없음, 학습 제외): 검사 위치 미확인 3(Dendrite receipt·alias 생성·3pid 삭제), Dendrite 전송·초대 3(유일한 방 역할 검사가 이벤트 auth이고 결과가 방의 power level 값에 달려 핸들러만으로 판정 불가), setting + self 2, 구성원+본인+방 역할 2(NodeBB 채팅 추방: 본인 탈퇴 OR 방 소유자), 소유자 OR 권한 + 구성원 1, 구성원 AND 전역 역할 1, 전역·그룹 역할 + 소유자(플래그 노트) 2, anonymous+owner 1, 구성원+소유자 1.
- rationale = label별 템플릿 문장 + auth_checks의 식별자(함수·데코레이터·권한 문자열)만. 파일 경로·시트명·규칙 ID·검수 문구 0건(정규식 점검). 식별자를 못 찾은 12건은 "핸들러 코드의 접근 검사"로 둔다.

## 3. 선정 결과 (프로젝트당 ≤150, 한 label ≤50%, 목표 label 우선, seed 42)

세 프로젝트 모두 규칙 라벨 건수가 150 이하이고 50% 규칙에 걸리지 않아 **규칙 라벨 416건 전부 선정**됐다.

| label | Dendrite | NodeBB | Taiga | 합 |
|---|---:|---:|---:|---:|
| owner_or_admin | 4 | 18 | 43 | **65** |
| membership_required | 7 | 11 | 1 | **19** |
| owner_match | 51 | 15 | 9 | 75 |
| role_required | 25 | 46 | 51 | 122 |
| manual_review_required | 29 | 44 | 34 | 107 |
| public | 13 | 5 | 10 | 28 |
| tenant_match | 0 | 0 | 0 | 0 |
| 합 | 129 | 139 | 148 | 416 |

- **실제 수 보고**: owner_or_admin 65건(세 프로젝트 분산, Taiga 43은 댓글·첨부 10종 경로 반복). membership_required는 19건에 그친다(Dendrite 7·NodeBB 11·Taiga 1). 합성·LLM으로 채우지 않았다.
- manual 107건(25.7%)은 공개/비공개 가시성 분기(46)·설정 의존(27)·인증만(17)·AND 결합(8)이다. data-v4 SFT의 manual 비율은 13.6%였고, 416건을 그대로 더하면 약 17%가 된다. **동결 전 결정 필요**: 보강분 manual을 그대로 넣을지, data-v4 방식처럼 10% 쿼터로 줄일지.
- Taiga owner_or_admin 43건 중 30건은 `history/{epic|userstory|task|issue|wiki}/{id}/{edit_comment|delete_comment|undelete_comment|comment_versions}` 같은 5종 자원 × 같은 권한식 반복이다(추출 단계에서 83건 유사 형제는 이미 제외). 같은 패턴 과다 학습이 우려되면 자원 종류당 1~2건으로 줄일 수 있다(현재는 규칙대로 전부 유지).

## 4. 검수 시트

- `review/v5_train_review.xlsx` — 시트 `v5_train_review` 90행: 선정 416건의 프로젝트 × label 층화 20%(올림, seed 42). Dendrite 28 · NodeBB 30 · Taiga 32. 열: id, project, method, path, auth_summary, permission_doc, 규칙 label, 규칙 ID, 인가 검사 목록(kind·함수·파일:줄·원문), 학습 rationale, controller_text, source permalink(고정 커밋 링크), **검수 label**(드롭다운), **검수 사유**, **검수자**. 보조 시트 '라벨 정의', '검수 규약'(G1~G8 + 통일 판단).
- 검수 완료본은 `review/v5_train_review_reviewed.xlsx`. `scripts/build_data_v5.py freeze`가 '검수 label'과 규칙 label의 일치율을 계산해 95% 미만이면 중단한다(불일치 목록 출력). 95% 이상이면 data-v5 = data-v4 + 보강분, 프로젝트별 핸들러 단위 val 분리(label별 약 10%), 정합성 점검(보류 표현·메타 문구·파일 경로·test 겹침 0), 4096 토큰 초과 제외, SFT·해시 생성.

## 5. 파일·해시 (동결 전, 이후 변경 가능)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/data_v5/candidates_train_v5.jsonl | 432 | `f82067e0a3e120129b58680211d49c175645ef5e2e53315f4d6eb772ef717f55` |
| datasets/blade/processed/data_v5/train_v5_rule_labeled.jsonl | 432 (라벨 416) | `f632ebd1982dee85aebb1b59166458bcdb435709d841b0d5ef0d00622c052083` |
| datasets/blade/processed/data_v5/train_v5_selected.jsonl | 416 | `ae4f421be103b334fc7979af685e929d791c772b344de7bfd769852579683b00` |
| review/v5_train_review.xlsx | 90행 | `f29fe1ba0689935d77bfbf77c4043412b57bf581b48df602663a257b8f955ed5` |
| training/data/rule_label_v5.py | - | `ec0b69e7f5dcccf3f6dbae13f6195e67cb26893d566957f9bf70e43406bf5180` |

보고서: label_select_report.json, sheets_train_report.json, assemble_train_report.json(같은 폴더).

## 6. 남은 순서

1. test_v5 검수 완료본(review/test_v5_review_reviewed.xlsx) → `build_test_v5.py freeze` → 정지 지점 2 보고(분포·해시).
2. v5_train 검수 완료본 → 일치율 확인 → `build_data_v5.py freeze` → 정지 지점 4 보고(분포·해시·RunPod 명령).
3. C-4 시작 마감 토요일 12:00. 넘기면 v4 유지.
