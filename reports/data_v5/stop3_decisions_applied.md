# 작업 C 정지 지점 3 결정 반영 — 규칙 수정·재적용, 검수 일치율, 쿼터 (2026-10-31)

사용자 결정(정지 지점 3) 1~5를 반영했다. 학습·동결은 하지 않았다. 동결(정지 지점 4)은 test_v5 동결(정지 지점 2) 뒤에만 한다. 기존 동결본은 해시 대조 후 읽기만 했고 test_v5 시트·test 파일의 label은 읽지 않았다.

## 1. 규칙 수정 (training/data/rule_label_v5.py)

- (a) `G5_owner_with_superuser_bypass`: 상위 권한 우회(bypass=true, Taiga `enough_perms = IsSuperUser()`)가 있어도, 대상을 경로 ID로 조회해 소유자를 비교(IsTheSameUser·obj.owner == request.user·owner_field)할 때만 owner_or_admin. 대상이 request.user로 필터·지정되거나(`filter(user=request.user)`, `/users/me`, change_password·change_avatar) 생성 요청(`obj.owner = request.user`)이면 owner_match(G4).
- (b) Dendrite: group_role 검사가 event auth(gomatrixserverlib.Allowed / PerformInvite)뿐이고 핸들러에 power level 검사가 없으면 kind `event_auth`로 보고 라벨하지 않고 제외(모든 경로). 가시성·설정 분기(G6)가 먼저 걸리는 join 2건은 그대로 manual.
- (c) 구성원 확인 뒤 "power level OR 본인 대상"(Dendrite kick의 `pl.UserLevel >= pl.Kick || target == caller`)은 kind `role_or_self`로 보고 제외 — NodeBB 채팅 추방(구성원+본인+방 역할) 제외와 통일.
- 부수 수정: OR_HINT 정규식의 단어 경계가 이전 파일에서 깨져 있던 것을 복구(결과 변화 0건).

## 2. 416건 재적용 — 변경 전후 label별 건수

| label | 변경 전 | 변경 후 | 차 |
|---|---:|---:|---:|
| public | 28 | 28 | +0 |
| role_required | 122 | 118 | -4 |
| membership_required | 19 | 19 | +0 |
| tenant_match | 0 | 0 | +0 |
| owner_match | 75 | 85 | +10 |
| owner_or_admin | 65 | 55 | -10 |
| manual_review_required | 107 | 107 | +0 |
| EXCLUDED | 16 | 20 | +4 |
| 합 | 432 | 432 | |

바뀐 id 14건:

| id | project | method | path | 변경 전 | 변경 후 |
|---|---|---|---|---|---|
| v5-dendrite-34e5d58eaa | dendrite | POST | /_matrix/client/v3/rooms/{roomId}/unban | role_required (G3_group_role) | EXCLUDED (ambiguous:event_auth_power_level_dependent) |
| v5-dendrite-3723cbb941 | dendrite | PUT | /_matrix/client/v3/rooms/{roomId}/state/{eventType} | role_required (G3_group_role) | EXCLUDED (ambiguous:event_auth_power_level_dependent) |
| v5-dendrite-39b5b19466 | dendrite | PUT | /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey} | role_required (G3_group_role) | EXCLUDED (ambiguous:event_auth_power_level_dependent) |
| v5-dendrite-e3f2d2d68f | dendrite | POST | /_matrix/client/v3/rooms/{roomId}/kick | role_required (G3_group_role) | EXCLUDED (ambiguous:role_or_self_after_membership_row) |
| v5-taiga-2a1c77f476 | taiga | GET | /api/v1/applications/{id}/token | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-4efc46e994 | taiga | POST | /api/v1/users/change_password | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-658912caa5 | taiga | PATCH | /api/v1/user-project-settings/{id} | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-744b188463 | taiga | GET | /api/v1/user-project-settings | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-cbab3f8b9b | taiga | GET | /api/v1/users/me | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-d1d231bf27 | taiga | PATCH | /api/v1/notify-policies/{id} | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-de6fcc1213 | taiga | GET | /api/v1/application-tokens | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-e25501120b | taiga | POST | /api/v1/projects | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-f03481c78f | taiga | GET | /api/v1/notify-policies | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |
| v5-taiga-f5b8c6f1a8 | taiga | POST | /api/v1/users/change_avatar | owner_or_admin (G5_owner_with_superuser_bypass) | owner_match (G4_self_target) |

제외는 16 → 20건(event_auth 6: send 2·invite·unban·state PUT 2, role_or_self 1: kick, 그 외 13 변동 없음). 나머지 402건은 label·규칙 ID·rationale 모두 동일.

## 3. 검수 완료본 일치율 (review/v5_train_review_reviewed.xlsx, 90건, 검수자 이혜인)

- **수정 전 규칙 0.956(86/90), 불일치 4건은 규칙 수정으로 해소, 수정 후 88/88.** (사용자 확정 표기, 2026-10-31)
- 불일치 4건: Taiga bypass 3건(applications/{id}/token, POST /projects, user-project-settings) → 검수 owner_match = 수정 규칙 (a); Dendrite unban → 검수 "제외 권고(불가 시 manual)" = 수정 규칙 (b)로 제외.
- 수정 후 분모 88 = 90 − 제외로 바뀐 2건(unban, kick). kick은 검수자가 수정 전 규칙과 같은 role_required를 적었으나 결정 (c)로 제외한다.
- freeze 단계는 시트의 규칙 label 열이 아니라 현재 train_v5_rule_labeled.jsonl의 label과 검수 label을 비교한다(제외 전환 건은 분모 제외, freeze_report.json review.now_excluded에 기록).

## 4. 선정 (프로젝트당 ≤150, 한 label ≤50%, 목표 label 우선 → Taiga 댓글 계열 축소 → manual 쿼터 10%, 모두 seed 42)

- Taiga history 댓글 계열 owner_or_admin 20건(epic·userstory·task·issue·wiki × edit/delete/undelete_comment·comment_versions) → 자원 종류당 2건, 10건 유지. 제외 10건은 pool(pool_reason=taiga_comment_family_cap). 첨부(attachments) 10건·IsTheSameUser 3건은 패턴이 달라 그대로 둔다.
- manual 쿼터: 구체 295건 / 9 = 33건(10.0%). 하위 유형(규칙 ID)별 가용 → 선정: auth_only 17→5, compound_and 8→3, compound_and_visibility_branch 5→2, setting_dependent 27→8, setting_dependent_visibility_branch 4→1, visibility_branch 46→14. 제외 74건은 pool(pool_reason=manual_quota_10pct).
- 최종 보강분 **328건**(manual 10.06%), pool 84건(datasets/blade/processed/data_v5/train_v5_pool.jsonl, 학습 미사용).

| label | Dendrite | NodeBB | Taiga | 합 |
|---|---:|---:|---:|---:|
| public | 13 | 5 | 10 | 28 |
| role_required | 21 | 46 | 51 | 118 |
| membership_required | 7 | 11 | 1 | 19 |
| tenant_match | 0 | 0 | 0 | 0 |
| owner_match | 51 | 15 | 19 | 85 |
| owner_or_admin | 4 | 18 | 23 | 45 |
| manual_review_required | 9 | 14 | 10 | 33 |
| 합 | 105 | 109 | 114 | 328 |

- 실제 수: owner_or_admin 45(Dendrite 4·NodeBB 18·Taiga 23), membership_required 19(7·11·1). 합성·LLM으로 채우지 않았다. Dendrite owner_match 51/105 = 48.6%로 50% 규칙 안.

## 5. 동결 사전 검증 (`build_data_v5.py freeze --dry-run`, 파일 미생성)

- val 분리(프로젝트별 핸들러 그룹, label별 약 10%): train 296 / val 32 — Dendrite 95/10, NodeBB 98/11, Taiga 103/11. val 분포 {"owner_match": 9, "membership_required": 2, "manual_review_required": 3, "public": 2, "role_required": 12, "owner_or_admin": 4}. Dendrite 발췌는 인증 래퍼(MakeAuthAPI·MakeAdminAPI)로 시작해 함수명 그룹이 60건으로 뭉쳤으므로 래퍼일 때는 핸들러 파일로 그룹화(WRAPPERS).
- SFT 예상: train 1274(data-v4 978 + 296), val 179(147 + 32). **SFT train manual 비율 12.79%**(data-v4 13.6%). 4096 토큰 초과 0건.
- 정합성: 구체 label 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, test_v30·test_v31_supp·test_v5 후보와 (서비스, method, 경로) 겹침 0.
- 동결 시 추가 산출: data_v5/train_v5_manifest.json(id·저장소·커밋·고정 링크·label·split, 코드 본문 없음), data_v5_hashes.json에 rule_label_v5.py·검수본·pool 해시 포함.

## 6. 라이선스·공개 범위 (결정 5)

- NodeBB(GPL-3.0) controller_text가 든 파일은 .gitignore에 추가: data/raw_v5_train/nodebb/candidates.jsonl, data_v5/{candidates_train_v5, train_v5_rule_labeled, train_v5_selected, train_v5_pool}.jsonl, processed/{train_v5, val_v5}.jsonl, training/lora/data_v5/{train_sft_v5, val_sft_v5}.jsonl, review/v5_train_review*.xlsx. NodeBB 레코드 meta.license_notice_required=true. DATA_CARD "data-v5 학습 보강분" 절에 "링크·커밋만 공개" 명시. 공개 추적 파일은 train_v5_manifest.json·보고서·해시뿐이다.

## 7. 파일·해시 (동결 전)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/data_v5/candidates_train_v5.jsonl | 432 | `f82067e0a3e120129b58680211d49c175645ef5e2e53315f4d6eb772ef717f55` |
| datasets/blade/processed/data_v5/train_v5_rule_labeled.jsonl | 432 | `6f2e02f933a88cbb84a6d8c7ea57f42a81b2c3d8db62d4559c20217209876988` |
| datasets/blade/processed/data_v5/train_v5_selected.jsonl | 328 | `12f45304c9f4a1884a09dc62ca877b8e04da21c0f6a20751109742c5bc1f8e8d` |
| datasets/blade/processed/data_v5/train_v5_pool.jsonl | 84 | `d5916fb43ea34c81b69aca2f3d252c175cada01156aa8ec59d99c2631acc0ebf` |
| review/v5_train_review.xlsx | - | `f29fe1ba0689935d77bfbf77c4043412b57bf581b48df602663a257b8f955ed5` |
| review/v5_train_review_reviewed.xlsx | - | `4d70711494bf63ad0a0644e75967f236a204b5799b8dd67847aa508a010d519b` |
| training/data/rule_label_v5.py | - | `daa28db3992b2d2bfd4a99a863c1b8d3d86045fdde52e6d9f66d1f2d8fcd7c67` |
| scripts/build_data_v5.py | - | `13df6a64d71aa48048bd8127cb4c483b4814d4166860356405d2b8c470181125` |

보고서: label_select_report.json(규칙별·쿼터·댓글 계열 id 목록). 변경 전 규칙 결과(f632ebd1…)는 정지 지점 3 보고서에 기록된 해시로만 남긴다.

## 8. 남은 순서

1. **test_v5 검수 완료본(review/test_v5_review_reviewed.xlsx) 미수령** → 받으면 `build_test_v5.py freeze` → 정지 지점 2 보고.
2. 이어서 `build_data_v5.py freeze`(test_v5 manifest 해시 확인 포함) → run_train.py v5 항목·RunPod 번들 → 정지 지점 4 보고(최종 분포·SFT manual 비율·해시·RunPod 명령).
3. C-4 시작 마감 토요일 12:00. 넘기면 v4 유지.
