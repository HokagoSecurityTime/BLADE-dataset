# 작업 S0 정지 지점 2 — test_v6 후보 레코드·검수 시트 (2026-11-03, 재조립본)

학습·추론·동결·커밋은 하지 않았다. 기존 동결본(data-v1~v5, test_v30, test_v31_supp, test_v5)은 조립 시작·끝에 해시를 대조하고 읽기만 했다. 사용자 승인 A안(seahub 90→상한 110 · Redash 70 · GlitchTip 70 · Penpot 60)과 검수 규약 보충 1~8, 그리고 1차 보고(301건) 뒤 사용자 결정(3.1 Penpot 5b 유지·seahub 보충, 3.2 seahub `is_repo_admin` 단독 → manual, 3.3 Redash `require_admin` G1-b)을 반영해 **재조립**했다. AGENTS.md "작업 S0" 절 보충 규약 1·2에 결정을 기록했다.

## 1. 산출 (재조립본)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| data/raw_v6/seahub/candidates.jsonl | 94 | `f8becb4f16f06a38050de783aa49ca53a59eedbf9b0cc39eedca1a0a4eb5d176` |
| data/raw_v6/redash/candidates.jsonl | 74 | `0712c0307a0608c352d7ca7a0a20377fc4aa584c94f9d07cd6752527a692bd8e` |
| data/raw_v6/glitchtip/candidates.jsonl | 73 | `7206fcde6b2dbc27117b604d14e08b94313e93a9de40f7459c7bc6deab6c74e1` |
| data/raw_v6/penpot/candidates.jsonl | 61 | `0e311d03ec7a6ca2acbad55f696646f8acf31d95fc248df45c0873eeeae194bb` |
| data/raw_v6/penpot/candidates_5b_excluded.jsonl (보조, **조립 미사용**) | 48 | `1e01b15bc695b49812a2c97bd84c92f71a3b8843f91e2b1265bd3fe52e65ad61` |
| datasets/blade/processed/data_v6/test_v6_candidates.jsonl (label=None, draft_pending_human_confirmation) | 302 | `4bf830fb84adae969059555ed1527cb75422bdafffc62f60c0ed2b44160a9eb8` |
| datasets/blade/processed/data_v6/redash_g1b_boundary_ids.json (S9 별도 집계용, G1-b 16 + 일관 적용 2) | - | 커밋 해시 참조 |
| review/test_v6_review.xlsx (커밋하지 않음) | 302행 | `46fc5dd9a6085b5b7ff4d6e3eae5d997ffcdb48a6c05d1c59092ea575546524c` |

**Redash `User.permissions` 블록 통일(2026-11-03 사용자 확인 요청)**: 1차 재조립본에서는 `require_*` 체인을 쓰는 50건 중 18건(tenant 16·role 1·membership 1)에만 블록이 있었다. 추출기를 고쳐 체인(`require_admin|require_super_admin|require_permission|require_any_of_permission|has_permission`)이 발췌에 있는 레코드 전부에 `PermissionsCheckMixin.has_permission(s)`(users.py:63-74) + `User.permissions`(users.py:172-175)를 정확히 한 번 넣었다(빌드 assert). 결과 label별 "체인 사용 / 블록 포함": tenant_match 20/20 · manual 12/12 · owner_or_admin 15/15 · owner_match 3/3 · role_required 3/3 · membership 2/2 · public 0/0, 합 55/55(불일치 0). 지시의 네 데코레이터 이름만 세면 50건이고, `has_permission`·`is_admin_or_owner`를 직접 호출하는 5건(GET `/api/groups`, GET `/api/groups/{id}`, POST `/api/users/{id}/regenerate_api_key`, GET `/api/{type}/{id}/acl`, GET `/api/data_sources/{id}`)도 같은 메커니즘이라 포함했다(되돌리려면 정규식에서 `|has_permission` 제거). label·confidence·evidence·draft_reason·경로 집합은 불변. 길이 3,000 유지를 위해 GET `/api/users`(2,686)·GET `/api/queries/{query_id}/results`(2,862)의 비인가 본문을 추가 생략했다(인가 줄 유지; 상세 Redash SOURCE.md).

- 추출기 `data/raw_v6/<project>/extract_<project>.py`(정적 읽기, `python -I`, LLM API·모델 호출 없음, 두 번 실행 해시 동일), 설명 `SOURCE.md`(사유별 제외 건수·불확실 목록·tenant_match 포함 명시·정지 지점 2 결정 반영). 규격 `data/raw_v6/EXTRACTION_SPEC_v6.md`(G1-b 반영).
- 조립 `scripts/build_test_v6.py assemble|sheets|freeze`(freeze는 3번). 중복 대조 키 6,545건(APIs.guru 후보 424 services, data-v1~v5 train/val/pool/rule_labeled, test_v30, test_v31_supp 확정·제외, test_v5 확정·제외·후보)과 대조해 **겹침 0, 내부 중복 0, 형식 오류 0, label 50% 상한 위반 0**. 보고 `data_v6/assemble_report.json`, `sheets_report.json`.
- 추론 가드 `scripts/testv6_guard.py`: manifest 부재·해시 불일치면 거부, `BLADE_TESTV6_STAGE=S9`가 아니면 추론·채점 거부(현재 "not frozen"으로 거부 확인). 3번 동결 때 eval 스크립트에 연결한다.

## 2. 초안 label 분포 (302건, 전 건 사람 확정 대상)

| 초안 label | seahub | Redash | GlitchTip | Penpot | **합** | 1차(301) | 1번 예상 |
|---|---:|---:|---:|---:|---:|---:|---:|
| membership_required | 8 | 2 | 27 | 0 | **37** | 36 | 58 |
| owner_or_admin | 9 | 15 | 1 | 1 | **26** | 29 | 25 |
| tenant_match | 11 | 26 | 0 | 0 | **37** | 19 | 14 |
| role_required | 22 | 3 | 17 | 27 | 69 | 87 | 85 |
| owner_match | 23 | 8 | 12 | 18 | 61 | 61 | 44 |
| manual_review_required | 17 | 16 | 11 | 7 | 51 | 48 | 47 |
| public | 4 | 4 | 5 | 8 | 21 | 21 | 17 |
| **합** | 94 | 74 | 73 | 61 | **302** | 301 | 290 |

- `EXCLUDE 후보`(추출기 제안, confidence 0.5) 12건 = **4.0%**(시트 '초안 EXCLUDE 후보' 열 Y: seahub 3 · Redash 3 · GlitchTip 2 · Penpot 4). 보충 규약 8의 10% 기준 미만.
- security_state: declared 296, explicitly_anonymous 6. controller_text 99~2,985자(500자 미만 1건: Redash `GET /ping` 99자, 핸들러 전체 4줄).
- 프로젝트별 최대 label 비율: seahub owner_match 24.5%, Redash tenant_match 35.1%, GlitchTip membership 37.0%, Penpot role_required 44.3%.

## 3. 정지 지점 2 결정 적용 결과

### 3.1 Penpot — 5b 유지, membership 0 (한계)

- 결정: 5b 유지. Penpot read 명령 48건(`get-read-permissions`/`get-file-read-permissions` = `(or 구성원 조직소유자)`, teams.clj:63-66 · projects.clj:66-69 · files.clj:86-90 · permissions.clj:136-146)은 투입하지 않는다. 근거: v3.1 보류 5(설정 의존 → manual), test_v5 resetAvatar 선례, `:admin-console` 플래그 기본값이 입력 코드 밖(nitrate.clj:562-574)에 있어 모델이 볼 수 없음. 보조 파일 48건(membership 29 · manual 19)은 참고용으로만 남기고 조립이 읽지 않는다. Penpot SOURCE.md에 한계 절을 추가했다.
- **한계**: Penpot membership_required 0건. test_v6 membership 37건 중 GlitchTip 27(73%) — test_v5의 Rocket.Chat 편중(28/33 = 85%)보다는 낮지만 편중은 남는다. 동결 보고·DATA_CARD 한계에 기록한다.
- **seahub 보충 결과: 7 → 8건(목표 15 미달, 실제 수 부족).** 클론의 `is_group_member(` 호출·`api_group_check`·`IsGroupMember`·`ccnet_api.is_group_user` 사용처를 전수 확인한 결과 구성원 조회가 **결정 조건**인 DRF 엔드포인트는 8건이 전부였다(추가 1건: POST `/api2/groups/{group_id}/repos/`, `@api_group_check` = 구성원 OR sysadmin). 나머지 `is_group_member` 호출은 대상 사용자 검증(email이 요청자가 아님), 그룹 관리자 역할이 결정(role_required), 소유자/관리자 AND 대상 그룹 구성원(manual), 라우트 없는 내부 헬퍼, 대상 그룹 지정 없는 본인 소속 목록(owner_match)이었다. 거부 목록과 사유는 seahub SOURCE.md '2차 갱신 A' 절. 수를 채우기 위한 동형 중복 투입은 하지 않았다.

### 3.2 seahub `is_repo_admin` 단독 → manual (3건 변경)

`is_repo_admin`(share/utils.py:39-73) = 소유자 OR ACL 공유 관리 권한 OR 부서 관리자. 단독으로 결정하는 3건을 owner_or_admin → manual(0.8)로 바꿨다: GET `/api/v2.1/repos/{repo_id}/webhooks/`, PUT `/api/v2.1/repos/{repo_id}/auto-delete/`, DELETE `/api/v2.1/repos/{repo_id}/trash/`. 명시적 `repo_owner == username` 비교가 `is_repo_admin`과 OR로 함께 있는 3건(DELETE `/api/v2.1/groups/{group_id}/libraries/{repo_id}/`, DELETE `/api2/groups/{group_id}/repos/{repo_id}/`, POST `/api2/repos/{repo_id}/dir/shared_items/`)은 owner_or_admin 유지. 1차 보고의 "4건"은 6건 후보 중 코드 확인 결과 3건이었다.

### 3.3 Redash `require_admin` — 구현 확인과 G1-b 적용 (18건 변경)

- 코드 확인: `require_admin = require_permission("admin")`(redash/permissions.py:86-87), `require_super_admin = require_permission("super_admin")`(:90-91), `require_permissions.__call__`은 `current_user.has_permission(s)`(:57-75), `User.permissions`는 요청자 그룹들의 권한 합(redash/models/users.py:173-175), `Group`은 `org_id`로 조직 귀속(users.py:268), 조직 admin 그룹 권한 `ADMIN_PERMISSIONS = ["admin", "super_admin"]`(users.py:261). → `require_admin`은 `require_permission`과 같은 **조직 그룹 권한** 메커니즘이다.
- 적용: `@require_admin` + `get_by_id_and_org(..., self.current_org)` 10건, + 생성 시 `org=self.current_org` 강제 4건, + `current_org` 목록·설정 고정 2건 → tenant_match(G1-b, 0.75~0.8). 기능 권한만 + `current_org` 필터·강제 2건(GET `/api/data_sources`, POST `/api/dashboards`)도 같은 규칙으로 tenant_match. role_required 잔류 3건: GET `/api/data_sources/types`(`@require_admin`이지만 조직 객체·필터 없음, 전역 query_runner 목록), GET `/api/admin/queries/outdated`(`@require_super_admin`, 조직 횡단), GET `/api/alerts`(기능 권한만, `Alert.all(group_ids)`에 org 필터 없음). 재라벨 목록은 Redash SOURCE.md "G1-b 적용" 절.
- 결과 Redash tenant_match 26/74 = 35.1%(상한 50% 이내). controller_text에 `User.permissions` 블록을 넣어 admin이 그룹 권한임이 입력에 드러난다.

### 3.4 그 밖의 검수 주의(각 SOURCE.md 불확실 절)

- seahub: `/api/v2.1/org/{org_id}/admin/...` 6건은 경로에 테넌트 ID가 있으나 `request.user.org.org_id == org_id` 비교라 보충 규약 4로 tenant_match(0.75~0.8); 부서 관리자 OR 소유자(commit revert, repo-api-tokens GET), `can_create_wiki AND can_generate_share_link AND (owner OR admin)`(wikis POST)은 EXCLUDE 후보; `POST groups/{id}/libraries/`는 `can_add_repo AND is_group_member`(membership 0.6).
- Redash: `POST /api/alerts/{id}`는 `require_admin_or_owner AND require_access`(manual 0.6); `GET /api/users/{user_id}`는 본인 OR 기능 권한 `list_users`(EXCLUDE 후보); `GET /api/dashboards` 범위 결정이 ACL·소유자·draft 복합(manual 0.6). G1-b 16건은 모델이 role_required로 읽을 가능성이 큰 경계(SOURCE.md 3a).
- GlitchTip: PUT teams/projects·POST keys·PUT alerts는 구성원 필터만으로 쓰기 허용인데 같은 자원 DELETE는 ADMIN(코드대로 membership 0.7); `set_owner`는 현 소유자 OR OWNER 역할(role 0.7); `status-pages/`는 경로 slug 미사용(EXCLUDE 후보); tenant_match 0건은 '현재 조직' 세션 상태가 없는 구조 때문.
- Penpot: `delete-share-link`(유일한 owner_or_admin, can-edit AND (작성자 OR admin), 0.6); snapshot lock/delete는 역할 AND 작성자(manual); 팀 관리 명령은 인가는 구성원 전용 `get-permissions`지만 조회에 `get-team`(조직 소유자 폴백 포함)을 호출 — 5b를 "read 권한 경로"로 해석해 유지.

## 4. 검수 시트

- `review/test_v6_review.xlsx` 시트 `test_v6_review` 302행. 열: id, **담당자**(검수자A/B/C — 재조립본 기준으로 project × 초안 label 층화 후 순환 **재배정**, 101/101/100건; label·프로젝트 구성 거의 동일), project, service, method, path, auth_summary, permission_doc, 초안 label, 초안 confidence, **초안 EXCLUDE 후보**(Y), 초안 근거 설명, 근거(코드 줄·문서), controller_text(입력 코드), source permalink(GitHub `blob`, GlitchTip은 GitLab `/-/blob/`), **확정 label**(드롭다운 7종), **확정 근거**, **비고(EXCLUDE + 사유)**. 보조 시트 '라벨 정의'(프롬프트 v3.0.1 발췌 + BLADE 규약), '검수 규약'(G1~G8 원문 + 작업 S0 test_v6 보충 1~8, 정지 지점 2 결정 포함).
- **모델 예측 열은 없다**(스크립트 assert). 검수 전·후 어떤 모델로도 test_v6 입력을 추론하지 않았다.
- 검수 완료본은 `review/test_v6_review_reviewed.xlsx`로 저장한다. 3번은 `build_test_v6.py freeze`가 '확정 label'·'비고' 열을 읽어 test_v6.jsonl / test_v6_excluded.jsonl / test_v6_manifest.json(SHA-256) / training/lora/data_v6/test_v6_inputs.jsonl을 만들고, 제외율 10% 초과면 멈춘다(`--allow-exclusion-rate`는 사용자 승인 후에만).

## 5. 라이선스·공개 범위

- seahub Apache-2.0, Redash BSD-2-Clause, GlitchTip MIT, Penpot MPL-2.0 — 네 프로젝트 모두 코드 본문 공개 가능(GPL·상용 디렉터리 없음). test_v6 파일을 .gitignore에 넣을 사유는 현재 없다(동결 시 재확인). seahub `v14.0.9-server`와 `v14.0.8-server`는 같은 커밋 `0841826c`를 가리킨다.
- test_v6은 tenant_match를 포함(초안 37건: Redash 26 · seahub 11)하므로 label 구성이 test_v5(tenant 0건)와 다르다. 네 SOURCE.md에 명시했고 DATA_CARD는 3번 동결 때 갱신한다.

## 6. 이 세션이 만든/바꾼 파일

- 신규: data/raw_v6/**(규격 + 4개 프로젝트), datasets/blade/processed/data_v6/{test_v6_candidates.jsonl, assemble_report.json, sheets_report.json}, review/test_v6_review.xlsx, scripts/build_test_v6.py, scripts/testv6_guard.py, reports/data_v6/{stop1_test_v6_candidates.md, stop2_test_v6_candidates.md}.
- 수정: AGENTS.md 끝 "작업 S0" 절(추가 + 보충 규약 1·2에 정지 지점 2 결정, 재조립본 확정과 동결 보고·DATA_CARD 필수 한계 항목 (a)(b)(c) 기록). 다른 세션의 "작업 S2"·"S3" 절과 .gitignore 수정, reports/eval/context_aug_v5/ 등은 건드리지 않았다.
- 커밋(사용자 지시 2026-11-03, xlsx 제외): data/raw_v6/**, datasets/blade/processed/data_v6/*, scripts/build_test_v6.py, scripts/testv6_guard.py, reports/data_v6/*, AGENTS.md.

## 8. AI 1차 검수 완료본 (2026-11-04, 사람 확인 전 — 동결하지 않음)

- 검수자 Claude(AI), 프로젝트별 4개 검수 에이전트가 controller_text + 클론 직접 확인으로 초안과 독립 판정 → `scripts/merge_test_v6_ai_review.py`가 `review/test_v6_review_reviewed.xlsx`(SHA-256 `cd2b6ad7e86c8af7e12c43f366e29345b2f41df5e1a3f2358b32a3e7f84f7047`)를 생성. 담당자 열 = Claude(AI), 원 층화 배정은 '원 배정' 열, 판정 메모는 '검수 메모' 시트. 레코드별 판정 원본 `data_v6/review_ai/<project>_review.jsonl`, 집계 `ai_review_report.json`. 모델 예측은 어떤 것도 참조하지 않았다.
- 결과: 302건 중 확정 289, **EXCLUDE 13(4.3%)**, 초안 대비 변경 7. 확정 분포: role_required 66 · owner_match 59 · manual 53 · membership_required 37 · tenant_match 37 · public 20 · **owner_or_admin 17**.

| 확정 label | seahub | Redash | GlitchTip | Penpot | 합 |
|---|---:|---:|---:|---:|---:|
| membership_required | 8 | 2 | 27 | 0 | 37 |
| owner_or_admin | 3 | 13 | 1 | 0 | 17 |
| tenant_match | 11 | 26 | 0 | 0 | 37 |
| role_required | 22 | 2 | 16 | 26 | 66 |
| owner_match | 23 | 8 | 12 | 16 | 59 |
| manual_review_required | 21 | 16 | 9 | 7 | 53 |
| public | 3 | 4 | 5 | 8 | 20 |
| EXCLUDE | 3 | 3 | 3 | 4 | 13 |

- 변경 7건(초안 → 확정): GlitchTip POST projects/{org}/{proj}/alerts/ manual → membership(팀 구성원 OR 조직 ADMIN = G2 "구성원 OR 관리자 우회"); Penpot delete-share-link owner_or_admin → manual(can-edit AND (작성자 OR admin), 보류 3), delete-team role → manual(admin-console 플래그 분기가 입력 코드 안에 보여 G6); **seahub 4건 owner_or_admin → manual**(DELETE groups/{id}/libraries/{repo}, DELETE api2 groups/{id}/repos/{repo}, POST api2 repos/{id}/dir/shared_items, POST wikis): 검수자는 명시적 `repo_owner == username` 비교가 `is_repo_admin`의 소유자 분기(share/utils.py:63-64)와 중복돼 허용 집합이 `is_repo_admin` 단독과 같다고 보아 보충 규약 2를 넓게 적용했다. **이는 정지 지점 2 결정 3.2("단독 3건 → manual, 명시적 소유자 비교 OR는 owner_or_admin 유지")보다 넓은 해석이므로 사용자 확인 대상**이다. 결정 3.2 문구대로 되돌리면 seahub owner_or_admin 3 → 6(wikis는 EXCLUDE 후보였음), 합 20.
- **한계(사용자 확인)**: owner_or_admin support 17(test_v5 21)이며 Redash 13(76%)에 집중. tenant_match 37 중 Redash 26(70%), membership 37 중 GlitchTip 27(73%). Penpot은 membership·tenant·owner_or_admin 모두 0.
- EXCLUDE 13건(사유별): 두 label 경계 8(seahub revert·repo-api-tokens: 개인 저장소 소유자/부서 관리자 분기; Redash GET groups·GET users/{id}·GET alerts; GlitchTip set_owner; Penpot create-team·delete-share-link는 manual), 의도·구현 충돌 1(GlitchTip status-pages slug 미사용), 의도 미확정 2(seahub group-members-import-example 인증 선언 누락 추정, GlitchTip wizard-set-token), 인증 절차·익명 스텁 경계 3(Penpot logout·get-profile·get-error-reports). 초안 EXCLUDE 후보 12건 중 9건 EXCLUDE, 3건은 label 확정(Redash POST query_snippets tenant 0.6, seahub POST wikis manual, Penpot delete-team manual).
- 확정 confidence < 0.7 10건은 시트 '확정 confidence(AI)' 열로 사람 확인 우선 대상.
- **입력 결함 수정(조립 단계)**: 익명 operation(`security: []`) 16건(seahub 4·Redash 4·Penpot 8)이 스펙 최상위 security가 없어 `security_state=declared`로 계산됐다(GlitchTip은 추출기가 전역 security를 넣어 `explicitly_anonymous`). 프롬프트 v3.0.1 규칙상 declared 입력에는 모델이 public을 낼 수 없으므로 `build_test_v6.py`에 `anonymous_fix`를 추가해 프로젝트 기본 보안 스킴을 스펙 전역 security로 넣고(meta.anonymous_global_security_added, 빌드 assert), 재조립했다: explicitly_anonymous 26(public 초안 21 + 조건부 익명 5), declared 276. test_v5에서는 Ghost·Umami public 13건이 declared, Rocket.Chat 6건이 explicitly_anonymous로 섞여 있었다(동결본 불변, 한계로 기록 권장). 재조립 후 test_v6_candidates.jsonl SHA-256 `d3f5600f6f5d78268a1396ab6d64f2a8c89287ee6789d56c1c77b8549d1f9092`, 시트 `529f77c11aafd6b85ab8dd4c3316d8f81a4ea21eed8e7c23e33afba91039263e`(행 내용 동일, 재층화 결과 동일).
- 이 절의 산출(build_test_v6.py 수정, 재조립 후보, merge 스크립트, review_ai/)은 2026-11-04 사용자 지시로 커밋한다(xlsx 제외).

## 9. 사람 확인 프로토콜 (2026-11-04 사용자 결정, 동결 보류)

- 시트 `review/test_v6_human_check.xlsx`(SHA-256 `8bb43882573707f139d44256531c958cb0525955309ff1e3993125ddbf49bf03`, 생성 `scripts/build_test_v6_human_check.py`, 보고 `data_v6/review_ai/human_check_report.json`).
  - **공개_우선확인 44건**(AI 확정 label·근거·비고 공개, 사람 판정 열 채움): EXCLUDE 13 ∪ AI confidence<0.7 10 ∪ 초안 대비 변경 7 ∪ seahub owner_or_admin→manual 4 ∪ Redash G1-b 경계 18(16 + 일관 적용 2) — 중복 제거 전 52 → 44. 프로젝트별 seahub 9 · Redash 24 · GlitchTip 4 · Penpot 7. seahub 4건 행에는 확인 질문("repo_owner == username과 is_repo_admin 내부 소유자 검사가 같은 소유자 개념인가(그룹 소유 라이브러리의 repo_owner 포함)")을 '확인 질문' 열에 명시.
  - **블라인드_감사 41건**(나머지 258건에서 AI 확정 label × project 층화 15%, seed 42; AI·초안 label·근거·evidence 숨김): seahub 14 · GlitchTip 10 · Redash 9 · Penpot 8; label별 role 10 · owner 8 · manual 7 · membership 6 · public 4 · owner_or_admin 3 · tenant 3. 정답키 `data_v6/review_ai/human_check_audit_key.json`(시트 밖).
  - 검수자 A/B/C 균등: 우선확인 15/15/14, 감사 14/14/13. 보조 시트 '라벨 정의'(프로토콜 문구 포함)·'검수 규약'.
- **사전 기록(AGENTS.md 작업 S0)**: 블라인드 감사 불일치율(사람 판정 ≠ AI 확정) ≤ 5%(41건 중 ≤ 2건)면 나머지 AI 확정을 수용하고, 5% 초과면 전수 사람 검수. 불일치 건은 사람 판정 우선. 공개_우선확인 44건은 전부 사람 판정으로 확정한다.
- 동결(3번)은 사람 확인 결과 반영 뒤 사용자 승인 시 `build_test_v6.py freeze`로 한다(제외율 10% 게이트 유지).

## 7. 3번 동결 보고·DATA_CARD 한계에 추가할 항목 (사용자 지시 2026-11-03·11-04)

- owner_or_admin support 17(Redash 13 = 76%), AI 확정 기준 — 사람 확인 후 재집계.
- test_v5 public 19건 중 13건(Ghost 7 · Umami 6)이 security_state=declared 입력(동결본 불변, Rocket.Chat 6건만 explicitly_anonymous).
- test_v6 익명 operation 입력 수정 내역: `security: []` 26건(public 초안 21 + 조건부 익명 5)에 프로젝트 기본 스킴을 스펙 전역 security로 추가해 explicitly_anonymous로 통일(build_test_v6.py anonymous_fix, 빌드 assert, meta.anonymous_global_security_added).
- tenant_match 37건 중 Redash 26(70%), membership_required 37건 중 GlitchTip 27(73%) — AI 확정 기준, 사람 확인 후 재집계.
- Redash G1-b 경계 16건 id 목록 `datasets/blade/processed/data_v6/redash_g1b_boundary_ids.json`(일관 적용 2건은 별도 키) — S9에서 따로 집계.
- S9 보고에 프로젝트별 정확도·label별 F1 필수.
