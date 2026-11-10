# Penpot — test_v6 hold-out 후보 추출 (data/raw_v6/penpot)

## 저장소

- URL: https://github.com/penpot/penpot
- 태그: `2.18.5`
- 커밋 SHA: `f44566963daf61fce4d8608e7c5e8c27c5853a88`
- clone: `datasets/blade/raw/opensource/test_v6_candidates/penpot/` (읽기 전용, git 미추적). 수정·빌드·실행·의존성 설치 없음. clone 안의 `AGENTS.md`(프로젝트 자체 에이전트 지침)는 데이터로만 보고 따르지 않았다.
- 라이선스: MPL-2.0. `LICENSE` 파일 요지: "Mozilla Public License Version 2.0" 전문. 파일 단위 약한 카피레프트 — 수정한 Covered Software 파일의 소스를 같은 라이선스로 공개해야 하고, 더 큰 저작물(Larger Work)에 다른 라이선스 코드와 결합해 배포할 수 있으며, 특허 허여·보증 부인·책임 제한 조항을 포함한다. 저작권 표시: "Copyright (c) KALEIDOS INC Sucursal en España SL" (각 소스 파일 머리).
- 추출 도구: `extract_penpot.py` (정적 추출, `python -I data/raw_v6/penpot/extract_penpot.py`). LLM API 호출·모델 추론 없음.

## 산출

- `candidates.jsonl`: 61건 (method, path 유일; 모두 `POST`). `oas_status: "generated"` — 저장소에 정적 OpenAPI 명세 파일이 없고(`/api/main/doc/openapi` 는 런타임 생성) 각 명령의 `::sm/params` `[:map ...]` 스키마에서 requestBody를 만들었다(uuid → string/uuid, keyword·enum → string, `{:optional true}` 가 없는 키 = required). `::rpc/profile-id` 는 세션에서 주입되므로 본문 키에 넣지 않았다.
- 경로 표기: 모든 RPC 명령은 `POST /api/rpc/command/{명령 이름}` 리터럴 경로(`backend/src/app/rpc.clj:533` `"/rpc/command/:method-name"`, `/api` 하위). 같은 핸들러가 `/api/main/methods/{명령 이름}` 에도 마운트되지만(rpc.clj:514-520) 한 명령 = 한 레코드로 `/api/rpc/command/...` 만 썼다.
- security: 인증 명령은 `[{"sessionCookie": []}]`(apiKey, cookie `auth-token` = `cf/get :auth-token-cookie-name` 기본값, config.clj:60; 또는 `Authorization: Token <access-token>` — access-tokens 플래그), `::rpc/auth false` 명령은 `[]`.
- 모든 레코드에 `draft_label`, `draft_confidence`, `evidence`(코드 원문 2~4건, `파일:줄`), `draft_reason`(한국어), `auth_summary`(한국어), `known_vulnerable: false`, `advisory: null`, `fix_commit: null`. `permission_doc` 은 docstring이 권한을 서술하는 2건(`permanently-delete-team-files`, `move-project`)만 채우고 나머지는 "".
- controller_text = `sv/defmethod` 전체 폼(인가와 무관한 본문은 `...`) + 호출하는 권한 헬퍼 원문(`get-permissions`+`sql:team-permissions`, `sql:project-permissions`, `bfc/get-file-permissions`+`sql:file-permissions`, `app.rpc.permissions` 팩토리, `wrap-authentication`). Clojure 폼 끝은 문자열·`;` 주석·문자 리터럴 밖의 `(`/`)` 균형으로 찾았다(`form_end`). 길이 872~2,943자(500 미만·3,000 초과 없음).

## 추출 범위와 방법

- 대상: `backend/src/app/rpc/commands/*.clj` 의 `(sv/defmethod ::name {metadata} [cfg params] ...)` 154개 전부를 읽고 인가 구조로 분류한 뒤 61건을 선정했다. `/api/management/methods/*`(shared-key 운영 API)와 HTTP 자산 경로(`/assets/*`)·웹훅 수신·SSE 는 RPC 명령이 아니어서 범위 밖.
- 선정 원칙: (1) 결정 5b(조직 소유자 viewer OR 경로)에 걸리는 명령은 라벨과 무관하게 **추출하지 않음**(아래 제외 A). (2) 남은 명령에서 membership_required·owner_or_admin·tenant_match 후보를 먼저 모두 모으고(결과: owner_or_admin 1, membership 0, tenant 0), (3) role_required·owner_match·public·manual 은 동형 조건(같은 권한 함수) 그룹당 대표 2~8건만 넣어 한 label 50% 이하를 맞췄다.

## 인증·인가 구조

- 인증: `rpc.clj` `make-rpc-handler`(95-147)가 `::session/profile-id`(세션 쿠키, `app.http.session/authz`) 또는 `::actoken/profile-id`(`Authorization: Token`, `app.http.access-token/authz`, access-tokens 플래그)에서 `::rpc/profile-id` 를 넣는다. `wrap-authentication`(163-198): 메타데이터 `::rpc/auth` 기본 true → profile-id 없으면 `:authentication-required`; `::rpc/auth false` → 익명 허용; `::rpc/auth-type :token`·`::rpc/perms #{...}` → 토큰 인증과 토큰 권한 문자열 요구. `wrap-nitrate-sso`(261-337)는 admin-console 플래그가 켜진 경우에만 조직 SSO 세션을 추가 검사(기본 꺼짐, 라벨에 반영 안 함).
- 역할 모델: `team_profile_rel`(팀)·`project_profile_rel`·`file_profile_rel` 행의 `is_owner / is_admin / can_edit` 플래그. `app.common.types.team/permissions-for-role`(team.cljc:14-18): viewer {can-edit false}, editor {can-edit true}, admin {can-edit, is-admin}, owner {can-edit, is-admin, is-owner}. 모든 권한 맵은 `:is-admin = is_owner OR is_admin`, `:can-edit = is_owner OR is_admin OR can_edit`, `:can-read true`(행이 있을 때만).
- 권한 제공 함수와 그것이 감싸는 SQL:
  - `teams/get-permissions`(teams.clj:51-61) ← `sql:team-permissions`(41-49): `team_profile_rel WHERE profile_id = ? AND team_id = ?`. **구성원 전용.**
  - `teams/get-read-permissions`(63-66) = `(or (get-permissions …) (perms/get-organization-owner-permissions … :team-id))` → **조직 소유자 viewer OR 포함.**
  - `projects/get-permissions`(projects.clj:52-64) ← `sql:project-permissions`(31-50): 팀 행 UNION 프로젝트 행(팀 구성원 존재 조건). 구성원 전용. `projects/get-read-permissions`(66-69) = OR 조직 소유자.
  - `bfc/get-file-permissions`(binfile/common.clj:387-418) ← `sql:file-permissions`(343-377): 파일·팀·프로젝트 행 UNION(모두 팀 구성원 존재 조건); 4-인자 형태는 `share-link` 행이 있으면 `{:type :share-link :can-read true :pages …}`. `perms/get-file-read-permissions`(permissions.clj:148-155) = OR `get-organization-owner-permissions`.
  - `perms/get-organization-owner-permissions`(permissions.clj:136-146): 요청자가 팀을 소유한 조직(Nitrate)의 비구성원 소유자면 read-only viewer 권한 반환. 주석(96-100): "Edit/admin permission providers intentionally stay membership-only."
- 술어·검사 팩토리(permissions.clj): `make-admin-predicate-fn`(:is-admin, 52-58), `make-edition-predicate-fn`(:can-edit, 60-66), `make-read-predicate-fn`(:can-read, 68-74), `make-comment-predicate-fn`(:is-logged AND who-comment="all", 76-84), `make-check-fn`(거짓이면 `:not-found/:object-not-found`, 86-94).
- 네임스페이스별 검사 함수: `teams/check-admin-permissions!`·`check-edition-permissions!`(구성원 전용) / `teams/check-read-permissions!`(조직 소유자 OR); `projects/check-edition-permissions!`(구성원 전용) / `projects/check-read-permissions!`(OR); `files/check-edition-permissions!`(구성원 전용) / `files/check-read-permissions!`·`has-comment-permissions?`·`check-comment-permissions!`(모두 `perms/get-file-read-permissions` → OR, share-id 겸용); `webhooks/check-webhook-edition-permissions!`(teams/get-permissions can-edit).
- share-id 의미: `get-file-fragment`·`get-page`·`get-view-only-bundle`·`get-font-variants(file-id)`·comments 명령은 `[:share-id {:optional true}]` 를 받아 `get-file-read-permissions cfg profile-id file-id share-id` 로 구성원 OR 유효한 share-link 를 허용한다(`:type :share-link` 면 허용 페이지로 제한). 보충 규약 5에 따르면 manual 이지만, 같은 함수가 조직 소유자 OR 도 포함해 결정 5b 로 전부 제외했다.
- 직접 플래그 비교: `update-team-member-role`·`delete-team-member`(is-owner OR is-admin), `create-team-invitations`·`update-team-invitation-role`·`delete-team-invitation`(:is-admin), `delete-team`(기본 is-owner; admin-console 플래그면 `cto/allowed? :delete-team`), `leave-team`(본인 행 삭제, owner 는 reassign-to 필요), `delete-share-link`(can-edit AND (share-link owner OR is-admin)), 스냅샷 lock/unlock(can-edit AND 작성자 본인), `delete-file-snapshot`(can-edit AND 잠금자 본인 또는 미잠금).
- 본인 고정: profile 명령·access-token·upload-session·`get-teams`·`get-all-projects`·`mark-all-threads-as-read` 는 세션 `::rpc/profile-id` 로 행을 고정하고 대상 id 를 본문에서 받지 않는다.
- 익명(`::rpc/auth false`): login-with-password, logout, recover-profile, prepare-register-profile, register-profile, request-profile-recovery, get-sso-provider, login-with-ldap, create-demo-profile, verify-token, get-enabled-flags, get-team-info, get-file-info, get-profile, get-file-fragment, get-view-only-bundle (16개).
- 테넌트: Penpot 자체에는 요청자의 현재 테넌트로 자원을 필터하는 구조가 없다. 조직(Nitrate)은 admin-console 플래그 전용 외부 서비스라 tenant_match 후보가 없다(아래 제외 C). **이 프로젝트의 tenant_match 는 0건**이며 test_v6 의 tenant_match 는 seahub·Redash 에서 나온다.

## 제외한 범위와 이유 (사유별 건수, 합계 93 = 154 − 61)

### A. 규약상 EXCLUDE(플래그 의존) — 결정 5b, 조직 소유자 viewer OR 경로: 48건

read 권한이 `teams/get-read-permissions`·`projects/get-read-permissions`·`perms/get-file-read-permissions`·`get-organization-owner-viewer-team` 중 하나를 지나는 명령. 모두 `(or <membership> <organization-owner viewer>)` 라서 추출하지 않았다. 이 중 17건은 share-id 겸용(보충 규약 5 → manual)이지만 5b 가 우선해 함께 제외.

- `teams/check-read-permissions!`(15): get-team-members, get-team-users(team-id/file-id 둘 다), get-team-stats, get-team-invitations, get-projects, get-team-shared-files, get-team-recent-files, get-team-deleted-files, get-unread-comment-threads, get-webhooks, search-files, get-font-variants(team-id·project-id·file-id 세 분기 모두 read 변형), download-font, download-font-family, check-nitrate-sso(`teams/has-read-permissions?`)
- `teams/get-team` 의 `get-organization-owner-viewer-team` 폴백(1): get-team
- `projects/check-read-permissions!`(3): get-project, update-project-pin, get-project-files
- `files/check-read-permissions!` 또는 `perms/get-file-read-permissions` 직접(16): get-file, get-file-fragment(share-id), has-file-libraries, get-library-usage, get-page(share-id), get-file-summary, get-file-stats, get-file-libraries, get-library-file-references, export-binfile, get-file-snapshots, get-file-snapshot, get-file-object-thumbnails, get-file-data-for-thumbnail, clone-file-media-object(원본 미디어 파일 read), get-view-only-bundle(share-id, `::rpc/auth false`)
- `files/check-comment-permissions!`(share-id 겸용, 13): get-comment-threads, get-comment-thread, get-comments, get-profiles-for-file-comments, create-comment-thread, update-comment-thread-status, update-comment-thread, create-comment, update-comment, delete-comment-thread, delete-comment, update-comment-thread-position, update-comment-thread-frame. — update-comment·delete-comment·delete-comment-thread 는 추가로 `(= owner-id profile-id)` 작성자 검사가 있어 5b 가 없었다면 owner_match 후보였다(관리자 우회 없음).

영향: 결정 5 가 membership_required 로 예정했던 team/project/file read 명령 전부가 이 그룹에 들어가 **membership_required 후보는 0건**이다. 구성원 전용 제공 함수(`get-permissions`·`bfc/get-file-permissions`)는 전부 edition/admin 검사에만 쓰여 role_required 로 간다.

### B. 동형 조건 중복(대표만 수집): 26건

- teams/check-edition-permissions!(대표 update-team·create-project·create-webhook·create-font-variant·permanently-delete-team-files·move-project): get-team-invitation-token, update-font, restore-deleted-team-files, duplicate-project, clone-template (5)
- teams/get-permissions :is-admin 직접(대표 create-team-invitations·delete-team-invitation): update-team-invitation-role (1)
- get-team 팀 행 permissions → check-edition-permissions!(대표 delete-font): delete-font-variant (1)
- check-webhook-edition-permissions!(대표 delete-webhook): update-webhook (1)
- projects/check-edition-permissions!(대표 rename-project·delete-project·create-file·move-files·import-binfile): duplicate-file (1)
- files/check-edition-permissions!(대표 rename-file·update-file·delete-file·set-file-shared·link-file-to-library·create-share-link·upload-file-media-object·create-file-snapshot): unlink-file-from-library, update-file-library-sync-status, ignore-file-library-sync-status, restore-file-snapshot, update-file-snapshot, create-file-media-object-from-url, assemble-file-media-object, create-file-object-thumbnail, delete-file-object-thumbnail, delete-file-object-thumbnails, create-file-thumbnail (11)
- can-edit AND 작성자 본인(대표 lock-file-snapshot): unlock-file-snapshot (1)
- 세션 profile-id 고정 owner_match 동형(대표 profile·access-token 명령): delete-profile-photo, get-owned-teams, get-current-mcp-token, get-subscription-usage (4)
- create-team 동형(+초대): create-team-with-invitations (1)

### C. Nitrate 외부 인가·admin-console 플래그 전용: 13건

조직(organization) 구성원·권한을 외부 Nitrate 서비스가 판정(`nitrate/assert-membership`, `nitrate/call :get-organization-permissions`, `cto/allowed?`)하고 플래그가 꺼지면 동작하지 않는 명령. 외부 인가(G6)이자 플래그 의존이라 제외: get-nitrate-connectivity, get-subscription-warning, redeem-nitrate-activation-code, get-nitrate-activation-code-request, leave-organization, get-leave-organization-summary, remove-team-from-organization, add-team-to-organization, check-organization-members, all-organization-members-in-team, all-team-members-in-organizations, check-team-external-invitations (nitrate.clj 12; check-nitrate-sso 는 A 에 계상), get-owned-organizations-summary (profile.clj, 1).

### D. public 동형 중복(`::rpc/auth false`, 대표 8건 외): 4건

get-sso-provider(이메일 도메인 → SSO 설정 조회), login-with-ldap(login-with-password 동형), create-demo-profile(demo-users 플래그, 익명 생성), get-enabled-flags.

### E. 인증만·객체 없음 동형(대표 send-user-feedback·push-audit-events 외): 2건

get-builtin-templates(설정의 템플릿 목록 반환), get-error-report(get-error-reports 와 같은 토큰 권한 조건, 단건).

## draft_label 건수 (61)

| label | 건수 | 비율 |
|---|---:|---:|
| role_required | 27 | 44.3% |
| owner_match | 18 | 29.5% |
| public | 8 | 13.1% |
| manual_review_required | 7 | 11.5% |
| owner_or_admin | 1 | 1.6% |
| membership_required | 0 | 0% |
| tenant_match | 0 | 0% |

- role_required (27): 팀 can-edit(teams/check-edition-permissions!) 6 — update-team, create-project, create-webhook, create-font-variant, permanently-delete-team-files, move-project(양쪽 팀); 팀 is-admin/is-owner 직접 5 — update-team-member-role, delete-team-member, create-team-invitations, delete-team-invitation, update-team-photo(check-admin-permissions!); get-team 팀 행 can-edit 1 — delete-font; webhook can-edit 1 — delete-webhook; delete-team 1(EXCLUDE 후보, 기본 경로 is-owner); 프로젝트 can-edit 5 — rename-project, delete-project, create-file, move-files(대상·원 프로젝트), import-binfile; 파일 can-edit 8 — rename-file, update-file, delete-file, set-file-shared, link-file-to-library(양쪽 파일), create-share-link, upload-file-media-object, create-file-snapshot. 모두 구성원 행 확인 뒤 그룹 안 역할 플래그(editor/admin/owner)가 결정 조건(G3).
- owner_match (18): profile 8 — get-profile(EXCLUDE 후보), update-profile, update-profile-password, update-profile-notifications, update-profile-photo, delete-profile, update-profile-props, request-email-change; leave-team(본인 구성원 행 삭제); get-teams·get-all-projects(본인 소속 목록); create-access-token·delete-access-token·get-access-tokens; create-upload-session·upload-chunk; mark-all-threads-as-read(본인 읽음 상태 행); create-team(본인 명의 생성, owner 역할 자동 부여).
- public (8): login-with-password, prepare-register-profile, register-profile, request-profile-recovery, recover-profile, verify-token, get-team-info, get-file-info — 모두 `::rpc/auth false` 이고 핸들러에 요청자 조건이 없다.
- manual_review_required (7): lock-file-snapshot(can-edit AND 작성자), delete-file-snapshot(can-edit AND 잠금자/미잠금), create-team-access-request(인증만, 비구성원의 접근 요청), send-user-feedback(인증만), push-audit-events(인증만), logout(EXCLUDE 후보), get-error-reports(EXCLUDE 후보, 토큰 권한 문자열).
- owner_or_admin (1): delete-share-link — `files/check-edition-permissions!`(can-edit) 통과 후 `(or (= (:owner-id slink) profile-id) (:is-admin perms))`. 관리자는 항상 can-edit 이므로 실질 조건은 '관리자 OR (작성자 AND 편집 권한)'. Penpot 의 유일한 owner_or_admin 후보이며 confidence 0.6.
- membership_required (0): 결정 5 가 예정한 ~18건은 전부 제외 A(결정 5b) 에 해당. 솔직히 0건이다.
- tenant_match (0): 위 '테넌트' 항목.

## EXCLUDE 후보 (4건, confidence ≤ 0.5, draft_reason 첫머리 `EXCLUDE 후보:`)

| 명령 | draft_label | 사유 |
|---|---|---|
| delete-team | role_required 0.5 | admin-console 플래그 꺼짐: `(:is-owner perms)` 만; 켜지고 조직 팀이면 `cto/allowed? :delete-team`(조직 권한) — 설정에 따라 허용 주체가 바뀜(G6) |
| logout | manual_review_required 0.5 | `::rpc/auth false` 익명 허용이지만 익명이면 `{}` no-op, 본문 profile-id == 세션 profile-id 일 때만 본인 세션 삭제 — public/owner_match/인증 절차 경계 |
| get-error-reports | manual_review_required 0.5 | `::rpc/auth-type :token` + `::rpc/perms #{"error-reports:read"}`(운영자가 SQL/REPL 로만 부여) — 역할(G3)인지 토큰 스코프(GlitchTip has_permission 선례처럼 근거 제외)인지 경계 |
| get-profile | owner_match 0.5 | `::rpc/auth false`: 익명이면 Anonymous User 스텁, 로그인이면 세션 본인 프로필 — public/owner_match 경계 |

## 불확실한 엔드포인트 (검수 시 주의)

- delete-share-link (owner_or_admin 0.6): can-edit 가 AND 로 선행한다. AND 결합을 중시하면 manual.
- lock-file-snapshot (manual 0.7) / delete-file-snapshot (manual 0.6): 파일 can-edit 역할 AND 스냅샷 작성자(또는 잠금자) 본인. 작성자 조건 중심이면 owner_match, 역할 중심이면 role_required.
- create-team (owner_match 0.6): 기본 경로는 인증 + quota 뒤 본인 owner 로 팀 생성(본인 명의 생성, G4). organization-id + admin-console 플래그면 조직 구성원·정책 검사가 추가된다. 객체 없는 인증 전용으로 보면 manual.
- create-upload-session (owner_match 0.7): 본인 명의 세션 생성, 객체 없음 → manual 대안.
- mark-all-threads-as-read (owner_match 0.6): 스레드 접근 검사 없이 (thread_id, 본인 profile_id) 상태 행만 기록. 객체 관계 검사 없음을 중시하면 manual.
- leave-team (owner_match 0.75): 본인 행 삭제가 본질이지만 owner 의 reassign-to 분기는 다른 구성원 행에 owner 역할을 쓴다(그 부분만 보면 역할 조건).
- delete-team-member·update-team-member-role (role_required 0.85~0.9): 허용 결정은 `get-permissions`(구성원 전용) 의 is-owner/is-admin 이지만, 같은 핸들러가 `get-team`(조직 소유자 viewer 폴백 포함)을 조회용으로 호출한다. 결정 5b 는 read 권한 경로에 적용했고 이 두 명령의 인가 결정은 구성원 플래그라서 유지했다. 검수자가 5b 를 더 넓게 적용하면 EXCLUDE 가능. 같은 구조(get-team 조회 + 구성원 전용 검사): delete-project, delete-file, create-file, update-file, delete-font, update-team-photo, delete-team.
- create-team-invitations (role_required 0.85): 기본 is-admin 단일 조건; admin-console 플래그·조직 팀이면 `cto/allowed? :send-invitations` 가 AND 로 붙는다.
- get-team-info·get-file-info (public 0.8): `::rpc/auth false` 로 임의 id 의 최소 정보(존재·is-default·features / deleted-at)를 조건 없이 반환. 정보량이 적어 의도된 공개 조회로 보았다.
- controller_text 의 `wrap-authentication` 발췌는 토큰 유형·권한 검사 부분(178-196)을 `...` 로 줄였고(get-error-reports 만 전체 포함), `bfc/get-file-permissions` 는 1-인자 형태(343-399)까지만 넣었다(share-id 4-인자 형태는 5b 로 제외된 명령에서만 쓰임).

## 결정 5·5b 적용 결과 요약

- 결정 5 예정: membership ~18, role ~18, owner_match ~10, owner_or_admin ~1, public ~5, manual(share-id) ~8.
- 실제: membership 0(5b 로 48건 제외, share-id 겸용 17건 포함), role 27, owner_match 18, owner_or_admin 1, public 8, manual 7(share-id 겸용은 0 — 전부 5b 에 흡수).
- 5b 를 적용하지 않았다면 membership_required 후보는 teams/projects/files read 명령 31건(A 의 15+1+3+16 중 share-id 없는 것), manual(share-id) 17건이 추가됐을 것이다.

## 5b 제외 48건 보조 파일

- 파일: `candidates_5b_excluded.jsonl` (48건, `extract_penpot.py` 가 `candidates.jsonl` 과 함께 생성; 주 산출 `candidates.jsonl` 61건은 바이트 동일, SHA-256 `0e311d03ec7a6ca2acbad55f696646f8acf31d95fc248df45c0873eeeae194bb`).
- **이 48건은 사용자가 결정 5b 를 완화하지 않는 한 test_v6 후보(`candidates.jsonl`)가 아니다.** 조립(`scripts/build_test_v6.py`)은 이 파일을 읽지 않는다. 검수자가 5b 완화 여부를 판단할 수 있게 같은 형식(모든 필드, `draft_label`·`draft_confidence`·`evidence`·`draft_reason`·`auth_summary`)으로만 보존한다.
- 라벨 가정: 조직 소유자 viewer OR 경로(`rpc/permissions.clj:136-146 get-organization-owner-permissions` → `nitrate/organization-owner-of-team?`, `nitrate.clj:562-574`; admin-console 플래그가 꺼진 기본 설정에서는 항상 false)를 **무시**한 것으로 보고 라벨했다. 모든 `draft_reason` 은 `5b 제외: ` 로 시작하며 read 검사가 그 OR 경로를 포함한다는 사실을 먼저 적고 라벨 근거를 잇는다. `controller_text` 는 `sv/defmethod` 폼 + 해당 read 제공 함수(`teams/get-read-permissions` 63-66 / `projects/get-read-permissions` 66-69 / `perms/get-file-read-permissions` 148-155) + `get-organization-owner-permissions`(136-146) 원문을 포함한다(get-team 만 폴백 함수 `get-organization-owner-viewer-team` 251-264 와 `nitrate/organization-owner-of-team?` 562-574 를 대신 포함). 길이 1,867~2,945자.
- 규칙: 구성원 행만 보는 read(share-id 없음) → membership_required(G2); share-id 겸용 read(구성원 OR 공유 링크) → manual_review_required(결정 5, G6); comments 명령(check-comment-permissions!, share-id 겸용) → manual.

| draft_label | 건수 | 명령 |
|---|---:|---|
| membership_required | 29 | teams read 13 — get-team-members, get-team-users, get-team-stats, get-team-invitations, get-projects, get-team-shared-files, get-team-recent-files, get-team-deleted-files, get-unread-comment-threads, get-webhooks, search-files, download-font, download-font-family; get-team 1; projects read 3 — get-project, update-project-pin, get-project-files; files read 12 — get-file, has-file-libraries, get-library-usage, get-file-summary, get-file-stats, get-file-libraries, get-library-file-references, export-binfile, get-file-snapshots, get-file-snapshot, get-file-object-thumbnails, get-file-data-for-thumbnail |
| manual_review_required | 19 | share-id 겸용 read 4 — get-file-fragment(`::rpc/auth false`), get-page, get-view-only-bundle(`::rpc/auth false`), get-font-variants(쿼리 모드별 정책); comments 13 — get-comment-threads, get-comment-thread, get-comments, get-profiles-for-file-comments, create-comment-thread, update-comment-thread-status, update-comment-thread, create-comment, update-comment, delete-comment-thread, delete-comment, update-comment-thread-position, update-comment-thread-frame; 그 외 2 — check-nitrate-sso(플래그 꺼짐: 인증만·객체 없음, 켜져도 비구성원 거부 아님), clone-file-media-object(대상 파일 can-edit AND 원본 파일 구성원 read 의 AND 결합) |
| 그 외 5종 | 0 | — |

- 위 '결정 5·5b 적용 결과 요약' 의 추정(membership 31 / manual 17)과 다른 2건: check-nitrate-sso 와 clone-file-media-object 를 membership 이 아니라 manual 로 두었다(사유는 표). 낮은 confidence(0.6~0.7) 와 대안 label 을 `draft_reason` 에 적은 건: search-files(결과 필터가 편집 플래그 → role_required 대안), update-project-pin·update-comment-thread-status(본인 플래그 행 → owner_match 대안), update-comment·delete-comment·delete-comment-thread(작성자 본인 AND → owner_match 대안), clone-file-media-object(role_required 대안), get-unread-comment-threads(본인 미읽음 필터 → owner_match 대안).
- search-files 와 clone-file-media-object 는 `cfg` 대신 raw `conn` 을 넘겨 `nitrate-client?` 가 false 가 되므로 조직 소유자 경로가 코드상으로도 비활성이다(`draft_reason` 에 기재). 5b 를 완화할 때 이 두 건은 5b 대상이 아니었다고 볼 여지가 있다.

## 정지 지점 2 결정 (2026-11-03, 사용자) — 5b 유지, 한계 기록

- 결정 5b는 **유지**한다. Penpot read 명령 48건(`get-read-permissions`/`get-file-read-permissions`의 조직 소유자 OR 경로)은 test_v6 후보에 넣지 않으며 보조 파일 `candidates_5b_excluded.jsonl`은 조립(`scripts/build_test_v6.py`)이 읽지 않는다.
- 근거: 프롬프트 v3.0.1 보류 5(설정 의존 → manual)와 test_v5 resetAvatar 선례와 일관. `:admin-console` 플래그 기본값(꺼짐)은 입력 코드 밖(`nitrate.clj:562-574`)에 있어 모델이 볼 수 없다.
- **한계**: 이로써 Penpot의 membership_required는 0건이다(제외 48건 중 membership 후보 29). test_v6 membership_required의 Penpot 몫이 없고, 보충은 seahub(`is_group_member` 엔드포인트, 상한 93→110)로 한다. 보고서 reports/data_v6/stop2_test_v6_candidates.md 3.1절.
