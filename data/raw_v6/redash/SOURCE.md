# Redash — test_v6 hold-out 후보 추출 (data/raw_v6/redash)

## 저장소

- URL: https://github.com/getredash/redash
- 태그: `v26.9.0`
- 커밋 SHA: `42fdf9d4a0fdb83841130ab78f69899a224f281b`
- clone: `datasets/blade/raw/opensource/test_v6_candidates/redash/` (읽기 전용). 수정·빌드·실행·의존성 설치 없음.
- 라이선스: BSD-2-Clause. `LICENSE` 파일 요지: "Copyright (c) 2013-2020, Arik Fraimovich. All rights reserved. Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. 2. Redistributions in binary form must reproduce the above copyright notice ... THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" ..."
- 추출 도구: `extract_redash.py` (정적 추출, `python -I data/raw_v6/redash/extract_redash.py`). LLM API 호출·모델 추론 없음. 블록 끝은 Python 들여쓰기 기반(`func_end`: def/class 줄의 들여쓰기 이하인 다음 비공백 줄 직전까지)으로 찾고, 실제 레코드는 검토한 줄 범위를 명시해 넣었다.

## 산출

- `candidates.jsonl`: 74건 (목표 70 ± 5, (method, path) 유일). `oas_status: "generated"` (저장소에 OpenAPI 명세 없음; URL 규칙·`request.args`·`request.get_json()` 키·`project(req, (...))` 필드에서 파라미터·본문을 생성).
- 모든 레코드에 `draft_label`, `draft_confidence`, `evidence`(인가 결정 줄 원문, 파일:줄 2~4개), `draft_reason`(한국어), `auth_summary`(한국어), `permission_doc: ""`, `known_vulnerable: false`, `advisory: null`, `fix_commit: null`. 라벨은 전부 초안이며 사람이 확정한다.
- security: 보호 엔드포인트 `[{"apiKeyOrSession": []}]`(scheme: apiKey/header `Authorization: Key <api_key>` 또는 세션 쿠키), 익명 도달 가능 엔드포인트(`/api/config`, `/ping`, `/login`, `/forgot`, `/api/dashboards/public/{token}`)는 `[]`.
- controller_text 길이: 최소 99(`GET /ping`), 최대 2,973자(`GET /api/dashboards`). 3,000자 초과 0건. 500자 미만 1건: `GET /ping` — 핸들러 전체가 4줄(`redash/handlers/__init__.py:11-14`)이고 인가 코드가 없어 더 붙일 것이 없다.
- `candidates.jsonl` SHA-256 (2026-11-03 블록 포함 규칙 통일 후): `0712c0307a0608c352d7ca7a0a20377fc4aa584c94f9d07cd6752527a692bd8e`.

## 추출 범위와 방법

- 라우트: `redash/handlers/api.py`의 `api.add_org_resource(Resource, "/api/...")`(Flask-RESTful) 전부와 `redash/handlers/*.py`의 `@routes.route(...)` 함수 라우트(`/api/config`, `/api/session`, `/api/organization/status`, `/api/admin/queries/*`, `/api/queries/format`, `/login`, `/forgot`, `/ping` 등).
- 경로 표기: `add_org_resource`의 첫 URL을 `/api/...`로 쓰고 Flask 변환자 `<alert_id>`→`{alert_id}`, `<int:widget_id>`→`{widget_id}`. `add_org_resource`는 `org_scoped_rule(url)`(`redash/handlers/base.py:103-107`)을 거쳐 `REDASH_MULTI_ORG=true`일 때만 `/<org_slug>/api/...` 변형을 등록하고(기본값 false, `redash/settings/__init__.py:137`), 어느 경우든 핸들러의 `self.current_org`는 `redash/authentication/org_resolving.py:9-20`이 `request.view_args['org_slug']` 또는 기본 `"default"` slug로 해석한다. 사용자는 로그인 시 그 조직의 사용자 행(`User.get_by_id_and_org(user_id, org)`, `redash/authentication/__init__.py:55`)으로 로드되므로 요청자 조직은 세션에 고정되고 경로·본문에 대상 조직 ID가 들어가지 않는다. `<org_slug>` 접두 변형은 레코드로 넣지 않았다.
- controller_text 구성: `BaseResource` 헤더(`decorators = [login_required]`, `current_org` 프로퍼티; `base.py:21-39`) + 자원 클래스 헤더(`decorators = ...` 포함) + 대상 메서드(데코레이터 포함, 인가와 무관한 본문은 `...`) + 호출하는 `redash/permissions.py` 헬퍼 원문 + 의존 시 `get_object_or_404`(`base.py:70-77`), `BelongsToOrgMixin.get_by_id_and_org`(`models/mixins.py:20-28`), `_get_current_org`(`org_resolving.py:9-20`), 모델 classmethod(클래스 헤더 줄 + `...` + 메서드). 그룹 권한 해석 블록 `PermissionsCheckMixin.has_permission(s)`(`models/users.py:63-74`) + `User.permissions`(`models/users.py:172-175`, 그룹 권한 합집합)는 label과 무관하게 코드 메커니즘으로만 넣는다 — 아래 "User.permissions 블록 포함 규칙" 참조(G1-b 근거가 admin 레코드뿐 아니라 체인을 쓰는 모든 레코드에 동일하게 드러난다).
- 선정: membership_required·owner_or_admin·tenant_match 후보를 먼저 전부 모으고(require_admin_or_owner/is_admin_or_owner를 쓰는 메서드는 전부 수집, 단 DELETE mute 1건은 동형이라 제외), role_required·owner_match·public·manual은 동형 조건 대표 1~3건으로 줄였다. 한 label 최대 26건(35.1%, tenant_match; G1-b 적용 후)으로 50% 상한 안.

## 인증·인가 구조

- 인증: `BaseResource.decorators = [login_required]`(flask-login). `redash/authentication/__init__.py`: `request_loader`(:64-76)가 `AUTH_TYPE`(기본 `api_key`, settings:55)에 따라 `api_key_load_user_from_request`(:154-162) → `get_api_key_from_request`(:139-151; `?api_key=`, `Authorization: Key ...`, 또는 path `token` view_arg) → `get_user_from_api_key`(:109-136; 사용자 API 키 → `User`, 대시보드 공유 `ApiKey` → `ApiUser(groups=[])`, 쿼리 API 키 → `ApiUser(groups=query.groups)`)로 로드한다. 세션 사용자는 `load_user`(:45-61). 미인증 `/api/` 요청은 404 JSON(:217-225). `ApiUser.permissions = ["view_query"]`, `ApiUser.has_access(...) = False`(`models/users.py:413-419`).
- 권한 모델: 사용자 권한은 소속 그룹 `permissions` 배열의 합집합(`models/users.py:172-175`), `PermissionsCheckMixin.has_permission(s)`(:63-74). 기본 그룹 권한 `Group.DEFAULT_PERMISSIONS`(:247-260: create_dashboard, create_query, edit_dashboard, edit_query, view_query, view_source, execute_query, list_users, schedule_query, list_dashboards, list_alerts, list_data_sources), 관리자 권한 `admin`, `super_admin`(:261).
- 데코레이터 (`redash/permissions.py`): `require_permissions`(:57-75) → `require_permission`(:78-79), `require_any_of_permission`(:82-83), `require_admin = require_permission("admin")`(:86-87), `require_super_admin`(:90-91).
- 소유자 헬퍼: `has_permission_or_owner(permission, owner_id) = int(owner_id) == current_user.id or current_user.has_permission(permission)`(:94-95), `is_admin_or_owner`(:98-99), `require_permission_or_owner`(:102-104), `require_admin_or_owner`(:107-109, 403).
- 데이터소스 그룹 ACL: `has_access(obj, user, need_view_only)`(:17-21) — 쿼리 API 키 사용자면 `has_access_to_object`(:24-31, `obj.api_key == api_key` 또는 대시보드 공유 키), 아니면 `has_access_to_groups`(:34-49: `admin` 권한이면 True, 대상의 `groups`(data source group 매핑)와 `user.group_ids` 교집합 없으면 False, 교집합의 view_only 레벨로 결정). `require_access`(:52-54, 403).
- 객체 공유 ACL: `can_modify(obj, user) = is_admin_or_owner(obj.user_id) or user.has_access(obj, "modify")`(:112-113), `require_object_modify_permission`(:116-118). `User.has_access → AccessPermission.exists(obj, access_type, grantee)`(`models/users.py:232-233`, :346-348).
- 테넌트 필터: `BelongsToOrgMixin.get_by_id_and_org(id, org[, org_cls])`(`models/mixins.py:20-28`; Alert·Visualization·Widget은 Query/Dashboard를 join해 org 비교), `Model.all(org)` 류(`QuerySnippet.all`, `NotificationDestination.all`, `User.all`, `DataSource.all`).
- 본인 범위: `Query.by_user`(`models/__init__.py:572-574`), `Dashboard.by_user`(:1206-1208), `Query.favorites`/`Dashboard.favorites`(:546-555, :1188-1204; `Favorite.user_id == user.id`).
- 가시성 목록: `Dashboard.all(org, group_ids, user_id)`(:1144-1162: org 일치 AND (data source 그룹 ∈ 요청자 그룹 OR 소유자) AND (draft는 소유자만)), `Query.all_queries(group_ids, user_id, ...)`(:522-544), `Alert.all(group_ids)`(:1002-1009).

## 제외한 범위와 이유 (사유별 건수)

1. 동형 중복 — `@require_admin`/`@require_super_admin` 전용 (15건): DELETE `/api/data_sources/{id}`, POST·DELETE `/api/data_sources/{id}/pause`, GET `/api/destinations/types`, POST·DELETE `/api/destinations/{id}`, GET `/api/settings/organization`, POST `/api/users/{id}/invite`, DELETE `/api/users/{id}/disable`, DELETE `/api/groups/{id}`, GET `/api/groups/{id}/data_sources`, POST·DELETE `/api/groups/{id}/data_sources/{ds}`, GET `/api/admin/queries/rq_status`, GET `/status.json`(비 `/api`).
2. 동형 중복 — `require_access`/`has_access` 데이터소스 그룹 ACL (21건): POST `/api/alerts/{id}/eval`(require_admin_or_owner AND require_access, POST `/api/alerts/{id}`와 동형), POST·GET `/api/alerts/{id}/subscriptions`, POST `/api/alerts`, POST·DELETE `/api/queries/{id}/favorite`, POST `/api/dashboards/{id}/fork`, POST `/api/queries/{id}/fork`, POST `/api/queries/{id}/refresh`, GET `/api/data_sources/{id}/schema`, GET `/api/databricks/databases/{id}`·`/{db}/tables`·`/{db}/columns/{table}`, GET `/api/queries/{id}/dropdown`, GET `/api/queries/{id}/dropdowns/{dq}`, GET `/api/query_results/{id}`·`/api/query_results/{id}.{filetype}`·`/api/queries/{id}/results.{filetype}`·`/api/queries/{id}/results/{qr}.{filetype}`, POST `/api/queries/{id}/results`, OPTIONS `/api/queries/{id}/results`(CORS).
3. 동형 중복 — `require_object_modify_permission` (5건): DELETE `/api/dashboards/{id}`, POST·DELETE `/api/visualizations/{id}`, POST·DELETE `/api/widgets/{id}`.
4. 동형 중복 — `require_admin_or_owner` (1건): DELETE `/api/alerts/{id}/mute`(POST mute와 동형).
5. 동형 중복 — 가시성 필터(그룹 ACL OR 소유자) 목록 (4건): GET `/api/queries`, GET `/api/queries/archive`, GET `/api/queries/tags`, GET `/api/dashboards/tags`(GET `/api/dashboards`를 대표로 유지).
6. 동형 중복 — 인증만(객체 관계 검사 없음) (3건): DELETE `/api/jobs/{job_id}`, GET `/api/queries/{query_id}/jobs/{job_id}`, POST `/api/queries/format`(GET `/api/jobs/{job_id}`·POST `/api/events`를 대표로 유지).
7. 리다이렉트만 (1건): GET `/api/queries/search`(`/api/queries`로 301).
8. HTML 페이지·인증 절차·초기 설정 (10건, API 인가 대상 아님): GET `/logout`, GET/POST `/invite/{token}`, GET/POST `/reset/{token}`, GET `/verify/{token}`, POST `/verification_email/`, GET/POST `/setup`, GET `/embed/query/{query_id}/visualization/{visualization_id}`, GET `/public/dashboards/{token}`(HTML; API 변형 `/api/dashboards/public/{token}`은 유지), GET `/dashboard/{slug}`, 정적 index(`/`, `/<path>`).
9. `<org_slug>` 접두 변형: 모든 `add_org_resource` 경로의 `/<org_slug>/api/...` 변형(MULTI_ORG 전용, 조건 동일).

## draft_label 건수 (74)

| label | 건수 | 비율 |
|---|---:|---:|
| tenant_match | 26 | 35.1% |
| manual_review_required | 16 | 21.6% |
| owner_or_admin | 15 | 20.3% |
| owner_match | 8 | 10.8% |
| public | 4 | 5.4% |
| role_required | 3 | 4.1% |
| membership_required | 2 | 2.7% |

(G1-b 적용 전: role_required 21 · tenant_match 8. 레코드 수·(method, path) 집합은 적용 전후 동일 74건.)

- `EXCLUDE 후보` 3건(confidence 0.5): GET `/api/groups`(owner_or_admin), GET `/api/users/{user_id}`(owner_or_admin), POST `/api/query_snippets`(tenant_match).
- owner_or_admin (15): `require_admin_or_owner`/`is_admin_or_owner`가 결정 — DELETE `/api/alerts/{id}`, POST `/api/alerts/{id}/mute`, DELETE `/api/alerts/{id}/subscriptions/{sid}`, POST·DELETE `/api/dashboards/{id}/share`, POST·DELETE `/api/{type}/{id}/acl`, DELETE `/api/queries/{id}`, POST `/api/queries/{id}/regenerate_api_key`, POST·DELETE `/api/query_snippets/{id}`, POST `/api/users/{id}/regenerate_api_key`, POST `/api/users/{id}` + EXCLUDE 후보 2건.
- tenant_match (26):
  - `current_org` 필터만(권한 데코레이터 없음 또는 기능 권한) 8건: GET `/api/dashboards/{id}`(list_dashboards + get_by_id_and_org), GET `/api/destinations`, GET `/api/query_snippets`, GET `/api/query_snippets/{id}`, GET `/api/users`(list_users + User.all(org)), GET `/api/{type}/{id}/acl/{access_type}`(0.7), GET `/api/organization/status`(0.6) + EXCLUDE 후보 POST `/api/query_snippets`(0.5).
  - G1-b: `@require_admin` + `get_by_id_and_org(..., self.current_org)`/`current_org` 필터·강제 16건(0.75~0.8): POST `/api/data_sources/{id}`, POST `/api/data_sources`, POST `/api/data_sources/{id}/test`, GET `/api/destinations/{id}`, POST `/api/destinations`, GET `/api/events`, POST `/api/groups`, POST `/api/groups/{id}`, POST `/api/groups/{id}/members`, DELETE `/api/groups/{id}/members/{uid}`, POST `/api/groups/{id}/data_sources`, POST `/api/settings/organization`, POST `/api/users`, POST `/api/users/{id}/reset_password`, DELETE `/api/users/{id}`, POST `/api/users/{id}/disable`.
  - G1-b 일관 적용(기능 권한 + `current_org` 필터·강제) 2건: GET `/api/data_sources`(0.7, list_data_sources + DataSource.all(current_org)), POST `/api/dashboards`(0.65, create_dashboard + Dashboard(org=current_org, user=current_user)).
- membership_required (2): GET `/api/groups/{id}`, GET `/api/groups/{id}/members` — `admin OR int(group_id) in current_user.group_ids`(구성원 OR 관리자 우회, G2). Redash에 그룹 구성원 조회를 쓰는 엔드포인트는 이 둘뿐이다(한계).
- role_required (3): `@require_admin`이지만 대상 객체도 `current_org` 필터도 없는 GET `/api/data_sources/types`(0.9, 전역 query_runners 목록 — G1-b 비적용, G3), `@require_super_admin` 1건(GET `/api/admin/queries/outdated` 0.95, 조직 횡단 → G1-b대로 role_required), 기능 권한만 있고 `current_org` 필터가 없는 GET `/api/alerts`(0.65, `Alert.all(group_ids)`는 org 필터 없음 — G3 '객체 없는 기능에 RBAC 권한만').
- owner_match (8): GET `/api/dashboards/my`, GET `/api/queries/my`, GET `/api/queries/recent`, GET `/api/queries/favorites`, GET `/api/dashboards/favorites`, POST(0.6)·DELETE(0.7) `/api/dashboards/{id}/favorite`, GET `/api/session`.
- manual_review_required (16): `require_access`/`has_access` 그룹 ACL 6건(GET `/api/alerts/{id}`, GET `/api/data_sources/{id}`, GET `/api/queries/{id}`, POST `/api/queries`, GET `/api/queries/{id}/results`, POST `/api/query_results`), `require_object_modify_permission`(owner OR admin OR ACL 공유) 4건(POST `/api/dashboards/{id}`, GET `/api/{type}/{id}/acl`, POST `/api/queries/{id}`, POST `/api/visualizations`), 둘의 AND 1건(POST `/api/widgets`), owner_or_admin AND 그룹 ACL 1건(POST `/api/alerts/{id}` 0.6), 가시성 OR 목록 1건(GET `/api/dashboards` 0.6), 토큰 조건부 익명 1건(GET `/api/dashboards/public/{token}`), 인증만 2건(POST `/api/events`, GET `/api/jobs/{job_id}`).
- public (4): GET `/api/config`, GET `/ping`, POST `/login`, POST `/forgot`(0.75; 조직 설정 `auth_password_login_enabled` 꺼지면 404).

## 보충 규약 적용 (test_v6에서 tenant_match 포함)

- test_v5에는 tenant_match 정답이 0건이었으나 test_v6(Redash·seahub)에는 tenant_match가 들어간다. Redash에서는 `self.current_org`(세션·slug로 고정된 요청자 조직)로 `get_by_id_and_org`/`Model.all(org)` 필터만 하고 소유자·그룹 ACL 검사가 없는 핸들러를 **보충 규약 1**에 따라 tenant_match(G1)로 적었다. `@require_permission("list_dashboards"|"list_users"|"view_query")` 같은 기능 권한이 함께 있어도 G1대로 기능 권한으로 보고 판정을 바꾸지 않았다(draft_reason에 명시). `@require_admin`도 같은 메커니즘이므로 `get_by_id_and_org`/`current_org`가 함께 있으면 tenant_match(아래 G1-b). `@require_super_admin`은 조직 횡단 기능이라 role_required.
- `get_by_id_and_org` 뒤 추가 검사(소유자·그룹 ACL·object modify)가 있는 핸들러는 그 검사의 label로 분류했다. tenant_match는 `current_org`-only 8건(EXCLUDE 후보 1 포함) + G1-b 18건 = 26건(35.1%)으로 50% 상한(37건) 안이다.

### G1-b 적용(require_admin → tenant_match) — 정지 지점 2 결정(2026-11-03)

- 코드 근거(`v26.9.0`): `require_admin(fn) = require_permission("admin")(fn)`(`redash/permissions.py:86-87`); `require_permissions.__call__`는 `current_user.has_permission(s)`만 검사하고 실패 시 403(`permissions.py:57-75`); `User.permissions`는 요청자 소속 그룹 `permissions`의 합집합(`redash/models/users.py:172-175`, `Group.query.filter(Group.id.in_(self.group_ids))`); `Group`은 `org_id`/`org`로 조직에 귀속(`users.py:268-269`)되고 `ADMIN_PERMISSIONS = ["admin", "super_admin"]`(`users.py:261`). 따라서 `@require_admin`은 `@require_permission`과 동일한 조직 그룹 권한 메커니즘이며, G1("라우트 RBAC 권한이 함께 있어도 기능 권한으로 보고 tenant_match")에 따라 `get_by_id_and_org(..., self.current_org)`·`current_org` 목록 필터·`org=self.current_org` 생성 강제가 있는 핸들러는 tenant_match로 적었다. `@require_super_admin`(`permissions.py:90-91`, `redash/handlers/admin.py` 시스템 상태 등 조직 횡단)은 role_required로 유지.
- 적용 방식: 레코드 추가·삭제 없음((method, path) 74건 집합 동일). 바뀐 것은 `draft_label`·`draft_confidence`(0.65~0.8)·`evidence`(`permissions.py:86-87`, `users.py:173-175`, 핸들러의 org 필터 줄)·`draft_reason`(메커니즘 줄 + 핸들러 org 필터 줄 인용)·`auth_summary`(`@require_admin(조직 그룹 권한 'admin')` 표기)이고, `@require_admin` 레코드의 controller_text에 `User.permissions` 블록을 추가했다(최대 길이 2,680 → 2,929자, 3,000 이하). (2026-11-03: 이 블록은 아래 "User.permissions 블록 포함 규칙"대로 체인을 쓰는 모든 레코드에 통일 포함했다.)
- 재라벨 목록 (전 → 후), 18건:
  - `@require_admin` + `get_by_id_and_org(..., self.current_org)` (role_required 0.9 → tenant_match 0.8): POST `/api/data_sources/{id}`(data_sources.py:54), POST `/api/data_sources/{id}/test`(:226), GET `/api/destinations/{id}`(destinations.py:24), POST `/api/groups/{id}`(groups.py:35), POST `/api/groups/{id}/members`(:76-77), DELETE `/api/groups/{id}/members/{uid}`(:103, 사용자만 org 필터), POST `/api/groups/{id}/data_sources`(:127-128), POST `/api/users/{id}/reset_password`(users.py:171), DELETE `/api/users/{id}`(:278), POST `/api/users/{id}/disable`(:302).
  - `@require_admin` + 생성 시 `org=self.current_org` 강제 (role_required 0.9 → tenant_match 0.75): POST `/api/data_sources`(data_sources.py:145-147), POST `/api/destinations`(destinations.py:115-121), POST `/api/groups`(groups.py:13), POST `/api/users`(users.py:139-145).
  - `@require_admin` + `current_org` 목록 필터·고정 (role_required 0.9 → tenant_match 0.75): GET `/api/events`(events.py:69 `self.current_org.events`), POST `/api/settings/organization`(settings.py:39-40 `self.current_org.settings`).
  - 기능 권한만 + `current_org` 필터·강제, 같은 규칙 일관 적용: GET `/api/data_sources`(role_required 0.65 → tenant_match 0.7; `list_data_sources` + `DataSource.all(self.current_org)` data_sources.py:104-107, models/__init__.py:185), POST `/api/dashboards`(role_required 0.6 → tenant_match 0.65; `create_dashboard` + `Dashboard(org=self.current_org, user=self.current_user)` dashboards.py:98-104; G4 '본인 명의 생성' 대안 병기).
- role_required로 남긴 `@require_admin`/`@require_super_admin`: GET `/api/data_sources/types`(대상 객체·org 필터 없음, 전역 query_runners 목록 — G1-b 비적용), GET `/api/admin/queries/outdated`(super_admin, 조직 횡단). 기능 권한만 있는 GET `/api/alerts`는 `Alert.all(group_ids)`(models/__init__.py:1002-1009)에 org 필터가 없어 role_required 유지.
- 제외 목록 1번의 `@require_admin` 동형 15건(DELETE `/api/data_sources/{id}` 등)도 넣었다면 같은 규칙으로 tenant_match가 되지만 레코드로 추가하지 않았다.
### User.permissions 블록 포함 규칙 (2026-11-03 사용자 지시)

- **User.permissions 블록은 require_* 체인을 쓰는 레코드 55건 전부에 동일 포함(2026-11-03 사용자 지시).** 이전에는 `@require_admin` 레코드 18건에만 있어 label과 상관(tenant_match 16/20, owner_or_admin 0/13 등)이 생겼다.
- 규칙(`extract_redash.py` `CHAIN_RX`·`with_perm_resolution`): 레코드의 블록 원문에 `require_admin`·`require_super_admin`·`require_permission`·`require_any_of_permission`(`require_admin_or_owner`·`require_permission_or_owner` 포함, 50건) 또는 그 체인이 종단에서 호출하는 `has_permission(s)` 직접 호출(추가 5건: GET `/api/groups`·GET `/api/groups/{id}`의 `self.current_user.has_permission("admin")`, POST `/api/users/{id}/regenerate_api_key`의 `is_admin_or_owner`, GET `/api/{type}/{id}/acl`의 `can_modify → is_admin_or_owner`, GET `/api/data_sources/{id}`의 `has_permission("list_data_sources"|"admin")`)이 있으면 `PermissionsCheckMixin`(`users.py:63-74`) + `User.permissions`(`users.py:172-175`) 두 블록을 정확히 한 번, 마지막 `redash/permissions.py` 헬퍼 블록 바로 뒤(없으면 끝)에 넣는다. 없으면 넣지 않는다(public 4건·`current_org`/본인 필터만인 레코드 15건). 빌드가 label별 "체인 사용 = 블록 포함"을 assert한다: manual 12/12 · owner_or_admin 15/15 · tenant_match 20/20 · owner_match 3/3 · role_required 3/3 · membership 2/2 · public 0/0.
- 적용 결과: 레코드 추가·삭제 없음((method, path) 74건 동일), `draft_label`·`draft_confidence`·`evidence`·`draft_reason`·`auth_summary`·OAS 필드 변경 0. controller_text만 36건 변경(블록 추가 35 + GET `/api/groups/{id}` 순서만). 길이 3,000 유지를 위해 2건만 핸들러 본문의 비인가 줄을 추가 생략: GET `/api/users`(`handlers/users.py:99-125` page·그룹 이름 직렬화·q/disabled/pending 파싱 → `...`; 2,577 → 2,686), GET `/api/queries/{query_id}/results`(`handlers/query_results.py:298-324` docstring·초기화·이 경로에서 도달하지 않는 `query_result_id` 분기, `335-338` API 키 사용자의 query_hash 불일치 404 캐시 검사 → `...`; 2,585 → 2,862). 인가 줄(데코레이터, `get_by_id_and_org(..., self.current_org)`, `require_access`, `User.all(current_org)`)은 생략하지 않았다. 최대 길이 2,973(GET `/api/dashboards`), 최소 99(GET `/ping`).

- **보충 규약 2**: `require_object_modify_permission`(owner OR admin OR AccessPermission 공유) → manual(G6), `require_access`/`has_access`(데이터소스·그룹 ACL 합산) → manual(G6, 외부 ACL), `require_admin_or_owner`/`is_admin_or_owner` → owner_or_admin(G5). 모두 그대로 적용.
- G7: `/api/dashboards/public/{token}`은 경로 token이 API 키로 인증되는 조건부 익명 + `disable_public_urls` 설정 의존이라 public이 아니고 manual.

## 불확실한 엔드포인트 (검수 시 주의)

1. POST `/api/alerts/{alert_id}` (manual 0.6): `require_admin_or_owner(alert.user.id)` AND `require_access(query, view_only)`. alert 자체의 조건만 보면 owner_or_admin, 두 독립 조건의 AND로 보면 보류(프롬프트 보류 3). 제외한 POST `/api/alerts/{id}/eval`도 동일 구조.
2. GET `/api/dashboards` (manual 0.6): `list_dashboards` 권한 뒤 `Dashboard.all`이 org 일치 AND (그룹 ACL OR 소유자) AND (draft는 소유자만)으로 범위를 정한다. 거부 조건은 RBAC만이라 role_required, 조직 필터 기준 tenant_match, 가시성 OR 기준 manual이 모두 가능.
3. GET `/api/alerts` (role_required 0.65), GET `/api/data_sources` (tenant_match 0.7), POST `/api/dashboards` (tenant_match 0.65): 기능 권한(`list_alerts`·`list_data_sources`·`create_dashboard`, 기본 그룹에 모두 포함)이 유일한 거부 조건. GET `/api/alerts`는 `Alert.all(group_ids)`(org 필터 없음)라 G3 유지, 나머지 둘은 `current_org` 필터·강제가 있어 G1-b를 일관 적용했다. RBAC를 결정으로 보면 role_required, 그룹 범위 필터를 결정으로 보면 manual, POST `/api/dashboards`는 `user=self.current_user`도 고정돼 G4(owner_match) 해석도 가능.
3a. G1-b 16건(`@require_admin` + `current_org`, tenant_match 0.75~0.8): 사용자 결정으로 고정된 규칙이지만, 모델 입력만 보면 'admin 권한 필요'를 전역 역할로 읽어 role_required로 예측할 가능성이 크다(검수 시 label은 규칙대로 두고, 평가 보고서에서 이 경계를 한계로 기록).
4. GET `/api/users/{user_id}` (EXCLUDE 후보, owner_or_admin 0.5): `require_permission_or_owner("list_users", user_id)` — 본인 OR `list_users` 권한(관리자 역할이 아닌 기본 기능 권한). owner_or_admin·role_required 어느 쪽도 정확하지 않음.
5. GET `/api/groups` (EXCLUDE 후보, owner_or_admin 0.5): 거부 없이 admin이면 조직 전체, 아니면 본인 소속 그룹만 반환하는 범위 분기.
6. POST `/api/query_snippets` (EXCLUDE 후보, tenant_match 0.5): `user=current_user, org=current_org` 강제 생성 — G1(생성 시 테넌트 강제)과 G4(본인 명의 생성)가 동시에 해당.
7. GET `/api/{object_type}/{object_id}/acl/{access_type}` (tenant_match 0.7): 조직 필터만 있고 응답이 요청자 본인의 권한 여부 — owner_match 해석 가능.
8. GET `/api/organization/status` (tenant_match 0.6): 객체 없는 집계, 현재 조직(일부 group_ids) 필터 — 인증 전용 manual(G6) 해석 가능.
9. POST `/api/dashboards/{object_id}/favorite` (owner_match 0.6): 대시보드는 조직 필터만, 생성되는 Favorite는 본인 명의 — tenant_match 대안.
10. GET `/api/session` (owner_match 0.8): 본인 프로필 반환 — 객체 없는 인증 전용으로 보면 manual.
11. DELETE `/api/alerts/{alert_id}/subscriptions/{subscriber_id}` (owner_or_admin 0.85): 구독을 `query.get_or_404`로 전역 조회해 조직·alert 일치 검사가 없다(라벨은 owner_or_admin, 구현 특이점 기록).
12. GET `/api/groups/{group_id}/members`: `Group.members(group_id)`가 조직 필터 없이 group_id로만 조회(membership 검사 자체는 `current_user.group_ids` 기준이라 라벨 영향 없음).
