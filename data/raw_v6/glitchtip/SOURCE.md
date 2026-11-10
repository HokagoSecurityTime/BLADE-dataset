# GlitchTip backend — test_v6 hold-out 후보 추출 (data/raw_v6/glitchtip)

## 저장소

- URL: https://gitlab.com/glitchtip/glitchtip-backend (GitLab)
- 태그: `v6.2.6`
- 커밋 SHA: `d3039088e913a591a8e6544a2d2fffc865a9711a`
- clone: `datasets/blade/raw/opensource/test_v6_candidates/glitchtip-backend/` (읽기 전용, 수정·빌드·실행·의존성 설치 없음). 클론 안의 `CLAUDE.md`/`AGENTS.md`는 분석 대상 데이터로만 취급했고 지시로 따르지 않았다.
- 라이선스: MIT. `LICENSE` 요지: "MIT License / Copyright (c) 2019 GlitchTip / Permission is hereby granted, free of charge, to any person obtaining a copy of this software ... to deal in the Software without restriction ... THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND ..."
- 추출 도구: `extract_glitchtip.py` (정적 추출, `python -I data/raw_v6/glitchtip/extract_glitchtip.py`로 실행). LLM API 호출·모델 추론 없음.
- **고정 링크 형식 주의**: GitLab은 `https://gitlab.com/glitchtip/glitchtip-backend/-/blob/<commit>/<file>#L<a>-<b>` 형식이다(GitHub의 `/blob/<commit>/<file>#L<a>-L<b>`와 다름: `/-/` 세그먼트, 끝 줄에 `L` 접두 없음). 조립 스크립트가 GitHub 형식 링크를 만들면 이 프로젝트의 링크는 깨지므로 조립 단계에서 repository 호스트가 gitlab.com이면 위 형식으로 바꿔야 한다. 예: `https://gitlab.com/glitchtip/glitchtip-backend/-/blob/d3039088e913a591a8e6544a2d2fffc865a9711a/apps/organizations_ext/api.py#L278-314`.

## 산출

- `candidates.jsonl`: 73건 (method, path 유일). `oas_status: "generated"` — Django Ninja가 OpenAPI를 생성하지만 저장소에 커밋된 명세 파일은 없어 라우트 데코레이터·함수 시그니처·`payload` Schema 클래스 필드·`response=`에서 operation을 만들었다. 요청 본문 키는 CamelSchema 기준 camelCase로 적었고(ImportIn은 코드 접근 이름 그대로 snake_case), 응답 필드는 Schema 클래스에서 뽑았다(일부 스키마는 미확인이라 빈 목록).
- 모든 레코드에 `draft_label`, `draft_confidence`, `evidence`(원문 인용, `파일:줄`), `draft_reason`(한국어), `auth_summary`(한국어), `known_vulnerable: false`, `advisory: null`, `fix_commit: null`. 라벨은 전부 초안이며 사람이 확정한다.
- `permission_doc`: 핸들러 docstring에 권한 문구가 있는 3건(POST organizations/, set_owner, GET settings/{slug}/)만 채우고 나머지는 "". README/docs에 엔드포인트별 권한 규칙 문서는 없다.
- controller_text: 최소 533 · 중앙값 1,902 · 최대 2,890자. 500자 미만·3,000자 초과 없음.

## 경로 표기

- `glitchtip/urls.py`의 `path("api/", api.urls)` + `glitchtip/api/api.py`의 `api.add_router("0", ...)` → `/api/0/<라우터 경로>`. 인제스트 라우터는 `add_router("", ...)` → `/api/{project_id}/store/`; 임베드 라우터는 `add_router("embed", ...)` → `/api/embed/error-page/`; `api.get("settings/")`는 NinjaAPI에 직접 붙어 `/api/settings/`. 봉투 인제스트는 Ninja가 아닌 Django 뷰 `path("api/<int:project_id>/envelope/", event_envelope_view)` → `/api/{project_id}/envelope/`.
- `{slug:organization_slug}` → `{organization_slug}`, `{int:member_id}` → `{member_id}`, `{uuid:key_id}` → `{key_id}`, `{str:version}` → `{version}`. 라우트의 끝 슬래시는 그대로 둠. `@optional_slash`로 등록된 슬래시 없는 변형은 넣지 않았다.

## 추출 범위와 방법

- 대상: `apps/*/api.py`, `apps/issue_events/api/*.py`, `apps/organizations_ext/social_app_api.py`, `apps/event_ingest/embed_api.py`, `glitchtip/api/api.py`의 Ninja 라우트 175건 + Django 뷰 `event_envelope_view`. 이 중 73건 선정.
- 선정 기준: membership_required·owner_or_admin 후보를 먼저 모두 검토한 뒤, 같은 queryset 헬퍼를 쓰는 동형 엔드포인트는 앱별 대표 1~4건만 남기고(한 label 50% 상한), role_required·owner_match·public·manual을 섞었다. 사용자 결정 6: `@has_permission([...])`은 **API 토큰 scope 검사**(세션 인증에는 적용되지 않음)이므로 라벨 근거로 쓰지 않았고 draft_reason에도 그렇게 적었다.
- 발췌 방법: Python 들여쓰기 기준 블록 끝 찾기(`py_end`: `def` 줄 들여쓰기 이하인 다음 비공백 줄 직전까지, 위의 `@router...`/`@has_permission` 데코레이터 포함) + 명시 범위 블록(`block`). 인가와 무관한 본문(직렬화·스로틀·캐시·이메일 발송·docstring 일부)은 `...`로 줄였다. 공통 블록은 `NinjaAPI(auth=[TokenAuth(), SessionAuth()])` 선언(인가와 무관한 인자 생략), `TokenAuth.authenticate`, `has_permission` 본문(docstring 생략), 역할 상수 `OrganizationUserRole`, 각 queryset 헬퍼. 길이 제한 때문에 `SessionAuth.authenticate`는 api-tokens 라우터(세션 전용) 레코드에만 넣었고, 팀 구성원 추가/삭제 2건에서는 `get_team_queryset` 본문을, `POST social-apps/`에서는 `get_organizations_queryset` 본문을 생략했다(해당 조건은 호출 코드와 `get_organization_for_manager`에 드러남).

## 인증·인가 구조

- 인증: `glitchtip/api/api.py:48-54` `NinjaAPI(auth=[TokenAuth(), SessionAuth()])`. `TokenAuth`(Bearer API 토큰, `glitchtip/api/authentication.py:44-69`)는 `APIToken.objects.aget(token=key, user__is_active=True)`로 `Auth(token.user_id, "token", data=token)`를, `SessionAuth`(`:28-41`)는 Django 세션의 user_id로 `Auth(user_id, "session")`을 만든다. 핸들러는 `request.auth.user_id`만 쓴다. `apps/api_tokens/api.py:10` `Router(auth=SessionAuth())`는 세션 전용. `auth=None`은 익명 허용(settings/, settings/{slug}/, 0/, wizard/, heartbeat_check, GET accept/…).
- `has_permission(permissions)` (`glitchtip/api/permissions.py:8-28`): `request.auth.auth_type == "token"`일 때만 토큰 scope가 하나라도 맞는지 검사. **인가 결정이 아니라 토큰 scope 제한**이며 세션 사용자에게는 아무 효과가 없다. 근거로 사용하지 않음.
- 구성원 필터(membership): `apps/organizations_ext/queryset_utils.py` `get_organizations_queryset(user_id, role_required, add_details, organization_slug)` = `Organization.objects.filter(users=user_id, is_deleted=False)[.filter(slug=...)]`, `get_organization_users_queryset(user_id, organization_slug, team_slug)` = `OrganizationUser.objects.filter(organization__users=user_id, organization__slug=...)`, `get_organization_for_user` = `Organization.objects.filter(users=user_id, slug=...)`. 앱별 동형: `get_team_queryset(..., user_id)` → `organization__users=user_id` (`apps/teams/api.py:39-79`), `get_projects_queryset` / `get_project_keys_queryset` (`apps/projects/api.py:45-68`), `issue_events.services.get_queryset` → `aget_object_or_404(Organization, users=user_id, slug=...)` (`services.py:87-130`), `events.get_queryset` → `issue__project__organization__users=user_id`, `get_releases_queryset`, `get_project_alert_queryset`, `get_monitor_queryset`, `Environment.filter(organization__users=...)`, `Organization(slug=..., users=user_id)` 직접 조회(releases·uptime·files·difs·sourcecode·hashes). 팀 소속(`is_member`)은 annotate만 하고 접근 조건으로 쓰이지 않는다.
- 조직 안 역할(role): `OrganizationUserRole` MEMBER=0 < ADMIN=1 < MANAGER=2 < OWNER=3 (`constants.py:124-128`). 두 형태: (a) `role_required=True`로 `actor_role` 서브쿼리 annotate 후 `if organization.actor_role < OrganizationUserRole.MANAGER: raise HttpError(403)` (조직 수정·삭제, 멤버 초대·역할 변경, social apps); (b) 조회 조건에 `organization_users__role__gte=ADMIN|MANAGER` 추가(팀 생성·삭제, 프로젝트 생성·삭제, 키·알림 삭제, 프로젝트-팀 연결, import).
- 본인(self): `/api/0/users/{user_id}/...`는 `MeID = Literal["me"] | int`이며 `if user_id != request.auth.user_id and user_id != "me": raise Http404` 후 `user_id = request.auth.user_id`로 고정. 일부(GET users/{id}/, GET notifications/)는 검사 없이 바로 본인 id로 덮어쓴다. api-tokens는 `APIToken.objects.filter(user_id=request.auth.user_id)`.
- 본인 OR 역할: `delete_organization_member` `actor_role < MANAGER and not (org_user.user.id == user_id)` → 403 (`organizations_ext/api.py:298-302`).
- 설정 의존: `modify_member_for_team` `open_membership and is_self`면 역할 검사 생략, 아니면 팀원이면 ADMIN·비팀원이면 MANAGER (`teams/api.py:191-235`); `create_organization` `is_organization_creation_open() or user.is_superuser` (`utils.py:7-11`); `organization_can_customize_sso` BILLING_ENABLED이면 allow_sso 플랜 구독 필요 (`utils.py:14-33`).
- DSN 키 인증(사용자 아님): `apps/event_ingest/authentication.py` `event_auth` → `get_project`: `auth_from_request`로 `sentry_key`(쿼리/Bearer/X-Sentry-Auth)를 뽑아 `get_project_auth_info(project_id, sentry_key)` 저장 프로시저로 ProjectKey를 검증, 조직/프로젝트 스로틀로 거부. `embed_auth`(`embed_api.py:19-38`)는 쿼리 `dsn`의 public_key + project_id로 Project 조회.
- 초대 토큰: `validate_token` `InvitationTokenGenerator().check_token(org_user, token)` (`organizations_ext/api.py:394-404`).

## 제외한 범위와 이유 (Ninja 175건 중 103건 + Django 뷰)

| 사유 | 건수 | 내용 |
|---|---:|---|
| 동형 membership_required (같은 `organization__users=user_id` / `Organization(users=user_id, slug)` 필터만, 대표 유지) | 80 | issues.py 13 (GET/PUT/DELETE `/issues/{id}/`, `/issues/{id}/commits|tags/`, 조직 경로 commits·tags·DELETE issue, bulk PUT/DELETE `organizations/{slug}/issues/`, `projects/{org}/{proj}/issues/`, `issues-stats/`) · events.py 8 (bare `/issues/{id}/events/*`, latest, `{event_id}`, project events, `json/`) · comments.py 7 (bare 경로 4, 조직 경로 GET/PUT/DELETE) · hashes 2 · user_reports 2 · releases 19 (GET/PUT/DELETE `{version}`, files 6, project releases 6, deploys 2, commits 2, assemble) · environments 2 (project environments GET/PUT) · alerts 2 (GET 목록, POST test) · uptime 5 (GET/PUT/DELETE monitor, checks, POST status-pages) · projects 4 (GET team projects, GET keys, GET/PUT key) · sourcecode 3 (repos GET/POST, artifactbundle assemble) · difs 1 (difs/assemble) · performance 5 · logs 3 · stripe 4 (GET subscriptions/{slug}/, events_count period·daily, GET overage — 구독 정보라 보류 규칙 1과도 겹침) |
| 동형 owner_match (`user_id`를 본인으로 고정) | 8 | GET `/users/` (본인만 반환), PUT/DELETE `/users/{id}/emails/`, POST `emails/confirm/`, PUT `/users/{id}/notifications/`, GET `/users/{id}/notifications/alerts/`, GET/POST `/generate-recovery-codes/` |
| 인증만, 객체 없음 (manual 동형, G6) | 5 | GET `0/instance-license/`, GET `0/instance-license/support-link/`, GET `organizations/{slug}/chunk-upload/`(설정 반환, 구성원 검사 없음), POST `projects/{org}/{proj}/reprocessing/`(더미, 검사 없음), GET `stripe/products/` |
| DSN 키 인증 동형 (manual) | 2 (+1) | POST `/api/{project_id}/security/`, GET `/api/embed/error-page/` (+ Django 뷰 `/api/{project_id}/minidump/`, Ninja 아님) |
| 해시 소지 조건부 익명 (G7 조건부 → public 아님, 경계) | 2 | GET/DELETE `wizard/{wizard_hash}/` — 데코레이터가 아닌 함수 인자 `auth=None`이라 실제로는 `TokenAuth.__call__`의 url_name 특례로 익명 통과(`authentication.py:50-58`); 해시 소지가 유일 조건이고 코드 의도가 불분명해 제외 |
| 미검토 | 6 | stripe POST `create-stripe-subscription-checkout/`, `create-billing-portal/`, `subscriptions/`, `overage/`(결제·구독 — 보류 규칙 1 대상이라 우선순위 낮음), difs GET/POST `files/dsyms/`(파일 하반부 미열람) |
| 스키마 비노출 | 1 | `api_fallback_404` (`/{path:path}`, include_in_schema=False, JSON 404 반환) |

- Django 뷰 중 `api/0/internal/health/`는 열람하지 않아 넣지 않았다.
- 규약상 EXCLUDE로 **빼지 않고** `EXCLUDE 후보:`로 표시한 2건은 아래 '불확실한 엔드포인트' 참조(검수자가 G8 판단).

## draft_label 건수 (73)

| label | 건수 | 비율 |
|---|---:|---:|
| membership_required | 27 | 37.0% |
| role_required | 17 | 23.3% |
| owner_match | 12 | 16.4% |
| manual_review_required | 11 | 15.1% |
| public | 5 | 6.8% |
| owner_or_admin | 1 | 1.4% |
| tenant_match | 0 | 0% |

- membership_required (27): GET `organizations/{slug}/`, GET `members/`, GET `teams/{org}/{team}/members/`, GET `members/{member_id}/`, GET/PUT `teams/{org}/{team}/`, GET `organizations/{slug}/teams/`, GET `projects/{org}/{proj}/teams/`, GET/PUT `projects/{org}/{proj}/`, GET `organizations/{slug}/projects/`, POST `projects/{org}/{proj}/keys/`, GET `organizations/{slug}/issues/`, PUT `issues/{id}/`(조직 경로), GET `issues/{id}/events/`, POST `issues/{id}/comments/`, GET/POST `releases/`, GET `environments/`, PUT `alerts/{alert_id}/`, GET/POST `monitors/`, GET `status-pages/`(EXCLUDE 후보), GET `stats_v2/`, POST `chunk-upload/`, GET `transaction-groups/`, GET `logs/`. 전부 조직 slug 경로 + `organization__users=user_id`(또는 `Organization(users=user_id, slug)`) 필터, 역할 조건 없음.
- role_required (17): PUT/DELETE `organizations/{slug}/`, POST `members/`, PUT `members/{id}/`, POST `members/{id}/set_owner/`(0.7), DELETE `teams/{org}/{team}/`, POST `organizations/{slug}/teams/`, POST/DELETE `projects/{org}/{proj}/teams/{team}/`, DELETE `projects/{org}/{proj}/`, POST `teams/{org}/{team}/projects/`, DELETE `keys/{key_id}/`, DELETE `alerts/{alert_id}/`, GET/PUT/DELETE `social-apps/`, POST `import/`. 구성원 확인 뒤 조직 안 역할(ADMIN/MANAGER/OWNER)이 결정 조건(G3).
- owner_or_admin (1): DELETE `organizations/{slug}/members/{member_id}/` — 본인 행 OR MANAGER 이상(G5). 다른 self-OR-role 우회는 코드에 없었다(팀 구성원 추가/삭제의 본인 우회는 open_membership 설정 조건부라 manual).
- owner_match (12): GET `organizations/`(본인 소속 목록, 0.75), GET `projects/`(0.75), GET/PUT/DELETE `users/{user_id}/`, GET/POST `users/{user_id}/emails/`, GET `users/{user_id}/notifications/`, PUT `users/{user_id}/notifications/alerts/`, GET/POST/DELETE `api-tokens/`.
- manual_review_required (11): POST `organizations/`(설정 OR superuser), GET/POST `accept/{org_user_id}/{token}/`(초대 토큰), POST/DELETE `members/{id}/teams/{team}/`(open_membership 분기), POST `projects/{org}/{proj}/alerts/`(조직 ADMIN OR 팀 구성원), POST `social-apps/`(MANAGER AND 플랜), POST `/api/{project_id}/store/`, POST `/api/{project_id}/envelope/`, POST `/api/embed/error-page/`(DSN 키), POST `wizard-set-token/`(EXCLUDE 후보).
- public (5): GET `/api/settings/`, GET `/api/settings/{organization_slug}/`, GET `/api/0/`, GET `/api/0/wizard/`, POST `heartbeat_check/{endpoint_id}/`(0.75).
- **tenant_match 0건**: GlitchTip은 요청자의 '현재 조직' 세션 상태가 없고 모든 조직 자원이 경로 slug + 구성원 조회로 접근되므로 G1에 해당하는 엔드포인트가 없다. test_v6의 tenant_match는 seahub·Redash에서 나온다.

## 불확실한 엔드포인트 (검수 시 주의)

1. GET `organizations/{slug}/status-pages/` (membership_required 0.5, **EXCLUDE 후보**): 경로에 organization_slug가 있지만 핸들러는 `StatusPage.objects.filter(organization__users=request.auth.user_id)`만 적용하고 slug로 필터하지 않아(`uptime/api.py:369-371`) 요청자가 속한 모든 조직의 상태 페이지가 반환된다. 경로 의도(대상 조직 구성원)와 구현이 불일치(G8).
2. POST `wizard-set-token/` (manual 0.5, **EXCLUDE 후보**): 인증 + 캐시에 존재하는 임의 hash 소지만 조건이고 저장 데이터는 본인 프로젝트·본인 토큰. 대안 owner_match.
3. POST `members/{member_id}/set_owner/` (role_required 0.7): `old_owner.user_id == user_id`(현 대표 소유자) OR 조직 역할 OWNER. 둘 다 OWNER 지위로 보아 role_required로 두었지만 대표 소유자 신분 OR 역할의 결합으로 보면 manual. docstring의 "org:admin scope" 문구는 토큰 scope 설명으로 코드에 우회가 없다.
4. PUT `teams/{org}/{team}/`, PUT `projects/{org}/{proj}/`, POST `projects/{org}/{proj}/keys/`, PUT `alerts/{alert_id}/` (membership_required 0.7): 구성원 필터만으로 쓰기를 허용하는데 같은 자원의 DELETE(및 alerts POST)는 ADMIN 이상을 요구한다. 코드대로면 membership_required이나 역할 의도가 누락된 것일 수 있다(의도·구현 충돌 여부는 검수자 판단; 명시 정책 문서는 없음).
5. GET `organizations/`, GET `projects/` (owner_match 0.75): 대상 그룹 지정 없이 `users=user_id` / `organization__users=user_id`로 본인 소속 목록을 돌려준다. G4 '본인 목록'으로 owner_match를 택했으나 구성원 필터라는 점에서 membership_required 판단도 가능(Umami GET /api/teams 선례는 owner_match).
6. POST `heartbeat_check/{endpoint_id}/` (public 0.75): auth=None이지만 UUID endpoint_id가 비밀 URL 역할. Umami GET /api/share/{slug} 선례대로 public으로 두었고 조건부 익명(manual) 해석 가능.
7. GET `accept/{org_user_id}/{token}/` (manual 0.6): auth=None + 초대 토큰 검증. G7 조건부 익명 → manual로 두었으나 토큰을 URL 비밀로 보면 public.
8. POST `social-apps/` (manual 0.6): MANAGER 역할 AND `organization_can_customize_sso`(BILLING_ENABLED이면 allow_sso 플랜 구독). 셀프호스트 배포만 보면 role_required.
9. POST `organizations/` (manual 0.7): `is_organization_creation_open() or is_superuser`. 설정이 닫힌 배포만 보면 role_required(전역 superuser). EXCLUDE 대신 G6(설정에 따라 허용 주체 변경)로 manual.
10. GET `users/{user_id}/`, GET `users/{user_id}/notifications/` (owner_match 0.8): 경로 user_id를 검사하지 않고 본인 id로 덮어써 타인 id를 넣어도 본인 정보가 반환된다. 처리 대상이 본인으로 고정되므로 owner_match로 두었다.
11. GET `/api/0/` (public 0.8): 익명 허용이지만 세션/토큰이 있으면 본인 user·auth를 추가 반환.
