# Umami — test_v5 hold-out 후보 추출 (data/raw_v5/umami)

## 저장소

- URL: https://github.com/umami-software/umami
- 태그: `v3.4.1` (GitHub releases/latest, 2026-10-31 조회)
- 커밋 SHA: `559e3c607c23d2c72d9bd4f6481bda428255323c`
- clone: `datasets/blade/raw/opensource/umami-software_umami/` (`git clone --depth 1 --branch v3.4.1`), 읽기 전용. 수정·빌드·실행·의존성 설치 없음.
- 라이선스: MIT. `LICENSE` 파일 요지: "MIT License / Copyright (c) 2022 Umami Software, Inc. <hello@umami.is> / Permission is hereby granted, free of charge, to any person obtaining a copy of this software ... to deal in the Software without restriction ... subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies ... THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND ..."
- 추출 도구: `extract_umami.py` (정적 추출, `python -I`로 실행). LLM API 호출 없음.

## 산출

- `candidates.jsonl`: 60건 (method, path 유일). `oas_status: "generated"` (저장소에 OpenAPI 명세 없음; `src/lib/schema.ts`·각 route의 zod 스키마에서 파라미터·본문 키를 생성).
- 모든 레코드에 `draft_label`, `draft_confidence`, `evidence`(코드 원문 인용, 파일:줄), `draft_reason`(한국어), `known_vulnerable: false`, `advisory: null`, `fix_commit: null`을 넣었다. 라벨은 전부 초안이며 사람이 확정한다.
- `permission_doc`은 전부 "" (저장소 README/docs에 엔드포인트별 권한 규칙 문구 없음).

## 추출 범위

- Next.js App Router `src/app/api/**/route.ts` (pages API 없음). 총 136개 route 파일 중 60개 (method, path)를 선정.
- 선정 기준: 인가 함수(`src/permissions/*.ts`의 `can*`)별로 대표 엔드포인트를 모두 포함하고, membership_required·owner_or_admin·role_required 후보를 우선 수집. 같은 `canViewWebsiteSection` 조건을 쓰는 웹사이트 통계 하위 라우트(stats, pageviews, metrics, events, sessions, breakdown, funnels, goals, journeys, retention, utm, revenue, attribution, performance, event-data*, session-data* 등 약 60개)는 조건이 동일하므로 stats·sessions·active·realtime만 대표로 넣었다.

## 인증·인가 구조

- 모든 보호 라우트는 `parseRequest(request, schema?, { skipAuth? })` (`src/lib/request.ts:16-60`) → `checkAuth(request)` (`src/lib/auth.ts:71-147`)로 인증한다. checkAuth는 Bearer 세션 JWT(또는 API 키 `checkApiKeyAuth`) 또는 공유 토큰 헤더(`x-umami-share-token`, `parseShareToken`)를 받는다. 사용자 토큰·공유 토큰 둘 다 없으면 401. 공유 토큰만 있으면 `x-umami-share-context` 헤더가 있어야 하고 `auth.user`는 null, `authType: 'share'`. `user.isAdmin = user.role === 'admin'`.
- 라우트 핸들러는 `if (!(await canXxx(auth, ...))) return unauthorized();` 패턴으로 인가한다. `/api/me/*`, `/api/teams`(GET), `/api/websites`(GET), `/api/dashboard`, `/api/boards`(GET) 등은 can* 없이 쿼리를 `auth.user.id`로 고정한다.
- 역할 상수 (`src/lib/constants.ts:174-234`): 전역 role `admin`/`user`/`view-only`, 팀 role `team-owner`/`team-manager`/`team-member`/`team-view-only`. `ROLE_PERMISSIONS`: admin=all; user=website:create/update/delete, team:create; view-only=없음; team-owner=team:update, team:delete, website:create/update/delete, website:transfer-to-team/-to-user; team-manager=team:update, website:create/update/delete, website:transfer-to-team; team-member=website:create/update/delete; team-view-only=없음. `hasPermission(role, perm)` (`src/lib/auth.ts:163-165`).
- 구성원 조회: `getTeamUser(teamId, userId)` = `prisma.teamUser.findFirst({ where: { teamId, userId, team: { deletedAt: null } } })` (`src/queries/prisma/teamUser.ts:19-27`).
- `src/permissions/user.ts`: `canCreateUser`/`canViewUsers`/`canDeleteUser`/`canEnforceTwoFactorAuthForEveryone`/`canEnforceTwoFactorAuthForUser` = `user.isAdmin`; `canViewUser`/`canUpdateUser` = `isAdmin || user.id === viewedUserId`.
- `src/permissions/team.ts`: `canViewTeam` = `isAdmin || getTeamUser(teamId, user.id)`; `canCreateTeam` = `isAdmin || hasPermission(user.role, team:create)`; `canUpdateTeam` = `isAdmin || (teamUser && hasPermission(teamUser.role, team:update))`; `canDeleteTeam` = `... team:delete`; `canDeleteTeamUser` = `isAdmin || removeUserId === user.id || (teamUser && team:update)`; `canCreateTeamWebsite` = `isAdmin || (teamUser && website:create)`; `canViewAllTeams` = isAdmin; `canEnforceTwoFactorAuthForTeam` = isAdmin (teamId 미사용).
- `src/permissions/website.ts`: `canViewWebsite` = `isAdmin || shareToken이 websiteId/pixelId/linkId(또는 *Ids)에 포함 || (entity.userId ? user.id === entity.userId : entity.teamId ? getTeamUser 존재 : false)`; `canUpdateWebsite`/`canDeleteWebsite` = `isAdmin || (website.userId ? owner : teamUser && website:update|delete)`; `canTransferWebsiteToUser` = `isAdmin || (website.teamId && user.id === userId && teamUser(website.teamId).role has website:transfer-to-user)`; `canTransferWebsiteToTeam` = `isAdmin || (website.userId === user.id && teamUser(teamId).role has website:transfer-to-team)`; `canCreateWebsite` = `isAdmin || hasPermission(user.role, website:create)`; `canViewAllWebsites` = isAdmin; `canViewBatchWebsites` = id별 share/owner/team 필터.
- `src/permissions/share.ts`: `canViewWebsiteSection(auth, id, section)` = `auth.user ? canViewWebsite : (shareToken이 id 포함 && (섹션 파라미터 없음 || 섹션 true))`; `canViewSharedWebsite` = `auth.user ? canViewWebsite : shareToken 포함`; `canViewSharedWebsiteFilters` = `... && allowFilter !== false`; `canViewAuthenticatedWebsite` = `auth.user && canViewWebsite`.
- `src/permissions/entity.ts` (`canViewEntity`/`canUpdateEntity`/`canDeleteEntity`): website/link/pixel/board 공통, `isAdmin || owner || (teamId ? teamUser[&& website:update|delete])`.
- `src/permissions/report.ts`: `canViewReport` = `isAdmin || user.id === report.userId || canViewWebsiteSection(report.websiteId, 섹션)`; `canUpdateReport`/`canDeleteReport` = `isAdmin || 작성자 || canUpdateWebsite|canDeleteWebsite`.
- `src/permissions/board.ts`/`link.ts`/`pixel.ts`: `canViewBoard|Link|Pixel` = `isAdmin || shareToken 일치 || owner || team member`; update/delete는 팀 role website:update|delete.
- 인증 생략(`skipAuth: true` 또는 parseRequest 미호출): `/api/auth/login`, `/api/send`, `/api/batch`, `/api/heartbeat`, `/api/config`, `/api/share/{slug}`, `/api/websites/{websiteId}/recorder`, `/api/scripts/telemetry`, `/api/record`(미수집), `/api/2fa/verify`(partial token, 미수집).

## 제외한 범위와 이유

- `canViewWebsiteSection`/`canViewSharedWebsiteFilters` 공통 조건의 나머지 웹사이트 하위 라우트(~60개): 조건이 동일해 중복이므로 대표 4건만 수집 (`websites/{id}/stats`, `sessions`, `active`, `realtime/{id}`). 제외: pageviews, metrics(+expanded), events/*, sessions/* 하위, breakdown, funnels/*, goals(목록·stats), journeys, retention, utm, revenue/*, attribution, performance/*, heatmaps, daterange, values, event-data/*, event-data-pivot/*, session-data/*, session-data-pivot, segments/*, annotations/*, replays/*, export 외 유사 라우트.
- `links/{linkId}`·`pixels/{pixelId}`·`boards/{boardId}` update/delete, `links/charts`·`pixels/charts`·`websites/charts`, `boards/{id}/clone`·`shares`, `teams/{teamId}/boards`: canViewWebsite/canUpdateEntity 계열과 조건 동형이라 대표만 유지 (`boards/{boardId}` GET, `share/id/{shareId}` GET/DELETE).
- `/api/2fa/*` 본인 2FA 설정(status, setup/*, disable): `auth.user.id` 고정 owner_match 동형이라 생략. `/api/2fa/verify`: 로그인 2단계(partial token)로 인증 절차이지 인가가 아니어서 제외.
- `/api/admin/users/{userId}/2fa`, `/api/admin/teams/{teamId}/2fa`: isAdmin 전용이 `/api/admin/*` 목록·`/api/admin/2fa/global`과 동형이라 생략.
- `/api/me/api-keys` POST, `/api/auth/sso`, `/api/config`, `/api/scripts/telemetry`, `/api/record`, `/api/websites/charts`, `/api/share` POST, `/api/websites/{id}/sessions/{sessionId}` DELETE, `/api/websites/{id}/goals/{goalId}` DELETE: 동형 조건 중복으로 60건 한도에 맞춰 제외.
- MCP 서버(`src/lib/mcp`)·페이지 라우트(`src/app/(app)`)는 HTTP API 엔드포인트가 아니므로 제외.

## draft_label 건수 (60)

| label | 건수 |
|---|---:|
| manual_review_required | 20 |
| role_required | 13 |
| owner_match | 12 |
| public | 6 |
| membership_required | 5 |
| owner_or_admin | 4 |
| tenant_match | 0 |

- membership_required (5, 전부 `canViewTeam`): GET `/api/teams/{teamId}`, GET `/api/teams/{teamId}/users`, GET `/api/teams/{teamId}/websites`, GET `/api/teams/{teamId}/links`, GET `/api/teams/{teamId}/pixels` — `isAdmin || getTeamUser(teamId, user.id)` (구성원 OR 관리자 우회).
- owner_or_admin (4): GET/POST `/api/users/{userId}` (`canViewUser`/`canUpdateUser`: `isAdmin || user.id === viewedUserId`), GET `/api/users/{userId}/teams`·`/api/users/{userId}/websites` (핸들러 인라인 `auth.user.id === userId || auth.user.isAdmin`).
- role_required (13): isAdmin 전용 7건(POST `/api/users`, DELETE `/api/users/{userId}`, GET `/api/admin/users|teams|websites`, POST `/api/admin/2fa/global`) + 팀 안 역할 5건(POST/DELETE `/api/teams/{teamId}`, POST `/api/teams/{teamId}/users`, GET/POST `/api/teams/{teamId}/users/{userId}`: `canUpdateTeam`/`canDeleteTeam` = 구성원 확인 뒤 team-owner/team-manager 권한, G3) + 전역 역할 권한 1건(POST `/api/teams`: `hasPermission(user.role, team:create)`).
- public (6): POST `/api/auth/login`, POST `/api/send`, POST `/api/batch`, GET `/api/heartbeat`, GET `/api/share/{slug}`, GET `/api/websites/{websiteId}/recorder`.
- owner_match (12): `/api/me*` 5건, GET `/api/teams`, GET `/api/websites`, GET/POST `/api/dashboard`, POST `/api/auth/logout`, POST `/api/auth/verify` — 모두 `auth.user.id`로 대상 고정, 관리자 우회 없음.
- manual_review_required (20): `canViewWebsite` 계열(admin OR 공유 토큰 OR 소유자 OR 팀 구성원) 8건, `canUpdateWebsite`/`canDeleteWebsite`/`canUpdateEntity`/`canDeleteEntity`(admin OR 소유자 OR 팀 역할, 자원 소유 형태별 분기) 6건, `canViewReport`/`canUpdateReport`(작성자 OR 웹사이트 접근) 2건, transfer(본인 AND 팀 역할 결합) 1건, DELETE 팀 구성원(본인 탈퇴 OR 팀 역할 OR admin) 1건, `/api/teams/join`(accessCode만) 1건, `/api/auth/subscription`(teamId 유무로 조건 변경) 1건.

## 불확실한 엔드포인트 (검수 시 주의)

- POST `/api/websites` (role_required 0.6): `canCreateWebsite`(전역 role 권한) AND teamId 시 `canCreateTeamWebsite`(팀 role 권한). 둘 다 역할 조건이지만 전역+팀 AND 결합이라 manual도 가능.
- DELETE `/api/teams/{teamId}/users/{userId}` (manual 0.6): `canDeleteTeamUser` = admin OR 본인 탈퇴 OR team-owner/manager, 추가로 비관리자는 소유자 제거 불가·순위 검사. 타인 제거 기준으로 보면 role_required.
- POST/DELETE `/api/teams/{teamId}` 등 `canUpdateTeam` 계열 (role_required 0.85): 구성원 행 조회 뒤 role 권한이 결정 조건. G3에 따라 role_required로 두었으나 membership_required 판단 가능.
- POST `/api/auth/logout` (owner_match 0.6), POST `/api/auth/verify` (0.75): 객체 없는 인증 전용으로 보면 manual(G6). 본인 세션·본인 정보로 고정된다는 점에서 owner_match로 초안.
- GET `/api/auth/subscription` (manual 0.6): teamId 쿼리가 있으면 `canViewTeam`(membership), 없으면 본인 계정(owner_match).
- POST `/api/teams/join` (manual 0.7): 인증 + 비밀 accessCode. 6종에 대응 없음.
- `canUpdateWebsite`/`canDeleteWebsite`/`canUpdateEntity`/`canDeleteEntity` 계열 (manual 0.7): 개인 소유 자원이면 정확히 owner OR admin(owner_or_admin)이고, 팀 소유면 팀 역할. 자원 소유 형태로 분기하므로 보류했으나 검수자가 owner_or_admin으로 볼 수 있다.
- `canViewWebsite` 계열은 공유 토큰(익명) 허용이 조건부라 G7에 따라 public이 아니고, 소유자 OR 팀 구성원 OR 관리자 OR 공유 토큰의 OR 결합이라 manual(G6).
- GET `/api/heartbeat` controller_text는 파일 전체가 3줄(69자)이라 500자 미만이다.
- controller_text의 `parseRequest`·`checkAuth` 발췌는 인가와 무관한 zod 파싱·redis 세션·로그 부분을 `...`로 줄였다(source_locations는 함수 전체 범위). 웹사이트 섹션 라우트에서는 `shareTokenIncludesWebsite` 헬퍼를 길이 제한 때문에 생략했으나 동일 조건이 `canViewWebsite` 13-20행에 원문 그대로 포함돼 있다.
