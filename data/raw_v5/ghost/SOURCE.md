# Ghost (Admin API) — test_v5 hold-out 후보 추출 출처

- 저장소: https://github.com/TryGhost/Ghost
- 태그: `v6.73.0` (GitHub releases/latest, 2026-10-31 기준)
- 커밋 SHA: `5794cfd8daca61fd60cd8659acd6591ece3b7956`
- 라이선스: MIT (LICENSE 파일 요지: "Copyright (c) 2013-2026 Ghost Foundation … Permission is hereby granted, free of charge, to any person obtaining a copy of this software … to deal in the Software without restriction … subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies … THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND")
- clone: `datasets/blade/raw/opensource/TryGhost_Ghost/` (`--depth 1 --filter=blob:none --sparse`, sparse 경로: `ghost/core/server/{api,services/permissions,services/posts,models,data/schema/fixtures,web/api,web/shared,auth}`). v6 트리는 `ghost/core/server/`(구 `ghost/core/core/server/`)이며 `ghost/admin-api-schema` 패키지는 이 태그에 없다. 저장소 코드는 읽기만 했고 수정·빌드·실행·설치 없음. LLM API 호출 없음.
- 산출: `candidates.jsonl` 73건(1건 = Admin API operation 1개), 생성 스크립트 `extract_ghost.py`(줄 범위 기반 원문 인용, `python -I extract_ghost.py <clone_root> <out_dir>`).

## 추출 범위

- Admin API(`/ghost/api/admin/…`)만. 라우트 정의: `ghost/core/server/web/api/endpoints/admin/routes.js`, 컨트롤러: `ghost/core/server/api/endpoints/<name>.js|ts`.
- 경로는 Express `:id` → OAS `{id}`, 마운트 prefix `/ghost/api/admin` + 끝 슬래시(Ghost 정식 URL 형식).
- `oas_status: "generated"`: 저장소에 OAS 명세가 없어 라우트·컨트롤러에서 최소 operation을 만들었다(summary, path parameters, requestBody 최상위 키 = docName, security). securitySchemes: `adminApiKey`(Authorization: Ghost <JWT>, 통합 키·스태프 토큰), `sessionCookie`, `adminApiKeyUrl`(스케줄러용 URL 키). 인증 없는 라우트는 `security: []`.

## 인가 구조 (controller_text에 인용한 체인)

1. **라우트 미들웨어** (`web/api/endpoints/admin/middleware.js`)
   - `authAdminApi` = `auth.authenticate.authenticateAdminApi`(Admin API 키 JWT 또는 세션) → `auth.authorize.authorizeAdminApi`(req.user 또는 req.api_key 필수) → … → `tokenPermissionCheck`.
   - `tokenPermissionCheck`: 스태프 토큰(api_key.user_id 있음)은 `DELETE /db`, `PUT /users/owner`, `POST /authentication/reset` 차단; 통합 토큰은 리소스별 허용목록(`allowlisted`) 밖이면 403.
   - `authAdminApiWithUrl`: URL의 Admin API 키만(스케줄러·gifts). `publicAdminApi`: 인증 없음(`GET /site`).
   - 세션 로그인·2FA·비밀번호 재설정·초대 수락·최초 설정 라우트는 인증 미들웨어 없이 brute 제한만 붙는다.
2. **api-framework `permissions` 옵션** (`api/endpoints/utils/permissions.js`): 컨트롤러 메서드의 `permissions: true | {docName?, method?, identifier?, unsafeAttrs?, unsafeAttrsObject?, before?} | false | function(frame)`.
   - `false`: 권한 단계 생략(인증만). `function`: 컨트롤러가 직접 검사(예: `permissionOnlySelf`, Owner 확인, `canThis(...).assign.role`).
   - 그 외: `permissions.handle` → `parseContext`(user·api_key 없으면 `public: true` → pass-through, Content API 키도 public) → `nonePublicAuth` → `permissions.canThis(context)[method][singular(docName)](identifier, unsafeAttrs)`.
3. **permissions 서비스 `canThis`** (`services/permissions/can-this.js`): `providers.user`가 사용자 역할 → `rolePermissions.forRoles`로 권한 목록 로드. `getGrantFlags`: Owner 역할은 무조건 통과(`isOwner → hasUserPermission = true`), 아니면 `(action_type, object_type)` 일치 권한 보유 여부. API 키만 있으면 키 역할의 권한으로 검사, 스태프 토큰(user 있음)은 사용자 역할 우선. `objectTypeModelMap`(post, role, user, setting, invite, integration, comment)에 모델 `permissible`이 있으면 그 함수가 최종 결정.
4. **역할→권한 데이터** (`services/permissions/permissions-data.ts`, v6에서 fixtures.json의 Role→Permission 관계를 코드로 이동): `permissions`(object_type별 action 목록)와 `rolePermissions`(역할별 object_type → 'all' | action 목록). 역할: Administrator, Super Editor, Editor, Author, Contributor, Admin Integration, DB Backup Integration, Scheduler Integration, Self-Serve Migration Integration (+ Owner: 권한 없이 canThis 우회). `data/schema/fixtures/fixtures.json`의 Role entries에는 이름·설명만 남아 있다(`permission_doc`에 인용).
5. **모델 `permissible`** (객체 단위 조건)
   - `models/relations/authors.js` → `Post`(pages 포함): Contributor edit = `!isChangingAuthors() && isCoAuthor()`; Contributor/Author add = `isOwner()`(요청 authors[0].id === context.user); Contributor/Author destroy = `isPrimaryAuthor()`; Author edit = `isCoAuthor() && !isChangingAuthors()`; 그 외(Editor/Super Editor/Administrator/Owner/통합) = 역할 권한 `|| isPrimaryAuthor()`. 이어서 `models/post.js` `permissible`: Contributor는 draft만·status/visibility 변경 제한.
   - `models/user.js`: edit = 본인(`context.user === userModel.id`) 허용, Owner 대상은 Owner만, Editor는 Author/Contributor 대상만, 역할 변경은 `canThis.assign.role`; destroy = Owner 삭제 불가, Editor는 본인 또는 Author/Contributor.
   - `models/role.js`: assign = Owner는 모든 역할, Administrator는 Owner 제외, Editor는 Author/Contributor만; API 키는 Owner 할당 불가.
   - `models/invite.js`: add = 초대 역할이 요청자 역할 범위 안(Owner 초대 불가); 그 외 역할 플래그만.
   - `models/integration.js`: limit 검사 후 역할 플래그만.
   - `api/endpoints/users.js` `permissionOnlySelf`: 스태프 토큰 조회·재발급은 본인 id('me' 포함)만. `webhooks.js` `permissions.before`: 통합 키 요청은 자기 integration의 webhook만.

## 제외한 범위와 이유

- Content API(`/ghost/api/content/`), Members API, 댓글 프런트 API, ActivityPub, webmentions: Admin API 외 범위. Content API 키는 `parseContext`에서 public 취급이나 키 인증이 필요하므로 public 라벨 근거로 쓰지 않았다.
- `labs.enabledMiddleware` 뒤의 실험 기능 라우트(posts/upload, stripe/checkout/*, members/metafields 변경, apps/*): 기능 플래그 조건부라 제외.
- `POST|PUT /session/verify`(2FA 코드 발송·검증): 인증 중간 상태의 세션을 요구해 익명/인증 어느 쪽으로도 단정하기 어려워 제외.
- `GET /users/{id}`, `GET /settings`, `GET /members/{id}`, stats/*, emails 조회, search-index 등 조회 다수: 같은 역할 권한 패턴(role_required 또는 모든 역할 보유)의 반복이라 대표만 남김. `GET /users/{id}`는 user:read를 모든 역할이 보유해 `GET /users`와 같은 manual 패턴.
- 통합 전용 조작(`GET /integrations/{id}/api_key/{keyid}/refresh`, `members/stripe_connect`, tinybird/featurebase token, support_requests, mail 등): 역할 패턴 중복 또는 외부 서비스 연동이라 제외.
- gift_links ensure/create/remove_all, automations·automated_emails·recommendations 일부, offers/newsletters edit 등: Administrator·Admin Integration role_required 반복이라 대표만 포함.

## draft_label 건수 (73)

| draft_label | 건수 |
|---|---:|
| owner_or_admin | 10 |
| owner_match | 3 |
| public | 8 |
| manual_review_required | 8 |
| role_required | 44 |
| membership_required / tenant_match | 0 (Ghost는 단일 사이트·단일 테넌트, 그룹 구성원 개념 없음) |

### owner_or_admin (10)

- `PUT /posts/{id}/`, `PUT /pages/{id}/`: Contributor/Author는 공동 저자인 글만(isCoAuthor), Editor 이상·Administrator·Owner·Admin Integration은 모든 글.
- `DELETE /posts/{id}/`, `DELETE /pages/{id}/`: Contributor/Author는 1저자인 글만(isPrimaryAuthor; Contributor는 draft만), Editor 이상은 모든 글.
- `PUT /users/{id}/`: 본인이면 허용, 그 외 Administrator/Owner/Editor(하위 역할 대상).
- `PUT /users/password/`: 본문 user_id에 users edit와 같은 User.permissible 적용.
- `POST /posts/`, `POST /pages/` (0.6): Contributor/Author는 요청 authors[0]이 본인일 때만(본인 명의 생성), Editor 이상은 제한 없음. 생성이라 소유 개념이 약해 role_required 대안.
- `PUT|DELETE /webhooks/{id}/` (0.5): Administrator 세션은 모든 webhook, 통합 키는 자기 integration의 webhook만. 소유 주체가 integration이고 역할 AND 소유 검사가 겹쳐 manual 대안.

## 불확실한 엔드포인트 메모

- **posts/pages add**: `isOwner()`는 `unsafeAttrs.authors`가 없으면 false라 Contributor/Author가 authors를 보내지 않으면 거부된다(Admin 클라이언트는 항상 보냄). 라벨은 코드 조건 기준.
- **posts/pages copy, posts bulkDestroy**: add/destroy 권한을 모델 또는 unsafeAttrs 없이 검사해 Contributor/Author 분기가 항상 false → 사실상 Editor 이상만. role_required(0.7).
- **users destroy** (0.55): user:destroy 권한(Administrator·Editor)이 전제이고 Editor만 본인 삭제 경로가 있다(Author/Contributor는 본인도 불가). role_required로 두었으나 owner_or_admin 판단 가능.
- **schedules publish** (0.6): URL Admin API 키 전용 라우트. 모델의 `|| isPrimaryAuthor()` 우회는 세션 사용자가 없어 실질적으로 비활성이나, 스태프 토큰을 URL로 쓰면 작동할 가능성이 있어 낮춤.
- **gift_links browse** (0.55): `manage.gift_link` AND `edit.post` — 독립 조건 AND 결합. manage 보유 역할(Editor 이상)은 모든 글 edit 권한이 있어 역할이 실질 조건이지만 manual 대안.
- **manual_review_required 8건**은 모두 "권한을 모든 스태프 역할이 보유(인증만이 조건)" 또는 `permissions: false`(인증만) 유형. role_required(아무 스태프 역할)로 볼지 검수에서 확정 필요.
- **public**: `POST /authentication/setup`(0.5)은 사이트 미설정 상태에서만 동작(요청자 조건은 없음). `POST /authentication/invitation`(0.7), `PUT /authentication/password_reset`(0.8)은 본문 토큰이 자격증명 역할. `POST /authentication/password_reset`은 `permissions: true`지만 익명 context가 `public: true`로 pass-through되어 익명 허용이 코드로 확인됨.
- **comments edit** (0.8): `objectTypeModelMap`에 comment가 있으나 `models/comment.js`의 `permissible` 유무는 확인하지 않았다(grep 결과 `permissible`은 integration·invite·post·role·user 모델에만 존재 → comment 모델에는 없음).
- api-framework의 `http()`/`pipeline`(frame.options.context 구성: req.user.id → context.user, req.api_key → context.api_key/integration)은 node 모듈(`@tryghost/api-framework`)이라 저장소 발췌에 없다.
- `known_vulnerable`은 전부 false, advisory/fix_commit 없음(현행 코드의 의도 정책만 추출).
