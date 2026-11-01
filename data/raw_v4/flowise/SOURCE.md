# Flowise (FlowiseAI/Flowise) — test_v31_supp 추출 출처

## 저장소·고정 버전

- 저장소: https://github.com/FlowiseAI/Flowise
- 태그: `flowise@3.0.13` (git ls-remote로 확인. `flowise-components@3.0.13`·`flowise-ui@3.0.13`도 같은 커밋)
- 커밋: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7`
- clone: `datasets/blade/raw/opensource/FlowiseAI_Flowise/` (`--depth 1 --filter=blob:none --branch flowise@3.0.13`, git 추적 대상 아님)
- 정적 분석만 했다. 빌드·실행·의존성 설치·테스트 실행은 하지 않았다. 네트워크는 clone, `gh api`(advisory, 커밋 diff, 태그 간 비교)에만 썼다.

## 기준 advisory

- GHSA-3prp-9gf7-4rxx / CVE-2026-41277: "Mass Assignment in DocumentStore Create Endpoint Leads to Cross-Workspace Object Takeover (IDOR)". npm `flowise`, 취약 범위 `<= 3.0.13`, 패치 `3.1.0`. CWE-284/639/915, CVSS 3.1 8.8.
  - 수정 커밋: `840d2ae14d25230579a58aa4305f8506672a0a45` "Prevent IDOR Takeover of DocumentStores (#5914)" (2026-03-10, `flowise@3.1.0`에 포함). `DocumentStoreDTO.toEntity`와 `updateDocumentStore`에 필드 allowlist를 넣었고, create와 upsert(createNewDocStore) 경로에서 `workspaceId`를 서버의 `activeWorkspaceId`로 강제한다.
- 3.0.13에 영향을 주는 다른 인가·IDOR advisory 가운데 REST 엔드포인트가 특정되는 것도 포함했다. 범위가 `<= 3.1.1`이나 `<= 3.1.2`인 것도 3.0.13을 포함한다. advisory·수정 커밋 대응은 다음과 같다.

| advisory | 엔드포인트 | 수정 커밋 | 대응 근거 |
|---|---|---|---|
| GHSA-5wxp-qjgq-fx6m | PUT /chatflows/{id} | 0d29e4d0 (#5953) | PR 제목 |
| GHSA-p5w8-m249-4r4v | DELETE /chatflows/{id} | 2f528cec (#6445) | advisory 참조 |
| GHSA-c2c9-mfw7-p8hw | GET /chatflows/apikey/{apikey} | f7d86912 (#6043) | PR 제목 |
| GHSA-6fw7-3q8r-m5vj | PUT /variables/{id} | 7dc48adb (#5955) | PR 제목 |
| GHSA-x5v6-pj28-cwwm | PUT /tools/{id} | f8defac0 (#5954) | PR 제목 |
| GHSA-78pr-c5x5-jggc | POST /assistants | 1cf247ea (#6128) | advisory 참조 |
| GHSA-hp26-q66v-q2w7 | PUT /assistants/{id} | faa571c9 (#5945) | PR 제목 |
| GHSA-5h9v-837x-m97r / GHSA-7j65-65cr-6644 | POST·PUT /datasets/set, PUT /datasets/rows/{id} | 49a2259b (#6051) | advisory 참조 |
| GHSA-wxrr-jp8m-qq7f / GHSA-mq53-pc65-wjc4 | POST·PUT /evaluators, POST /evaluations | dc07f406 (#6050) | advisory 참조 |
| GHSA-fm2f-4339-4p2f | PUT /executions/{id} | 96a9b23b (#6409) | advisory 참조 |
| GHSA-fr6g-7cq8-fg82 | GET /upsert-history/{id}, PATCH /upsert-history | d81483b7 (#6170, flowise-146) | advisory 참조 |
| GHSA-chm3-vqcf-52rx / GHSA-hmg2-jjjx-jcp2 | /openai-assistants-vector-store | d81483b7 / b93ccf31 (#6045) | advisory 참조 / PR 제목 |
| GHSA-wp74-f5hh-5f3r | GET /files | bc22bf8b (#6435) | advisory 참조 |
| GHSA-728h-4mwj-f2p4 | POST /marketplaces/custom | f64047bd (#6129) | advisory 참조 |
| GHSA-59fh-9f3p-7m39 | PUT /user | 06dc0e1e (#5986) | PR 제목 |
| GHSA-2364-jh4q-m9vm | GET /organization/customer-default-source | 4d7899d0 (#6321) | advisory 참조 |
| GHSA-gmmw-qg98-6j6p | POST /organization/update-subscription-plan, update-additional-seats | 4d7899d0 (#6321) | advisory 참조 |

- advisory는 없지만 같은 수정 커밋(d81483b7 flowise-146 "tenant guards")에서 검사가 추가된 엔드포인트는 `known_vulnerable=true`, `advisory=null`, `fix_commit=d81483b7…`로 기록했다. 해당 엔드포인트는 GET /workspace, GET /workspaceuser, GET /user, GET·PUT /role, GET /organizationuser, GET /chatflows/has-changed, DELETE /evaluations/{id}, POST /document-store/loader/preview다. POST /document-store/generate-tool-desc/{id}의 수정 커밋은 03c853cb(#5837)다.
- 제외: GHSA-wch5(OAuth2 credential 메타데이터), GHSA-48m6(가입 mass assignment)은 경로가 플랫폼별로 복잡하거나 인증 전 흐름이어서 뺐다. GHSA-7g73(encryptedData 노출)과 GHSA-8r8h($vars 주입)는 라벨과 무관한 정보 노출이라 뺐다. GHSA-cwc3(SSO)과 GHSA-mq4r(leads)는 3.0.13에서 이미 수정되었다. RCE·SSRF·XSS 계열은 인가와 무관해 넣지 않았다.

## 라이선스

- 루트 `LICENSE.md` 요지: 대부분은 Apache-2.0이다. 예외로 `packages/server/src/enterprise/` 디렉터리 전체와 명시 저작권 표기 파일(예: `packages/server/src/IdentityManager.ts`)은 FlowiseAI Commercial License(`packages/server/src/enterprise/LICENSE.md`)를 따른다. `packages/server/package.json`의 license는 "SEE LICENSE IN LICENSE.md"다.
- Commercial License 요지: 프로덕션 사용에는 구독이 필요하다. 개발·테스트 목적의 복사·수정은 허용된다. 그 밖의 복사·병합·게시·배포·재라이선스·판매는 금지된다.
- 영향: 레코드마다 `license` 필드에 표시했다. 56/67건의 발췌가 enterprise 코드를 포함한다. 대부분은 라우트 RBAC 미들웨어 `enterprise/rbac/PermissionCheck.ts`(checkPermission/checkAnyPermission)나 `enterprise/middleware/passport` 세션 사용자 구성이다. 12건은 enterprise 컨트롤러·서비스(workspace, user, role, organization) 본문을 포함한다. 11건은 Apache-2.0 코드만 포함한다. 평가셋을 공개·배포하려면 조립 단계에서 enterprise 발췌를 요약으로 바꾸거나 해당 레코드를 비공개로 두는 판단이 필요하다.

## 추출 범위와 OAS

- 저장소 명세 `packages/api-documentation/src/yml/swagger.yml`(OpenAPI 3.0.3, server `http://localhost:3000/api/v1`)에 있는 operation은 `oas_status=repository_spec`으로 두고 원문 operation을 그대로 넣었다(tags만 제외). 이런 operation은 26건이다. 경로는 `/api/v1` prefix를 붙인 실제 경로다. 명세의 path 파라미터 이름이 라우트와 다른 경우가 있다(예: chunks의 `{loaderId}` ↔ 라우트 `:fileId`). 이때는 명세를 따랐다.
- 명세에 없는 41건은 `packages/server/src/routes/**`, `packages/server/src/enterprise/routes/*`(마운트는 `routes/index.ts`)에서 생성했다(`oas_status=generated`). 이 레코드의 security는 bearer(API 키)와 cookie(JWT)로 일반화했다. `response_schema_fields`는 TypeORM 엔티티 컬럼에서 뽑았다.
- 명세의 `PATCH /upsert-history/{id}`는 실제 라우트(`router.patch('/')`)와 경로가 달라 generated로 기록했다.
- 범위: DocumentStore 라우트 23건(라우트 정의 25개 중 provider 목록 components/vectorstore·components/recordmanager 2개만 제외), 워크스페이스 범위 자원 32건(chatflows, credentials, variables, apikey, tools, assistants, datasets, evaluators, evaluations, executions, upsert-history, openai-assistants-vector-store, files, marketplaces, chatmessage), 사용자·조직·워크스페이스 관리 12건.
- 제외: 공개 예측·임베드 경로(prediction, public-chatflows 등 화이트리스트)와 노드·컴포넌트 메타데이터 경로. 인가 대상 객체가 없거나 라벨 우선순위와 거리가 멀다. DELETE /workspace/{id}, POST /workspaceuser 등은 3.0.13에 조직 일치 검사가 없지만 advisory·수정 근거가 없어 의도 정책을 확정할 수 없으므로 뺐다.

## 인증·인가 구조 요약

- 전역 미들웨어(`packages/server/src/index.ts` 214-280행) 순서: `/api/v1/` 경로가 `WHITELIST_URLS`(`utils/constants.ts`)에 있으면 통과한다. `x-request-from: internal`이면 `verifyToken`(passport JWT 쿠키 + 세션)을 거친다. 그 외에는 `validateAPIKey`로 API 키를 확인한 뒤 `req.user = { permissions: apiKey.permissions, activeWorkspaceId: apiKey.workspaceId의 workspace.id, activeOrganizationId, isOrganizationAdmin: false, ... }`를 설정한다.
- 세션 사용자(`enterprise/middleware/passport/index.ts`): 로그인 시 첫 `workspaceUser`로 `activeWorkspaceId`, 역할 permissions, `isOrganizationAdmin`(OWNER 역할)을 정한다. `POST /workspace/switch`는 대상 워크스페이스의 `workspaceUser(workspaceId, userId)`를 조회해 세션을 바꾼다.
- 라우트 RBAC: `enterprise/rbac/PermissionCheck.ts`의 `checkPermission(p)`·`checkAnyPermission('a,b')`는 `isOrganizationAdmin`이면 통과하고, 아니면 `user.permissions` 포함 여부를 본다. 기능 게이트는 `IdentityManager.checkFeatureByPlan('feat:…')`다(플랜 기반이며 라벨 근거가 아니다).
- 객체 범위: 서비스가 `findOneBy({ id, workspaceId: activeWorkspaceId })`, `getWorkspaceSearchOptions(workspaceId)`(`enterprise/utils/ControllerServiceUtils.ts`), `entity.workspaceId !== workspaceId → 'Unauthorized access'`로 활성 워크스페이스에 한정한다. 공유 자원은 `WorkspaceShared`로 허용한다(credentials 등).
- 수정 버전의 가드(`enterprise/utils/tenantRequestGuards.ts`, 3.1.3): `assertQueryOrganizationMatchesActiveOrg`, `assertWorkspaceIdAccessibleToUser`, `assertMayReadTargetUser`, `assertStripeIdMatchesSession`, `getChatflowByIdForWorkspace`.

## 라벨 판단 규약 (draft, 사람 검수 전)

- tenant_match: 요청이 대상 워크스페이스를 지정하지 않고, 서버가 자원을 요청자의 `activeWorkspaceId`/`activeOrganizationId`로 필터링한다(세션에서는 workspaceUser, API 키에서는 apiKey.workspaceId가 그 값을 정한다). "요청자의 현재 테넌트 = 자원 테넌트" 구조이므로 이 라벨로 통일했다.
- membership_required: 요청이 대상 워크스페이스를 지정하고(query `id`/`workspaceId`), `(userId, workspaceId)` 구성원 조회로 허용한다. 해당 레코드는 workspace/switch, GET /workspace, GET /workspaceuser다.
- 라우트 RBAC 권한과 워크스페이스 범위는 AND 결합이다. 규격의 "그룹 안 역할이 핵심이면 role_required, 구성원·소속이 핵심이면 그 라벨" 규칙을 따라, 객체 수준 조건(또는 수정 커밋이 추가한 조건)이 워크스페이스 일치면 tenant_match, 권한이면 role_required로 하고 confidence를 낮췄다. 대상 객체가 없는 컴포넌트 목록은 role_required다.
- 취약 엔드포인트는 3.0.13 코드를 입력으로 하고, 수정 커밋이 보여주는 의도 정책을 라벨로 한다.

## 건수

- candidates.jsonl: 67건(repository_spec 26, generated 41). `known_vulnerable=true` 37건(advisory 있음 27, 수정 커밋만 있음 10).
- draft_label: tenant_match 54, role_required 5, membership_required 3, manual_review_required 3, owner_or_admin 1, owner_match 1.
- controller_text 길이는 1,450–2,999자다(최대 3,000). 길이를 맞추려고 오류 메시지만 다르고 인가와 무관한 throw 블록과 일부 본문을 `...`로 줄였다. 인가 관련 줄은 남겼다. 블록 사이는 빈 줄 하나로 구분했다.
