# 작업 S0 정지 지점 1 — hold-out test_v6 후보 프로젝트 (2026-11-03)

학습·추론·동결·커밋은 하지 않았다. 후보 저장소는 `datasets/blade/raw/opensource/test_v6_candidates/`(.gitignore 84행 `datasets/blade/raw/opensource/` 적용, `git status`에 미표시)에 릴리스 태그로 얕게 받아 읽기만 했다(수정·빌드·실행·LLM 호출 없음). 기존 동결본은 열지 않았고, 출처 겹침 확인에는 `reports/data_sources.md`(2026-11-01 전수 조사본)와 APIs.guru 후보 424개 서비스 이름만 썼다.

## 0. 선정 조건 적용

- 제외 출처: data-v1~v5·test_v30·test_v31_supp·test_v5 출처 전부(APIs.guru 424 services 포함)와 그 포크·파생, AGPL. 아래 후보 6개의 이름은 APIs.guru 424 services·`datasets/blade/processed`·`data/raw_v4|raw_v5|raw_v5_train`·`training/data` 어디에도 없다(grep 0건).
- 라이선스: 6개 모두 OSI(Apache-2.0 · MIT · MPL-2.0 · BSD-2-Clause). GPL 계열은 없어 코드 비공개 처리가 필요한 후보가 없다.
- 언어: test_v5(TS/JS 3종)와 겹치지 않는 Python 3종, Clojure 1종, Elixir 1종. JS는 Wekan 1종(B안).
- 두 판정 label(owner_or_admin·membership_required) 실제 사례: 아래 1절 "검사 메커니즘" 열에 코드 위치를 적었다. Papercups는 두 label 사례가 없어 **조건 미충족(보조 후보)** 로만 둔다.

## 1. 후보 프로젝트

| # | 프로젝트 | 태그 · 커밋 | 언어 / 프레임워크 | 라이선스 (원문 경로) | API 규모(정적 집계) | 제안 추출 |
|---|---|---|---|---|---|---:|
| 1 | Seafile **seahub** | `v14.0.9-server` · `0841826c7ce738caf92121d94d7741ba0f2373d5` | Python / Django REST Framework | Apache-2.0 (`seahub/LICENSE.txt`; 서드파티 고지 `LICENSE-thirdparty.txt`) | `seahub/urls.py` api/v2.1 라우트 370(이 중 `admin/` 130) + `api2/urls.py` 74; 엔드포인트 파일 92 | 90 |
| 2 | **Redash** | `v26.9.0` · `42fdf9d4a0fdb83841130ab78f69899a224f281b` | Python / Flask-RESTful | BSD-2-Clause (`redash/LICENSE`) | `handlers/api.py` 리소스 66, 핸들러 메서드 107 | 70 |
| 3 | **GlitchTip backend** | `v6.2.6` · `d3039088e913a591a8e6544a2d2fffc865a9711a` (gitlab.com/glitchtip/glitchtip-backend) | Python / Django Ninja(async) | MIT (`glitchtip-backend/LICENSE`) | `@router.*` 116 (get 56 · post 29 · put 14 · delete 17) | 70 |
| 4 | **Penpot** backend | `2.18.5` · `f44566963daf61fce4d8608e7c5e8c27c5853a88` | Clojure / 자체 RPC (`POST /api/rpc/command/{name}`) | MPL-2.0 (`penpot/LICENSE`) | `sv/defmethod` 명령 154 (무인증 `::rpc/auth false` 16) | 60 |
| 5 | **Wekan** (B안) | `v12.87` · `1ac4d1b1f93adcdfdde0675987250af7fa8deb75` | JavaScript / Meteor `WebApp.handlers` | MIT (`wekan/LICENSE`) | REST 경로 124(등록 162, 별칭 포함) | 40 |
| 6 | Papercups (보조) | master `6a6f5adc7f0cef5813b2c2f1c0659922defaf976` (2022-05-10, 보관 상태) | Elixir / Phoenix | MIT (`papercups/LICENSE`) | router 명시 116 + `resources` 31(≈110 액션) | 조건 미충족 |

### 검사 메커니즘과 label 매핑 근거

| 프로젝트 | membership_required(G2) | owner_or_admin(G5) | 그 외 주요 패턴 |
|---|---|---|---|
| seahub | `is_group_member(group_id, username)` — `api2/endpoints/group_members.py` 65·154·181, group_libraries·group_owned_libraries·address-book 등(사용 파일 12) | `GroupMember.delete`(group_members.py 234~): `username == email`이면 탈퇴, 아니면 `is_group_owner`/`is_group_admin` → 본인 OR 그룹 관리자. 소유자 검사와 `is_staff`/`is_repo_admin` 우회가 섞인 파일 10개(be_shared_repo, dir_shared_items, file, group_owned_libraries, multi_share_links, repo_commit_revert, shared_repos, wiki2, wikis) | role: `IsAdminUser`(58 파일), `is_group_admin_or_owner`, `is_repo_admin`(20); owner: `FileShare.is_owner`, 본인 starred·monitored·avatar·devices; **tenant: `request.user.org.org_id` 필터 62곳**(org 관리 API, G1 "RBAC 동반해도 tenant_match"); manual: `check_folder_permission`(38, seaf-server 공유 권한 RPC = 외부 인가), via-repo-token |
| Redash | 없음(그룹 API는 `require_admin`) | `require_admin_or_owner(obj.user_id)` 호출 21곳, 서로 다른 핸들러 메서드 15개(alerts 6 · dashboards 2 · permissions 2 · queries 2 · query_snippets 2 · users 1) — `permissions.py` 94~109: `owner_id == current_user.id or has_permission("admin")` | role: `require_admin` 59 · `require_permission` 39; manual: `require_access`(데이터소스 그룹 ACL) 35 · `require_object_modify_permission`(owner OR admin OR ACL 공유, 3유형) 15 · 공개 대시보드 토큰; tenant 후보: `get_by_id_and_org(id, self.current_org)` 87곳 |
| GlitchTip | 조직 slug 경로 + `get_organizations_queryset(user_id, organization_slug)` = `organization_users__user` 필터(`organizations_ext/queryset_utils.py` 27) — 조직 하위 projects·issues·releases·environments·alerts·uptime·teams·stats | `delete_organization_member`(organizations_ext/api.py 278~316): `actor_role < MANAGER and not (org_user.user.id == user_id)` → 본인 OR 매니저 | role: `actor_role < OrganizationUserRole.{MANAGER,ADMIN,OWNER}`(조직 안 역할, G3) · `is_superuser` 12; owner: `/users/{me}/…` 13(본인 고정); manual: `open_membership` 설정 분기(teams/api.py 215~226), DSN 키 인제스트 `auth=event_auth`; `has_permission([...])`는 토큰 스코프만 검사(세션 인증은 통과) |
| Penpot | `teams/check-read-permissions!`(40회) = `team_profile_rel` 행 존재(teams.clj 42~60) — 팀·프로젝트·파일 조회 명령 | 사실상 없음: `delete-team-member`는 admin 전용(본인 제거 금지, teams.clj 971~), `leave-team`은 본인(owner_match), 댓글 삭제는 `owner-id = profile-id`만 | role: `check-edition-permissions!`(51, `can-edit` 플래그) · `is-owner or is-admin`; public: 무인증 명령 16(login·register·verify-token·get-view-only-bundle 등); manual: `share-id` 겸용 조회(files 10곳·comments 39곳·viewer) = 구성원 OR 공유 링크, `get-organization-owner-permissions`(admin-console 플래그 시 읽기 OR 경로, permissions.clj 96~155) |
| Wekan | `Authentication.checkBoardAccess(userId, boardId)` 33회 = 보드 members 행(전체 읽기 가능한 구성원) | `checkAdminOrCondition(req.userId, req.userId === paramUserId)` — `GET /api/users/:userId/boards`(boards.js 949) 등 사이트 admin OR 본인; 나머지 `checkAdminOrCondition` 5곳은 admin OR 보드 권한(→ role) | role: `checkBoardWriteAccess` 41(쓰기 역할) · `checkBoardAdmin` 15 · `checkUserId`(사이트 admin) 31; `checkLoggedIn` 22(인증만 → G6 또는 본인 생성 owner_match); public: `apiAuthRoutes.js` 3 |
| Papercups | 없음 | 없음(`UserController.delete`는 본인만 403 "cannot delete another user") | **tenant: `conn.assigns.current_user.account_id` 필터 507곳**(모든 보호 라우트); role: `EnsureRolePlug :admin` 3; public: ping·registration·session·widget 20여 개(고객 토큰은 manual) |

## 2. label별 예상 분포 (제안 추출 수 기준, 사람 검수 전 추정)

A안 = 1~4번(290건, Python 3 + Clojure 1). B안 = 1~5번(300건, Wekan 추가; 각 프로젝트 추출을 80·65·60·55·40으로 조정).

| label | seahub 90 | Redash 70 | GlitchTip 70 | Penpot 60 | **A안 합 290** | Wekan 40 | **B안 합 300** |
|---|---:|---:|---:|---:|---:|---:|---:|
| membership_required | 15 | 0 | 25 | 18 | **58** | 12 | **63** |
| owner_or_admin | 8 | 14 | 2 | 1 | **25** | 3 | **26** |
| owner_match | 18 | 6 | 10 | 10 | 44 | 3 | 43 |
| role_required | 22 | 25 | 20 | 18 | 85 | 18 | 94 |
| tenant_match | 8 | 6 | 0 | 0 | 14 | 0 | 13 |
| manual_review_required | 15 | 15 | 9 | 8 | 47 | 3 | 44 |
| public | 4 | 4 | 4 | 5 | 17 | 1 | 17 |

- **owner_or_admin 여유가 작다**(25~26, test_v5 21). Redash에 집중(14)돼 있고 G8 제외·owner_match 재판정이 나오면 20 아래로 갈 수 있다. Redash `require_object_modify_permission` 10건을 검수에서 owner_or_admin으로 보면 +10, 3유형 OR(G6)로 보면 manual이다 — 검수 규약 추가 결정 사항(3절). seahub의 owner+admin 혼합 파일 10개는 추출 후 실제 수가 정해진다.
- membership_required는 세 프로젝트에 분산(GlitchTip·Penpot·seahub)돼 test_v5의 Rocket.Chat 편중(28/33)이 완화된다.
- tenant_match는 test_v5 0건 → seahub org API·Redash `current_org`로 10여 건 확보 가능. Papercups를 보조로 넣으면 +30~40이 가능하나 두 판정 label이 없고 2022년 보관 저장소라 권하지 않는다.
- 추출은 후보 레코드 생성 단계(2번)에서 프로젝트별 상한과 label 상한(한 label 50% 이하, data-v4 선정 규칙과 동일)을 두고 seed 42로 뽑는다. 추정치는 라우트·검사 호출 집계에서 나온 것이며 사람 검수로 바뀐다.

## 3. 검수자가 미리 정해야 할 것 (G1~G8 적용 쟁점)

1. **Redash `current_org`**: `add_org_resource`가 `/api/...`와 `/<org_slug>/api/...` 두 경로를 등록한다. 사용자 로그인 시 `User.get_by_id_and_org(user_id, current_org)`로 요청자 조직이 고정되므로 G1(요청자 테넌트로 필터)로 볼지, slug가 경로에 있으므로 제외(G8)할지.
2. **Redash `require_object_modify_permission`**(owner OR admin OR ACL 공유): owner_or_admin vs manual(G6 서로 다른 유형 OR).
3. **seahub `check_folder_permission`**: seaf-server RPC(공유·그룹·공개 권한 합산)라 코드로 의도를 못 읽으면 manual. 그룹 라이브러리 API처럼 `is_group_member` 선행 검사가 있으면 membership_required.
4. **seahub org 관리 API**(`/api/v2.1/org/admin/...`, org_admin + `request.user.org.org_id` 필터): G1 문구대로 tenant_match로 통일할지, 조직 안 역할(G3)로 볼지. test_v31_supp의 Flowise(워크스페이스 필터 + RBAC → tenant_match) 선례가 있다.
5. **Penpot share-id 겸용 조회**(구성원 OR 공유 링크) → manual(G6)로 통일. `get-organization-owner-permissions`는 `admin-console` 플래그가 켜진 경우만 OR 경로가 생기므로, 기본 구성 기준 membership_required로 볼지 결정.
6. **GlitchTip `has_permission`**: 토큰 스코프 검사이지 역할이 아니다. label 근거는 `get_organizations_queryset`·`actor_role`만 쓴다. `open_membership` 설정에 따라 본인 팀 가입 허용 → manual(G6).
7. **Wekan `checkBoardAccess`**: 구성원 중 "전체 보드 읽기" 역할만 통과(assigned-only 제외) → membership_required로 볼지 role_required로 볼지. `checkBoardWriteAccess`는 역할 능력표 기반이라 role_required.
8. 경계·근거 부족 건은 manual로 넣지 말고 EXCLUDE + 사유(G8). 2번 단계 검수 시트에 모델(v5) 예측 열은 넣지 않는다.

## 4. 검토 후 제외한 프로젝트

| 분류 | 프로젝트 | 사유 |
|---|---|---|
| AGPL | Mattermost, Plane, Mastodon, Lemmy, Nextcloud, Cal.com, Vikunja, Wiki.js, Immich, PhotoPrism, Listmonk, Grafana, Metabase, Synapse, Misskey, Mealie(또한 2026-11-02 `verification/mealie_static_eval`에서 v5 추론에 이미 사용됨) | 라이선스 제외 규칙(Mealie는 사용 이력도 있음) |
| 비OSI | Outline(BSL), Directus(BSL), Planka(Fair Use), Sentry(FSL), n8n(Sustainable Use), Invoice Ninja(Elastic) | OSI 아님 |
| APIs.guru 겹침 | Keycloak(keycloak.local), Jellyfin, Etherpad, NetBox(netbox.dev), Apache Superset(superset.apache.local), Traccar, Meshery, Netlify, Appwrite, GitLab, Discourse 등 | 라벨링 풀 424 services에 포함 |
| 포크·동일 API 표면 | Gogs·Forgejo(Gitea 계보), Conduit·Conduwuit(Dendrite와 같은 Matrix 클라이언트-서버 명세 → 경로·의미 동일), GitBucket(GitHub 호환 API = Gitea API 표면과 유사) | 학습 출처와 엔드포인트 표면이 겹침 |
| 라벨 적합성 부족 | Flarum·Vanilla(편집 시간창 조건), BookStack(엔티티 권한 오버라이드), Apache Answer(평판 기반 권한), Harbor(RBAC 정책표 기반, owner_or_admin 소수), Kanboard(JSON-RPC, 경로 없음), Matomo(module/method 호출 방식·GPL), DSpace(DB 리소스 정책 기반), Redmine(공개/비공개 프로젝트 분기로 membership 대부분 manual·GPL) | G2·G5 사례가 적거나 코드만으로 의도 판정이 어려움 |
| 보조 후보 | Papercups | 두 판정 label 0건, 2022년 이후 보관. tenant_match 보강이 필요할 때만 |

## 5. 승인 후 2번 단계 계획 (요약)

- `data/raw_v6/<project>/{extract_*.py, candidates.jsonl, SOURCE.md}` — test_v5와 같은 형식(oas·oas_code 두 조건, 프롬프트 v3.0.1 입력). Penpot은 `POST /api/rpc/command/{name}`을 경로로, `::sm/params` 스키마를 요청 본문 스키마로 쓴다.
- 중복 대조 키(서비스 정규화, method, 경로 정규화)를 APIs.guru 후보 424 services·data-v1~v5 train/val/pool·test_v30·test_v31_supp·test_v5 확정·제외분과 대조해 0건 확인.
- AI 1차 판정 + 근거(코드 줄·고정 링크) → `review/test_v6_review.xlsx`(담당자 열 분할, 보조 시트 '라벨 정의'·'검수 규약'·3절 결정 사항). **v5 예측 열 없음**, 검수 전 어떤 모델로도 test_v6 입력을 추론하지 않는다.
- 3번 동결 시 `scripts/eval_*`에 manifest 해시 게이트와 S9 이전 추론 가드를 추가한다.

## 6. 미확정·주의

- 라이선스는 저장소 루트 LICENSE 파일만 확인했다. seahub `LICENSE-thirdparty.txt`에 GPL 서드파티가 열거돼 있으나 발췌 대상은 seahub 자체 코드(`seahub/api2/`)뿐이다. Penpot `plugins/LICENSE`·Redash `LICENSE.borders`는 발췌 범위 밖이다.
- GlitchTip 원본은 GitLab이다(GitHub `rh-cssre/glitchtip-backend`는 미러). 고정 링크는 GitLab 커밋 URL로 적는다.
- 예상 분포는 검사 호출 수 집계에서 나온 추정이며 추출·검수 결과와 다를 수 있다.
