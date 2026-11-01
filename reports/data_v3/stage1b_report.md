# data-v3 1b단계 — 변형 label 규칙 적용, 출처 보강, petclinic 상한, 1b 검수 반영 (학습·API 라벨링 없음)

빌더 `training/data/build_data_v3_pairs_1b.py`, seed 42. 1단계 산출물(`pairs_*_v3s1.jsonl`)은 그대로이며, 확장한 1단계 빌더를 `.cache/`에 다시 돌려 바이트 동일함을 확인했다. 쌍 80개, 레코드 137건(원본 80 + 유지 변형 57). 사람 확정 전, 동결 안 함.

## 변형 규칙 (사용자 확정, 첫 일치 규칙 적용)

| 규칙 | 변형 | 사유 | 1단계 쌍(petclinic 상한 후) | 새 쌍 |
|---|---|---|---:|---:|
| drop_owner_or_admin | 제외 | 소유자 부분은 경로로 보이지만 관리자 우회는 경로·스키마·본문으로 알 수 없음 | 4 | 11 |
| drop_check_in_sql | 제외 | 검사가 SQL 문자열 안에 있어 줄 단위로 제거할 수 없음 | 0 | 0 |
| keep_realworld_article_comment_write | 유지 | RealWorld 게시글·댓글 수정/삭제: 경로·메서드로 작성자 정책이 드러남 | 17 | 20 |
| keep_reference_data_write | 유지 | 공용 기준 데이터(pettypes·specialties·vets) 생성/수정/삭제 = 관리 역할 | 9 | 0 |
| drop_reference_data_read | 제외 | 기준 데이터 조회는 경로상 일반 조회로 보임 | 1 | 0 |
| drop_owner_pet_visit | 제외 | owners·pets·visits는 소유자 관점(owner_match)으로 읽혀 직원 역할 의도를 알 수 없음 | 3 | 0 |
| keep_user_create_or_list | 유지 | 사용자 생성·전체 목록 = 관리자 기능(가입은 별도 엔드포인트) | 3 | 0 |
| drop_user_by_id_write | 제외 | /users/{id} 수정·삭제는 본인 수정·탈퇴로도 읽힘 | 2 | 0 |
| keep_user_self_subresource | 유지 | 본인만(관리자 경로 없음) 쓰는 /users/{id} 하위 보안 자원(webhooks·토큰·연동 계정): 경로로 owner_match 의도가 드러남 | 0 | 8 |
| drop_user_subresource | 제외 | /users/{id} 하위 자원의 관리자 우회(self_or_admin)는 경로로 알 수 없음 | 0 | 0 |
| drop_utility_endpoint | 제외 | 유틸 엔드포인트는 경로로 관리자 의도를 알 수 없음 | 2 | 0 |

변형을 manual로 바꾸지 않았다. 규칙이 없는 변형은 빌더가 중단한다. 1단계 검수 40건과 1b 검수 시트(rw_axum 제외 후 38건)의 `variant_label_inferable_from_path_schema` 판정이 규칙 결과와 모두 일치해야 빌드가 통과한다(아래 일치표). 1b 검수 반영: memos self_only 8쌍(본인만, 관리자 경로 없음)의 /users/{id} 하위 자원 변형을 `keep_user_self_subresource`로 생성·유지하고, `drop_user_subresource`는 owner_or_admin에만 적용한다.

petclinic 상한 24건: 변형 유지 쌍(기준 데이터 쓰기 9 + 사용자 생성 1) 20건 + 원본만 4건(seed 42). 상한으로 뺀 쌍 22개는 manifest에 기록.

## 저장소

| key | 저장소 | 커밋 | 언어 | 스타 | 라이선스 | split | 쌍 | 레코드 | 변형 유지 |
|---|---|---|---|---:|---|---|---:|---:|---:|
| rw_spring | [gothinkster/spring-boot-realworld-example-app](https://github.com/gothinkster/spring-boot-realworld-example-app) | `ee17e31aafe7` | java | 1596 | MIT | train | 3 | 6 | 3 |
| rw_express | [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | `30b68e1e8814` | typescript | 3797 | none declared | train | 3 | 6 | 3 |
| rw_django | [Sean-Miningah/realWorld-DjangoRestFramework](https://github.com/Sean-Miningah/realWorld-DjangoRestFramework) | `8e4729aaee0a` | python | 66 | MIT | val | 2 | 4 | 2 |
| rw_flask | [gothinkster/flask-realworld-example-app](https://github.com/gothinkster/flask-realworld-example-app) | `4b95fb2227df` | python | 899 | MIT | train | 3 | 6 | 3 |
| rw_rails | [gothinkster/rails-realworld-example-app](https://github.com/gothinkster/rails-realworld-example-app) | `a2ae4fff78b3` | ruby | 423 | none declared | train | 3 | 6 | 3 |
| rw_gin | [gothinkster/golang-gin-realworld-example-app](https://github.com/gothinkster/golang-gin-realworld-example-app) | `626c372d2594` | go | 2718 | MIT | train | 3 | 6 | 3 |
| fastapi_tpl | [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) | `f4bcfaba7c85` | python | 46068 | MIT | val | 10 | 12 | 2 |
| petclinic_rest | [spring-petclinic/spring-petclinic-rest](https://github.com/spring-petclinic/spring-petclinic-rest) | `afc8fc1d3b8e` | java | 631 | Apache-2.0 | train | 14 | 24 | 10 |
| rw_nest | [adr1enbe4udou1n/nestjs-realworld-example-app](https://github.com/adr1enbe4udou1n/nestjs-realworld-example-app) | `d4ddf3fd9ebd` | typescript | 24 | none declared | train | 3 | 6 | 3 |
| rw_laravel | [gothinkster/laravel-realworld-example-app](https://github.com/gothinkster/laravel-realworld-example-app) | `e45c37c8a5f5` | php | 1200 | MIT | train | 3 | 6 | 3 |
| rw_aspnet | [realworld-apps/aspnetcore-realworld-example-app](https://github.com/realworld-apps/aspnetcore-realworld-example-app) | `8aa617abed5d` | csharp | 2094 | MIT | val | 3 | 6 | 3 |
| rw_kotlin | [gothinkster/kotlin-spring-realworld-example-app](https://github.com/gothinkster/kotlin-spring-realworld-example-app) | `848c29e3abfe` | kotlin | 476 | none declared | train | 3 | 6 | 3 |
| rw_koa | [gothinkster/koa-knex-realworld-example](https://github.com/gothinkster/koa-knex-realworld-example) | `602e234139c4` | javascript | 232 | none declared | train | 2 | 4 | 2 |
| rw_fastify | [avanelli/fastify-realworld-example-app](https://github.com/avanelli/fastify-realworld-example-app) | `bdb8ce4e1309` | javascript | 25 | MIT | val | 3 | 6 | 3 |
| rw_fastapi | [nsidnev/fastapi-realworld-example-app](https://github.com/nsidnev/fastapi-realworld-example-app) | `029eb7781c60` | python | 3100 | MIT | train | 3 | 6 | 3 |
| memos | [usememos/memos](https://github.com/usememos/memos) | `6387991fdd1d` | go | 64084 | MIT | train | 16 | 24 | 8 |
| kutt | [thedevs-network/kutt](https://github.com/thedevs-network/kutt) | `029da42b2459` | javascript | 11172 | MIT | train | 3 | 3 | 0 |

새 출처 후보와 채택 사유:

- NestJS: lujakob(3364)·mikro-orm(344)·neo4j-examples(48)·mutoe(44)는 수정/삭제 핸들러에 소유자 검사가 없어 탈락 → adr1enbe4udou1n(24).
- Elixir Phoenix(gothinkster 892): 소유자 검사 없음(세션 403만) → 미채택. Koa는 댓글 삭제에 검사가 없어 2쌍.
- owner_or_admin: memos(64k, "본인 또는 관리자" 사용자 자원·반응 "작성자 또는 관리자")와 kutt(11k, "관리자가 아니면 본인 링크로 조회 한정"). teamhephy/controller는 `IsOwnerOrAdmin`이 정의만 있고 ViewSet은 협업자 권한이 섞인 `IsAppUser`라 제외. DRF `IsOwnerOrAdmin` 코드 검색 결과는 대부분 개인 소규모 저장소였다.
- memos는 메모 자체의 접근(공간 멤버십·공유·공개 범위)이 복잡해 사용자 자원·반응 핸들러만 썼다. memos 명세에 security 선언이 없어 security_state=unknown.
- launchbadge/realworld-axum-sqlx(AGPL-3.0)는 사용자 결정(2026-10-26)으로 제외했다. Rust 출처는 없다.

라이선스 미선언 저장소(GitHub API 기준 license 없음, 학습 투입 전 확인 필요): rw_express(gothinkster/node-express-realworld-example-app), rw_rails(gothinkster/rails-realworld-example-app), rw_nest(adr1enbe4udou1n/nestjs-realworld-example-app), rw_kotlin(gothinkster/kotlin-spring-realworld-example-app), rw_koa(gothinkster/koa-knex-realworld-example).

## 건수

| label | train | val |
|---|---:|---:|
| owner_match | 74 | 16 |
| owner_or_admin | 11 | 4 |
| role_required | 24 | 8 |
| **합계** | **109** | **28** |

| 언어 | train | val |
|---|---:|---:|
| csharp | 0 | 6 |
| go | 30 | 0 |
| java | 30 | 0 |
| javascript | 7 | 6 |
| kotlin | 6 | 0 |
| php | 6 | 0 |
| python | 12 | 16 |
| ruby | 6 | 0 |
| typescript | 12 | 0 |

| label × 언어 (train 레코드) | csharp | go | java | javascript | kotlin | php | python | ruby | typescript |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| owner_match | 0 | 22 | 6 | 4 | 6 | 6 | 12 | 6 | 12 |
| owner_or_admin | 0 | 8 | 0 | 3 | 0 | 0 | 0 | 0 | 0 |
| role_required | 0 | 0 | 24 | 0 | 0 | 0 | 0 | 0 | 0 |

| 원본/변형 | train | val |
|---|---:|---:|
| 원본 | 62 | 18 |
| 변형 | 47 | 10 |

train owner_or_admin 11건(목표 ≥ 10). petclinic 24건(상한 24). val 28건, 언어 ['csharp', 'javascript', 'python'] — 목표 50건 안팎 대비 미달. owner_or_admin 출처(memos·kutt)는 train 최소 10건 조건 때문에 val에 둘 수 없었고, 새 RealWorld 구현은 저장소당 2~3쌍이라 1~2개 추가로는 50건에 닿지 않는다.

## 탐지와 제외 (새 저장소)

검사 패턴 탐지 85줄 = 채택 범위 67 + 제외 규칙 18 + 미설명 0.

| 저장소 | 파일 | 제외 사유 |
|---|---|---|
| rw_nest | src/articles/comments/comments.service.ts | comment-belongs-to-article integrity check, not authorization |
| rw_fastapi | (전체) | import line |
| rw_aspnet | (전체) | using line |
| rw_kotlin | src/main/kotlin/io/realworld/web/ArticleHandler.kt | import line |
| memos | server/api/user_service.go | other user_service handlers (admin-only create/list/role change, self-delete flags): not selected in this stage |
| memos | server/api/user_service_access_tokens.go | helper call / denial inside an adopted handler span is counted there; outside spans none |
| memos | (전체) | import line |
| memos | server/api/reaction_service.go | mapReactionMutationError: store error -> status mapping, not a check |
| kutt | server/handlers/links.handler.js | other link handlers (admin table, ban, report, create): not selected in this stage |

변형 생성 후 제외(문법 실패·검사 잔존·무변화): 0건

## 1단계 검수 판정과 규칙 일치

| pair_id | 경로 | 검수 판정 | 규칙 | 일치 |
|---|---|---|---|---|
| v3s1-338782f969e0 | DELETE /api/articles/{slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1-1b83c4d229f8 | DELETE /articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-239f42b04c5f | POST /users | Y | keep_user_create_or_list | O |
| v3s1-9dae7350c00f | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-d62176a2d816 | PUT /api/v1/items/{id} | N | drop_owner_or_admin | O |
| v3s1-e36d9c1c97cb | GET /api/v1/users/ | Y | keep_user_create_or_list | O |
| v3s1-c367a5fc909d | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-de0f1158ae25 | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-7ca06aecde3d | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-030d06269626 | DELETE /articles/{slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1-9912d711f9cb | GET /pettypes | N | drop_reference_data_read | O (상한으로 제외됨) |
| v3s1-29348f8959c6 | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-a42f4f50a656 | DELETE /api/v1/items/{id} | N | drop_owner_or_admin | O |
| v3s1-934b7c07defe | DELETE /api/v1/users/{user_id} | N | drop_user_by_id_write | O |
| v3s1-5ea873db33b6 | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-8cc54198aa11 | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-df2556e9c725 | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-622b969fa579 | PUT /articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-73189440afda | PUT /owners/{ownerId} | N | drop_owner_pet_visit | O (상한으로 제외됨) |
| v3s1-d547a98a35e2 | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-c3bebf89ebb9 | GET /api/v1/items/{id} | N | drop_owner_or_admin | O |
| v3s1-7bb25cc513bb | PATCH /api/v1/users/{user_id} | N | drop_user_by_id_write | O |
| v3s1-faa0f4d53113 | DELETE /api/articles/{article_slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1-d4d241b5dfde | DELETE /api/articles/{slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1-54ae16e6763a | DELETE /pets/{petId} | N | drop_owner_pet_visit | O (상한으로 제외됨) |
| v3s1-e19bd27b6afc | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1-49a345634686 | GET /api/v1/users/{user_id} | N | drop_owner_or_admin | O |
| v3s1-f8bdf69f216c | POST /api/v1/password-recovery-html-content/{email} | N | drop_utility_endpoint | O |
| v3s1-a6d715ef6e8c | GET /specialties | N | drop_reference_data_read | O (상한으로 제외됨) |
| v3s1-52e3bfffe943 | DELETE /api/articles/{slug}/comments/{cid} | Y | keep_realworld_article_comment_write | O |
| v3s1-983c21ce9e68 | POST /api/v1/users/ | Y | keep_user_create_or_list | O |
| v3s1-c1c330f93949 | POST /owners/{ownerId}/pets | N | drop_owner_pet_visit | O (상한으로 제외됨) |
| v3s1-29ad95b327e9 | POST /api/v1/utils/test-email/ | N | drop_utility_endpoint | O |
| v3s1-c76f05bda286 | DELETE /specialties/{specialtyId} | Y | keep_reference_data_write | O |
| v3s1-2293ae988865 | PUT /visits/{visitId} | N | drop_owner_pet_visit | O (상한으로 제외됨) |
| v3s1-aef763073a7e | GET /v2/pets | N | drop_owner_pet_visit | O (상한으로 제외됨) |
| v3s1-ca7c13a5d2fa | PUT /vets/{vetId} | Y | keep_reference_data_write | O |
| v3s1-eb70aa5e51fc | POST /vets | Y | keep_reference_data_write | O |
| v3s1-d78516634950 | DELETE /vets/{vetId} | Y | keep_reference_data_write | O |
| v3s1-e99388b585bd | DELETE /owners/{ownerId} | N | drop_owner_pet_visit | O (상한으로 제외됨) |

## 1b 검수 판정과 규칙 일치

| pair_id | 저장소 | 경로 | 검수 판정 | 규칙 | 일치 |
|---|---|---|---|---|---|
| v3s1b-18536c608fcf | rw_aspnet | DELETE /api/articles/{slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1b-b11fd359f43a | memos | GET /api/users/{user}/webhooks/{webhook}:getSigningSecret | Y | keep_user_self_subresource | O |
| v3s1b-f42bbf86995f | memos | DELETE /api/memos/{memo}/reactions/{reaction} | N | drop_owner_or_admin | O |
| v3s1-8ef65985158c | petclinic_rest | GET /owners/{ownerId} | N | drop_owner_pet_visit | O |
| v3s1b-7951090b1b9c | rw_koa | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-f6d06d014b56 | kutt | GET /api/links/{id}/stats | N | drop_owner_or_admin | O |
| v3s1b-aa0f10374811 | rw_kotlin | DELETE /api/articles/{slug}/comments/{id} | Y | keep_realworld_article_comment_write | O |
| v3s1b-52ba5370f6ed | rw_laravel | DELETE /api/articles/{article}/comments/{comment} | Y | keep_realworld_article_comment_write | O |
| v3s1b-140535b02e3f | rw_fastapi | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-9ee5a7bac2ff | rw_axum | - | Y | (저장소 제외) | - |
| v3s1b-f6410e36e25f | rw_nest | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-838d82d5ecf0 | rw_aspnet | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-770874ab6230 | memos | DELETE /api/users/{user}/webhooks/{webhook} | Y | keep_user_self_subresource | O |
| v3s1b-43db66dfd931 | memos | GET /api/users/{user}/personalAccessTokens | N | drop_owner_or_admin | O |
| v3s1-b6c698de0857 | petclinic_rest | POST /pettypes | Y | keep_reference_data_write | O |
| v3s1b-57738529d9ee | rw_fastify | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-f6a99fa24b51 | kutt | PATCH /api/links/{id} | N | drop_owner_or_admin | O |
| v3s1b-55f27134c84b | rw_kotlin | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-0f28735e9a97 | rw_laravel | PUT /api/articles/{article} | Y | keep_realworld_article_comment_write | O |
| v3s1b-46500171b7f9 | rw_fastapi | DELETE /api/articles/{slug}/comments/{comment_id} | Y | keep_realworld_article_comment_write | O |
| v3s1b-e83a6b34d149 | rw_axum | - | - | (저장소 제외) | - |
| v3s1b-9c42795ee44b | rw_nest | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-0203b894d99b | rw_aspnet | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-d976e162e716 | memos | POST /api/users/{user}/webhooks | Y | keep_user_self_subresource | O |
| v3s1b-9e3b5a87dc74 | memos | GET /api/users/{user}/usage | N | drop_owner_or_admin | O |
| v3s1-fe9d75c89f73 | petclinic_rest | PUT /specialties/{specialtyId} | Y | keep_reference_data_write | O |
| v3s1b-855b8ea4c5e9 | rw_fastify | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-7d260de829b5 | kutt | DELETE /api/links/{id} | N | drop_owner_or_admin | O |
| v3s1b-1530fe6a4a9f | rw_kotlin | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-a3b06ddb0440 | rw_laravel | DELETE /api/articles/{article} | Y | keep_realworld_article_comment_write | O |
| v3s1b-9dd5ff7f9f9b | rw_fastapi | PUT /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-d2f777699679 | rw_axum | - | - | (저장소 제외) | - |
| v3s1b-81467dd5ddd4 | rw_nest | DELETE /api/articles/{slug}/comments/{commentId} | Y | keep_realworld_article_comment_write | O |
| v3s1b-922263c3a4f7 | memos | DELETE /api/users/{user}/personalAccessTokens/{personalAccessToken} | Y | keep_user_self_subresource | O |
| v3s1b-bbda6d7eee64 | memos | DELETE /api/users/{user}/linkedIdentities/{linkedIdentity} | N | drop_owner_or_admin | O |
| v3s1-9de933d85b3c | petclinic_rest | DELETE /pettypes/{petTypeId} | Y | keep_reference_data_write | O |
| v3s1b-f6669aad0c3a | rw_koa | DELETE /api/articles/{slug} | Y | keep_realworld_article_comment_write | O |
| v3s1b-72ef24a683a7 | memos | POST /api/users/{user}/linkedIdentities | Y | keep_user_self_subresource | O |
| v3s1b-01a377f65a6b | memos | PATCH /api/users/{user} | N | drop_owner_or_admin | O |
| v3s1-ff63004954c8 | petclinic_rest | POST /owners/{ownerId}/pets/{petId}/visits | N | drop_owner_pet_visit | O |

## 한계

- role_required는 train 24건이 전부 Java(petclinic)다. 다른 언어의 역할 검사 출처가 없다(사용자 결정: 그대로 진행).
- owner_or_admin은 train 11건이 Go(memos)·JavaScript(kutt)뿐이고 변형이 없다(규칙상 전부 제외).
- val 28건(언어 csharp, javascript, python)은 목표 50건 안팎에 못 미친다. 실험 규칙대로 학습 정상 확인용으로만 쓴다.
- 라이선스 미선언 저장소가 있다(위 목록). Go·Java·TS·Kotlin·C#·PHP 변형은 파서 수준 문법 검사만 했다(컴파일 안 함).

## 검수 시트

`reports/data_v3/review_pairs_v3s1b_reviewed.xlsx` — 1단계 검수 40쌍을 뺀 40쌍(새 출처 35), (언어, label) 층별 균형(seed 42): csharp/owner_match 3, go/owner_match 5, go/owner_or_admin 5, java/role_required 5, javascript/owner_match 4, javascript/owner_or_admin 3, kotlin/owner_match 3, php/owner_match 3, python/owner_match 3, rust/owner_match 3, typescript/owner_match 3. 검수 완료본(rw_axum 2쌍 포함, 저장소 제외로 미반영).

## 산출물

- `datasets/blade/processed/data_v3_stage1b/pairs_train_v3s1b.jsonl` — 109건, SHA-256 `cc34308a149dee2d92998087002e6f63ab771d083cae07f5604d6828fdfab303`
- `datasets/blade/processed/data_v3_stage1b/pairs_val_v3s1b.jsonl` — 28건, SHA-256 `f1826e1c24957e42abbf4d60b6bc5aaeabbf99bd0b60893d1b9014bc8ccf7138`
- `datasets/blade/processed/data_v3_stage1b/manifest_v3s1b.json` — 변형 규칙·상한 제외 목록·새 저장소 커밋·원본 파일 SHA-256·탐지 집계

해시 가드(시작·종료): data-v1 a99d30da2d29907e…, 62bdadb29cae7aaf…, 9bd47216575afc60…, d0913c27b5de185e… / data-v2 f26c368d051e1ec2…, d0e216dd1267ba7f…, 32e23716422f43dc…, 9bd47216575afc60…, d0913c27b5de185e…. test_v30 읽기만 함. 학습·API 라벨링 없음.
