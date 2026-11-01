# data-v3 1단계 — 실제 오픈소스 핸들러 "검사 유지/제거" 쌍 (학습·API 라벨링 없음)

빌더 `training/data/build_data_v3_pairs.py`, seed 42. 쌍 63개 = 레코드 126건(원본 63 + 변형 63). label은 원본 코드의 검사 내용으로 규칙 결정했고 변형 label = 원본 label이다. 사람 확정 전이며 동결하지 않았다.

## 저장소 (커밋 고정)

| key | 저장소 | 커밋 | 언어/프레임워크 | 스타 | split | OAS | 쌍 | 선정 이유 |
|---|---|---|---|---:|---|---|---:|---|
| rw_spring | [gothinkster/spring-boot-realworld-example-app](https://github.com/gothinkster/spring-boot-realworld-example-app) | `ee17e31aafe7` | java / Spring Boot | 1596 | train | generated | 3 | RealWorld Spring, most stars |
| rw_express | [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | `30b68e1e8814` | typescript / Express | 3797 | train | generated | 3 | RealWorld Express/Node, most stars |
| rw_django | [Sean-Miningah/realWorld-DjangoRestFramework](https://github.com/Sean-Miningah/realWorld-DjangoRestFramework) | `8e4729aaee0a` | python / Django REST Framework | 66 | val | generated | 2 | RealWorld Django by stars after gothinkster/django-realworld-example-app (1648 stars, 0 explicit authorization checks -> nothing to pair) |
| rw_flask | [gothinkster/flask-realworld-example-app](https://github.com/gothinkster/flask-realworld-example-app) | `4b95fb2227df` | python / Flask | 899 | train | generated | 3 | RealWorld Flask, most stars |
| rw_rails | [gothinkster/rails-realworld-example-app](https://github.com/gothinkster/rails-realworld-example-app) | `a2ae4fff78b3` | ruby / Rails | 423 | train | generated | 3 | RealWorld Rails, most stars |
| rw_gin | [gothinkster/golang-gin-realworld-example-app](https://github.com/gothinkster/golang-gin-realworld-example-app) | `626c372d2594` | go / Gin | 2718 | train | generated | 3 | RealWorld Go, most stars |
| fastapi_tpl | [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) | `f4bcfaba7c85` | python / FastAPI | 46068 | val | generated | 10 | superuser dependency and owner-or-superuser checks; earlier used as isolated eval (external_paired_v29) -> kept out of train |
| petclinic_rest | [spring-petclinic/spring-petclinic-rest](https://github.com/spring-petclinic/spring-petclinic-rest) | `afc8fc1d3b8e` | java / Spring Boot | 631 | train | repository_spec | 36 | @PreAuthorize role checks on every protected handler (petclinic.security.enable=false by default; intended policy still the annotation) |

선정에서 뺀 저장소: gothinkster/django-realworld-example-app(커밋 `29c9d42831fa`) — 핸들러에 명시적 인가 검사가 0건이라 쌍을 만들 수 없다. c4ffein/realworld-django-ninja는 클론했으나 스타 순 2순위가 아니어서 쓰지 않았다(클론만 남음, gitignore).

test_v30 서비스: DVWS-node, Pixi, VAmPI, beacon_iot, crAPI, folio_wiki, juice-shop, quill_blog, summit_club — 선정 저장소와 겹침 없음. vAPI·DVRestaurant의 test_v30 포함 여부: {'vAPI': False, 'DVRestaurant': False} → 미포함이라 사용 가능하나 이번 단계에서는 쓰지 않았다(취약 설계 앱은 원본에 검사가 빠진 경우가 많아 '검사 명확 원본' 조건에 맞지 않음). controller_text가 test_v30 발췌와 겹치는 레코드: 0건.

## 건수 (레코드 = 원본 + 변형)

| split | 저장소 | 레코드 |
|---|---|---:|
| train | rw_spring | 6 |
| train | rw_express | 6 |
| train | rw_flask | 6 |
| train | rw_rails | 6 |
| train | rw_gin | 6 |
| train | petclinic_rest | 72 |
| **train 합계** | | **102** |
| val | rw_django | 4 |
| val | fastapi_tpl | 20 |
| **val 합계** | | **24** |

| label | train | val |
|---|---:|---:|
| owner_match | 30 | 4 |
| owner_or_admin | 0 | 8 |
| role_required | 72 | 12 |

| 언어 | train | val |
|---|---:|---:|
| go | 6 | 0 |
| java | 78 | 0 |
| python | 6 | 24 |
| ruby | 6 | 0 |
| typescript | 6 | 0 |

| 규칙 (rule_id) | label | 쌍 | 근거 |
|---|---|---:|---|
| owner_compare | owner_match | 13 | requester id compared with the object owner id; mismatch -> 403/401 |
| owner_or_parent_owner | owner_match | 1 | requester must own the object or its parent object (comment author or article author); no admin path |
| owner_filter | owner_match | 3 | object lookup filtered by the requester as owner (author = current user) |
| owner_or_superuser | owner_or_admin | 3 | superuser passes; otherwise requester must own the object, else 403 |
| self_or_superuser | owner_or_admin | 1 | requester may read their own user record; any other record requires superuser, else 403 |
| superuser_dependency | role_required | 6 | route dependency get_current_active_superuser: non-superuser -> 403 |
| role_annotation | role_required | 36 | @PreAuthorize hasRole/hasAnyRole on the handler method |

**목표 대비**: 코드 val 목표 150건 이상 → 실제 24건(미달). 선정 기준(RealWorld 6 + 중형 1~2)으로는 검사가 명확한 핸들러 자체가 적다(RealWorld 구현당 2~3개). val 150건을 채우려면 역할·소유자 검사가 많은 저장소를 val 전용으로 2~4개 더 넣어야 한다.

## 탐지와 제외

검사 패턴(403·Forbidden·PreAuthorize·is_superuser·소유자 비교·소유자 필터 등) 탐지 109줄 = 채택 핸들러 안 82 + 제외 규칙 27 + 미설명 0. 탐지된 줄이 채택·제외 어느 쪽에도 속하지 않으면 빌더가 중단한다.

| 저장소 | 파일 | 제외 사유 |
|---|---|---|
| rw_spring | src/main/java/io/spring/graphql/ArticleMutation.java | GraphQL mutation: no REST route / OAS operation |
| rw_spring | src/main/java/io/spring/graphql/CommentMutation.java | GraphQL mutation: no REST route / OAS operation |
| rw_spring | (전체) | import line |
| rw_flask | conduit/articles/views.py | make_article: sets the author of a new article, not a check |
| rw_express | src/app/routes/auth/auth.service.ts | login credential failure (403), not an authorization check |
| fastapi_tpl | backend/app/api/routes/items.py | read_items: list scoping branch (superuser sees all, others own) — no removable check line |
| fastapi_tpl | backend/app/api/routes/users.py | delete_user_me / delete_user: self-delete guard for superusers, not an access check |
| fastapi_tpl | (전체) | import line |
| petclinic_rest | (전체) | import line |

변형 생성 후 제외(문법 실패·검사 잔존·무변화): 0건

## 변형 규칙

- 검사 문장(if 블록·애너테이션·의존성 인자·쿼리 소유자 필터)과 거기에 붙은 주석, 검사에만 쓰이던 조회 줄(Gin의 요청자·존재 조회)을 지운다. Rails의 `if 소유자 … else 403 end`는 본문만 남기고 한 단계 내어쓴다.
- 지운 자리에 빈 줄이 겹치면 하나로 줄인다. 그 밖의 줄은 바이트 동일(발췌 공통 들여쓰기 제거는 원본·변형 같게 적용).
- 원본 발췌의 검사 헬퍼(Spring `AuthorizationService`, FastAPI `get_current_active_superuser`)는 변형 핸들러가 더 이상 부르지 않으므로 변형 발췌에서 빠진다.
- 수정한 파일 전체를 tree-sitter(언어별 문법)로 파싱해 ERROR/MISSING 노드가 없을 때만 채택, Python은 `ast.parse`도 통과해야 한다. Go·Java·TS는 컴파일러가 없어 파서 수준 검사다(미사용 변수 같은 컴파일 오류는 확인하지 않음).
- OAS: petclinic-rest는 저장소 `openapi.yml`의 operation 발췌 + 참조 스키마(명세에 security 선언 없음 → security_state=unknown). 나머지는 라우트·경로 파라미터만으로 만든 최소 OAS(description 빈 문자열, summary 없음, 라우트 인증 미들웨어가 있어 bearer security 선언 → declared). 원본·변형의 OAS는 같다.

## 주의 (학습 투입 전 결정 필요)

- **변형 label의 근거**: 지시대로 변형 label = 원본 label이다. data-v2 기준은 '검사가 빠져도 경로·스키마로 의도가 드러나면 그 정책, 아니면 manual'이다. petclinic-rest 변형 36건(`@PreAuthorize`만 제거)은 경로·명세(security 선언 없음)로 역할을 읽을 근거가 없고, RealWorld 변형(빈 description의 최소 OAS)도 경로만으로는 owner_match 근거가 약하다. 검수 시트의 `variant_label_inferable_from_path_schema` 열로 판정한 뒤 변형 label을 유지할지 정해야 한다.
- **분포 쏠림**: train 레코드 102건 중 petclinic-rest(Java·role_required)가 72건이다. train에는 owner_or_admin이 없고(전부 val의 fastapi_tpl), val은 Python만 있다.
- **val 크기**: 위 목표 대비 참조. 체크포인트·문턱 선택에 쓰기에는 작다.

## 사람 검수 시트

`reports/data_v3/review_pairs_v3s1.xlsx` — 쌍 40건, (언어, label) 층마다 한 건씩 돌아가며 뽑아 작은 층은 전부 포함(seed 42). 층별: go/owner_match 3, java/owner_match 3, java/role_required 13, python/owner_match 5, python/owner_or_admin 4, python/role_required 6, ruby/owner_match 3, typescript/owner_match 3. reviewer 열은 비워 두었다. 검수 결과를 학습·프롬프트 예시에 쓰려면 별도 승인이 필요하다.

## 산출물

- `datasets/blade/processed/data_v3_stage1/pairs_train_v3s1.jsonl` — 102건, SHA-256 `fddf09bf1b046cea83a2227e98870831f0df58ad0ba3e6011a27cb6d83fb6418`
- `datasets/blade/processed/data_v3_stage1/pairs_val_v3s1.jsonl` — 24건, SHA-256 `b3816655df0d01f6a9c2e248ffc443a48229644eca080b5ef02b1b98c4553265`
- `datasets/blade/processed/data_v3_stage1/manifest_v3s1.json` — 저장소·커밋·원본 파일 SHA-256·탐지 집계·제외 목록
- 클론: `datasets/blade/raw/opensource/<owner>_<repo>/` (gitignore, 경로·커밋만 기록)

해시 가드(시작·종료): data-v1 a99d30da2d29907e…, 62bdadb29cae7aaf…, 9bd47216575afc60…, d0913c27b5de185e… / data-v2 f26c368d051e1ec2…, d0e216dd1267ba7f…, 32e23716422f43dc…, 9bd47216575afc60…, d0913c27b5de185e…. test_v30은 읽기만 했다. 학습·API 라벨링 없음.
