# BLADE 데이터셋 출처 전체 목록 (2026-11-01, 읽기 전용 조사)

- 대상: data-v1~v5 학습 데이터(train/val)와 보강분, test_v30, test_v31_supp, test_v5.
- 근거: `datasets/blade/DATA_CARD.md`, `AGENTS.md` 동결 절, 각 manifest(`data_v4/test_v31_supp_manifest.json`, `data_v5/test_v5_manifest.json`, `data_v5/train_v5_manifest.json`, `data_v3_stage1/manifest_v3s1.json`, `data_v3_stage1b/manifest_v3s1b.json`, `opensource/gitea_v28.2.0_manifest.json`, `opensource/netbox_v4.7.3_manifest.json`, `verification/test_frozen_manifest.json`, `verification/test_v30_manifest.json`), `data/raw_v4|raw_v5|raw_v5_train/<project>/SOURCE.md`, `reports/data_v2_freeze.md`, `reports/data_v3/stage1b_report.md`, `reports/data_v4_build.md`, `reports/data_v5/stop1_*.md`·`stop3_*.md`, `reports/eval/data_v2/vuln_api_candidates.md`, `.gitignore`.
- 사용 건수는 동결 파일을 SHA-256 대조(AGENTS.md 기록값과 일치 확인, 17개 파일 모두 OK)한 뒤 레코드의 `meta.source`/`meta.project`/`service`로 집계했다. 근거가 없는 칸은 "미기록"으로 둔다.
- 이 문서는 조사 결과만 담는다. 데이터·manifest·동결 파일은 수정하지 않았고 커밋하지 않았다.

## 1. 버전·split별 구성 요약

| 데이터 버전 | split | 건수 | 출처 구성(건수) |
|---|---|---:|---|
| data-v1 | train_v30 | 471 | APIs.guru 411(173 services) + 합성 60(orbit_tickets 14 · copper_wallet 14 · campus_records 14 · relay_forum 18) |
| data-v1 | val_v30 | 52 | APIs.guru 52(22 services) |
| data-v2 | train_v2 | 799 | APIs.guru 411 + Gitea 217 + 합성 171(원 4개 서비스 60 + 변형 57 + 신규 harbor_manifests 18 · pixel_gallery 18 · meadow_plots 18) |
| data-v2 | val_v2 | 98 | APIs.guru 52 + Gitea 28 + 합성 atlas_leases 18 |
| data-v3a | train_v3a | 930 | APIs.guru 411 + Gitea 239(217 + pool 22) + 합성 171 + 코드 쌍 109(13개 저장소) |
| data-v3b | train_v3b | 787 | APIs.guru 338(136 services) + Gitea 197 + 합성 143 + 코드 쌍 109 |
| data-v3 | val_v3 | 126 | val_v2 98 + 코드 쌍 val 28(4개 저장소) |
| data-v4 | train_v4 | 981 | train_v31b 787(= v3b 구성, rationale 문구만 치환) + Zulip 134 + Label Studio 60 |
| data-v4 | val_v4 | 148 | val_v31 126 + Zulip 16 + Label Studio 6 |
| data-v5 | train_v5 | 1,277 | train_v4 981 + Dendrite 95 + NodeBB 98 + Taiga 103 |
| data-v5 | val_v5 | 180 | val_v4 148 + Dendrite 10 + NodeBB 11 + Taiga 11 |
| 평가 | test_v30 | 269 | 공개 취약 API 211(juice-shop 69 · crAPI 53 · Pixi 52 · DVWS-node 25 · VAmPI 12) + 합성 58(quill_blog 14 · folio_wiki 14 · beacon_iot 14 · summit_club 16) |
| 평가 | test_v31_supp | 222 | Chatwoot 79 · Flowise 60 · Chamilo 58 · Generic University 21 · multitenant lab 4 |
| 평가 | test_v5 | 283 | Rocket.Chat 157 · Ghost 69 · Umami 57 |

data-v3.1b(train_v31b 787 / val_v31 126)는 data-v3b와 레코드·출처가 같고 학습 target 문구만 바뀐 버전이다. 모든 학습 버전의 평가셋은 test_v30이며, data-v4 이후 test_v31_supp, data-v5 이후 test_v5가 별도 조건으로 추가됐다.

## 2. 출처 상세

열: 데이터 버전/split · 프로젝트명 · 저장소 URL · 태그·커밋 · 라이선스 · 사용 건수 · 용도 · 공개 범위.
"공개 범위"는 현재 git 추적 상태(`.gitignore`, `git ls-files`) 기준이다. "코드 본문 공개" = 코드 발췌(controller_text)가 든 레코드 파일이 추적됨. "링크만" = manifest(id·저장소·커밋·고정 링크·label)만 추적되고 코드 본문 파일은 .gitignore.

### 2.1 APIs.guru 공개 OpenAPI (명세만, 코드 없음)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v1 train_v30 / val_v30 | APIs.guru openapi-directory | https://github.com/APIs-guru/openapi-directory | 커밋 `f04b8d0bcd39c52e1cf3ad7a5fe744709832ae49`(태그 없음) | CC0-1.0(디렉터리 LICENSE) | 411 / 52 (173 / 22 services) | train / val | 레코드 공개(train_v30·val_v30 추적). 원본 디렉터리 클론은 .gitignore |
| data-v2 train_v2 / val_v2 | 〃 | 〃 | 〃 | 〃 | 411 / 52 | train / val | 공개 |
| data-v3a train_v3a | 〃 | 〃 | 〃 | 〃 | 411 | train | 공개 |
| data-v3b·v3.1b·v4·v5 train | 〃 | 〃 | 〃 | 〃 | 338 (136 services) | train | v3b·v4 공개. train_v5.jsonl은 NodeBB 포함 때문에 파일 전체 .gitignore |
| data-v3·v4·v5 val | 〃 | 〃 | 〃 | 〃 | 52 (22 services) | val | val_v3·val_v4 공개, val_v5 .gitignore |
| test_v30 | (없음) | - | - | - | 0 | - | APIs.guru는 평가셋에 쓰지 않음 |

### 2.2 공개 취약 API (test_v30 전용, 코드 포함)

커밋은 test 레코드 meta에 없고 test 원천 파일 `processed/vuln_review_candidates.jsonl`의 `meta.commit`과 로컬 클론 HEAD(`datasets/blade/raw/vuln_apis/`, .gitignore)가 일치한다. 라이선스는 클론의 LICENSE 파일과 `reports/eval/data_v2/vuln_api_candidates.md`에서 확인했다(레코드 meta에는 미기록).

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| test_v30 (test.jsonl 253 포함) | OWASP Juice Shop | https://github.com/juice-shop/juice-shop | 커밋 `399fba76194305a312693eee44f4df64bdf0c3ce`(태그 미기록) | MIT | 69 | test | 코드 본문 공개(test_v30.jsonl 추적) |
| test_v30 | OWASP crAPI | https://github.com/OWASP/crAPI | 커밋 `b5fc307f3e5f875809b095b771108ef342a33724` | Apache-2.0 | 53 | test | 코드 본문 공개 |
| test_v30 | Pixi (DevSlop) | https://github.com/DevSlop/Pixi | 커밋 `cb716a94fa368acade96e9bdb8b25c1a68703e60` | Apache-2.0 | 52 | test | 코드 본문 공개 |
| test_v30 | DVWS-node (snoopysecurity) | https://github.com/snoopysecurity/dvws-node | 커밋 `eb6e2886f2206b88bf709fe1fa311adc3ae3c34f` | GPL-3.0 | 25 | test | 코드 본문 공개. GPL-3.0 발췌 공개 시 라이선스 고지 필요(DATA_CARD data-v2 고지 절). 레코드에 license_notice_required 표시 없음 |
| test_v30 | VAmPI (erev0s) | https://github.com/erev0s/VAmPI | 커밋 `f16052dce83f05847133ec98f01c5193a41de7d8` | MIT | 12 | test | 코드 본문 공개 |

### 2.3 합성 서비스 (자체 제작 fixture, 라이선스 파일 없음 → 라이선스 "미기록")

저장소 URL은 없고 원본은 저장소 안 `datasets/blade/raw/synthetic/`, `datasets/blade/raw/synthetic_v2/`(모두 git 추적)이다. 배정은 `training/data/synthetic_partition_v30.json`과 `data_v2_synthetic_additions.manifest.json`에 고정됐다(seed 42). 라벨은 intended_labels.yaml의 설계 의도다.

| 데이터 버전/split | 프로젝트명(프레임워크) | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v1~v5 train | orbit_tickets (FastAPI) | 자체 제작 | - | 미기록 | 14 (v3b 이후 12) | train | 코드·OAS·intended_labels 공개 |
| data-v1~v5 train | copper_wallet (Express) | 자체 제작 | - | 미기록 | 14 (v3b 이후 12) | train | 공개 |
| data-v1~v5 train | campus_records (Spring Boot) | 자체 제작 | - | 미기록 | 14 (v3b 이후 11) | train | 공개 |
| data-v1~v5 train | relay_forum (FastAPI, v3.0 그룹 멤버십) | 자체 제작 | - | 미기록 | 18 (v3b 이후 17) | train | 공개 |
| data-v2~v5 train | orbit_tickets_variants / copper_wallet_variants / campus_records_variants / relay_forum_variants (인가 제거 변형 authonly·extauth·extguard) | 자체 제작(`synthetic_v2/variants/`) | - | 미기록 | 12 / 12 / 12 / 21 (v3b 이후 10 / 9 / 8 / 16) | train | 공개 |
| data-v2~v5 train | harbor_manifests (Django REST) · pixel_gallery (NestJS) · meadow_plots (Gin) | 자체 제작(`synthetic_v2/`) | - | 미기록 | 각 18 (v3b 이후 각 16) | train | 공개 |
| data-v2~v5 val | atlas_leases (Rails) | 자체 제작(`synthetic_v2/`) | - | 미기록 | 18 | val | 공개 |
| test_v30 | quill_blog (FastAPI) · folio_wiki (Express) · beacon_iot (Django) | 자체 제작 | - | 미기록 | 각 14 | test | 공개 |
| test_v30 | summit_club (FastAPI, v3.0 그룹 멤버십) | 자체 제작 | - | 미기록 | 16 | test | 공개 |

### 2.4 Gitea (data-v2 이후 학습)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v2 train_v2 / val_v2 | Gitea | https://github.com/go-gitea/gitea | `v28.2.0` · `829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1` | MIT | 217 / 28 | train / val | 코드 본문 공개(train_v2·val_v2, `processed/opensource/gitea_v28.2.0_endpoints.jsonl` 추적). 클론은 발췌 후 삭제(2026-10-21) |
| data-v3a train_v3a | Gitea | 〃 | 〃 | MIT | 239 | train | 공개 |
| data-v3b·v4·v5 train / val | Gitea | 〃 | 〃 | MIT | 197 / 28 | train / val | train_v3b·v4 공개, v5 파일은 .gitignore |

Gitea 라벨은 gpt-4o-mini(프롬프트 v3.0.1) + 규칙(R1'·R4·VIS cap) + 사람 검수 56건이며 추출 455건 중 쿼터로 400건 상한을 적용했다(`reports/eval/data_v2/train_v2_composition_proposal.md`).

### 2.5 data-v3 코드 쌍 (검사 유지 원본 + 검사 제거 변형, 규칙 라벨)

건수는 pairs_train_v3s1b 109 / pairs_val_v3s1b 28의 레코드 수이며 data-v3a·v3b·v4·v5 train/val에 그대로 들어 있다(SFT에서는 4096 토큰 초과 memos 1건 제외). 라이선스는 레코드 `meta.license`; manifest의 "see repository"(rw_django)는 레코드에 MIT로 기록돼 있다.

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v3~v5 train | spring-petclinic-rest | https://github.com/spring-petclinic/spring-petclinic-rest | 커밋 `afc8fc1d3b8ec8de69414482b3bd70a1da78cb95` | Apache-2.0 | 24 | train | 코드 본문 공개 |
| data-v3~v5 train | memos | https://github.com/usememos/memos | 커밋 `6387991fdd1d1ae491b8435708357fa334e19f3a` | MIT | 24 | train | 공개 |
| data-v3~v5 train | kutt | https://github.com/thedevs-network/kutt | 커밋 `029da42b2459693681886665589fd9512d6b473c` | MIT | 3 | train | 공개 |
| data-v3~v5 train | RealWorld Spring Boot | https://github.com/gothinkster/spring-boot-realworld-example-app | 커밋 `ee17e31aafe733d98c4853c8b9a74d7f2f6c924a` | MIT | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Node/Express | https://github.com/gothinkster/node-express-realworld-example-app | 커밋 `30b68e1e881462b2f4164ea09ab4c4f5699c7b0b` | 미선언(none declared) | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Flask | https://github.com/gothinkster/flask-realworld-example-app | 커밋 `4b95fb2227dfeb5dd1a45d89b2bf48630b93fd28` | MIT | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Rails | https://github.com/gothinkster/rails-realworld-example-app | 커밋 `a2ae4fff78b3337683cea988c023281dcb5551b9` | 미선언 | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Go/Gin | https://github.com/gothinkster/golang-gin-realworld-example-app | 커밋 `626c372d259472148d93303f74aa9b9a1cdcef24` | MIT | 6 | train | 공개 |
| data-v3~v5 train | RealWorld NestJS (adr1enbe4udou1n) | https://github.com/adr1enbe4udou1n/nestjs-realworld-example-app | 커밋 `d4ddf3fd9ebd9112f117c0c6b2c5de3a76815c0c` | 미선언 | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Laravel | https://github.com/gothinkster/laravel-realworld-example-app | 커밋 `e45c37c8a5f57131c9d239f1fc104c227e66b6ee` | MIT | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Kotlin Spring | https://github.com/gothinkster/kotlin-spring-realworld-example-app | 커밋 `848c29e3abfe1bd72001cc7d7a3227aebec96e9b` | 미선언 | 6 | train | 공개 |
| data-v3~v5 train | RealWorld Koa | https://github.com/gothinkster/koa-knex-realworld-example | 커밋 `602e234139c453825eb3939cf24bdf00fc164e0e` | 미선언 | 4 | train | 공개 |
| data-v3~v5 train | RealWorld FastAPI (nsidnev) | https://github.com/nsidnev/fastapi-realworld-example-app | 커밋 `029eb7781c60d5f563ee8990a0cbfb79b244538c` | MIT | 6 | train | 공개 |
| data-v3~v5 val | full-stack-fastapi-template | https://github.com/fastapi/full-stack-fastapi-template | 커밋 `f4bcfaba7c85be3c6332cc74a20819f586dcdbc6` | MIT | 12 | val | 공개 |
| data-v3~v5 val | RealWorld ASP.NET Core | https://github.com/realworld-apps/aspnetcore-realworld-example-app | 커밋 `8aa617abed5dd645f8f9d99578a3e07b4e2e52e7` | MIT | 6 | val | 공개 |
| data-v3~v5 val | RealWorld Fastify | https://github.com/avanelli/fastify-realworld-example-app | 커밋 `bdb8ce4e130916a76970d8df1bf1a3291d0f5227` | MIT | 6 | val | 공개 |
| data-v3~v5 val | RealWorld Django REST (Sean-Miningah) | https://github.com/Sean-Miningah/realWorld-DjangoRestFramework | 커밋 `8e4729aaee0a3deef8fcf5ca53a02b1565440c97` | MIT(레코드) / "see repository"(manifest) | 4 | val | 공개 |

태그는 모든 코드 쌍 저장소에서 미기록(커밋만 고정). 라이선스 미선언 5개 저장소(Express·Rails·NestJS·Kotlin·Koa, 합계 28건)는 stage1b_report.md가 "학습 투입 전 확인 필요"로 기록했으나 이후 확인 기록은 없다.

### 2.6 data-v4 학습 보강분 (코드 규칙 라벨)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v4·v5 train / val | Zulip | https://github.com/zulip/zulip | `12.3` · `b31982251ff82d0b02e59f63ad21f19204e37aea` | Apache-2.0 | 134 / 16 | train / val | 코드 본문 공개(train_v4·val_v4, `data/raw_v4/zulip/candidates.jsonl` 추적) |
| data-v4·v5 train / val | Label Studio | https://github.com/HumanSignal/label-studio | `1.23.2` · `df96d79183156e556d91825d15fa7721f1145e1a` | Apache-2.0 | 60 / 6 | train / val | 코드 본문 공개 |

### 2.7 data-v5 학습 보강분 (코드 규칙 라벨)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| data-v5 train / val | Dendrite | https://github.com/matrix-org/dendrite | `v0.13.8` · `763c79f1421200c3fd74401fd68298bc00ecefbc` | Apache-2.0 | 95 / 10 (pool 20) | train / val | `data/raw_v5_train/dendrite/candidates.jsonl` 추적(코드 공개). train_v5·val_v5 파일은 NodeBB 때문에 .gitignore → 레코드 공개는 manifest(링크)만 |
| data-v5 train / val | NodeBB | https://github.com/NodeBB/NodeBB | `v4.16.5` · `c3d8dc512292a376f19e06cb93512bdff2505102` | GPL-3.0 | 98 / 11 (pool 30) | train / val | 링크만(`data_v5/train_v5_manifest.json`). candidates·rule_labeled·selected·pool·train_v5·val_v5·SFT·검수 xlsx 모두 .gitignore, meta.license_notice_required=true |
| data-v5 train / val | Taiga (taiga-back) | https://github.com/taigaio/taiga-back | `6.10.2` · `4b023d8414fc675780c6aae9d541b538c5c71369` | MPL-2.0 | 103 / 11 (pool 34) | train / val | `data/raw_v5_train/taiga/candidates.jsonl` 추적(코드 공개). 레코드 파일은 위와 같이 .gitignore |

Dendrite 레코드 82건(train 74 · val 8)의 `meta.tag`에 태그 대신 파일 경로(`clientapi/routing/room_tagging.go`)가 들어 있다. manifest·SOURCE.md의 태그는 `v0.13.8`이며 커밋은 동일하다(기록 오류, 데이터는 수정하지 않음).

### 2.8 test_v31_supp (평가 추가분, 학습 미사용)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| test_v31_supp | Chatwoot | https://github.com/chatwoot/chatwoot | `v4.19.1` · `caab07a8f00032d5205b5a5d7e2eb0ba2f3d2d82` | MIT (enterprise/ 제외) | 79 | test | 링크만(test_v31_supp.jsonl 전체가 .gitignore, manifest만 추적). `data/raw_v4/chatwoot/candidates.jsonl`은 추적 |
| test_v31_supp | Chamilo LMS | https://github.com/chamilo/chamilo-lms | `v2.0.0-RC.2` · `296654b9ce0e9b8d466808340a31c2666b9fc042` | GPL-3.0-or-later | 58 | test | 링크만. `data/raw_v4/chamilo/candidates.jsonl`은 추적 |
| test_v31_supp | Flowise (DocumentStore IDOR 포함) | https://github.com/FlowiseAI/Flowise | `flowise@3.0.13` · `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` | Apache-2.0; 60건 중 53건 발췌에 `packages/server/src/enterprise/`(FlowiseAI 상용 라이선스) 포함 | 60 | test | 링크만. candidates.jsonl도 .gitignore |
| test_v31_supp | Generic University (InsiderPhD) | https://github.com/InsiderPhD/Generic-University | master · `50dfa924b3a31d30c6d6c20373bc9f4dced8aac8`(태그 없음) | 미선언(NOASSERTION) | 21 | test | 링크만. candidates.jsonl .gitignore |
| test_v31_supp | cloud-security-multitenant-lab | https://github.com/RimaBenJaballah/cloud-security-multitenant-lab | main · `a428c4f85d479c932f49323ebc9b8c5e7e47f8fc`(태그 없음) | 미선언(NOASSERTION) | 4 | test | 링크만. candidates.jsonl .gitignore |

제외 41건(G8, 의도 불명확·경계)은 `data_v4/test_v31_supp_excluded.jsonl`(추적)에 사유와 함께 있다.

### 2.9 test_v5 (hold-out 평가셋)

| 데이터 버전/split | 프로젝트명 | 저장소 URL | 태그·커밋 | 라이선스 | 사용 건수 | 용도 | 공개 범위 |
|---|---|---|---|---|---:|---|---|
| test_v5 | Rocket.Chat | https://github.com/RocketChat/Rocket.Chat | `8.9.0` · `057a927d903c83b5d61cf236d650c4500ebb4b66` | MIT (`apps/meteor/ee/`·`ee/` EE 라이선스 코드 0건) | 157 | test | 코드 본문 공개(test_v5.jsonl·`data/raw_v5/rocketchat/candidates.jsonl` 추적) |
| test_v5 | Ghost | https://github.com/TryGhost/Ghost | `v6.73.0` · `5794cfd8daca61fd60cd8659acd6591ece3b7956` | MIT | 69 | test | 코드 본문 공개 |
| test_v5 | Umami | https://github.com/umami-software/umami | `v3.4.1` · `559e3c607c23d2c72d9bd4f6481bda428255323c` | MIT | 57 | test | 코드 본문 공개 |

제외 13건(G8)은 `data_v5/test_v5_excluded.jsonl`(추적)에 사유와 함께 있다.

## 3. 제외한 출처와 사유

| 출처 | 검토 단계 | 제외 사유 | 근거 |
|---|---|---|---|
| launchbadge/realworld-axum-sqlx (rw_axum, Rust) | data-v3 1b 코드 쌍 | AGPL-3.0, 사용자 결정 2026-10-26. 검수 시트의 해당 3쌍도 "(저장소 제외)" 처리 | reports/data_v3/stage1b_report.md, AGENTS.md data-v3 라벨 기준 |
| Mattermost | data-v4 학습 지시서 | AGPL-3.0 → Zulip(Apache-2.0)으로 대체, 사용자 결정 2026-10-27 | reports/data_v4_build.md 1절, AGENTS.md data-v4 동결 |
| Plane | data-v4 학습 지시서 | AGPL-3.0 → Label Studio(Apache-2.0)로 대체 | 〃 |
| Discourse | test_v5 후보 | APIs.guru 라벨링 풀에 `discourse.local` 9건(manual pool)이 있어 출처 겹침 | reports/data_v5/stop1_test_v5_candidates.md |
| Mastodon · Lemmy · Nextcloud · Cal.com | test_v5 후보 | AGPL | 〃 |
| Gogs · Forgejo | test_v5 후보 | Gitea 포크(data-v2 학습 출처와 계보 동일) | 〃 |
| Appwrite · GitLab | test_v5 후보 | APIs.guru train 서비스(appwrite.io, gitlab.com)와 겹침 | 〃 |
| Rocket.Chat · Ghost · Umami와 포크 | data-v5 학습 보강분 | test_v5 출처는 학습에 쓰지 않는다는 규칙 | AGENTS.md 작업 C, stop3 보고서 |
| gothinkster/django-realworld-example-app | data-v3 1단계 | 명시적 인가 검사 0건이라 쌍을 만들 수 없음(대신 Sean-Miningah 저장소 채택) | manifest_v3s1.json repositories.rw_django.why |
| lujakob · mikro-orm · mutoe · neo4j-examples NestJS RealWorld | data-v3 1b | 수정/삭제 핸들러에 소유자 검사 없음 | stage1b_report.md, manifest_v3s1b.json |
| gothinkster/elixir-phoenix-realworld-example-app | data-v3 1b | 소유자 검사 없음(세션 403만) | stage1b_report.md |
| teamhephy/controller | data-v3 1b (owner_or_admin 출처 후보) | `IsOwnerOrAdmin`이 정의만 있고 ViewSet은 협업자 권한 섞인 `IsAppUser` | stage1b_report.md |
| NetBox v4.7.3 (`3cd2c1d6`, Apache-2.0) | data-v2 held-out test 예정 | 1,256 operation 추출, 185건 제안 + LLM 참고 라벨(`netbox_v4.7.3_heldout185_llmref.jsonl`)까지 만들었으나 사람 확정·동결 없음. 어떤 동결 train/val/test에도 미포함. 미사용 사유 문서는 미기록 | processed/opensource/netbox_v4.7.3_manifest.json, reports/eval/data_v2/netbox_extraction_rules.md, train_v2_composition_proposal.md |
| vAPI (roottusk, `67152695`, GPL-3.0) · Damn Vulnerable RESTaurant (theowni, `d32d0997`, GPL-3.0) | data-v2 추가 취약 API(test_v2_extra) | 후보 파일(`test_v2_extra_candidates.jsonl`)과 LLM 참고 라벨만 있고 동결 test에 미포함(DATA_CARD: 별도 파일로 두고 test_v30에 합치지 않음). 이후 확정 기록 미기록. 클론은 삭제됨 | DATA_CARD data-v2 라이선스 고지 절, reports/untracked_artifacts.md 7절 |
| Checkmarx/capital | data-v2 취약 API 후보 조사 | AGPL-3.0(2순위, 미수집) | reports/eval/data_v2/vuln_api_candidates.md |
| payatu/Tiredful-API · appsecco/dvcsharp-api · Aif4thah/VulnerableLightApp · bnematzadeh/vulnerable-rest-api | 〃 | 2·3순위로 미수집(개별 사유 미기록) | 〃 |
| snoopysecurity/dvws (PHP 원본) | 〃 | DVWS-node와 원작자·계보 동일 | 〃 |
| payatu/DVAPI · Erdemstar/VulnerableApp4APISecurity 등 | 〃 | 라이선스 파일 없음 | 〃 |
| dolevf/Damn-Vulnerable-GraphQL-Application | 〃 | GraphQL(REST OAS 없음) | 〃 |
| cr0hn/vulnerable-node | 〃 | 라이선스 NOASSERTION, 확인 전 보류 | 〃 |
| InsiderPhD/Generic-University | data-v2 취약 API 후보 조사 | 라이선스 없음으로 제외됐으나, data-v4에서 평가 전용(test_v31_supp 21건, 코드 비공개)으로 사용됨. 학습 제외는 유지 | vuln_api_candidates.md, data/raw_v4/generic_university/SOURCE.md |
| Rocket.Chat `apps/meteor/ee/`·`ee/`, Chatwoot `enterprise/`, Flowise enterprise 라우트 | 추출 단계(디렉터리 단위) | 상용(EE) 라이선스. Rocket.Chat·Chatwoot는 체크아웃·인용 모두 제외. Flowise는 인가 경로에 enterprise 코드가 섞여 발췌에 포함됐고 그 때문에 test 파일 비공개 | 각 SOURCE.md |
| Label Studio 저장소 백엔드 변형(S3·GCS·Azure·Redis·Local) | data-v4 선정 | 거의 같은 코드 → 그룹당 1건만(76건 제외) | reports/data_v4_build.md 2절 |
| Dendrite send·invite·unban·state PUT 등, NodeBB 채팅 추방 | data-v5 규칙 라벨 | power level 검사가 핸들러 밖(event auth)이거나 "구성원 + 본인 OR 방 역할" 복합이라 라벨 불가(라벨 없이 제외, 16→정지 지점 3 후 20건) | reports/data_v5/stop3_decisions_applied.md, AGENTS.md 정지 지점 3 |
| data-v5 보강분 pool 84건(Dendrite 20 · NodeBB 30 · Taiga 34) | data-v5 선정 | manual 10% 쿼터·Taiga 댓글 계열 자원당 2건 축소로 미선정(출처 제외가 아니라 레코드 보류) | data_v5/train_v5_pool.jsonl(.gitignore), train_v5_manifest.json split=pool |

**DocumentStore 정정**: 지시문의 "DocumentStore"에 해당하는 출처는 Flowise의 DocumentStore IDOR(GHSA-3prp-9gf7-4rxx, CVE-2026-41277, 수정 커밋 `840d2ae1`)이며, 이는 제외된 출처가 아니라 test_v31_supp에 Flowise 60건으로 **포함**돼 있다(2.8절). 별도 "DocumentStore" 출처를 제외한 기록은 저장소 어디에도 없다. 공개 시 코드 본문을 제외하는 것(enterprise 상용 라이선스)과 출처 제외는 다른 조치다.

## 4. APIs.guru 사용 규모와 스냅샷

| 항목 | 값 | 근거 |
|---|---|---|
| 원본 | APIs-guru/openapi-directory, 커밋 `f04b8d0bcd39c52e1cf3ad7a5fe744709832ae49`(업스트림 커밋 일자 2026-04-20, "Mention BrowserStack testing in README") | 로컬 클론 `datasets/blade/raw/openapi-directory`(.gitignore) HEAD, reports/untracked_artifacts.md |
| 스냅샷(클론) 시점 | **2026-10-13**(클론 디렉터리 생성 시각 13:25, 후보 파일 `apisguru_candidates.jsonl` 생성 13:57). 명시적 스냅샷 날짜 문서는 미기록이며 파일 시각으로 추정 | 파일 시스템 타임스탬프 |
| 라이선스 | CC0-1.0 | 클론 LICENSE |
| 후보 추출 | 4,333 operation / 424 services | datasets/blade/raw/apisguru_candidates.jsonl |
| 라벨 대상(v2.5·v3.0.1 동일 입력) | 2,027 operation / **370 services** | datasets/blade/processed/apisguru_labeled_v301.jsonl |
| data-v1 사용 | train 411건 / 173 services, val 52건 / 22 services (manual 쿼터 25%, 미선택 manual 1,428건은 apisguru_manual_pool_v30.jsonl) | train_v30·val_v30 집계 |
| data-v2·v3a 사용 | train 411 / 173, val 52 / 22 (불변) | train_v2·train_v3a·val_v2·val_v3 집계 |
| data-v3b·v3.1b·v4·v5 사용 | train 338건 / 136 services, val 52 / 22 (manual 쿼터 10%로 축소) | train_v3b·v4·v5 집계 |
| 명세 출처 기록 | 레코드 `meta.source_file` = `<service>/<version>/openapi.yaml` 상대 경로 | apisguru_labeled_v301.jsonl |

"서비스"는 openapi-directory의 provider 디렉터리 이름(예: `1password.local`, `gitlab.com`)이다. 라벨은 gpt-4o-mini + 프롬프트 v3.0.1(oas 조건)이며 사람 확정 라벨이 아니다.

## 5. 미기록·주의 항목

- 공개 취약 API 5종의 태그는 미기록(커밋만). 커밋·라이선스는 test 레코드 meta에 없고 후보 파일·클론 LICENSE에서 확인했다.
- 합성 서비스 12종(+변형 4종)은 자체 제작이라 라이선스 파일이 없다(미기록).
- data-v3 코드 쌍 저장소는 태그 미기록이며 라이선스 미선언 저장소 5개(28건)가 train에 들어 있다. stage1b_report.md가 "학습 투입 전 확인 필요"로 적었고 이후 확인 기록은 없다.
- DVWS-node(GPL-3.0) 코드 발췌 25건은 공개 추적 파일 test_v30.jsonl에 들어 있다. DATA_CARD(data-v2 라이선스 고지 절)는 GPL-3.0 발췌 공개 시 고지가 필요하다고 적었으나 해당 레코드에는 `license_notice_required` 표시가 없다.
- Dendrite 레코드 82건의 `meta.tag`가 파일 경로로 잘못 기록돼 있다(manifest·SOURCE.md는 `v0.13.8`).
- NetBox·test_v2_extra(vAPI·DVRestaurant)는 수집·참고 라벨까지 진행됐으나 미사용 결정 사유가 문서에 없다(미기록).
- 라벨 방법 요약: APIs.guru = LLM(gpt-4o-mini, v3.0.1); 합성 = 설계 의도; Gitea = LLM + 규칙 + 사람 검수 56건; data-v3 코드 쌍·data-v4·data-v5 보강분 = 코드 규칙(사람 표본 검수); test_v30 취약 API = 사람 확정(2026-10-20); test_v31_supp = AI 확정 + 사람 표본 확인; test_v5 = AI 1차 + 사람 확인(범위 미기록, 사용자 전달 예정).
