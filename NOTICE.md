# NOTICE — 출처별 라이선스와 링크

이 저장소의 **라벨·rationale·메타데이터·합성 서비스·문서**는 CC BY 4.0([LICENSE](LICENSE))입니다. 레코드의 `controller_text`, SFT user 메시지 안의 코드, `data/*/candidates.jsonl`, `datasets/blade/raw/*`의 fixture 등 **제3자 코드 발췌는 아래 원 저장소의 라이선스를 그대로 따릅니다.** 각 발췌는 레코드 `meta.source_locations`(파일·줄 범위)와 manifest의 고정 링크로 원 위치를 확인할 수 있습니다. 재배포가 허용 라이선스로 보장되지 않는 출처(GPL-3.0, 상용 EE 라이선스, 라이선스 미선언)의 코드 본문은 포함하지 않았습니다. 상세 조사 기록: [reports/data_sources.md](reports/data_sources.md).

## 1. 명세만 사용(코드 없음)

| 출처 | 저장소 | 커밋 | 라이선스 | 용도 |
|---|---|---|---|---|
| APIs.guru openapi-directory (370 services, 2,027 operations) | https://github.com/APIs-guru/openapi-directory | `f04b8d0bcd39c52e1cf3ad7a5fe744709832ae49` (스냅샷 2026-10-13) | CC0-1.0 (디렉터리). 개별 명세의 저작권은 각 API 제공자 | data-v1~v5 train/val |

## 2. 코드 발췌 포함 — 허용 라이선스(본문 공개)

| 출처 | 저장소 | 태그 · 커밋 | 라이선스 | 용도 |
|---|---|---|---|---|
| OWASP Juice Shop | https://github.com/juice-shop/juice-shop | `399fba76194305a312693eee44f4df64bdf0c3ce` | MIT | test_v30 (69) |
| OWASP crAPI | https://github.com/OWASP/crAPI | `b5fc307f3e5f875809b095b771108ef342a33724` | Apache-2.0 | test_v30 (53) |
| Pixi (DevSlop) | https://github.com/DevSlop/Pixi | `cb716a94fa368acade96e9bdb8b25c1a68703e60` | Apache-2.0 | test_v30 (52) |
| VAmPI (erev0s) | https://github.com/erev0s/VAmPI | `f16052dce83f05847133ec98f01c5193a41de7d8` | MIT | test_v30 (12) |
| Gitea | https://github.com/go-gitea/gitea | `v28.2.0` · `829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1` | MIT | data-v2~v5 train/val |
| NetBox | https://github.com/netbox-community/netbox | `v4.7.3` · `3cd2c1d6…` | Apache-2.0 | 후보 추출만(동결 셋 미포함, `processed/opensource/`) |
| spring-petclinic-rest | https://github.com/spring-petclinic/spring-petclinic-rest | `afc8fc1d3b8ec8de69414482b3bd70a1da78cb95` | Apache-2.0 | data-v3~v5 코드 쌍 train |
| memos | https://github.com/usememos/memos | `6387991fdd1d1ae491b8435708357fa334e19f3a` | MIT | 코드 쌍 train |
| kutt | https://github.com/thedevs-network/kutt | `029da42b2459693681886665589fd9512d6b473c` | MIT | 코드 쌍 train |
| RealWorld Spring Boot | https://github.com/gothinkster/spring-boot-realworld-example-app | `ee17e31aafe733d98c4853c8b9a74d7f2f6c924a` | MIT | 코드 쌍 train |
| RealWorld Flask | https://github.com/gothinkster/flask-realworld-example-app | `4b95fb2227dfeb5dd1a45d89b2bf48630b93fd28` | MIT | 코드 쌍 train |
| RealWorld Go/Gin | https://github.com/gothinkster/golang-gin-realworld-example-app | `626c372d259472148d93303f74aa9b9a1cdcef24` | MIT | 코드 쌍 train |
| RealWorld Laravel | https://github.com/gothinkster/laravel-realworld-example-app | `e45c37c8a5f57131c9d239f1fc104c227e66b6ee` | MIT | 코드 쌍 train |
| RealWorld FastAPI (nsidnev) | https://github.com/nsidnev/fastapi-realworld-example-app | `029eb7781c60d5f563ee8990a0cbfb79b244538c` | MIT | 코드 쌍 train |
| full-stack-fastapi-template | https://github.com/fastapi/full-stack-fastapi-template | `f4bcfaba7c85be3c6332cc74a20819f586dcdbc6` | MIT | 코드 쌍 val |
| RealWorld ASP.NET Core | https://github.com/realworld-apps/aspnetcore-realworld-example-app | `8aa617abed5dd645f8f9d99578a3e07b4e2e52e7` | MIT | 코드 쌍 val |
| RealWorld Fastify | https://github.com/avanelli/fastify-realworld-example-app | `bdb8ce4e130916a76970d8df1bf1a3291d0f5227` | MIT | 코드 쌍 val |
| RealWorld Django REST (Sean-Miningah) | https://github.com/Sean-Miningah/realWorld-DjangoRestFramework | `8e4729aaee0a3deef8fcf5ca53a02b1565440c97` | MIT (레코드 기록; manifest는 "see repository") | 코드 쌍 val |
| Zulip | https://github.com/zulip/zulip | `12.3` · `b31982251ff82d0b02e59f63ad21f19204e37aea` | Apache-2.0 | data-v4·v5 train/val |
| Label Studio | https://github.com/HumanSignal/label-studio | `1.23.2` · `df96d79183156e556d91825d15fa7721f1145e1a` | Apache-2.0 | data-v4·v5 train/val |
| Dendrite | https://github.com/matrix-org/dendrite | `v0.13.8` · `763c79f1421200c3fd74401fd68298bc00ecefbc` | Apache-2.0 | data-v5 train/val (meta.tag 오기는 DATA_CARD Errata 참조) |
| Taiga (taiga-back) | https://github.com/taigaio/taiga-back | `6.10.2` · `4b023d8414fc675780c6aae9d541b538c5c71369` | MPL-2.0 | data-v5 train/val. MPL-2.0 3.1·3.2항에 따라 발췌 파일의 출처(저장소·커밋·파일·줄)를 레코드 meta에 기록했습니다 |
| Chatwoot (`enterprise/` 제외) | https://github.com/chatwoot/chatwoot | `v4.19.1` · `caab07a8f00032d5205b5a5d7e2eb0ba2f3d2d82` | MIT | test_v31_supp (79). 후보 파일 `data/raw_v4/chatwoot/candidates.jsonl`은 공개, 동결 test 파일은 비공개(아래 3절 Flowise 사유) |
| Rocket.Chat (`apps/meteor/ee/`·`ee/` 제외) | https://github.com/RocketChat/Rocket.Chat | `8.9.0` · `057a927d903c83b5d61cf236d650c4500ebb4b66` | MIT | test_v5 (157) |
| Ghost | https://github.com/TryGhost/Ghost | `v6.73.0` · `5794cfd8daca61fd60cd8659acd6591ece3b7956` | MIT | test_v5 (69) |
| Umami | https://github.com/umami-software/umami | `v3.4.1` · `559e3c607c23d2c72d9bd4f6481bda428255323c` | MIT | test_v5 (57) |
| EMB / WFD 벤치마크 Java 서비스(`datasets/blade/raw/source_pilot_wfd/`) | 각 폴더의 LICENSE 참조 | - | Apache-2.0 | 조건 추출 실험 fixture |
| `datasets/blade/raw/external_conditions_v1/`, `external_paired_v29/`, `paired_policy_v1/`, `adapter_v3_holdout/` | 각 폴더의 LICENSE·README 참조 | - | 각 폴더 LICENSE | 어댑터 실험 fixture |

## 3. 코드 본문을 포함하지 않은 출처(라벨·링크만)

| 출처 | 저장소 | 커밋 | 라이선스 | 처리 |
|---|---|---|---|---|
| DVWS-node (snoopysecurity) | https://github.com/snoopysecurity/dvws-node | `eb6e2886f2206b88bf709fe1fa311adc3ae3c34f` | GPL-3.0 | test_v30 25건: 공개 사본에서 `controller_text` 비움, `withheld_manifest.json`으로 복원 |
| NodeBB | https://github.com/NodeBB/NodeBB | `v4.16.5` · `c3d8dc512292a376f19e06cb93512bdff2505102` | GPL-3.0 | data-v5 109건(train 98 · val 11): 코드 비움, `data_v5/train_v5_manifest.json`·`withheld_manifest.json` |
| RealWorld Node/Express | https://github.com/gothinkster/node-express-realworld-example-app | `30b68e1e881462b2f4164ea09ab4c4f5699c7b0b` | 미선언 | 코드 쌍 6건 코드 비움 |
| RealWorld Rails | https://github.com/gothinkster/rails-realworld-example-app | `a2ae4fff78b3337683cea988c023281dcb5551b9` | 미선언 | 코드 쌍 6건 코드 비움 |
| RealWorld NestJS (adr1enbe4udou1n) | https://github.com/adr1enbe4udou1n/nestjs-realworld-example-app | `d4ddf3fd9ebd9112f117c0c6b2c5de3a76815c0c` | 미선언 | 코드 쌍 6건 코드 비움 |
| RealWorld Kotlin Spring | https://github.com/gothinkster/kotlin-spring-realworld-example-app | `848c29e3abfe1bd72001cc7d7a3227aebec96e9b` | 미선언 | 코드 쌍 6건 코드 비움 |
| RealWorld Koa | https://github.com/gothinkster/koa-knex-realworld-example | `602e234139c453825eb3939cf24bdf00fc164e0e` | 미선언 | 코드 쌍 4건 코드 비움 |
| Chamilo LMS | https://github.com/chamilo/chamilo-lms | `v2.0.0-RC.2` · `296654b9ce0e9b8d466808340a31c2666b9fc042` | GPL-3.0-or-later | test_v31_supp 58건: manifest 링크만, 후보 파일 미포함 |
| Flowise | https://github.com/FlowiseAI/Flowise | `flowise@3.0.13` · `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` | Apache-2.0, 단 발췌 53/60건이 `packages/server/src/enterprise/`(FlowiseAI 상용 라이선스) 포함 | test_v31_supp 60건: 링크만 |
| Generic University (InsiderPhD) | https://github.com/InsiderPhD/Generic-University | `50dfa924b3a31d30c6d6c20373bc9f4dced8aac8` | 미선언 | test_v31_supp 21건: 링크만 |
| cloud-security-multitenant-lab | https://github.com/RimaBenJaballah/cloud-security-multitenant-lab | `a428c4f85d479c932f49323ebc9b8c5e7e47f8fc` | 미선언 | test_v31_supp 4건: 링크만 |
| vAPI (roottusk) · Damn Vulnerable RESTaurant (theowni) | https://github.com/roottusk/vapi · https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game | `67152695…` · `d32d0997…` | GPL-3.0 | 후보 조사만(동결 셋 미포함). 후보 파일 미포함 |

## 4. 제외한 출처

AGPL-3.0 프로젝트(launchbadge/realworld-axum-sqlx, Mattermost, Plane, Mastodon, Lemmy, Nextcloud, Cal.com, Checkmarx/capital)와 상용 EE 디렉터리(Rocket.Chat `ee/`, Chatwoot `enterprise/`)는 수집 단계에서 제외했습니다. 사유는 [reports/data_sources.md](reports/data_sources.md) 3절.

## 5. 라벨 생성에 쓴 모델

APIs.guru 구간의 train 라벨은 OpenAI `gpt-4o-mini`(프롬프트 v3.0.1)로 생성했고, 코드 구간은 코드 규칙(`training/data/rule_label_v4.py`, `rule_label_v5.py`)과 사람 검수로 확정했습니다. 베이스라인·파인튜닝 베이스 모델은 Qwen2.5-7B-Instruct(Apache-2.0)입니다. 모델 가중치는 이 저장소에 없습니다.
