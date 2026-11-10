# 작업 C0 — v3.1 학습 정답 재작성 영향 행 분석 (2026-11-05, 학습·추론 없음, 커밋 금지)

생성: `scripts/c0_impact_v6d.py`. 대상 data-v5 SFT 행 train 1,274 / val 179 = 1453건(processed train_v5·val_v5에서 4096 토큰 초과로 SFT에 없는 4건 제외: v3s1b-01a377f65a6b-orig, v4-zulip-53bce36a36, v4-zulip-9fc47b3754, v4-label_studio-0cfa3eac15). 동결 파일은 해시 확인 후 읽기만 했다. 후보 추출은 입력(코드·미들웨어 체인·OAS 텍스트)과 규칙 라벨러 특징(meta.rule_v4/rule_v5/rule_id, auth_checks kind)만 썼고 정답 label은 비교 단계에서만 읽었다. rationale 분석은 실제 학습 target인 SFT assistant(train_sft_v5/val_sft_v5)를 기준으로 했다(processed rationale과 21건이 다름: data-v2 규칙 relabel 문장 — C2는 SFT assistant를 출발점으로 삼아야 한다). 산출: 행 단위 표 `c0_rows.csv`(1행 = 1레코드, 아래 모든 열), 후보 `c0_candidates.jsonl`, 집계 `c0_summary.json`, 무작위 5% 표본 id `c0_audit_sample_ids.json`.

**설계 변경(2026-11-05 사용자 결정, AGENTS.md "작업 C′" 절)**: 아래 설계 전제는 C0 당시 지시이며 C′로 대체됐다 — C′ = v5 설정 그대로(프롬프트 v3.0.1, label 먼저, 4096/256, 하이퍼파라미터 동일) + 학습 정답(label·rationale)만 교정, 비교는 C′ vs v5, user 입력은 data-v5 SFT와 바이트 동일.

설계 전제(C0 당시 지시, 대체됨): C는 S5(v6a) 설정(프롬프트 v3.1 `e8b6c506…`, 출력 순서 evidence→rationale→label→confidence, max_seq_len 6144, 그 외 v5 하이퍼파라미터)을 그대로 두고 학습 정답(label·rationale)만 v3.1 정의(label_defs_v3.1_draft.md)와 G1~G8에 맞춘다. C vs S5 = 정답 정합 효과, C vs v5 = 최종 비교. user 입력은 data_v6a와 바이트 동일하게 유지한다. test_v6은 추론하지 않는다.

## 1. 행별 출처·라벨 출처·사람 검수 여부

### 1.1 출처(프로젝트·APIs.guru·합성)

| split | 출처 | 건수: |
|---|---|---:|
| train | APIs.guru | 338 |
| train | 오픈소스 프로젝트 | 793 |
| train | 합성 | 143 |
| val | APIs.guru | 52 |
| val | 오픈소스 프로젝트 | 109 |
| val | 합성 | 18 |

| 프로젝트/출처 | 전체: | train: | val: |
|---|---:|---:|---:|
| APIs.guru | 390 | 338 | 52 |
| gitea | 225 | 197 | 28 |
| zulip | 148 | 132 | 16 |
| taiga | 114 | 103 | 11 |
| nodebb | 109 | 98 | 11 |
| dendrite | 105 | 95 | 10 |
| label_studio | 65 | 60 | 5 |
| 합성:relay_forum | 33 | 33 | 0 |
| spring-petclinic/spring-petclinic-rest | 24 | 24 | 0 |
| usememos/memos | 23 | 23 | 0 |
| 합성:orbit_tickets | 22 | 22 | 0 |
| 합성:copper_wallet | 21 | 21 | 0 |
| 합성:campus_records | 19 | 19 | 0 |
| 합성:atlas_leases | 18 | 0 | 18 |
| 합성:harbor_manifests | 16 | 16 | 0 |
| 합성:pixel_gallery | 16 | 16 | 0 |
| 합성:meadow_plots | 16 | 16 | 0 |
| fastapi/full-stack-fastapi-template | 12 | 0 | 12 |
| gothinkster/spring-boot-realworld-example-app | 6 | 6 | 0 |
| gothinkster/flask-realworld-example-app | 6 | 6 | 0 |
| gothinkster/golang-gin-realworld-example-app | 6 | 6 | 0 |
| gothinkster/rails-realworld-example-app | 6 | 6 | 0 |
| gothinkster/node-express-realworld-example-app | 6 | 6 | 0 |
| adr1enbe4udou1n/nestjs-realworld-example-app | 6 | 6 | 0 |
| gothinkster/laravel-realworld-example-app | 6 | 6 | 0 |
| gothinkster/kotlin-spring-realworld-example-app | 6 | 6 | 0 |
| nsidnev/fastapi-realworld-example-app | 6 | 6 | 0 |
| realworld-apps/aspnetcore-realworld-example-app | 6 | 0 | 6 |
| avanelli/fastify-realworld-example-app | 6 | 0 | 6 |
| gothinkster/koa-knex-realworld-example | 4 | 4 | 0 |
| Sean-Miningah/realWorld-DjangoRestFramework | 4 | 0 | 4 |
| thedevs-network/kutt | 3 | 3 | 0 |

### 1.2 라벨 출처(규칙 라벨러 / LLM / 사람 검수 / 합성 설계)

| split | 라벨 출처(1차) | 건수: |
|---|---|---:|
| train | LLM(gpt-4o-mini, v3.0.1) | 535 |
| train | 규칙 라벨러 rule_label_v4 | 192 |
| train | 규칙 라벨러 rule_label_v5 | 296 |
| train | 규칙 라벨러(검사 줄 규칙, data-v3 1b) | 108 |
| train | 합성 설계 intended_labels | 143 |
| val | LLM(gpt-4o-mini, v3.0.1) | 80 |
| val | 규칙 라벨러 rule_label_v4 | 21 |
| val | 규칙 라벨러 rule_label_v5 | 32 |
| val | 규칙 라벨러(검사 줄 규칙, data-v3 1b) | 28 |
| val | 합성 설계 intended_labels | 18 |

| split | 라벨 출처(세부: 1차 → data-v2 규칙 relabel / 사람 검수 교정) | 건수: |
|---|---|---:|
| train | LLM(gpt-4o-mini, v3.0.1) | 449 |
| train | 규칙 라벨러 rule_label_v5 | 296 |
| train | 규칙 라벨러 rule_label_v4 | 192 |
| train | 합성 설계 intended_labels | 124 |
| train | 규칙 라벨러(검사 줄 규칙, data-v3 1b) | 108 |
| train | LLM(gpt-4o-mini, v3.0.1) → 사람 검수 교정(data-v2) | 39 |
| train | LLM(gpt-4o-mini, v3.0.1) → data-v2 규칙 relabel(R1_self_owner) | 30 |
| train | 합성 설계 intended_labels → data-v2 규칙 relabel(variant_intended_policy) | 19 |
| train | LLM(gpt-4o-mini, v3.0.1) → data-v2 규칙 relabel(R4_noauth_public) | 9 |
| train | LLM(gpt-4o-mini, v3.0.1) → data-v2 규칙 relabel(R1_self_split) | 8 |
| val | LLM(gpt-4o-mini, v3.0.1) | 75 |
| val | 규칙 라벨러 rule_label_v5 | 32 |
| val | 규칙 라벨러(검사 줄 규칙, data-v3 1b) | 28 |
| val | 규칙 라벨러 rule_label_v4 | 21 |
| val | 합성 설계 intended_labels | 18 |
| val | LLM(gpt-4o-mini, v3.0.1) → data-v2 규칙 relabel(R4_noauth_public) | 5 |

### 1.3 사람 검수 여부와 적용 규약

행이 어느 검수 시트에 들어 있었는가(검수 시트의 검수자 열 표기를 그대로 적음):

| split | 검수 | 건수: | 적용 규약 |
|---|---|---:|---|
| train | v2 | 62 | data-v2 라벨 기준(2026-10-23, G 이전: 저장소 권한 레벨→role, org/팀→membership, VIS→manual, AUTH_ANY→manual, VIS+SELF) |
| train | v3 | 93 | data-v3 1b 쌍 검수(원본 label 정확·변형 유지 가능 판정; 라벨은 검사 줄 규칙, G 규약 아님; 검수자 열 "Claude 1차(사용자 확인 필요)") |
| train | v4 | 35 | data-v4 검수 규약 G1~G8(검수자 열 "Claude (AI 검수, 사람 확인 필요)") |
| train | v5 | 65 | data-v4 검수 규약 G1~G8 + 정지 지점 3 수정(검수자 열 "이혜인") |
| train | 없음 | 1019 | — |
| val | v3 | 26 | data-v3 1b 쌍 검수(원본 label 정확·변형 유지 가능 판정; 라벨은 검사 줄 규칙, G 규약 아님; 검수자 열 "Claude 1차(사용자 확인 필요)") |
| val | v4 | 5 | data-v4 검수 규약 G1~G8(검수자 열 "Claude (AI 검수, 사람 확인 필요)") |
| val | v5 | 8 | data-v4 검수 규약 G1~G8 + 정지 지점 3 수정(검수자 열 "이혜인") |
| val | 없음 | 140 | — |

- data-v5 검수 시트 90행(검수자 이혜인, G1~G8 + 정지 지점 3 수정 규칙) 중 train/val에 있는 행 73건(나머지는 제외 전환·pool 이동). data-v4 검수 시트 71행(두 시트, 검수자 열 "Claude (AI 검수, 사람 확인 필요)") 중 train/val에 있는 행 40건. data-v3 1b 쌍 검수(검수자 열 "Claude 1차(사용자 확인 필요)") 80쌍은 원본 label 정확 여부와 변형 유지 가능 여부를 봤고 G 규약 적용이 아니다 — 해당 행 119건. data-v2 사람 검수(review_sheet A/B/C + r3, 2026-10-23 라벨 기준) 62건은 G 이전 기준이지만 내용상 G3(저장소 권한 레벨→role)·G2(org/팀 멤버십)·G6-a(VIS)·G6-c(AUTH_ANY)와 같은 결론이다.
- G1~G8을 명시 적용한 검수를 거친 행은 data-v4·v5 검수분 113건(7.8%)뿐이고, 그중 사람(이혜인)이 확정한 행은 data-v5 73건이다. 나머지 1340건의 라벨은 LLM(v3.0.1 프롬프트, 615건)·G 규약 기반 규칙 라벨러(rule_label_v4/v5, 미검수분)·검사 줄 규칙(data-v3)·합성 설계에서 왔다.

## 2. v3.1 변경 규칙별 영향 후보 (입력 기준 추출)

탐지 방식: (a) G 규약으로 설계된 규칙 라벨러 프로젝트(Zulip·Label Studio·Dendrite·NodeBB·Taiga)는 규칙 이름·auth_checks kind만 사용(코드 정규식은 보일러플레이트 때문에 과검출), (b) LLM 라벨 프로젝트(gitea 미들웨어 체인·핸들러 본문, memos·kutt·realworld 등)는 미들웨어 이름·코드 정규식, (c) APIs.guru(OAS만)는 설명 문구 정규식 → 항상 `?`(판정 필요), (d) data-v3 쌍은 rule_id. 판정 종류: `rule` = 결정적 예측, `review` = 정규식 기반이라 C1에서 확인, `?` = 규칙만으로 label을 정할 수 없음, `=` = 현행 유지 점검만(OAS만 있는 생성 요청). 한 행이 여러 규칙에 걸릴 수 있다.

| 규칙 | 내용 | 후보: | 예상 변경(예측≠현재): | 판정 필요(?): | 유지 예상: |
|---|---|---:|---:|---:|---:|
| G3-a | 그룹 안 역할(구성원 확인 뒤 그룹 안 역할) → role_required | 148 | 28 | 4 | 116 |
| G3-b/G6-c | 객체 없는 RBAC 권한 → role_required, 모든 역할 보유 권한·인증만 → manual | 67 | 3 | 2 | 62 |
| G1-b | tenant 필터 + 기능 RBAC → tenant_match | 40 | 0 | 10 | 30 |
| G1-c | 생성 시 tenant 강제 → tenant_match | 2 | 0 | 0 | 2 |
| G7-a | 코드 근거 익명(declared mutation 포함) → public | 60 | 1 | 0 | 59 |
| G7-b | 조건부 익명 → manual | 33 | 0 | 0 | 33 |
| G2-b | 구성원 OR 관리자 → membership_required | 40 | 0 | 6 | 34 |
| G4-c/G6-b | 설정 의존 본인 분기(설정 제한만 우회 → owner_match / 분기 자체 → manual) | 11 | 0 | 2 | 9 |
| G5 | 당사자 OR 관리자 → owner_or_admin | 71 | 6 | 0 | 65 |
| G6-a | 다른 유형 OR 분기 → manual | 84 | 0 | 35 | 49 |
| 생성(절차5) | 생성 요청 라벨링 절차 5 | 21 | 0 | 2 | 19 |

- G7-a 세부: 코드상 인증 없는 행 60건 중 security_state=declared인 mutation(POST/PUT/PATCH/DELETE)은 6건(v4-zulip-18186d3562:public, v5-dendrite-167e69969f:public, v5-dendrite-96f495b4c6:public, v5-dendrite-a164737e92:public, v5-dendrite-ce2459efd9:public, v5-nodebb-35755854a9:public) — v3.0.1이 금지하던 "declared mutation public" 조합은 학습 데이터에 거의 없고, declared GET public은 v3.0.1에서도 허용되던 경우다.
- G3-a 세부: 유지 예상 116건은 rule_label_v5 group_role(Taiga 프로젝트 역할·NodeBB 카테고리 모더레이터·Dendrite power level)·rule_label_v4 zulip_realm_admin·gitea reqRepoWriter/reqAdmin이 이미 role_required인 행이다. 변경 예상의 대부분은 gitea reqOrgOwnership(조직 소유자 = 그룹 안 역할)을 LLM이 owner_match로 읽은 행이다.

규칙별 후보의 현재 label × 예상 label(행 상태가 변경 예상·판정 필요인 행만):

| 규칙 | 현재 label | 예상 label | 건수: | 그중 검수 행: |
|---|---|---|---:|---:|
| G3-a | owner_match | role_required | 23 | 0 |
| G3-a | manual_review_required | role_required | 5 | 0 |
| G3-a | role_required | ? | 2 | 0 |
| G3-a | owner_match | ? | 2 | 0 |
| G3-b/G6-c | role_required | ? | 2 | 0 |
| G3-b/G6-c | manual_review_required | owner_match | 2 | 0 |
| G3-b/G6-c | membership_required | owner_match | 1 | 0 |
| G1-b | role_required | ? | 7 | 0 |
| G1-b | tenant_match | ? | 2 | 0 |
| G1-b | membership_required | ? | 1 | 0 |
| G7-a | role_required | public | 1 | 0 |
| G2-b | role_required | ? | 3 | 0 |
| G2-b | membership_required | ? | 1 | 0 |
| G2-b | manual_review_required | ? | 1 | 0 |
| G2-b | tenant_match | ? | 1 | 0 |
| G4-c/G6-b | owner_match | ? | 2 | 1 |
| G5 | manual_review_required | ? | 3 | 0 |
| G5 | owner_match | owner_or_admin | 1 | 0 |
| G5 | owner_match | ? | 1 | 0 |
| G5 | owner_or_admin | ? | 1 | 1 |
| G6-a | manual_review_required | ? | 16 | 6 |
| G6-a | owner_match | ? | 15 | 5 |
| G6-a | owner_or_admin | ? | 2 | 2 |
| G6-a | role_required | ? | 1 | 1 |
| G6-a | membership_required | ? | 1 | 0 |
| 생성(절차5) | manual_review_required | ? | 2 | 0 |

## 3. 바뀔 가능성 있는 행 목록

행 상태(한 행 = 하나의 상태; 결정적 규칙 예측이 하나면 그것을 쓰고, 서로 다른 결정적 예측이 충돌하면 `?`):

| split | 상태 | 건수: |
|---|---|---:|
| train | 변경 예상 | 28 |
| train | 유지 예상 | 411 |
| train | 판정 필요 | 52 |
| train | 후보 아님 | 783 |
| val | 변경 예상 | 5 |
| val | 유지 예상 | 54 |
| val | 판정 필요 | 9 |
| val | 후보 아님 | 111 |

- **변경 예상 33건**(이 중 사람·AI 검수 행 0건은 "유지 후보"로 별도 표시), **판정 필요 61건**(코드 근거 39 · OAS 문구만 22). 전체 목록은 c0_candidates.jsonl(`status` 열).

변경 유형(v3.1 규칙 변경으로 바뀌는 행인지, v3.0.1 기준으로도 틀려 있던 label의 교정인지):

| 변경 유형 | 건수: |
|---|---:|
| v3.1 규칙 변경(보류 3 → role_required) | 28 |
| 경계 명문화(보류 6·G4 본인 목록) → 기존 label 교정 | 3 |
| v3.1 확장(당사자 OR 관리자) | 1 |
| v3.1 규칙 변경(declared mutation) 또는 교정(GET) | 1 |

현재 label → 예상 label(변경 예상 행):

| 현재 | 예상 | 건수: |
|---|---|---:|
| owner_match | role_required | 23 |
| manual_review_required | role_required | 5 |
| manual_review_required | owner_match | 2 |
| owner_match | owner_or_admin | 1 |
| role_required | public | 1 |
| membership_required | owner_match | 1 |

변경 예상 행 전부(검수 행은 ★ — 기존 검수 label 유지 후보):

| id | split | 프로젝트 | method path | 현재 | 예상 | 규칙 | 근거 |
|---|---|---|---|---|---|---|---|
| gitea:get:/notifications | train | gitea | GET /notifications | manual_review_required | owner_match | G3-b/G6-c | G3-b/G6-c: gitea reqToken만 + 본인 경로(/user, /notifications): G4 본인 목록·설정 |
| gitea:patch:/orgs/{org} | train | gitea | PATCH /orgs/{org} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org} | train | gitea | DELETE /orgs/{org} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/orgs/{org}/avatar | train | gitea | POST /orgs/{org}/avatar | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/avatar | train | gitea | DELETE /orgs/{org}/avatar | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:get:/orgs/{org}/blocks | train | gitea | GET /orgs/{org}/blocks | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:get:/orgs/{org}/blocks/{username} | train | gitea | GET /orgs/{org}/blocks/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:put:/orgs/{org}/blocks/{username} | train | gitea | PUT /orgs/{org}/blocks/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/blocks/{username} | train | gitea | DELETE /orgs/{org}/blocks/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:get:/orgs/{org}/hooks | train | gitea | GET /orgs/{org}/hooks | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/orgs/{org}/hooks | train | gitea | POST /orgs/{org}/hooks | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:get:/orgs/{org}/hooks/{id} | train | gitea | GET /orgs/{org}/hooks/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:patch:/orgs/{org}/hooks/{id} | train | gitea | PATCH /orgs/{org}/hooks/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/hooks/{id} | train | gitea | DELETE /orgs/{org}/hooks/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/orgs/{org}/labels | train | gitea | POST /orgs/{org}/labels | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:patch:/orgs/{org}/labels/{id} | train | gitea | PATCH /orgs/{org}/labels/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/labels/{id} | train | gitea | DELETE /orgs/{org}/labels/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/members/{username} | train | gitea | DELETE /orgs/{org}/members/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/orgs/{org}/rename | train | gitea | POST /orgs/{org}/rename | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/orgs/{org}/repos | train | gitea | DELETE /orgs/{org}/repos | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/orgs/{org}/teams | val | gitea | POST /orgs/{org}/teams | manual_review_required | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:post:/repos/{owner}/{repo}/actions/runs/{run}/force-cancel | train | gitea | POST /repos/{owner}/{repo}/actions/runs/{run}/force-cancel | manual_review_required | role_required | G3-a | G3-a: gitea middleware reqRepoWriter |
| gitea:put:/repos/{owner}/{repo}/branches/{branch} | val | gitea | PUT /repos/{owner}/{repo}/branches/{branch} | manual_review_required | role_required | G3-a | G3-a: gitea middleware reqRepoWriter |
| gitea:get:/repos/{owner}/{repo}/hooks/git | val | gitea | GET /repos/{owner}/{repo}/hooks/git | manual_review_required | role_required | G3-a | G3-a: gitea middleware reqAdmin |
| gitea:get:/repos/{owner}/{repo}/push_mirrors | train | gitea | GET /repos/{owner}/{repo}/push_mirrors | manual_review_required | role_required | G3-a | G3-a: gitea middleware reqAdmin |
| gitea:get:/settings/ui | val | gitea | GET /settings/ui | role_required | public | G7-a | G7-a: 코드상 인증 없음 [declared GET: v3.0.1에서도 public 가능 → 교정] |
| gitea:patch:/teams/{id} | train | gitea | PATCH /teams/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/teams/{id} | train | gitea | DELETE /teams/{id} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:put:/teams/{id}/members/{username} | train | gitea | PUT /teams/{id}/members/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:delete:/teams/{id}/members/{username} | train | gitea | DELETE /teams/{id}/members/{username} | owner_match | role_required | G3-a | G3-a: gitea middleware reqOrgOwnership |
| gitea:get:/user | train | gitea | GET /user | manual_review_required | owner_match | G3-b/G6-c | G3-b/G6-c: gitea reqToken만 + 본인 경로(/user, /notifications): G4 본인 목록·설정 |
| gitea:get:/user/hooks/{id} | train | gitea | GET /user/hooks/{id} | owner_match | owner_or_admin | G5 | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin |
| gitea:get:/user/teams | val | gitea | GET /user/teams | membership_required | owner_match | G3-b/G6-c | G3-b/G6-c: gitea reqToken만 + 본인 경로(/user, /notifications): G4 본인 목록·설정 |

판정 필요 행(`?`) — 규칙 조합·프로젝트별:

| 규칙 조합 | 프로젝트 | 근거 종류 | 건수: |
|---|---|---|---:|
| G6-a | gitea | 코드 | 30 |
| G1-b | APIs.guru | OAS 문구 | 10 |
| G2-b | APIs.guru | OAS 문구 | 6 |
| G5;G6-a | gitea | 코드 | 5 |
| G3-a | APIs.guru | OAS 문구 | 4 |
| G3-b/G6-c | APIs.guru | OAS 문구 | 2 |
| G4-c/G6-b | zulip | 코드 | 2 |
| 생성(절차5) | gitea | 코드 | 2 |

판정 필요 행 중 코드 근거 행 전부:

| id | 프로젝트 | method path | 현재 | 규칙 | 근거 |
|---|---|---|---|---|---|
| gitea:post:/orgs | gitea | POST /orgs | manual_review_required | 생성(절차5) | 생성(절차5): gitea reqToken만 + 생성(핸들러가 ctx.Doer 사용): 본인 명의면 owner_match, 아니면 보류 |
| gitea:get:/orgs/{org}/members | gitea | GET /orgs/{org}/members | membership_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:get:/orgs/{org}/members/{username} | gitea | GET /orgs/{org}/members/{username} | manual_review_required | G5;G6-a | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin / G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:get:/packages/{owner} | gitea | GET /packages/{owner} | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:post:/packages/{owner}/{type}/{name}/-/unlink | gitea | POST /packages/{owner}/{type}/{name}/-/unlink | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:get:/packages/{owner}/{type}/{name}/{version} | gitea | GET /packages/{owner}/{type}/{name}/{version} | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/migrate | gitea | POST /repos/migrate | manual_review_required | 생성(절차5) | 생성(절차5): gitea reqToken만 + 생성(핸들러가 ctx.Doer 사용): 본인 명의면 owner_match, 아니면 보류 |
| ★gitea:get:/repos/{owner}/{repo}/collaborators | gitea | GET /repos/{owner}/{repo}/collaborators | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:delete:/repos/{owner}/{repo}/contents/{filepath} | gitea | DELETE /repos/{owner}/{repo}/contents/{filepath} | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/{owner}/{repo}/contents/{filepath} | gitea | POST /repos/{owner}/{repo}/contents/{filepath} | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/{owner}/{repo}/diffpatch | gitea | POST /repos/{owner}/{repo}/diffpatch | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:post:/repos/{owner}/{repo}/forks | gitea | POST /repos/{owner}/{repo}/forks | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/{owner}/{repo}/issues | gitea | POST /repos/{owner}/{repo}/issues | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:patch:/repos/{owner}/{repo}/issues/comments/{id} | gitea | PATCH /repos/{owner}/{repo}/issues/comments/{id} | owner_or_admin | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/assets | gitea | POST /repos/{owner}/{repo}/issues/{index}/assets | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/assignees | gitea | POST /repos/{owner}/{repo}/issues/{index}/assignees | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:delete:/repos/{owner}/{repo}/issues/{index}/dependencies | gitea | DELETE /repos/{owner}/{repo}/issues/{index}/dependencies | role_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:delete:/repos/{owner}/{repo}/issues/{index}/reactions | gitea | DELETE /repos/{owner}/{repo}/issues/{index}/reactions | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:delete:/repos/{owner}/{repo}/issues/{index}/stopwatch/delete | gitea | DELETE /repos/{owner}/{repo}/issues/{index}/stopwatch/delete | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/stopwatch/start | gitea | POST /repos/{owner}/{repo}/issues/{index}/stopwatch/start | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/stopwatch/stop | gitea | POST /repos/{owner}/{repo}/issues/{index}/stopwatch/stop | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| ★gitea:get:/repos/{owner}/{repo}/issues/{index}/subscriptions/check | gitea | GET /repos/{owner}/{repo}/issues/{index}/subscriptions/check | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/times | gitea | GET /repos/{owner}/{repo}/issues/{index}/times | manual_review_required | G5;G6-a | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin / G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/times | gitea | POST /repos/{owner}/{repo}/issues/{index}/times | manual_review_required | G5;G6-a | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin / G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 |
| ★gitea:get:/repos/{owner}/{repo}/notifications | gitea | GET /repos/{owner}/{repo}/notifications | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| ★gitea:put:/repos/{owner}/{repo}/notifications | gitea | PUT /repos/{owner}/{repo}/notifications | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:post:/repos/{owner}/{repo}/pulls | gitea | POST /repos/{owner}/{repo}/pulls | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:get:/repos/{owner}/{repo}/subscription | gitea | GET /repos/{owner}/{repo}/subscription | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:put:/repos/{owner}/{repo}/subscription | gitea | PUT /repos/{owner}/{repo}/subscription | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:delete:/repos/{owner}/{repo}/subscription | gitea | DELETE /repos/{owner}/{repo}/subscription | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| ★gitea:get:/repos/{owner}/{repo}/teams | gitea | GET /repos/{owner}/{repo}/teams | manual_review_required | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:get:/repos/{owner}/{repo}/times | gitea | GET /repos/{owner}/{repo}/times | owner_or_admin | G5;G6-a | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin / G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 |
| gitea:post:/repos/{owner}/{repo}/transfer | gitea | POST /repos/{owner}/{repo}/transfer | owner_match | G5;G6-a | G5: gitea 핸들러 본문 본인/소유자 // IsAdmin / G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| ★gitea:post:/repos/{owner}/{repo}/transfer/reject | gitea | POST /repos/{owner}/{repo}/transfer/reject | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요 |
| gitea:get:/user/starred/{owner}/{repo} | gitea | GET /user/starred/{owner}/{repo} | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:put:/user/starred/{owner}/{repo} | gitea | PUT /user/starred/{owner}/{repo} | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| gitea:delete:/user/starred/{owner}/{repo} | gitea | DELETE /user/starred/{owner}/{repo} | owner_match | G6-a | G6-a: gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름 |
| ★v4-zulip-33f060c699 | zulip | DELETE /api/v1/users/me/avatar | owner_match | G4-c/G6-b | G4-c/G6-b: 설정 avatar_changes_disabled + 본인 대상(설정이 꺼지면 관리자만 가능 → 보류 5 manual / 설정 제한만 우회 → owner_match) |
| v4-zulip-d025c91689 | zulip | POST /api/v1/users/me/avatar | owner_match | G4-c/G6-b | G4-c/G6-b: 설정 avatar_changes_disabled + 본인 대상(설정이 꺼지면 관리자만 가능 → 보류 5 manual / 설정 제한만 우회 → owner_match) |

## 4. 집계

### 4.1 label 분포 변화 예상(변경 예상 행만 반영; 판정 필요 행은 현재 label 유지로 계산)

| label | 현재: | 예상: | 차이: |
|---|---:|---:|---:|
| public | 95 | 96 | 1 |
| role_required | 376 | 403 | 27 |
| membership_required | 85 | 84 | -1 |
| tenant_match | 91 | 91 | 0 |
| owner_match | 492 | 471 | -21 |
| owner_or_admin | 109 | 110 | 1 |
| manual_review_required | 205 | 198 | -7 |

manual 비율: 현재 14.1% → 예상 13.6%(판정 필요 61건의 결과에 따라 달라짐; data-v5 SFT train 기준 12.79%).

### 4.2 프로젝트별(전체·변경 예상·판정 필요)

| 프로젝트 | 전체: | 변경 예상: | 판정 필요: | 변경 비율: |
|---|---:|---:|---:|---:|
| APIs.guru | 390 | 0 | 22 | 0.0% |
| gitea | 225 | 33 | 37 | 14.7% |
| zulip | 148 | 0 | 2 | 0.0% |
| taiga | 114 | 0 | 0 | 0.0% |
| nodebb | 109 | 0 | 0 | 0.0% |
| dendrite | 105 | 0 | 0 | 0.0% |
| label_studio | 65 | 0 | 0 | 0.0% |
| 합성:relay_forum | 33 | 0 | 0 | 0.0% |
| spring-petclinic/spring-petclinic-rest | 24 | 0 | 0 | 0.0% |
| usememos/memos | 23 | 0 | 0 | 0.0% |
| 합성:orbit_tickets | 22 | 0 | 0 | 0.0% |
| 합성:copper_wallet | 21 | 0 | 0 | 0.0% |
| 합성:campus_records | 19 | 0 | 0 | 0.0% |
| 합성:atlas_leases | 18 | 0 | 0 | 0.0% |
| 합성:harbor_manifests | 16 | 0 | 0 | 0.0% |
| 합성:pixel_gallery | 16 | 0 | 0 | 0.0% |
| 합성:meadow_plots | 16 | 0 | 0 | 0.0% |
| fastapi/full-stack-fastapi-template | 12 | 0 | 0 | 0.0% |
| gothinkster/spring-boot-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/flask-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/golang-gin-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/rails-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/node-express-realworld-example-app | 6 | 0 | 0 | 0.0% |
| adr1enbe4udou1n/nestjs-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/laravel-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/kotlin-spring-realworld-example-app | 6 | 0 | 0 | 0.0% |
| nsidnev/fastapi-realworld-example-app | 6 | 0 | 0 | 0.0% |
| realworld-apps/aspnetcore-realworld-example-app | 6 | 0 | 0 | 0.0% |
| avanelli/fastify-realworld-example-app | 6 | 0 | 0 | 0.0% |
| gothinkster/koa-knex-realworld-example | 4 | 0 | 0 | 0.0% |
| Sean-Miningah/realWorld-DjangoRestFramework | 4 | 0 | 0 | 0.0% |
| thedevs-network/kutt | 3 | 0 | 0 | 0.0% |

### 4.3 v3.0.1 전용 논리를 쓴 rationale(label 유지 행 포함)

SFT assistant rationale에 v3.0.1에서만 타당하거나 v3.1과 어긋나는 표현이 든 행 수:

| 표현 유형 | 건수: |
|---|---:|
| 조직 소유자를 owner로 해석 | 24 |
| AND 결합·복합 조건 보류 | 20 |
| security 선언을 public 거부 근거로 사용 | 4 |
| 구성원+역할을 보류 사유로 | 2 |

label 유지 예상·후보 아님 행 중 위 표현이 든 행: 13건(c0_rows.csv `rationale_v301_wording` 열). "security 선언" 문구는 OAS만 있는 행에서는 v3.1에서도 유효하다(코드 없이 OAS만 있을 때 security 선언·mutation 제한 유지). 코드가 있는 행에서만 재작성 대상이다: 0건. "AND 결합" 문구는 합성 tenant AND membership(보류 3 유지)에서는 유효하고, LLM rationale의 복합 조건 보류 3건은 v3.1 예외(그룹 안 역할·tenant+RBAC)에 해당하는지 C1에서 본다.

## 5. C1(재판정)·C2(rationale 재작성) 작업량 추정과 검수 시트 설계안

- **C1 재판정 대상 94건** = 변경 예상 33 + 판정 필요 61. 결정적(rule) 예측 32건은 기계 적용 후 사람 확인, review 예측 1건과 `?` 61건은 사람이 v3.1 정의와 G1~G8로 확정한다. 검수 행 15건은 기존 검수 label 유지를 기본값으로 두고 바꾸려면 사유를 적는다. OAS 문구만 근거인 `?` 22건은 설명문 재독으로 끝나는 가벼운 판정이다.
- **C2 rationale 재작성 대상**: (a) label이 바뀌는 행 전부 33건(+ 판정 결과 바뀌는 행), (b) label 유지지만 v3.0.1 전용 논리 문구가 든 행 13건, (c) 규칙 라벨러·합성 템플릿 행은 label에 맞는 템플릿 문장으로 자동 재생성(2건이 C1 대상에 포함; rule_label_v4/v5 TEMPLATE·JUDGE 사전 재사용), LLM 자유문 행은 v3.1 프롬프트로 LLM 재작성 후 사람 확인 또는 사람이 직접 작성(92건이 C1 대상에 포함). 재작성 rationale은 data-v3 이후 정합성 규칙(구체 label에 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, 4096/6144 토큰 한도)을 빌드 assert로 다시 검사한다. 예상 작업량: 사람 판정 94건 × 약 3~5분 ≈ 4~7시간, 자유문 재작성 102건 × 약 2분 ≈ 3시간(LLM 초안 사용 시 확인만).
- **사람 확인 대상 162건** = 예상 변경 33 + 판정 필요 61 + 안 바뀐 행 5% 무작위 68(seed 42, 모집단 1359건, id는 c0_audit_sample_ids.json).
- **검수 시트 설계안** `review/c1_relabel_review.xlsx`(생성 스크립트는 C1 단계에서 작성, xlsx는 커밋하지 않음): 시트 "변경 예상"·"판정 필요(코드)"·"판정 필요(OAS 문구)"·"무작위 5%(블라인드)"·"검수 규약"(G1~G8 원문 + v3.1 변경 요약표 + 정지 지점 1 통일 판단). 열: id · split · 프로젝트 · method · path · 입력 요약(auth_summary 또는 미들웨어 체인) · controller_text(또는 OAS 설명) · 현재 label · 현재 rationale(SFT) · 후보 규칙 · 예상 label · 예상 근거 · 기존 검수 label·검수자(있으면) · **확정 label** · **확정 rationale(자유문) 또는 템플릿 선택** · 확정 근거(코드 줄) · 검수자. 무작위 5% 시트는 블라인드(현재·예상 label 숨김, 정답키는 시트 밖 json). 검수자 균등 배분. **사전 기록**: 블라인드 표본의 불일치율(사람 판정 ≠ 현재 label)이 5%를 넘으면 안 바뀐 행도 전수 검수한다(test_v6 사람 확인 프로토콜과 같은 기준).
- 처리 순서 제안: C1-1 결정적 규칙 예측을 기계 적용한 초안 → C1-2 review·`?` 행 사람 판정 → C2 템플릿 재생성 + 자유문 재작성(LLM 초안은 gpt-4o-mini + v3.1 프롬프트, 사람 확인) → 정합성 assert → data-v6d 동결(해시·DATA_CARD) → 학습은 별도 승인.

## 6. test 프로젝트 겹침 재확인

| test 셋 | 건수: | (서비스, method, 정규화 path) 겹침: | 서비스·프로젝트명 겹침 |
|---|---:|---:|---|
| test_v30 | 269 | 0 | 없음 |
| test_v31_supp(+excluded) | 263 | 0 | 없음 |
| test_v5(+excluded) | 296 | 0 | 없음 |
| test_v6_candidates | 302 | 0 | 없음 |

test_v31_supp·test_v5는 제외 목록(excluded)까지 포함해 대조했다. 네 test 셋 모두 겹침 0건이므로 C 데이터(= data-v5 행)의 출처는 test 프로젝트와 겹치지 않는다. C에는 새 출처를 추가하지 않는다.

## 7. 한계와 주의

- 후보 추출은 미들웨어 이름·정규식·규칙 라벨러 kind에 의존한다. OAS만 있는 APIs.guru 행(390건)은 설명 문구로만 걸러 `?`로 두었고, v3.1의 OAS-only 규칙(보류 2, security 선언·mutation 제한 유지)은 v3.0.1과 같아 label 변화는 드물 것으로 본다.
- G 규약 기반 규칙 라벨러(rule_label_v4/v5)로 라벨된 행은 정의상 v3.1과 거의 일치하므로 "유지 예상"이 대부분이다. 다만 규칙 라벨러가 G6으로 보류한 Zulip 설정 그룹 권한(has_permission)·Label Studio 전 역할 보유 권한은 v3.1 G3-b/G6-c 경계 문장대로 manual이 맞는지 C1에서 표본 확인한다.
- gitea 조직 소유자(reqOrgOwnership) 23건은 LLM이 "소유자"로 읽어 owner_match가 됐으나 v3.1 G3-a(그룹 안 역할)로는 role_required다. 이 묶음이 변경 예상의 가장 큰 덩어리다.
- `?` 행의 예상 label은 사람 판정 전까지 미정이며 4.1의 분포 예상에는 현재 label로 넣었다.
- 합성 레코드(161건)는 설계 라벨이며 v3.1에서도 유효하다(tenant AND membership → 보류 3 유지, premium → 보류 1 유지, owner_or_admin, 인증만 → 보류 8). 합성 "tenant AND role" 패턴은 없다.
- 이 보고는 영향 범위 추정이다. label·rationale 파일은 수정하지 않았고 학습·추론·커밋도 하지 않았다.
