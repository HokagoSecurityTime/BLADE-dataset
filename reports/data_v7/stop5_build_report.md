# data-v7 5단계 집계 보고 — 최종 학습셋 (2026-11-07, 학습 전 정지)

사용자 결정(2026-11-07): B안 + test_v31_supp·test_v5 학습 투입, test_v30 미투입, val은 data-v6d val에 재판정 반영분만. 빌드 scripts/build_data_v7.py(동결본 해시 assert, 학습·추론·LLM API 없음). 판정셋은 test_v6(사람 확인 후 동결)이며 test_v5·test_v31_supp는 더 이상 평가에 쓰지 않는다.

## 1. 최종 건수

| 구간 | 행 | manual 비율 | 구성 |
|---|---:|---:|---|
| train | 1540 | 17.1% | data-v6d train 1,274 − OAS 새 manual 236 = 1,038 + test_v31_supp 221 + test_v5 281 |
| val | 159 | 22.6% | data-v6d val 179 − OAS 새 manual 20 (재판정 label 반영 3) |
| pool(학습 제외) | 256 | 100% | OAS-only 새 manual(train 236 · val 20), datasets/blade/processed/data_v7/train_v7_oas_manual_pool.jsonl |
| 추가 제외 | 3 | - | 4096 토큰 초과: v4t-chatwoot-03a9708adc, v5t-rocketchat-2b42fcece3, v5t-rocketchat-a41ec34093 |

## 2. label 분포

| 구간 | n | public | role | member | tenant | owner | own+adm | manual | manual 비율 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| data-v6d train | 1274 | 82 | 351 | 75 | 83 | 425 | 97 | 161 | 12.6% |
| data-v7 train | 1540 | 88 | 425 | 138 | 111 | 382 | 132 | 264 | 17.1% |
| data-v6d val | 179 | 14 | 52 | 7 | 8 | 46 | 13 | 39 | 21.8% |
| data-v7 val | 159 | 14 | 46 | 6 | 6 | 38 | 13 | 36 | 22.6% |

추가 502행 label: public 21, role 149, member 87, tenant 55, owner 55, own+adm 41, manual 94. 재판정 반영 45건 전이: member→role 5, role→owner 4, member→manual 4, manual→role 4, own+adm→owner 3, tenant→role 3, owner→manual 3, own+adm→manual 3, public→manual 2, tenant→owner 2, member→tenant 2, manual→owner 2, member→owner 2, owner→tenant 2, manual→public 1, owner→role 1, role→manual 1, role→tenant 1.

## 3. 프로젝트별 (train)

| 프로젝트 | 행 |
|---|---:|
| gitea | 197 |
| rocketchat | 155 |
| synthetic | 143 |
| zulip | 132 |
| data_v3_pairs | 108 |
| taiga | 103 |
| apisguru | 102 |
| nodebb | 98 |
| dendrite | 95 |
| chatwoot | 78 |
| ghost | 69 |
| label_studio | 60 |
| flowise | 60 |
| chamilo | 58 |
| umami | 57 |
| generic_university | 21 |
| multitenant_lab | 4 |

추가 행 프로젝트: chamilo 58, chatwoot 78, flowise 60, generic_university 21, multitenant_lab 4, ghost 69, rocketchat 155, umami 57.

## 4. 추가 행 rationale

- 생성 방식: `description: 핸들러 코드의 <입력에 등장하는 auth_summary 식별자 ≤4개 | 입력에 등장하는 코드 인용> — <label 템플릿 절>; 판단: <label 판정 절>` (rule_label_v5 TEMPLATE/JUDGE 문구). 근거 출처: auth_summary 식별자 374, 코드 인용 118, 일반 문구(입력에서 식별자를 못 찾음) 10. 목록 reports/data_v7/added_rows_rationale.jsonl(auth_summary·검수 상태 포함).
- 정합성(전체 세트): 구체 label 보류 표현 0, 메타 문구 0(advisory·GHSA·취약 포함 금지), 규칙 ID·파일 경로 0. user 입력은 동결 입력과 바이트 동일. test_v30 id 겹침 0.

## 5. 사람 확인 시트

- review/data_v7_human_check.xlsx: 변경_확인 45(gitea 21 + OAS 24, 재판정 근거·새 rationale 포함) · 블라인드_안바뀐행 31(314의 10%, label 숨김, 정답키 reports/data_v7/human_check_key.json) · 추가행_rationale 50(502의 10%). seed 42, 검수자 A/B/C 균등. 검수 결과는 학습을 막지 않으며 불일치는 보고서 한계에 기록한다.

## 6. 동결 파일

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/train_v7.jsonl | 1540 | `662b16405d5775c0ecfceb8361c53953751b554390c5f1f63e30bfdfbffa32db` |
| datasets/blade/processed/val_v7.jsonl | 159 | `cf04b4b3b8928985377a53a69905d0e1a343f705850e8694bc3f38286b9da325` |
| training/lora/data_v7/train_sft_v7.jsonl | 1540 | `6654f79afb8cc984b42944cf3b246111c06d7704b02809577fa85cd5630b6178` |
| training/lora/data_v7/val_sft_v7.jsonl | 159 | `2173171ed412b2b3949c1d21f29fec69bcdd5b7e4732e67ace4fb84bc2e57087` |
| training/lora/data_v7/data_v7_hashes.json | - | `bd33f1bcf0f68ab5fe5b96195c0da3cf6affbb3486fb85bef542b3f77e88ba73` |
| datasets/blade/processed/data_v7/train_v7_oas_manual_pool.jsonl | 256 | `7e663b76526b3cbba1d36e2b03c84069bec72e037353e66c863ee2b2dd745688` |
| reports/data_v7/v7_changes.jsonl | 45 | `4be15fad7791fbe494f0647faad116ce94cbe732312de0522279555bc890ee05` |
| reports/data_v7/added_rows_rationale.jsonl | 505 | `dfd296d42b7fce0c3f97ea4004f519710154c45f0bc12d41d2671afd72eb9b33` |
| review/data_v7_human_check.xlsx | - | `b6a3d484abe700d62cdb59061effeea79c81b9d040b02fded6dd30f21508ac99` |

학습 번들 export/blade_v7_20261107.tgz SHA-256 `80fc379548d9d6d2c108c002d233495cffcf94480a99be487e3142dc1e9ff8d7`, Pod 평가는 test_v30만. 사전 기록·채택 기준은 AGENTS.md "작업 data-v7"·"data-v7 동결" 절. 학습은 승인 후.

## 7. 한계

- 재판정자·rationale 생성 모두 AI(Claude)이며 사람 확인은 시트 표본에 한정된다. OAS-only 256행 제외는 "근거 없는 구체 라벨 제거"이지 정답 확정이 아니다(pool 보존).
- test_v5·test_v31_supp가 학습에 들어가 두 셋은 더 이상 dev·평가에 쓸 수 없고, 판정은 test_v6 1회로만 한다. test_v6 label 구성(tenant 37·membership 37, Redash·GlitchTip 편중)은 test_v5와 다르다.
- 추가 행 rationale은 템플릿이라 자유문 rationale(gitea LLM 행)과 문체가 다르다. 학습 target 분포가 바뀌는 점은 v5 대비 단일 변수가 아니다(데이터 행 + 라벨 + rationale 문체).
