# C1 검수 반영·C2·data-v6d 동결 보고 (2026-11-05, 작업 C′ — 학습 전 정지, 커밋 금지)

검수 완료본 `review/c1_relabel_review_reviewed.xlsx`(SHA-256 `d9f8299f…`, 검수자 **Claude(AI)** — 사람 검수가 아님)를 `scripts/build_data_v6d.py`로 반영했다. 동결 파일(data-v5 processed·SFT, test 입력, 프롬프트 v3.0.1)은 해시 확인 후 읽기만 했고 수정하지 않았다. 학습·추론 없음, test_v6 미사용.

## 1. 블라인드 감사 (안 바뀐 행 5% 표본 68건, c1_audit_key.json 기준)

| 구분 | n | 불일치(확정 ≠ 현재) | 불일치율 | 그중 manual로 | 비고 |
|---|---:|---:|---:|---:|---|
| 전체 | 68 | 28 | **41.2%** | 24 | 사전 기준 5% 초과 → 한계 기록 |
| 코드 행 | 47 | 12 | 25.5% | 9 | has_code=Y(오픈소스·합성) |
| OAS-only 행 | 21 | 16 | 76.2% | 15 | APIs.guru 명세만 |
| 출처 APIs.guru | 21 | 16 | 76.2% | 15 | |
| 출처 오픈소스 프로젝트 | 36 | 9 | 25.0% | 6 | |
| 출처 합성 | 11 | 3 | 27.3% | 3 | |
| 기존 사람 검수 행(v2·v3) | 10 | 4 | 40.0% | 3 | 블라인드 AI 판정이 기존 사람 판정과 어긋난 건 |

전이(불일치 28건): owner_match->manual_review_required 8, tenant_match->manual_review_required 5, role_required->manual_review_required 5, owner_or_admin->manual_review_required 3, public->manual_review_required 2, tenant_match->owner_match 1, owner_or_admin->owner_match 1, manual_review_required->tenant_match 1, manual_review_required->public 1, membership_required->manual_review_required 1. 확신도 표기: {'확신도 중': 21, '확신도 상': 47}.

- **사전 기록 적용: 불일치율 41.2% > 5% → 한계로 기록한다. 안 바뀐 행 전수 검수는 마감(2026-11-08 12:00 KST) 후에 한다.** 블라인드 시트의 판정은 데이터에 반영하지 않았다(감사 표본이며, 반영하면 표본만 비무작위로 고쳐져 나머지와 기준이 달라진다).
- 해석: 불일치 28건 중 24건이 "→ manual"이고 OAS-only 행에서 76%(16/21)다. 블라인드 검수자(AI)가 v3.1 보류 2(명세 문구만으로 조건을 확정하지 않음)를 엄격히 적용한 결과로, data-v5의 APIs.guru LLM 라벨(gpt-4o-mini, confidence ≥ 0.6)과 기준이 다르다. 코드 행도 25.5%(12/47)가 어긋났고 그중 기존 사람 검수 행 4건(gitea 1·data-v3 쌍 3)이 포함되므로, 이 수치는 "AI 재판정 vs 기존 라벨"의 불일치이지 기존 라벨의 오류율 추정치로 바로 읽을 수 없다. 전수 검수(사람)의 우선 대상은 OAS-only 390행과 블라인드 불일치 28건이다(c1_blind_audit.json rows).

## 2. 확정 결과 반영 (C1 label + C2 rationale)

| 시트 | 행 | label 변경 | rationale 교체 | 비고 |
|---|---:|---:|---:|---|
| 판정필요_코드 | 39 | 3 | 4 | 변경 3: /orgs/{org}/members membership→manual(가시성 분기), issues/{index}/times manual→owner_or_admin(본인 OR 관리자·쓰기 권한자), repos/transfer owner_match→manual(관리 권한 미확정 + 조직 가시성 의존); /repos/.../subscription는 label 유지·rationale만 교정 |
| 판정필요_OAS문구 | 22 | 0 | 0 | 사용자 결정: OAS-only는 현행 label 유지. AI 의견(manual, 보류 2 엄격 적용) 21건(이 시트 20 + 변경예상_C2의 slmonitor emergency-audio 1)은 `oas_relabel_candidates_post_deadline.jsonl`에 보존(마감 후 APIs.guru OAS 라벨 일괄 점검 후보) |
| 변경예상_C2 | 46 | 33 | 38 | 결정적 초안 32 중 31 수용·1 거부(gitea GET /user/hooks/{id}: owner_or_admin 초안 → owner_match 유지, rationale만 교정), review 1(GET /notifications manual→owner_match) 수용, C2 전용 13 중 gitea 5건 rationale 재작성(그중 GET /teams/{id}/repos는 label도 membership→manual), APIs.guru 4(security 선언 문구)·합성 3(tenant AND membership, 영어 유지)은 그대로 |
| **합계** | 107 | **36** | **42** | 건드린 행 42 (train 36 / val 6) |

label 변경 내역(현재 → 확정): owner_match->role_required 23, manual_review_required->role_required 5, membership_required->manual_review_required 2, manual_review_required->owner_match 2, manual_review_required->owner_or_admin 1, owner_match->manual_review_required 1, role_required->public 1, membership_required->owner_match 1. 프로젝트: {'gitea': 36} (전부 gitea).
- 기존 사람 검수 행 중 label이 바뀐 것은 1건: gitea:get:/teams/{id}/repos (data-v2 사람 검수 membership_required, 태그 VIS) → manual_review_required. 근거: reqTeamReadAccess가 팀 공개 범위(CanNonMemberReadMeta)에 따라 비구성원 허용을 달리하는 가시성 분기(G6-a). 검수 안내의 "기존 검수 행은 유지 기본값"에서 벗어난 유일한 건이라 따로 표시한다.
- 확정 rationale에 든 소스 파일 경로 참조(예: `routers/api/v1/org/member.go:54-93`)는 모델 입력에 없는 정보라 4건에서 기계적으로 제거했다(함수명·조건은 유지): gitea:get:/orgs/{org}/members, gitea:get:/repos/{owner}/{repo}/issues/{index}/times, gitea:get:/repos/{owner}/{repo}/subscription, gitea:post:/repos/{owner}/{repo}/transfer.
- 재작성 rationale은 모두 "description: 근거; 판단: 결론" 형식이며 label 이름을 포함한다. 생성 confidence·evidence_fields·키 순서는 v5 그대로다.

### label 분포 (SFT)

| split | 행 | v5 → v6d | manual 비율 v5 → v6d |
|---|---:|---|---|
| train | 1274 | role_required 326→351, membership_required 77→75, owner_match 447→425, owner_or_admin 96→97, manual_review_required 163→161 | 12.8% → 12.6% |
| val | 179 | public 13→14, role_required 50→52, membership_required 8→7, owner_match 45→46, manual_review_required 42→39 | 23.5% → 21.8% |

## 3. 정합성 검사 (빌드 assert)

- 변경 행: 구체 label에 보류 표현 0, 검수 메타 문구(검수·초안·확신도·C1/C2·G1~G8 등) 0, 규칙 ID·파일 경로 0, 구체 label인데 rationale에 label 이름 없음 0. 전체 세트: v5 {'hold_in_concrete': 0, 'meta': 0, 'filepath': 0} → v6d {'hold_in_concrete': 0, 'meta': 0, 'filepath': 0} (증가 없음).
- user 입력·행 순서: data-v5 SFT와 바이트 동일(assert). 안 바뀐 행 1238 + 173은 줄 단위로 바이트 동일. assistant JSON 재직렬화는 v5 포맷과 1,453/1,453 동일.
- 토큰: 최대 4085(4096 초과 0). 계산은 tokenizers + Qwen2.5 chat template 수동 적용(transformers 미설치)이며 data_v6a SFT의 transformers 계산치 1,453행과 전부 일치해 검증했다. 참고(errata): data-v5 SFT의 `tokens` 필드는 gitea 69행에서 실제 토큰 수와 최대 24 어긋난다(data-v3.1 메타 문구 제거 전 값). 학습 코드는 자체 토큰화하므로 영향 없음. 바뀐 행만 재계산해 기록했고 안 바뀐 행은 바이트 보존을 위해 그대로 뒀다.
- test 겹침: id·입력이 data-v5와 같으므로 test_v30·test_v31_supp·test_v5·test_v6 후보와의 겹침 0(C0 재확인)은 그대로다.

## 4. data-v6d 동결 (수정·재생성 금지, 커밋·태그는 사용자 승인 후)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/train_v6d.jsonl | 1277 | `aed2b275a76fa684e426a656fb04b1c934a29bc987f45a146fe1c244ced4d372` |
| datasets/blade/processed/val_v6d.jsonl | 180 | `159e01780eb2d8aa1710146d2c06533c20c81920a828a60b889ec6db221361cf` |
| training/lora/data_v6d/train_sft_v6d.jsonl | 1274 | `63c1768949a0e8c7f0747712c6a55e4fb492e1d03baeddfa111884f31ff65b98` |
| training/lora/data_v6d/val_sft_v6d.jsonl | 179 | `1a421c836032ff3c611f3a74380b519374393deb44519c1772db8049d7d671ee` |
| training/lora/data_v6d/data_v6d_hashes.json | - | `82efda868e7bde511d0838e10bf0e8a5cc3e6aae577c68b15fcbf370a9d94b53` |
| reports/data_v6d/c1_changes.jsonl | 42 | `6258a226a04fa03cbfbe2248ce6a2cec73109d52c20966256db118f9ec5442a4` |
| reports/data_v6d/c1_blind_audit.json | - | `882fcb5a9af3a2b0097bc6ef7ab6ac4def052dbf02dd52e679c710759a393006` |
| reports/data_v6d/oas_relabel_candidates_post_deadline.jsonl | 21 | `bac1d5260a86489e4040fb90121349933cf83bf7d331ac936a27880bc685a8c9` |
| review/c1_relabel_review_reviewed.xlsx | 175행(5시트) | `d9f8299ff4a514b409e799515ad5e538c1d3810fba2c0ad8d3a492ad5377136e` |
| training/lora/data_v6d/test_v30_inputs.jsonl · test_v31_supp_inputs.jsonl · test_v5_inputs.jsonl · test_v5_manifest.json · policy_label_v3.0.1.md | 269 · 222 · 283 · - · - | data_v5와 바이트 동일(`d65f25b9…`, `97e618e7…`, `9103cd3d…`, `57fd384f…`, `d0913c27…`) |

- processed train_v6d/val_v6d는 train_v5/val_v5에 label·rationale(교체 행만)·meta.v6d_c1(from/to/근거/검수 파일)을 덧쓴 것이고, SFT는 run_train_v6d.py가 읽는 학습 파일이다. NodeBB(GPL-3.0) 코드 본문이 든 파일(processed·SFT)과 Flowise 코드가 든 test_v31_supp_inputs 사본, 검수 xlsx, 번들은 .gitignore에 추가했다. 공개 사본은 data-v5와 같은 규칙(public/ 디렉터리)으로 나중에 만든다.

## 5. 베이스 결정 — S8(v6c) 불채택 → 7B

S8 3 seed 결과(reports/eval/lora_v6c/report.md, 같은 채점기): test_v5 oas_code macro-F1 v5 0.683 → v6c 0.680(-0.003, 기준 ≥ +0.016 **미달**), test_v30 207 구체 정밀도 0.796 → 0.813(충족), public 오판 평균 1.67(충족). 조기 판정(s42 0.686 > 0.6661)은 통과했으나 3 seed 평균 차이가 표준편차보다 작다. **불채택, v5가 최종 모델(S9 대상)**, C′ 베이스는 `unsloth/Qwen2.5-7B-Instruct-bnb-4bit`.

## 6. C′ 학습 번들 (실행은 사용자 승인 후)

- `export/blade_v6d_20261105.tgz` SHA-256 `3c52b2cd300ce33fa1c7b7ef72de70de278d397490a7f54dd7eb7aa3add4657b` — data_v6d 8파일(동결본과 바이트 동일) + runpod/(run_train_v6d.py · run_v6d.sh · setup.sh · README_v6d.md, LF) + SHA256SUMS_bundle. 절차 training/lora/runpod/README_v6d.md.
- run_train_v6d.py = run_train_v6c.py에서 베이스를 7B로 되돌리고 데이터를 data_v6d(해시 게이트 `746926bc…`)로 바꾼 것. 그 외(프롬프트 v3.0.1, label 먼저, 4096/256, LoRA r16·α16·3 epoch·lr 2e-4·batch 2×4·cosine·adamw_8bit, completion-only, greedy, 평가 6작업·TESTV5 게이트)는 v5·S8과 동일. 로컬에서 해시 게이트·test_v5 게이트 통과를 확인했다(verify·testv5_rows).
- 순서 해시 → setup → preflight → s42 → s43 → s44 → 전체 tar → Pod 자동 정지(조기 판정 없음). 예상 seed당 약 70분(A100). 채택 판정(3 seed 평균, 기존 3조건)은 회수 후 로컬 채점으로 한다. 중단 규칙: 2026-11-08 12:00 KST.

## 7. 한계·메모

- 검수자가 사람이 아니라 Claude(AI)다. 블라인드 감사 41.2%도 AI 재판정 기준이다. 사람 확인 범위가 정해지면 여기와 DATA_CARD를 갱신한다.
- C1 변경 36건은 전부 gitea(data-v2) 행이며 대부분 reqOrgOwnership/reqRepoWriter/reqAdmin → role_required(G3-a)다. 다른 프로젝트(규칙 라벨러 출처)는 v3.1과 이미 일치해 변경이 없다.
- OAS-only 390행은 v3.1 보류 2 기준으로 보면 상당수가 manual 후보다(블라인드 76%). 이번 C′ 범위 밖이며 마감 후 일괄 점검 대상이다(후보 21건 + 블라인드 16건 기록).
