# 작업 C 정지 지점 4 — data-v5 동결, RunPod 실행 준비 (2026-10-31)

사용자 결정(정지 지점 3 반영 확인·순서 변경)에 따라 data-v5를 test_v5보다 먼저 동결했다. 학습은 시작하지 않았고 커밋하지 않았다. 기존 동결본(data-v1~v4, test_v30, test_v31_supp)은 해시 대조 후 읽기만 했으며 test_v5 label은 읽지 않았다(후보 키 겹침 0건 재확인).

## 1. 순서 변경 (AGENTS.md 기록)

- data-v5 동결 → (test_v5 검수본 도착 시) test_v5 동결 → LoRA v5 학습·평가. 사유: data-v5 구성은 test_v5 label을 읽지 않았고(키 겹침 검사만), test 우선 동결의 목적이 이미 충족됨.
- 강제 사항: (a) test_v5는 v5 예측 생성·열람 전에 동결. (b) run_train.py `TESTV5` 게이트 — `sha=None`(현재)이거나 manifest·입력이 없거나 해시가 다르면 test_v5 예측 작업을 만들지 않는다. (c) test_v30·test_v31_supp 평가는 학습 직후 진행.
- 판정 기준 구체 정밀도: 합성 제외 207건 v4 0.811 ± 0.025(기본 디코딩). 평가는 기본 디코딩.

## 2. data-v5 동결 결과

| 항목 | 값 |
|---|---|
| 구성 | data-v4(train_v4 981 + val_v4 148; SFT 행 바이트 동일, 빌드 확인) + 보강분 328(train 296 / val 32) |
| train_v5.jsonl / val_v5.jsonl | 1,277 / 180건 |
| SFT train / val | 1,274 / 179건 (4096 토큰 초과 0) |
| SFT train manual 비율 | 163/1,274 = **12.79%** (data-v4 13.6%) |
| 보강분 train 분포 | role 106 · owner_match 76 · owner_or_admin 41 · manual 30 · public 26 · membership 17 |
| 보강분 val 분포 | role 12 · owner_match 9 · owner_or_admin 4 · manual 3 · public 2 · membership 2 (Dendrite 10 · NodeBB 11 · Taiga 11, 핸들러 그룹 분리) |
| 검수 일치율 | 수정 전 규칙 0.956(86/90), 불일치 4건은 규칙 수정으로 해소, 수정 후 88/88 |
| 정합성 | 보류 표현 0 · 메타 문구 0 · 규칙 ID·파일 경로 0 · test_v30/supp 겹침 0 · test_v5 후보 키 겹침 0 |

SFT train 전체 label 분포: owner_match 447, role_required 326, manual 163, owner_or_admin 96, tenant_match 83, public 82, membership_required 77.

### 해시 (AGENTS.md 'data-v5 동결' 절과 동일)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/train_v5.jsonl | 1277 | `528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344` |
| datasets/blade/processed/val_v5.jsonl | 180 | `43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9` |
| datasets/blade/processed/data_v5/train_v5_rule_labeled.jsonl | 432 | `6f2e02f933a88cbb84a6d8c7ea57f42a81b2c3d8db62d4559c20217209876988` |
| datasets/blade/processed/data_v5/train_v5_selected.jsonl | 328 | `12f45304c9f4a1884a09dc62ca877b8e04da21c0f6a20751109742c5bc1f8e8d` |
| datasets/blade/processed/data_v5/train_v5_pool.jsonl | 84 | `d5916fb43ea34c81b69aca2f3d252c175cada01156aa8ec59d99c2631acc0ebf` |
| datasets/blade/processed/data_v5/train_v5_manifest.json | 412 레코드 | `95efb605c79f46081550f08c8d41d985c4fda6bb85cd09b77d43f677e2ff7659` |
| training/lora/data_v5/train_sft_v5.jsonl | 1274 | `2351afe93518f6e29c95ab9305a15b5a1cda7bd6e3c6d18bec7e8e3d45c3216b` |
| training/lora/data_v5/val_sft_v5.jsonl | 179 | `0df4642f439c812d4e7b9f5ca968c89fd966703bfc59229d6f7ea7f83115748f` |
| training/lora/data_v5/data_v5_hashes.json | - | `39c302c5fb33d1b1506487678cd15f40cc83ffd59435449522786388554753ac` (= run_train.py DATASETS['v5']['sha']) |
| training/data/rule_label_v5.py | - | `daa28db3992b2d2bfd4a99a863c1b8d3d86045fdde52e6d9f66d1f2d8fcd7c67` |
| review/v5_train_review_reviewed.xlsx | 90 | `4d70711494bf63ad0a0644e75967f236a204b5799b8dd67847aa508a010d519b` |
| test_v30_inputs.jsonl · test_v31_supp_inputs.jsonl · policy_label_v3.0.1.md (data_v5/) | 269 · 222 · - | data_v4와 바이트 동일 |

- `test_v5_inputs.jsonl`은 data_v5_hashes.json에 넣지 않았다(순서 변경). test_v5 동결 시 `data_v5/test_v5_manifest.json`의 해시로 run_train.py가 별도 검증한다.
- 공개 범위: NodeBB(GPL-3.0) 코드 본문이 든 파일은 .gitignore(확인: train_v5.jsonl, train_sft_v5.jsonl, pool, 검수본, raw candidates 모두 ignore). 추적되는 것은 train_v5_manifest.json(id·저장소·커밋·고정 링크·label·split), data_v5_hashes.json, 보고서다. DATA_CARD에 "링크·커밋만 공개" 명시.

## 3. RunPod 준비 (training/lora/runpod/)

| 파일 | 변경 |
|---|---|
| run_train.py | `DATASETS['v5']`(sha 39c302c5…), `TESTV5` 게이트 + `testv5_rows()`, 출력 `v5test_predictions_<cond>_<tag>.jsonl`, `--jobs v5test` |
| run_all.sh | RUNS에 `v5:`가 있으면 export 이름 `blade_v5`; 모든 run 뒤 `merge_gguf_v5.sh $GGUF_SEED`(기본 42, RUNS에 `v5:42` 학습 항목이 있을 때) → export → Pod 정지 |
| merge_gguf_v5.sh (신규) | seed 어댑터 fp32 병합(베이스 Qwen2.5-7B-Instruct 리비전 a09a3545…) → fp16 HF → llama.cpp b11693 f16 GGUF → Q4_K_M. 산출 `export/gguf/blade-qwen-lora-v5-s42-Q4_K_M.gguf`, `merge_manifest_v5_s42.json`, `SHA256SUMS_gguf_s42` |
| export_results.sh | SUMMARY v5test 열, gguf manifest 포함 |
| scripts/eval_test_v5.py (신규) | test_v5 채점기(eval_v31_supp.py 본). manifest 없으면 거부(확인됨) |
| training/lora/Modelfile.blade-qwen-lora-v5 (신규) | C-5용. 등록은 개선 인정 + 승인 후 |

README_runpod_rerun.md 4.5절에 실제 명령을 적었다. GPU 실행 없이 로컬에서 구문 검사만 했다(run_train.py ast, run_all.sh/merge_gguf_v5.sh `bash -n`). merge_gguf_v5.sh는 Pod에서 처음 실행되므로 llama.cpp 빌드·RAM(fp32 병합 32GB)·디스크(일시 35GB)가 실패 지점이 될 수 있다. 실패해도 export·Pod 정지는 진행되며 로그에 남는다.

### 번들

- `<USERPROFILE>\Downloads\blade_lora_runpod_v5_20261031.tgz` (1.65MB) SHA-256 `207dc7636ad2d61071c18e88ef3235b8f44085e48e9ac6410953286999ce5e74`. 내용: training/lora의 data_v2, data_v3, data_v4, data_v5(train_sft_v5·val_sft_v5·test_v30_inputs·test_v31_supp_inputs·prompt·data_v5_hashes.json), runpod/.
- 어댑터: v4 3 seed eval-only(test_v5 예측 추가)에 `blade_v4_adapters.tar.gz`(SHA a3ce55a4…) 복원이 필요하다. Network Volume이 살아 있으면 `runs/lora_v4_s4*/adapter/`가 이미 있다.

### 실행 명령 (Pod, A100 80GB 권장)

```bash
cd /workspace/blade_lora_v3 && tar -xzf /workspace/blade_lora_runpod_v5_20261031.tgz && bash runpod/setup.sh
sha256sum data_v5/data_v5_hashes.json      # 39c302c5fb33d1b1506487678cd15f40cc83ffd59435449522786388554753ac
df -h /workspace; nvidia-smi --query-gpu=name,memory.total --format=csv; free -g | head -2; command -v runpodctl && echo POD_ID=$RUNPOD_POD_ID
# 1단계(지금 시작 가능, test_v5 미동결): v5 s42·43·44 학습 + test_v30/supp 평가 → s42 GGUF Q4_K_M → export(blade_v5_*) → Pod 정지
tmux new -d -s blade "RUNS='v5:42 v5:43 v5:44' bash /workspace/blade_lora_v3/runpod/run_all.sh"
tail -f /workspace/blade_lora_v3/runs/run_all.log
# 2단계(test_v5 동결 후): data_v5/test_v5_inputs.jsonl + test_v5_manifest.json 업로드, run_train.py TESTV5['sha']에 manifest SHA-256 기입, 그 뒤
#   test_v5만 추론: base 1회 · v4 3 seed · v5 3 seed (항목 모드 v5test). test_v30·supp는 base·v4 기존 예측(reports/eval/lora_v4) 사용, v2·v3b 재추론 없음, 모두 기본 디코딩
tmux new -d -s blade "RUNS='v5:42:v5test v5:43:v5test v5:44:v5test v4:42:v5test v4:43:v5test v4:44:v5test base:0:v5test' GGUF_SEED= bash /workspace/blade_lora_v3/runpod/run_all.sh"
```

- 예상 시간(10-27 실측 기준): v5 학습 1,274건 ≈ 57분 + 평가 15분 ≈ 항목당 72분 × 3 ≈ 3.6시간, GGUF 25~40분, 설치 20분 → **약 4.5시간**. 2단계 test_v5 예측은 모델당 약 5분 × 7 ≈ 35분.
- C-4 평가 범위(사용자 결정 2026-10-31): v2·v3b 재추론 없음. test_v30·supp는 v5 3 seed만 새로 추론(base·v4는 reports/eval/lora_v4의 기존 예측으로 채점). test_v5는 base 1회·v4 3 seed·v5 3 seed. 모두 기본 디코딩.
- 마감: C-4 시작 토요일 12:00. 1단계는 test_v5 동결과 무관하게 지금 시작할 수 있다.

## 4. 남은 순서

1. 사용자 승인 → 1단계 실행(학습·test_v30/supp 평가·GGUF). 첫 항목 종료 시각으로 예상 시간 재계산 보고.
2. test_v5 검수 완료본 도착 → `build_test_v5.py freeze` → 정지 지점 2 보고 → TESTV5 sha 기입 → 2단계 실행.
3. 채점(`eval_v30.py`, `eval_v31_supp.py`, `eval_test_v5.py`) → `reports/eval/lora_v5/lora_v5_report.md` 판정(개선 인정/불인정) → 정지. C-5는 개선 인정 + 승인 시에만.
