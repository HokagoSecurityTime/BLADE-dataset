# 데이터 사전 (피처 인벤토리) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl `a99d30da2d29907e…`, val_v30.jsonl `62bdadb29cae7aaf…`, test_v30.jsonl `9bd47216575afc60…`, policy_label_v3.0.1.md `d0913c27b5de185e…`. 모든 파일 읽기 전용. 상세·필터 UI는 reports/data_dictionary.html, 원시 표는 reports/data_dictionary/*.csv.

## 대상 파일

| 파일 키 | 경로 | 건수 |
|---|---|---:|
| train_v30 | datasets/blade/processed/train_v30.jsonl | 471 |
| val_v30 | datasets/blade/processed/val_v30.jsonl | 52 |
| test_v30 | datasets/blade/processed/test_v30.jsonl | 269 |
| train_v2_draft | datasets/blade/processed/train_v2_draft.jsonl | 971 |
| gitea_labeled_455 | datasets/blade/processed/opensource/gitea_v28.2.0_labeled_v301.jsonl | 455 |
| synthetic_v2_129 | datasets/blade/processed/data_v2_synthetic_additions.jsonl | 129 |
| apisguru_labeled_2027 | datasets/blade/processed/apisguru_labeled_v301.jsonl | 2027 |

## 필드 요약 (존재 파일 · 타입 · 결측 · 고유값 · 용도)

용도 판정 근거: 프롬프트 페이로드 빌더(label_v3.payload → label_v5.payload, label_v30.q_payload, label_gitea_v30.payload, prepare_lora_inputs.test_inputs)와 SFT 타깃(prepare_lora_inputs.sft_rows)이 실제로 읽는 필드. 나머지는 메타.

| 필드 | 타입 | 존재 파일 | 결측 | 빈값 | 고유값 | 용도 | 근거 |
|---|---|---|---:|---:|---:|---|---|
| confidence | float | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 6% | 0% | 6 | 정답 | training/lora/prepare_lora_inputs.py:31 |
| controller_signals | null/dict | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 100% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.admin_bypass | bool/null | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 85% | 9% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.auth_outside_handler | bool | train_v2_draft,synthetic_v2_129 | 94% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.authz_lines_in_handler | int | train_v2_draft,gitea_labeled_455 | 81% | 0% | 14 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.binders | list | train_v2_draft,gitea_labeled_455 | 81% | 76% | 84 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.handler | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 453 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.handler_resolved | bool | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.has_auth_check | bool/null | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 85% | 9% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.membership_check | bool | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 93% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.middleware | list | train_v2_draft,gitea_labeled_455 | 81% | 0% | 109 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.owner_filter | bool/null | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 85% | 9% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.raw_snippet | str | train_v30,train_v2_draft,synthetic_v2_129 | 91% | 0% | 189 | 입력(oas_code, 합성) | training/data/label_v30.py:47 |
| controller_signals.route_authentication | bool | train_v2_draft,gitea_labeled_455 | 81% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.route_authorization | list | train_v2_draft,gitea_labeled_455 | 81% | 45% | 29 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_signals.tenant_check | bool/null | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 85% | 9% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| controller_text | str | test_v30,train_v2_draft,gitea_labeled_455 | 75% | 0% | 669 | 입력(oas_code, test·Gitea·취약 API) | training/data/label_gitea_v30.py:19 |
| description | str | train_v30,train_v2_draft,synthetic_v2_129 | 91% | 0% | 16 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| enrichment.source_file | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 397 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| enrichment.source_sha256 | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 397 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| enrichment.spec_version | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 6 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| enrichment.status | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| erd_snippet | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 24% | 1665 | 입력 | training/data/label_v30.py:59 |
| evidence_fields | list | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 658 | 정답 | training/lora/prepare_lora_inputs.py:29 |
| id | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 2940 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| inference_ms | float | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 2110 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| label | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 7 | 정답 | training/lora/prepare_lora_inputs.py:31 |
| label_reference_only | bool | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| labeled_at | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 2482 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| lookup_status | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.added | str | test_v30 | 100% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.api_go_line | int | train_v2_draft,gitea_labeled_455 | 81% | 0% | 455 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.api_original_label | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 7 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.commit | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.confidence_label_overridden | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.confidence_provenance | str | train_v30,train_v2_draft,synthetic_v2_129 | 91% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.controller_status | str | test_v30,train_v2_draft,gitea_labeled_455 | 75% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.data_version | str | train_v2_draft,gitea_labeled_455,synthetic_v2_129 | 75% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.erd_status | str | test_v30,train_v2_draft,gitea_labeled_455 | 75% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.evidence_correction_requested | bool | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.evidence_invalid | bool | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 6% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.extraction_rules | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.flag_review | bool | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 6% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.framework | str | train_v2_draft,synthetic_v2_129 | 94% | 0% | 7 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.group_membership_semantics | str | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 93% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.has_admin_scope | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.has_owner_col | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.has_security | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.has_tenant_col | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.human_confirmed | bool | train_v30,train_v2_draft,synthetic_v2_129 | 91% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.incomplete | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.intended_label_original | str | train_v30,train_v2_draft | 100% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.invalid_evidence_fields | list | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 100% | 4 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.known_vulnerable | bool | train_v30,test_v30,train_v2_draft,synthetic_v2_129 | 85% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.label_before_override | str | train_v30,train_v2_draft | 97% | 0% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.label_before_v30 | str | test_v30 | 100% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.label_error | bool | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.label_source | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.license | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.low_conf | bool | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.oas_file | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.oas_status | str | test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129 | 69% | 0% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.object_param_candidates | list | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 644 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.owner_cols | list | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 64% | 116 | 입력 | training/data/label_v3.py:71 |
| meta.partition | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.path_owner_signal | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.path_resource_depth | int | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.path_tenant_signal | bool | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.project | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.public_candidate | bool | train_v2_draft,gitea_labeled_455 | 81% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.repository | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.security_scopes | list | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 81% | 110 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.signal_class | str | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 0% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.source | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129 | 52% | 0% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.source_file | str | train_v30,val_v30,train_v2_draft,synthetic_v2_129,apisguru_labeled_2027 | 25% | 0% | 409 | 입력(코드 위치 표시) | training/data/label_v30.py:62 |
| meta.source_locations | list[dict]/list | test_v30,train_v2_draft,gitea_labeled_455 | 75% | 4% | 659 | 입력(코드 위치 표시, test) | training/lora/prepare_lora_inputs.py:75 |
| meta.tag | str | train_v2_draft,gitea_labeled_455 | 81% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.tenant_cols | list | train_v30,val_v30,train_v2_draft,apisguru_labeled_2027 | 34% | 79% | 69 | 입력 | training/data/label_v3.py:71 |
| meta.v30_override_reason | str | train_v30,train_v2_draft | 97% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.v30_override_trigger | list | train_v30,train_v2_draft | 100% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.v30_relabel_reason | str | train_v30,test_v30,train_v2_draft | 100% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.variant_kind | null/str | train_v2_draft,synthetic_v2_129 | 94% | 56% | 4 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.variant_of | null/str | train_v2_draft,synthetic_v2_129 | 94% | 56% | 5 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| meta.visibility_dependent | bool | train_v2_draft,gitea_labeled_455 | 81% | 0% | 2 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| method | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 5 | 입력 | training/data/label_v3.py:67 |
| model_id | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| model_id_returned | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| oas_snippet | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 2911 | 입력 | training/data/label_v3.py:48 |
| path | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 2369 | 입력 | training/data/label_v3.py:67 |
| prompt_version | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| provider | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| rationale | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 6% | 0% | 2003 | 정답 | training/lora/prepare_lora_inputs.py:31 |
| security_state | str | train_v30,val_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 6% | 0% | 3 | 파생 입력(저장값은 메타; 입력 시 OAS에서 재계산) | training/data/label_v5.py:33 |
| service | str | train_v30,val_v30,test_v30,train_v2_draft,gitea_labeled_455,synthetic_v2_129,apisguru_labeled_2027 | 0% | 0% | 392 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| source | str | test_v30,train_v2_draft,gitea_labeled_455 | 75% | 0% | 3 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| training_target_fields | list | train_v30,val_v30,train_v2_draft,synthetic_v2_129,apisguru_labeled_2027 | 25% | 0% | 1 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |
| usage_attempts | list[dict] | train_v30,val_v30,train_v2_draft,gitea_labeled_455,apisguru_labeled_2027 | 15% | 0% | 2370 | 메타 | 빌드·프롬프트 코드에서 읽지 않음 |

## 파일별 존재 여부 (존재 건수/전체)

| 필드 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| confidence | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| controller_signals | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| controller_signals.admin_bypass | 60/471 | 0/52 | 269/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.auth_outside_handler | 0/471 | 0/52 | 0/269 | 129/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.authz_lines_in_handler | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.binders | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.handler | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.handler_resolved | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.has_auth_check | 60/471 | 0/52 | 269/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.membership_check | 18/471 | 0/52 | 16/269 | 147/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.middleware | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.owner_filter | 60/471 | 0/52 | 269/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.raw_snippet | 60/471 | 0/52 | 0/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| controller_signals.route_authentication | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.route_authorization | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| controller_signals.tenant_check | 60/471 | 0/52 | 269/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| controller_text | 0/471 | 0/52 | 269/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| description | 60/471 | 0/52 | 0/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| enrichment.source_file | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| enrichment.source_sha256 | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| enrichment.spec_version | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| enrichment.status | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| erd_snippet | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| evidence_fields | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| id | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| inference_ms | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| label | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| label_reference_only | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| labeled_at | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| lookup_status | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.added | 0/471 | 0/52 | 16/269 | 0/971 | 0/455 | 0/129 | 0/2027 |
| meta.api_go_line | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.api_original_label | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| meta.commit | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.confidence_label_overridden | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.confidence_provenance | 60/471 | 0/52 | 0/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| meta.controller_status | 0/471 | 0/52 | 269/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.data_version | 0/471 | 0/52 | 0/269 | 500/971 | 455/455 | 129/129 | 0/2027 |
| meta.erd_status | 0/471 | 0/52 | 269/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.evidence_correction_requested | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| meta.evidence_invalid | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| meta.extraction_rules | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.flag_review | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| meta.framework | 0/471 | 0/52 | 0/269 | 129/971 | 0/455 | 129/129 | 0/2027 |
| meta.group_membership_semantics | 18/471 | 0/52 | 16/269 | 147/971 | 0/455 | 129/129 | 0/2027 |
| meta.has_admin_scope | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.has_owner_col | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.has_security | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.has_tenant_col | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.human_confirmed | 60/471 | 0/52 | 0/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| meta.incomplete | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.intended_label_original | 6/471 | 0/52 | 0/269 | 6/971 | 0/455 | 0/129 | 0/2027 |
| meta.invalid_evidence_fields | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| meta.known_vulnerable | 60/471 | 0/52 | 269/269 | 189/971 | 0/455 | 129/129 | 0/2027 |
| meta.label_before_override | 7/471 | 0/52 | 0/269 | 103/971 | 0/455 | 0/129 | 0/2027 |
| meta.label_before_v30 | 0/471 | 0/52 | 6/269 | 0/971 | 0/455 | 0/129 | 0/2027 |
| meta.label_error | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| meta.label_source | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| meta.license | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.low_conf | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| meta.oas_file | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.oas_status | 0/471 | 0/52 | 269/269 | 500/971 | 455/455 | 129/129 | 0/2027 |
| meta.object_param_candidates | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.owner_cols | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.partition | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.path_owner_signal | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.path_resource_depth | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.path_tenant_signal | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.project | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.public_candidate | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.repository | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.security_scopes | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.signal_class | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.source | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 0/2027 |
| meta.source_file | 471/471 | 52/52 | 0/269 | 600/971 | 0/455 | 129/129 | 2027/2027 |
| meta.source_locations | 0/471 | 0/52 | 269/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.tag | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| meta.tenant_cols | 411/471 | 52/52 | 0/269 | 411/971 | 0/455 | 0/129 | 2027/2027 |
| meta.v30_override_reason | 7/471 | 0/52 | 0/269 | 103/971 | 0/455 | 0/129 | 0/2027 |
| meta.v30_override_trigger | 7/471 | 0/52 | 0/269 | 7/971 | 0/455 | 0/129 | 0/2027 |
| meta.v30_relabel_reason | 6/471 | 0/52 | 6/269 | 6/971 | 0/455 | 0/129 | 0/2027 |
| meta.variant_kind | 0/471 | 0/52 | 0/269 | 129/971 | 0/455 | 129/129 | 0/2027 |
| meta.variant_of | 0/471 | 0/52 | 0/269 | 129/971 | 0/455 | 129/129 | 0/2027 |
| meta.visibility_dependent | 0/471 | 0/52 | 0/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| method | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| model_id | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| model_id_returned | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| oas_snippet | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| path | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| prompt_version | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| provider | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |
| rationale | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| security_state | 471/471 | 52/52 | 0/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| service | 471/471 | 52/52 | 269/269 | 971/971 | 455/455 | 129/129 | 2027/2027 |
| source | 0/471 | 0/52 | 269/269 | 371/971 | 455/455 | 0/129 | 0/2027 |
| training_target_fields | 471/471 | 52/52 | 0/269 | 600/971 | 0/455 | 129/129 | 2027/2027 |
| usage_attempts | 411/471 | 52/52 | 0/269 | 782/971 | 455/455 | 0/129 | 2027/2027 |

## 범주형 필드 값 (고유값 50개 이하)

**confidence**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0.9 | 300 | 38 | 0 | 446 | 229 | 0 | 478 |
| 0.85 | 50 | 4 | 0 | 275 | 226 | 0 | 518 |
| 0.7 | 44 | 8 | 0 | 44 | 0 | 0 | 682 |
| 0.8 | 17 | 1 | 0 | 17 | 0 | 0 | 344 |
| 1.0 | 60 | 0 | 0 | 189 | 0 | 129 | 0 |
| 0.75 | 0 | 1 | 0 | 0 | 0 | 0 | 5 |

**controller_signals**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| null | 0 | 0 | 0 | 0 | 0 | 0 | 2027 |
| {} | 411 | 52 | 0 | 411 | 0 | 0 | 0 |

**controller_signals.admin_bypass**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 55 | 0 | 204 | 171 | 0 | 116 | 0 |
| null | 0 | 0 | 59 | 0 | 0 | 0 | 0 |
| true | 5 | 0 | 6 | 18 | 0 | 13 | 0 |

**controller_signals.auth_outside_handler**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| true | 0 | 0 | 0 | 102 | 0 | 102 | 0 |
| false | 0 | 0 | 0 | 27 | 0 | 27 | 0 |

**controller_signals.authz_lines_in_handler**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 0 | 171 | 204 | 0 | 0 |
| 1 | 0 | 0 | 0 | 102 | 128 | 0 | 0 |
| 2 | 0 | 0 | 0 | 41 | 49 | 0 | 0 |
| 3 | 0 | 0 | 0 | 23 | 30 | 0 | 0 |
| 4 | 0 | 0 | 0 | 11 | 16 | 0 | 0 |
| 5 | 0 | 0 | 0 | 8 | 9 | 0 | 0 |
| 6 | 0 | 0 | 0 | 5 | 7 | 0 | 0 |
| 7 | 0 | 0 | 0 | 3 | 3 | 0 | 0 |
| 8 | 0 | 0 | 0 | 3 | 3 | 0 | 0 |
| 9 | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| 16 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| 11 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| 13 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| 18 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |

**controller_signals.handler_resolved**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| true | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**controller_signals.has_auth_check**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| true | 52 | 0 | 58 | 173 | 0 | 121 | 0 |
| false | 8 | 0 | 152 | 16 | 0 | 8 | 0 |
| null | 0 | 0 | 59 | 0 | 0 | 0 | 0 |

**controller_signals.membership_check**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 14 | 0 | 12 | 125 | 0 | 111 | 0 |
| true | 4 | 0 | 4 | 22 | 0 | 18 | 0 |

**controller_signals.owner_filter**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 51 | 0 | 202 | 159 | 0 | 108 | 0 |
| true | 9 | 0 | 8 | 30 | 0 | 21 | 0 |
| null | 0 | 0 | 59 | 0 | 0 | 0 | 0 |

**controller_signals.route_authentication**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| true | 0 | 0 | 0 | 257 | 341 | 0 | 0 |
| false | 0 | 0 | 0 | 114 | 114 | 0 | 0 |

**controller_signals.route_authorization**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| [] | 0 | 0 | 0 | 184 | 190 | 0 | 0 |
| ["reqRepoReader(unit.TypeCode)"] | 0 | 0 | 0 | 57 | 60 | 0 | 0 |
| ["reqSiteAdmin()"] | 0 | 0 | 0 | 33 | 33 | 0 | 0 |
| ["reqAdmin()"] | 0 | 0 | 0 | 7 | 44 | 0 | 0 |
| ["reqOrgOwnership()"] | 0 | 0 | 0 | 19 | 19 | 0 | 0 |
| ["reqRepoReader(unit.TypeActions)"] | 0 | 0 | 0 | 13 | 15 | 0 | 0 |
| ["reqAnyRepoReader()"] | 0 | 0 | 0 | 8 | 9 | 0 | 0 |
| ["reqRepoReader(unit.TypeActions)", "reqRepoWriter(unit.TypeActions)"] | 0 | 0 | 0 | 4 | 11 | 0 | 0 |
| ["reqRepoReader(unit.TypeReleases)"] | 0 | 0 | 0 | 6 | 6 | 0 | 0 |
| ["reqOrgVisible()"] | 0 | 0 | 0 | 6 | 6 | 0 | 0 |
| ["reqPackageAccess(perm.AccessModeRead)"] | 0 | 0 | 0 | 5 | 5 | 0 | 0 |
| ["reqOrgVisible()", "reqOrgOwnership()"] | 0 | 0 | 0 | 4 | 4 | 0 | 0 |
| ["reqTeamReadAccess()"] | 0 | 0 | 0 | 4 | 4 | 0 | 0 |
| ["reqRepoReader(unit.TypeReleases)", "reqRepoWriter(unit.TypeReleases)"] | 0 | 0 | 0 | 1 | 7 | 0 | 0 |
| ["reqRepoWriter(unit.TypeIssues, unit.TypePullRequests)"] | 0 | 0 | 0 | 2 | 6 | 0 | 0 |
| ["reqRepoReader(unit.TypeCode)", "reqRepoWriter(unit.TypeCode)"] | 0 | 0 | 0 | 1 | 7 | 0 | 0 |
| ["reqPackageAccess(perm.AccessModeRead)", "reqPackageAccess(perm.AccessModeWrite)"] | 0 | 0 | 0 | 2 | 4 | 0 | 0 |
| ["reqTeamMembership()"] | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| ["reqOrgMembership()"] | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| ["reqOrgVisible()", "reqOrgMembership()"] | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| ["reqRepoReader(unit.TypeIssues)"] | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| ["reqSelfOrAdmin()"] | 0 | 0 | 0 | 1 | 3 | 0 | 0 |
| ["reqTeamReadAccess()", "reqOrgMembership()"] | 0 | 0 | 0 | 2 | 2 | 0 | 0 |
| ["reqAnyRepoReader()", "reqAdmin()"] | 0 | 0 | 0 | 0 | 3 | 0 | 0 |
| ["reqRepoWriter(unit.TypeCode)"] | 0 | 0 | 0 | 1 | 2 | 0 | 0 |
| ["reqRepoDangerZone()"] | 0 | 0 | 0 | 1 | 2 | 0 | 0 |
| ["reqRepoWriter(unit.TypeWiki)"] | 0 | 0 | 0 | 0 | 3 | 0 | 0 |
| ["reqProjectsUnitAccess(perm.AccessModeRead)"] | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| ["reqOrgMembership()", "reqOrgOwnership()"] | 0 | 0 | 0 | 1 | 1 | 0 | 0 |

**controller_signals.tenant_check**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 54 | 0 | 204 | 167 | 0 | 113 | 0 |
| null | 0 | 0 | 59 | 0 | 0 | 0 | 0 |
| true | 6 | 0 | 6 | 22 | 0 | 16 | 0 |

**description**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| The record owner or an administrator may read it. | 10 | 0 | 0 | 26 | 0 | 16 | 0 |
| Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and sub | 4 | 0 | 0 | 20 | 0 | 16 | 0 |
| Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. | 0 | 0 | 0 | 19 | 0 | 19 | 0 |
| Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. A | 0 | 0 | 0 | 19 | 0 | 19 | 0 |
| Only administrators may read this operational resource. | 8 | 0 | 0 | 16 | 0 | 8 | 0 |
| Only the record owner may read it. | 8 | 0 | 0 | 16 | 0 | 8 | 0 |
| Caller and record must share a tenant. | 8 | 0 | 0 | 16 | 0 | 8 | 0 |
| Intentionally anonymous reference catalogue. | 8 | 0 | 0 | 16 | 0 | 8 | 0 |
| Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | 2 | 0 | 0 | 10 | 0 | 8 | 0 |
| Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| A premium plan is required. | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| The record owner or an administrator may read it. Authentication is enforced outside the handler; the authorization chec | 0 | 0 | 0 | 5 | 0 | 5 | 0 |
| Only the record owner may read it. Authentication is enforced outside the handler; the authorization check is inside. | 0 | 0 | 0 | 4 | 0 | 4 | 0 |
| Caller and record must share a tenant. Authentication is enforced outside the handler; the authorization check is inside | 0 | 0 | 0 | 4 | 0 | 4 | 0 |
| Only administrators may read this operational resource. Authentication is enforced outside the handler; the authorizatio | 0 | 0 | 0 | 4 | 0 | 4 | 0 |
| Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and sub | 0 | 0 | 0 | 2 | 0 | 2 | 0 |

**enrichment.spec_version**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 3.0.0 | 207 | 22 | 0 | 207 | 0 | 0 | 940 |
| 2.0 | 72 | 14 | 0 | 72 | 0 | 0 | 467 |
| 3.0.1 | 72 | 12 | 0 | 72 | 0 | 0 | 293 |
| 3.0.3 | 25 | 3 | 0 | 25 | 0 | 0 | 163 |
| 3.0.2 | 30 | 1 | 0 | 30 | 0 | 0 | 116 |
| 3.1.0 | 5 | 0 | 0 | 5 | 0 | 0 | 48 |

**enrichment.status**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| recovered | 411 | 52 | 0 | 411 | 0 | 0 | 2027 |

**label**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| manual_review_required | 118 | 13 | 15 | 442 | 225 | 46 | 1530 |
| owner_match | 134 | 12 | 114 | 182 | 36 | 12 | 138 |
| role_required | 112 | 20 | 51 | 161 | 37 | 12 | 124 |
| public | 27 | 3 | 66 | 47 | 61 | 8 | 173 |
| owner_or_admin | 11 | 0 | 11 | 32 | 85 | 21 | 1 |
| tenant_match | 40 | 3 | 8 | 52 | 2 | 12 | 35 |
| membership_required | 29 | 1 | 4 | 55 | 9 | 18 | 26 |

**label_reference_only**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**lookup_status**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| not_applicable | 252 | 37 | 0 | 252 | 0 | 0 | 1853 |
| unresolved | 159 | 15 | 0 | 159 | 0 | 0 | 174 |

**meta.added**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| test_v30 2026-10-21 | 0 | 0 | 16 | 0 | 0 | 0 | 0 |

**meta.api_original_label**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| manual_review_required | 97 | 13 | 0 | 322 | 225 | 0 | 1530 |
| owner_match | 126 | 12 | 0 | 162 | 36 | 0 | 138 |
| role_required | 104 | 20 | 0 | 141 | 37 | 0 | 124 |
| public | 26 | 3 | 0 | 87 | 61 | 0 | 173 |
| tenant_match | 32 | 3 | 0 | 34 | 2 | 0 | 35 |
| membership_required | 25 | 1 | 0 | 34 | 9 | 0 | 26 |
| owner_or_admin | 1 | 0 | 0 | 2 | 85 | 0 | 1 |

**meta.commit**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1 | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.confidence_label_overridden**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 411 | 52 | 0 | 411 | 0 | 0 | 2027 |

**meta.confidence_provenance**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| design_intent_not_model_probability | 60 | 0 | 0 | 189 | 0 | 129 | 0 |

**meta.controller_status**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| available | 0 | 0 | 265 | 371 | 455 | 0 | 0 |
| unavailable | 0 | 0 | 4 | 0 | 0 | 0 | 0 |

**meta.data_version**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| data-v2 | 0 | 0 | 0 | 500 | 0 | 129 | 0 |
| data-v2-candidate | 0 | 0 | 0 | 0 | 455 | 0 | 0 |

**meta.erd_status**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| unknown | 0 | 0 | 211 | 371 | 455 | 0 | 0 |
| available | 0 | 0 | 58 | 0 | 0 | 0 | 0 |

**meta.evidence_correction_requested**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 408 | 51 | 0 | 773 | 448 | 0 | 2011 |
| true | 3 | 1 | 0 | 9 | 7 | 0 | 16 |

**meta.evidence_invalid**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 471 | 52 | 0 | 970 | 454 | 129 | 2025 |
| true | 0 | 0 | 0 | 1 | 1 | 0 | 2 |

**meta.extraction_rules**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| R1-R5 gitea_extract.py | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.flag_review**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 471 | 52 | 0 | 970 | 454 | 129 | 2022 |
| true | 0 | 0 | 0 | 1 | 1 | 0 | 5 |

**meta.framework**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| fastapi | 0 | 0 | 0 | 33 | 0 | 33 | 0 |
| rails | 0 | 0 | 0 | 18 | 0 | 18 | 0 |
| django | 0 | 0 | 0 | 18 | 0 | 18 | 0 |
| gin | 0 | 0 | 0 | 18 | 0 | 18 | 0 |
| nestjs | 0 | 0 | 0 | 18 | 0 | 18 | 0 |
| express | 0 | 0 | 0 | 12 | 0 | 12 | 0 |
| spring | 0 | 0 | 0 | 12 | 0 | 12 | 0 |

**meta.group_membership_semantics**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| v3.0 | 18 | 0 | 16 | 147 | 0 | 129 | 0 |

**meta.has_admin_scope**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 380 | 50 | 0 | 380 | 0 | 0 | 1964 |
| true | 31 | 2 | 0 | 31 | 0 | 0 | 63 |

**meta.has_owner_col**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 327 | 38 | 0 | 327 | 0 | 0 | 1735 |
| true | 84 | 14 | 0 | 84 | 0 | 0 | 292 |

**meta.has_security**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| true | 338 | 38 | 0 | 338 | 0 | 0 | 1259 |
| false | 73 | 14 | 0 | 73 | 0 | 0 | 768 |

**meta.has_tenant_col**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 389 | 45 | 0 | 389 | 0 | 0 | 1927 |
| true | 22 | 7 | 0 | 22 | 0 | 0 | 100 |

**meta.human_confirmed**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 60 | 0 | 0 | 189 | 0 | 129 | 0 |

**meta.incomplete**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 395 | 48 | 0 | 395 | 0 | 0 | 1902 |
| true | 16 | 4 | 0 | 16 | 0 | 0 | 125 |

**meta.intended_label_original**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| membership_required | 6 | 0 | 0 | 6 | 0 | 0 | 0 |

**meta.invalid_evidence_fields**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| [] | 411 | 52 | 0 | 781 | 454 | 0 | 2025 |
| ["path_params:id,org,repo"] | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| ["owner_cols:user,userId"] | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| ["owner_cols:account,accountId", "tenant_cols:account,accountId"] | 0 | 0 | 0 | 0 | 0 | 0 | 1 |

**meta.known_vulnerable**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 38 | 0 | 239 | 101 | 0 | 63 | 0 |
| true | 22 | 0 | 30 | 88 | 0 | 66 | 0 |

**meta.label_before_override**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| public | 7 | 0 | 0 | 56 | 0 | 0 | 0 |
| manual_review_required | 0 | 0 | 0 | 43 | 0 | 0 | 0 |
| tenant_match | 0 | 0 | 0 | 2 | 0 | 0 | 0 |
| membership_required | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| owner_or_admin | 0 | 0 | 0 | 1 | 0 | 0 | 0 |

**meta.label_before_v30**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| membership_required | 0 | 0 | 6 | 0 | 0 | 0 | 0 |

**meta.label_error**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**meta.label_source**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| model_api | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |
| intended_labels | 60 | 0 | 0 | 189 | 0 | 129 | 0 |
| workbook_confirmed | 0 | 0 | 211 | 0 | 0 | 0 | 0 |
| user_approved_intended_labels | 0 | 0 | 42 | 0 | 0 | 0 | 0 |
| intended_labels_v30_design | 0 | 0 | 16 | 0 | 0 | 0 | 0 |

**meta.license**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| MIT | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.low_conf**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**meta.oas_file**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| templates/swagger/v1-openapi3.generated.json | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.oas_status**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| repo_generated_openapi3 | 0 | 0 | 0 | 371 | 455 | 0 | 0 |
| script_projection | 0 | 0 | 0 | 96 | 0 | 96 | 0 |
| original_export | 0 | 0 | 58 | 33 | 0 | 33 | 0 |
| route_only | 0 | 0 | 109 | 0 | 0 | 0 | 0 |
| repository_spec | 0 | 0 | 102 | 0 | 0 | 0 | 0 |

**meta.partition**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| undecided_until_heldout_policy | 0 | 0 | 0 | 0 | 455 | 0 | 0 |
| train | 0 | 0 | 0 | 371 | 0 | 0 | 0 |

**meta.path_owner_signal**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 318 | 42 | 0 | 318 | 0 | 0 | 1644 |
| true | 93 | 10 | 0 | 93 | 0 | 0 | 383 |

**meta.path_resource_depth**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | 281 | 38 | 0 | 281 | 0 | 0 | 1403 |
| 2 | 72 | 10 | 0 | 72 | 0 | 0 | 329 |
| 0 | 46 | 4 | 0 | 46 | 0 | 0 | 248 |
| 3 | 10 | 0 | 0 | 10 | 0 | 0 | 41 |
| 4 | 2 | 0 | 0 | 2 | 0 | 0 | 6 |

**meta.path_tenant_signal**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 330 | 48 | 0 | 330 | 0 | 0 | 1695 |
| true | 81 | 4 | 0 | 81 | 0 | 0 | 332 |

**meta.project**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| gitea | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.public_candidate**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 0 | 0 | 0 | 343 | 427 | 0 | 0 |
| true | 0 | 0 | 0 | 28 | 28 | 0 | 0 |

**meta.repository**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| https://github.com/go-gitea/gitea | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.signal_class**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| none | 102 | 17 | 0 | 102 | 0 | 0 | 800 |
| owner | 128 | 13 | 0 | 128 | 0 | 0 | 427 |
| path_only | 66 | 7 | 0 | 66 | 0 | 0 | 398 |
| both | 74 | 9 | 0 | 74 | 0 | 0 | 242 |
| tenant | 41 | 6 | 0 | 41 | 0 | 0 | 160 |

**meta.source**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| apisguru | 411 | 52 | 0 | 411 | 0 | 0 | 0 |
| opensource | 0 | 0 | 0 | 371 | 455 | 0 | 0 |
| synthetic | 60 | 0 | 0 | 189 | 0 | 129 | 0 |

**meta.tag**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| v28.2.0 | 0 | 0 | 0 | 371 | 455 | 0 | 0 |

**meta.v30_override_reason**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| visibility_dependent | 0 | 0 | 0 | 96 | 0 | 0 | 0 |
| security_declared_public | 7 | 0 | 0 | 7 | 0 | 0 | 0 |

**meta.v30_override_trigger**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| ["security_declared"] | 7 | 0 | 0 | 7 | 0 | 0 | 0 |

**meta.v30_relabel_reason**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| intended membership_required means premium plan (subscription tier); v3.0 defines membership_required as target group/te | 6 | 0 | 0 | 6 | 0 | 0 | 0 |
| intended membership_required means premium plan (subscription tier); v3.0 defines membership_required as target group/te | 0 | 0 | 6 | 0 | 0 | 0 | 0 |

**meta.variant_kind**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| null | 0 | 0 | 0 | 72 | 0 | 72 | 0 |
| extguard | 0 | 0 | 0 | 19 | 0 | 19 | 0 |
| authonly | 0 | 0 | 0 | 19 | 0 | 19 | 0 |
| extauth | 0 | 0 | 0 | 19 | 0 | 19 | 0 |

**meta.variant_of**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| null | 0 | 0 | 0 | 72 | 0 | 72 | 0 |
| relay_forum | 0 | 0 | 0 | 21 | 0 | 21 | 0 |
| campus_records | 0 | 0 | 0 | 12 | 0 | 12 | 0 |
| orbit_tickets | 0 | 0 | 0 | 12 | 0 | 12 | 0 |
| copper_wallet | 0 | 0 | 0 | 12 | 0 | 12 | 0 |

**meta.visibility_dependent**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| false | 0 | 0 | 0 | 275 | 359 | 0 | 0 |
| true | 0 | 0 | 0 | 96 | 96 | 0 | 0 |

**method**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| GET | 305 | 31 | 159 | 650 | 228 | 129 | 1304 |
| POST | 69 | 4 | 79 | 145 | 97 | 0 | 290 |
| PUT | 40 | 9 | 17 | 57 | 23 | 0 | 218 |
| DELETE | 23 | 7 | 13 | 69 | 77 | 0 | 84 |
| PATCH | 34 | 1 | 1 | 50 | 30 | 0 | 131 |

**model_id**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| gpt-4o-mini | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**model_id_returned**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| gpt-4o-mini-2024-07-18 | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**prompt_version**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| policy-label-v3.0.1 | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**provider**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| openai | 411 | 52 | 0 | 782 | 455 | 0 | 2027 |

**security_state**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| declared | 339 | 38 | 0 | 710 | 455 | 0 | 1267 |
| unknown | 128 | 12 | 0 | 257 | 0 | 129 | 754 |
| explicitly_anonymous | 4 | 2 | 0 | 4 | 0 | 0 | 6 |

**source**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| opensource | 0 | 0 | 0 | 371 | 455 | 0 | 0 |
| vuln | 0 | 0 | 211 | 0 | 0 | 0 | 0 |
| synthetic | 0 | 0 | 58 | 0 | 0 | 0 | 0 |

**training_target_fields**

| 값 | train_v30 | val_v30 | test_v30 | train_v2_draft | gitea_labeled_455 | synthetic_v2_129 | apisguru_labeled_2027 |
|---|---:|---:|---:|---:|---:|---:|---:|
| ["label", "rationale"] | 471 | 52 | 0 | 600 | 0 | 129 | 2027 |

## 텍스트·리스트 필드 통계

| 필드 | 텍스트 길이(문자·Qwen 토큰) | 리스트 통계 | 예시(300자) |
|---|---|---|---|
| controller_signals.binders |  | len median 0 max 1 |  |
| controller_signals.handler | chars median 19 p95 30 max 37; tokens median 4 p95 6 max 7 |  | misc.Version ‖ user.ListEmails ‖ repo.TopicSearch |
| controller_signals.middleware |  | len median 6 max 9 |  |
| controller_signals.raw_snippet | chars median 527 p95 769 max 844; tokens median 124 p95 176 max 194 |  | campus_records_audit_0(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {⏎  var obj=objects.get(item_id);⏎  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);⏎  var principal=principals.get(authorization.replaceF ‖ # DRF: @permission_classes([IsAuthenticated]) -> 401 for anonymous; IsAdminUser -> request.user.is_staff; AllowAny -> no authentication.⏎⏎@api_view(["GET"])⏎@permission_classes([IsAuthenticated])⏎def harbor_manifests_roster_0(request, item_id):⏎    """Only members of the group that owns the recor |
| controller_signals.route_authorization |  | len median 1 max 2 |  |
| controller_text | chars median 1484 p95 2540 max 3775; tokens median 353 p95 636 max 962 |  | def delete_user(username):⏎    resp = token_validator(request.headers.get('Authorization'))⏎    if "error" in resp:⏎        return Response(error_message_helper(resp), 401, mimetype="application/json")⏎    else:⏎        user = User.query.filter_by(username=resp['sub']).first()⏎        if user.admin: ‖ // ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryIssue), repoAssignment(), checkTokenPublicOnly()⏎⏎// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for th |
| enrichment.source_file | chars median 31 p95 47 max 78; tokens median 12 p95 18 max 38 |  | ably.net/control/1.0.14/openapi.yaml ‖ hetzner.cloud/1.0.0/openapi.yaml ‖ zoomconnect.com/1/swagger.yaml |
| enrichment.source_sha256 | chars median 64 p95 64 max 64; tokens median 57 p95 60 max 62 |  | 3531ad015f47bbbc12bb362528693631dcc754a1a727a3ec885142290b693505 ‖ 25e971a72f6abadcfda11c893dd5ef20a55ceeffc12f7a631575df40512e2980 ‖ bdb1f86477e3e9d27685752ac6c03edf456786cf7306c83d55f017f670886056 |
| erd_snippet | chars median 154 p95 948 max 3852; tokens median 38 p95 231 max 973 |  | CREATE TABLE apps (⏎  _links TEXT,⏎  accountId TEXT -- owner candidate,⏎  apnsUseSandboxEndpoint BOOLEAN,⏎  id TEXT,⏎  name TEXT,⏎  status TEXT,⏎  tlsOnly BOOLEAN⏎); ‖  ‖ CREATE TABLE voice (⏎  audioFileUrl TEXT,⏎  campaign TEXT,⏎  dateTimeSent TEXT,⏎  deleted BOOLEAN,⏎  language TEXT,⏎  links TEXT,⏎  message TEXT,⏎  messageStatus TEXT,⏎  toNumber TEXT,⏎  userDataField TEXT,⏎  voiceMessageId TEXT⏎); |
| evidence_fields |  | len median 2 max 6 |  |
| id | chars median 50 p95 88 max 148; tokens median 16 p95 26 max 38 |  | apisguru:ably.net:get:/accounts/{account_id}/apps ‖ gitea:get:/admin/packages ‖ apisguru:zoomconnect.com:get:/api/rest/v1/voice/{messageId} |
| labeled_at | chars median 32 p95 32 max 32; tokens median 32 p95 32 max 32 |  | 2026-10-21T08:26:36.087592+00:00 ‖ 2026-10-21T08:27:34.132518+00:00 ‖ 2026-10-21T08:39:25.852089+00:00 |
| meta.invalid_evidence_fields |  | len median 0 max 2 |  |
| meta.object_param_candidates |  | len median 1 max 10 |  |
| meta.owner_cols |  | len median 0 max 5 |  |
| meta.security_scopes |  | len median 0 max 13 |  |
| meta.source_file | chars median 32 p95 68 max 94; tokens median 13 p95 20 max 39 |  | ably.net\control\1.0.14\openapi.yaml ‖ credas.co.uk\pi\v1\openapi.yaml ‖ zoomconnect.com\1\swagger.yaml |
| meta.source_locations |  | len median 2 max 6; subkeys ['end_line', 'file', 'file_sha256', 'start_line'] |  |
| meta.tenant_cols |  | len median 0 max 3 |  |
| meta.v30_override_trigger |  | len median 1 max 1 |  |
| oas_snippet | chars median 234 p95 2214 max 4349; tokens median 62 p95 618 max 1477 |  | {"summary": "Lists apps", "operationId": null, "tags": ["apps"], "security": [{"bearer_auth": []}], "path_params": ["account_id"], "query_params": []} ‖ {"openapi": "3.0.3", "security": [{"BasicAuth": []}, {"Token": []}, {"AccessToken": []}, {"AuthorizationHeaderToken": []}, {"SudoParam": []}, {"SudoHeader": []}, {"TOTPHeader": []}], "paths": {"/admin/packages": {"get": {"operationId": "adminListPackages", "parameters": [{"description": "page number ‖ {"summary": "get", "operationId": null, "tags": ["voice"], "security": null, "path_params": ["messageId"], "query_params": []} |
| path | chars median 32 p95 63 max 122; tokens median 8 p95 17 max 28 |  | /accounts/{account_id}/apps ‖ /admin/packages ‖ /api/rest/v1/voice/{messageId} |
| rationale | chars median 89 p95 135 max 245; tokens median 40 p95 61 max 87 |  | description: 요청된 account_id에 대한 애플리케이션 목록을 반환하며, owner_cols에 accountId가 포함되어 있어 요청자가 해당 계정의 소유자여야 함; 판단: 단일 소유자 조건이므로 owner_match ‖ Only administrators may read this operational resource. ‖ path_params:messageId; 판단: 요청자와 객체의 관계를 확인할 수 있는 조건이 없으며, security_state가 unknown이므로 접근 조건을 확정할 수 없음 |
| service | chars median 10 p95 19 max 34; tokens median 3 p95 5 max 9 |  | ably.net ‖ gitea ‖ zoomconnect.com |
| training_target_fields |  | len median 2 max 2 |  |
| usage_attempts |  | len median 1 max 2; subkeys ['input_tokens', 'input_tokens_details', 'output_tokens', 'output_tokens_details', 'total_tokens'] |  |

## 같은 의미·다른 이름 매핑

| 필드 A | 필드 B | 의미 | 상태 |
|---|---|---|---|
| controller_signals.raw_snippet | controller_text | 핸들러 원문 발췌(train 합성·synthetic_v2 ↔ test·Gitea·취약 API). train은 함수 전체, test는 403 검사 근처 2~3줄, Gitea는 미들웨어 정의+핸들러 60줄 상한 | 추정(의미 동일, 범위 다름) |
| meta.source_file | meta.source_locations[].file | 코드 위치. train 합성은 파일 경로 문자열, test·Gitea·NetBox는 {file,start_line,end_line} 리스트 | 추정 |
| enrichment.operation.description (apisguru 2027·enriched) | description (합성 train) / OAS op.description (test·Gitea oas_snippet 내) | OAS operation 설명. train_v30 APIs.guru 레코드는 slim 저장이라 enriched_v2에서 다시 읽음 | 추정 |
| rationale (APIs.guru·Gitea: 모델 문장) | rationale (합성: intended reason 영어 문장) | 같은 필드명이지만 출처가 다름(LLM 생성 vs 설계 사유) | 확인 |
| label (train: LLM/설계 라벨) | label (test: 사람 확정·설계 라벨) / llm_reference_label (NetBox·test_v2_extra 후보) | 정답 지위가 다름. meta.label_source로 구분 | 확인 |
| meta.known_vulnerable | intended_labels.yaml vulnerable | 합성 취약 변형 표시 | 확인 |
| security_state (train 저장값) | test_v30_inputs.security_state (OAS에서 계산) | label_v5.security_state 규칙 동일; test 레코드에는 저장돼 있지 않음 | 확인 |
| meta.v30_override_reason / meta.label_before_override | meta.v30_relabel_reason / meta.intended_label_original | 빌드 시 라벨 변경 기록(APIs.guru·Gitea override vs 합성 relabel) | 확인 |
| service | meta.project (Gitea·NetBox) / source (test: vuln|synthetic) | 출처 식별자 계층이 다름 | 추정 |

## 출처별 대표 레코드 (코드 필드 800자 절단)

### apisguru (train_v30)

```json
{
 "id": "apisguru:ably.net:get:/accounts/{account_id}/apps",
 "service": "ably.net",
 "method": "GET",
 "path": "/accounts/{account_id}/apps",
 "oas_snippet": "{\"summary\": \"Lists apps\", \"operationId\": null, \"tags\": [\"apps\"], \"security\": [{\"bearer_auth\": []}], \"path_params\": [\"account_id\"], \"query_params\": []}",
 "erd_snippet": "CREATE TABLE apps (\n  _links TEXT,\n  accountId TEXT -- owner candidate,\n  apnsUseSandboxEndpoint BOOLEAN,\n  id TEXT,\n  name TEXT,\n  status TEXT,\n  tlsOnly BOOLEAN\n);",
 "controller_signals": {},
 "label": "owner_match",
 "rationale": "description: 요청된 account_id에 대한 애플리케이션 목록을 반환하며, owner_cols에 accountId가 포함되어 있어 요청자가 해당 계정의 소유자여야 함; 판단: 단일 소유자 조건이므로 owner_match",
 "meta": {
  "object_param_candidates": [
   "account_id"
  ],
  "has_owner_col": true,
  "has_tenant_col": false,
  "has_security": true,
  "source_file": "ably.net\\control\\1.0.14\\openapi.yaml",
  "owner_cols": [
   "accountId"
  ],
  "tenant_cols": [
   "accountId"
  ],
  "path_owner_signal": true,
  "path_tenant_signal": true,
  "path_resource_depth": 1,
  "security_scopes": [],
  "has_admin_scope": false,
  "signal_class": "both",
  "incomplete": false,
  "label_error": false,
  "evidence_invalid": false,
  "invalid_evidence_fields": [],
  "evidence_correction_requested": false,
  "flag_review": false,
  "low_conf": false,
  "label_source": "model_api",
  "api_original_label": "owner_match",
  "confidence_label_overridden": false,
  "source": "apisguru"
 },
 "enrichment": {
  "status": "recovered",
  "source_file": "ably.net/control/1.0.14/openapi.yaml",
  "source_sha256": "3531ad015f47bbbc12bb362528693631dcc754a1a727a3ec885142290b693505",
  "spec_version": "3.0.1"
 },
 "confidence": 0.9,
 "evidence_fields": [
  "description",
  "path_params:account_id"
 ],
 "security_state": "declared",
 "provider": "openai",
 "model_id": "gpt-4o-mini",
 "model_id_returned": "gpt-4o-mini-2024-07-18",
 "prompt_version": "policy-label-v3.0.1",
 "labeled_at": "2026-10-21T08:26:36.087592+00:00",
 "inference_ms": 1510.1,
 "usage_attempts": [
  {
   "input_tokens": 2613,
   "input_tokens_details": {
    "cache_write_tokens": 0,
    "cached_tokens": 2304
   },
   "output_tokens": 82,
   "output_tokens_details": {
    "reasoning_tokens": 0
   },
   "total_tokens": 2695
  }
 ],
 "lookup_status": "unresolved",
 "training_target_fields": [
  "label",
  "rationale"
 ]
}
```

### gitea (gitea_labeled_455)

```json
{
 "id": "gitea:get:/users/{username}/starred",
 "source": "opensource",
 "service": "gitea",
 "method": "GET",
 "path": "/users/{username}/starred",
 "label": "owner_match",
 "oas_snippet": "{\"openapi\": \"3.0.3\", \"security\": [{\"BasicAuth\": []}, {\"Token\": []}, {\"AccessToken\": []}, {\"AuthorizationHeaderToken\": []}, {\"SudoParam\": []}, {\"SudoHeader\": []}, {\"TOTPHeader\": []}], \"paths\": {\"/users/{username}/starred\": {\"get\": {\"operationId\": \"userListStarred\", \"parameters\": [{\"description\": \"username of the user whose starred repos are to be listed\", \"in\": \"path\", \"name\": \"username\", \"required\": true, \"schema\": {\"type\": \"string\"}}, {\"description\": \"page number of results to return (1-based)\", \"in\": \"query\", \"name\": \"page\", \"schema\": {\"type\": \"integer\"}}, {\"description\": \"page size of results\", \"in\": \"query\", \"name\": \"limit\", \"schema\": {\"type\": \"integer\"}}], \"responses\": {\"200\": {\"$ref\": \"#/components/responses/RepositoryList\"}, \"403\": {\"$ref\": \"#/components/responses/forbidden\"}, \"404\"…[truncated]",
 "erd_snippet": "",
 "controller_text": "// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), context.UserAssignmentAPI(), checkTokenPublicOnly(), individualPermsChecker, reqStarsEnabled()\n\n// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.\n\n// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.\n\n// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.\n\n// context.UserAssignmentAPI(): resolves {username} into ctx.ContextUser (404 if missing); no authorization.\n\n// checkTokenPublicOnly(): tokens restricted to public-on…[truncated]",
 "controller_signals": {
  "middleware": [
   "sudo()",
   "tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser)",
   "reqToken()",
   "context.UserAssignmentAPI()",
   "checkTokenPublicOnly()",
   "individualPermsChecker",
   "reqStarsEnabled()"
  ],
  "binders": [],
  "handler": "user.GetStarredRepos",
  "handler_resolved": true,
  "authz_lines_in_handler": 1,
  "route_authentication": true,
  "route_authorization": []
 },
 "meta": {
  "source": "opensource",
  "project": "gitea",
  "repository": "https://github.com/go-gitea/gitea",
  "tag": "v28.2.0",
  "commit": "829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1",
  "license": "MIT",
  "oas_status": "repo_generated_openapi3",
  "oas_file": "templates/swagger/v1-openapi3.generated.json",
  "api_go_line": 1155,
  "erd_status": "unknown",
  "controller_status": "available",
  "source_locations": [
   {
    "file": "routers/api/v1/user/star.go",
    "start_line": 51,
    "end_line": 89
   },
   {
    "file": "routers/api/v1/api.go",
    "start_line": 1155,
    "end_line": 1155
   }
  ],
  "extraction_rules": "R1-R5 gitea_extract.py",
  "data_version": "data-v2-candidate",
  "partition": "undecided_until_heldout_policy",
  "label_error": false,
  "evidence_invalid": false,
  "invalid_evidence_fields": [],
  "evidence_correction_requested": false,
  "flag_review": false,
  "low_conf": false,
  "label_source": "model_api",
  "public_candidate": false,
  "visibility_dependent": false,
  "api_original_label": "owner_match"
 },
 "confidence": 0.9,
 "rationale": "description: 요청자가 ctx.ContextUser.ID와 ctx.Doer.ID가 일치해야만 private 리포지토리에 접근 가능; 판단: 요청자가 소유자 본인만 허용하는 조건이므로 owner_match",
 "evidence_fields": [
  "description",
  "path_params:username"
 ],
 "security_state": "declared",
 "provider": "openai",
 "model_id": "gpt-4o-mini",
 "model_id_returned": "gpt-4o-mini-2024-07-18",
 "prompt_version": "policy-label-v3.0.1",
 "labeled_at": "2026-10-21T11:44:40.969905+00:00",
 "inference_ms": 1636.2,
 "usage_attempts": [
  {
   "input_tokens": 3076,
   "input_tokens_details": {
    "cache_write_tokens": 0,
    "cached_tokens": 2048
   },
   "output_tokens": 74,
   "output_tokens_details": {
    "reasoning_tokens": 0
   },
   "total_tokens": 3150
  }
 ],
 "label_reference_only": false
}
```

### synthetic (train_v30)

```json
{
 "id": "campus_records_audit_0",
 "service": "campus_records",
 "method": "GET",
 "path": "/fixtures/campus_records/transcripts/audit/current/{item_id}",
 "oas_snippet": "{\"paths\": {\"/fixtures/campus_records/transcripts/audit/current/{item_id}\": {\"get\": {\"tags\": [\"app\"], \"operationId\": \"campus_records_audit_0\", \"parameters\": [{\"name\": \"item_id\", \"in\": \"path\", \"required\": true, \"schema\": {\"type\": \"string\"}}, {\"name\": \"Authorization\", \"in\": \"header\", \"required\": false, \"schema\": {\"type\": \"string\", \"default\": \"\"}}], \"responses\": {\"200\": {\"description\": \"OK\", \"content\": {\"*/*\": {\"schema\": {\"type\": \"object\", \"additionalProperties\": {\"type\": \"string\"}}}}}}}}}}",
 "erd_snippet": "CREATE TABLE campus_records_transcripts (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, value TEXT NOT NULL);\n",
 "controller_signals": {
  "has_auth_check": true,
  "owner_filter": false,
  "tenant_check": false,
  "admin_bypass": false,
  "raw_snippet": "campus_records_audit_0(@PathVariable(\"item_id\") String item_id, @RequestHeader(value=\"Authorization\",defaultValue=\"\") String authorization) {\n  var obj=objects.get(item_id);\n  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);\n  var principal=principals.get(authorization.replaceFirst(\"^Bearer \",\"\"));\n  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);\n  if(!principal.role().equals(\"admin\")) throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n  return obj;\n }"
 },
 "label": "role_required",
 "rationale": "Only administrators may read this operational resource.",
 "confidence": 1.0,
 "description": "Only administrators may read this operational resource.",
 "security_state": "unknown",
 "meta": {
  "source": "synthetic",
  "label_source": "intended_labels",
  "human_confirmed": false,
  "evidence_invalid": false,
  "flag_review": false,
  "known_vulnerable": false,
  "confidence_provenance": "design_intent_not_model_probability",
  "source_file": "datasets\\blade\\raw\\synthetic\\campus_records\\src\\main\\java\\fixture\\App.java"
 },
 "training_target_fields": [
  "label",
  "rationale"
 ]
}
```

### synthetic_v2 (129)

```json
{
 "id": "orbit_tickets_drafts_extauth",
 "service": "orbit_tickets_variants",
 "method": "GET",
 "path": "/fixtures/orbit_tickets/reservations/drafts/extauth/{item_id}",
 "oas_snippet": "{\"paths\": {\"/fixtures/orbit_tickets/reservations/drafts/extauth/{item_id}\": {\"get\": {\"summary\": \"Orbit Tickets Drafts Extauth\", \"description\": \"Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.\", \"operationId\": \"orbit_tickets_drafts_extauth_fixtures_orbit_tickets_reservations_drafts_extauth__item_id__get\", \"parameters\": [{\"name\": \"item_id\", \"in\": \"path\", \"required\": true, \"schema\": {\"type\": \"string\", \"title\": \"Item Id\"}}, {\"name\": \"authorization\", \"in\": \"header\", \"required\": false, \"schema\": {\"type\": \"string\", \"default\": \"\", \"title\": \"Authorization\"}}], \"responses\": {\"200\": {\"description\": \"Successful Response\", \"content\": {\"application/json\": {\"schema\": {}}}}, \"422\": {\"desc…[truncated]",
 "erd_snippet": "CREATE TABLE orbit_tickets_reservations (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, value TEXT NOT NULL);\n",
 "controller_signals": {
  "has_auth_check": true,
  "admin_bypass": false,
  "tenant_check": false,
  "owner_filter": false,
  "membership_check": false,
  "auth_outside_handler": true,
  "raw_snippet": "def require_principal(authorization: str = Header(default=\"\")):\n    \"\"\"Dependency: authentication only (401). It performs no authorization.\"\"\"\n    principal = principal_for(authorization)\n    if principal is None: raise HTTPException(401)\n    return principal\n\n@app.get('/fixtures/orbit_tickets/reservations/drafts/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')\ndef orbit_tickets_drafts_extauth(item_id: str, principal: dict = Depends(require_principal)):\n    obj = OBJECTS.get(item_id)\n    if obj is None: raise HTTPException(404)\n    # Variant: authentication via dependency only; no authorization check.\n    return obj"
 },
 "label": "manual_review_required",
 "rationale": "Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.",
 "confidence": 1.0,
 "description": "Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.",
 "security_state": "unknown",
 "meta": {
  "source": "synthetic",
  "label_source": "intended_labels",
  "human_confirmed": false,
  "evidence_invalid": false,
  "flag_review": false,
  "known_vulnerable": true,
  "confidence_provenance": "design_intent_not_model_probability",
  "source_file": "datasets/blade/raw/synthetic_v2/variants/orbit_tickets/app_variants.py",
  "framework": "fastapi",
  "data_version": "data-v2",
  "variant_kind": "extauth",
  "variant_of": "orbit_tickets",
  "oas_status": "original_export",
  "group_membership_semantics": "v3.0"
 },
 "training_target_fields": [
  "label",
  "rationale"
 ]
}
```

### vuln_route_only (test_v30)

```json
{
 "id": "887fef961a2a2394c816",
 "source": "vuln",
 "service": "crAPI",
 "method": "GET",
 "path": "/identity/api/auth/jwks.json",
 "label": "public",
 "oas_snippet": "{\"openapi\": \"3.0.0\", \"paths\": {\"/identity/api/auth/jwks.json\": {\"get\": {\"parameters\": [], \"responses\": {}}}}}",
 "erd_snippet": "",
 "controller_text": "  @GetMapping(\"/jwks.json\")\n  public ResponseEntity<String> verifyJwtToken() {\n    return ResponseEntity.status(HttpStatus.OK).body(jwtProvider.getPublicJwkSet());\n  }",
 "controller_signals": {
  "has_auth_check": null,
  "admin_bypass": null,
  "tenant_check": null,
  "owner_filter": null
 },
 "meta": {
  "label_source": "workbook_confirmed",
  "known_vulnerable": false,
  "oas_status": "route_only",
  "erd_status": "unknown",
  "controller_status": "available",
  "source_locations": [
   {
    "file": "services/identity/src/main/java/com/crapi/controller/AuthController.java",
    "start_line": 101,
    "end_line": 104
   }
  ]
 }
}
```

### vuln_repository_spec (test_v30)

```json
{
 "id": "b98a2ab3b50a679bfa16",
 "source": "vuln",
 "service": "VAmPI",
 "method": "DELETE",
 "path": "/users/v1/{username}",
 "label": "role_required",
 "oas_snippet": "{\"openapi\": \"3.0.1\", \"info\": {\"title\": \"VAmPI\", \"description\": \"OpenAPI v3 specs for VAmPI\", \"version\": \"0.1\"}, \"servers\": [{\"url\": \"http://localhost:5000\"}], \"paths\": {\"/users/v1/{username}\": {\"delete\": {\"security\": [{\"bearerAuth\": []}], \"tags\": [\"users\"], \"summary\": \"Deletes user by username (Only Admins)\", \"description\": \"Deletes user by username (Only Admins)\", \"operationId\": \"api_views.users.delete_user\", \"parameters\": [{\"name\": \"username\", \"in\": \"path\", \"description\": \"Delete username\", \"required\": true, \"schema\": {\"type\": \"string\", \"example\": \"name1\"}}], \"responses\": {\"200\": {\"description\": \"Successfully deleted user\", \"content\": {\"application/json\": {\"schema\": {\"type\": \"object\", \"properties\": {\"message\": {\"type\": \"string\", \"example\": \"User deleted.\"}, \"status\": {\"type\": \"string\", \"…[truncated]",
 "erd_snippet": "",
 "controller_text": "def delete_user(username):\n    resp = token_validator(request.headers.get('Authorization'))\n    if \"error\" in resp:\n        return Response(error_message_helper(resp), 401, mimetype=\"application/json\")\n    else:\n        user = User.query.filter_by(username=resp['sub']).first()\n        if user.admin:\n            if bool(User.delete_user(username)):\n                responseObject = {\n                    'status': 'success',\n                    'message': 'User deleted.'\n                }\n                return Response(json.dumps(responseObject), 200, mimetype=\"application/json\")\n            else:\n                return Response(error_message_helper(\"User not found!\"), 404, mimetype=\"application/json\")\n        else:\n            return Response(error_message_helper(\"Only Admins may delete use…[truncated]",
 "controller_signals": {
  "has_auth_check": false,
  "admin_bypass": false,
  "tenant_check": false,
  "owner_filter": false
 },
 "meta": {
  "label_source": "workbook_confirmed",
  "known_vulnerable": false,
  "oas_status": "repository_spec",
  "erd_status": "unknown",
  "controller_status": "available",
  "source_locations": [
   {
    "file": "api_views/users.py",
    "start_line": 206,
    "end_line": 222
   }
  ]
 }
}
```

## 실제 모델 입력 예시 (v3.0.1 user 메시지 원문; system은 프롬프트 전문)

### apisguru / oas

```
Return JSON.
{"method": "GET", "path": "/accounts/{account_id}/apps", "path_params": ["account_id"], "query_params": [], "summary": "Lists apps", "description": "List all applications for the specified account ID.", "security": [{"bearer_auth": []}], "schema_fields": ["[]._links", "[].accountId", "[].apnsUseSandboxEndpoint", "[].id", "[].name", "[].status", "[].tlsOnly"], "schema_provenance": "Fields extracted from API response schema; not a verified database ERD", "owner_cols": ["accountId"], "tenant_cols": ["accountId"], "security_state": "declared"}
```

### apisguru / oas_code

```
(코드 없음 — oas_code 조건 해당 없음)
```

### gitea / oas_code

```
Return JSON.
{"method": "GET", "path": "/users/{username}/starred", "path_params": ["username"], "query_params": ["page", "limit"], "summary": "The repos that the given user has starred", "description": "핸들러 원문(근거). 라우트 미들웨어 체인 정의와 핸들러 발췌(routers/api/v1). 요약된 미들웨어는 주석으로 표시.\n// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), context.UserAssignmentAPI(), checkTokenPublicOnly(), individualPermsChecker, reqStarsEnabled()\n\n// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.\n\n// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.\n\n// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.\n\n// context.UserAssignmentAPI(): resolves {username} into ctx.ContextUser (404 if missing); no authorization.\n\n// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.\n\n// individualPermsChecker: a user with restricted visibility is only visible to admins/self; otherwise no effect.\n\nfunc reqStarsEnabled() func(ctx *context.APIContext) {\n\treturn func(ctx *context.APIContext) {\n\t\tif setting.Repository.DisableStars {\n\t\t\tctx.APIError(http.StatusForbidden, \"stars disabled by administrator\")\n\t\t\treturn\n\t\t}\n\t}\n}\n\n// ---- handler user.GetStarredRepos (routers/api/v1/user/star.go:51-89)\nfunc GetStarredRepos(ctx *context.APIContext) {\n\n\tprivate := ctx.ContextUser.ID == ctx.Doer.ID\n\trepos, err := getStarredRepos(ctx, ctx.ContextUser, private)\n\tif err != nil {\n\t\tctx.APIErrorInternal(err)\n\t\treturn\n\t}\n\n\tctx.SetLinkHeader(int64(ctx.ContextUser.NumStars), utils.GetListOptions(ctx).PageSize)\n\tctx.SetTotalCountHeader(int64(ctx.ContextUser.NumStars))\n\tctx.JSON(http.StatusOK, &repos)\n}", "security": [{"BasicAuth": []}, {"Token": []}, {"AccessToken": []}, {"AuthorizationHeaderToken": []}, {"SudoParam": []}, {"SudoHeader": []}, {"TOTPHeader": []}], "security_state": "declared", "schema_fields": [], "schema_provenance": "Fields extracted from API response schema; not a verified database ERD", "owner_cols": [], "tenant_cols": []}
```

### gitea / oas

```
Return JSON.
{"method": "GET", "path": "/users/{username}/starred", "path_params": ["username"], "query_params": ["page", "limit"], "summary": "The repos that the given user has starred", "description": "", "security": [{"BasicAuth": []}, {"Token": []}, {"AccessToken": []}, {"AuthorizationHeaderToken": []}, {"SudoParam": []}, {"SudoHeader": []}, {"TOTPHeader": []}], "security_state": "declared", "schema_fields": [], "schema_provenance": "Fields extracted from API response schema; not a verified database ERD", "owner_cols": [], "tenant_cols": []}
```

### vuln_repository_spec / oas

```
Return JSON.
{"method": "DELETE", "path": "/users/v1/{username}", "path_params": ["username"], "query_params": [], "summary": "Deletes user by username (Only Admins)", "description": "Deletes user by username (Only Admins)", "security": [{"bearerAuth": []}], "security_state": "declared", "schema_fields": ["message", "status"], "schema_provenance": "Fields extracted from API response schema; not a verified database ERD", "owner_cols": [], "tenant_cols": []}
```

### vuln_repository_spec / oas_code

```
Return JSON.
{"method": "DELETE", "path": "/users/v1/{username}", "path_params": ["username"], "query_params": [], "summary": "Deletes user by username (Only Admins)", "description": "Deletes user by username (Only Admins)\n핸들러 원문(근거). 해당 엔드포인트의 인가 관련 코드 발췌이며 다른 검사가 더 있을 수 있다.\nFILE api_views/users.py\ndef delete_user(username):\n    resp = token_validator(request.headers.get('Authorization'))\n    if \"error\" in resp:\n        return Response(error_message_helper(resp), 401, mimetype=\"application/json\")\n    else:\n        user = User.query.filter_by(username=resp['sub']).first()\n        if user.admin:\n            if bool(User.delete_user(username)):\n                responseObject = {\n                    'status': 'success',\n                    'message': 'User deleted.'\n                }\n                return Response(json.dumps(responseObject), 200, mimetype=\"application/json\")\n            else:\n                return Response(error_message_helper(\"User not found!\"), 404, mimetype=\"application/json\")\n        else:\n            return Response(error_message_helper(\"Only Admins may delete users!\"), 401, mimetype=\"application/json\")", "security": [{"bearerAuth": []}], "security_state": "declared", "schema_fields": ["message", "status"], "schema_provenance": "Fields extracted from API response schema; not a verified database ERD", "owner_cols": [], "tenant_cols": []}
```

