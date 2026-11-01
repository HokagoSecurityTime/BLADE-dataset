# BLADE-dataset — BLADE API 인가 정책 라벨 데이터셋

REST 엔드포인트(OpenAPI 명세 + DB 스키마 발췌 + 선택적 핸들러 코드 발췌)에 필요한 **인가 정책을 7종 라벨**로 붙인 데이터셋입니다. BLADE 프로젝트([blade-project](https://github.com/HokagoSecurityTime/BLADE))의 LoRA 분류기 학습·평가에 쓰였습니다. 레코드는 JSON Lines이고 라벨마다 confidence·rationale·근거 필드가 있습니다.

> 코드 발췌의 재배포가 허용 라이선스로 보장되지 않는 레코드 162건은 **코드 본문만 비운 공개 사본**으로 제공합니다. 라벨·명세·메타데이터·링크는 그대로 있고, 원본은 `scripts/rebuild_from_public.py`로 바이트 동일하게 복원할 수 있습니다(아래 "공개 사본과 복원").

## 구성

| 용도 | 파일 | 건수 | 비고 |
|---|---|---:|---|
| **학습 train (data-v5)** | `datasets/blade/processed/public/train_v5_public.jsonl` | 1,277 | 코드 본문 제외 126건(NodeBB 98 + 미선언 저장소 28) |
| **학습 val (data-v5)** | `datasets/blade/processed/public/val_v5_public.jsonl` | 180 | 코드 본문 제외 11건(NodeBB) |
| **평가 test_v30** (주지표) | `datasets/blade/processed/public/test_v30_public.jsonl` | 269 | 공개 취약 API 211 + 합성 58. 코드 본문 제외 25건(DVWS-node) |
| **평가 test_v31_supp** (별도 조건) | `datasets/blade/processed/data_v4/test_v31_supp_manifest.json` | 222 | 라벨·저장소·커밋·고정 링크만(코드 비공개: Flowise enterprise/, 미선언 출처 2개) |
| **평가 test_v5** (hold-out) | `datasets/blade/processed/test_v5.jsonl` | 283 | Rocket.Chat·Ghost·Umami(모두 MIT), 코드 포함 전체 공개 |
| SFT 입력(train / val) | `training/lora/public/data_v5_train_sft_v5_public.jsonl` · `data_v5_val_sft_v5_public.jsonl` | 1,148 / 168 | 원본 1,274 / 179에서 코드가 든 행 126 / 11 제외 |
| 프롬프트(system) | `training/data/prompts/policy_label_v3.0.1.md` | - | 라벨 정의·판단 절차. 학습·추론 공통, SHA-256 `d0913c27…` |

이전 버전(data-v1 `train_v30`/`val_v30`, data-v2 `train_v2`/`val_v2`, data-v3a/b, v3.1b, data-v4)도 같은 폴더에 있습니다. 동결 파일의 SHA-256과 구성 규칙은 [datasets/blade/DATA_CARD.md](datasets/blade/DATA_CARD.md), 출처별 저장소·커밋·라이선스는 [reports/data_sources.md](reports/data_sources.md)에 있습니다.

### 라벨 분포

| label | train_v5 | val_v5 | test_v30 | test_v31_supp | test_v5 |
|---|---:|---:|---:|---:|---:|
| owner_match | 447 | 45 | 114 | 21 | 34 |
| role_required | 326 | 50 | 51 | 39 | 111 |
| manual_review_required | 165 | 42 | 15 | 30 | 65 |
| owner_or_admin | 97 | 13 | 11 | 20 | 21 |
| tenant_match | 83 | 9 | 8 | 55 | 0 |
| public | 82 | 13 | 66 | 2 | 19 |
| membership_required | 77 | 8 | 4 | 55 | 33 |
| **합계** | **1,277** | **180** | **269** | **222** | **283** |

### 출처 요약

- 학습: APIs.guru 공개 OpenAPI(명세만) · Gitea · 13개 오픈소스 저장소의 핸들러 "검사 유지/검사 제거" 쌍 · Zulip · Label Studio · Dendrite · NodeBB · Taiga · 자체 제작 합성 서비스 11개.
- 평가: OWASP Juice Shop · crAPI · Pixi · DVWS-node · VAmPI(test_v30), Chatwoot · Chamilo · Flowise · Generic University · multitenant lab(test_v31_supp), Rocket.Chat · Ghost · Umami(test_v5). 평가 출처와 그 포크는 학습에 쓰지 않았습니다.
- AGPL 프로젝트는 모두 제외했습니다. 전체 목록과 제외 사유: [reports/data_sources.md](reports/data_sources.md).

## 레코드 형식

```json
{"id": "…", "source": "repository_spec|route_only|synthetic|apisguru|…", "service": "…", "method": "GET", "path": "/orders/{orderId}",
 "label": "owner_match", "oas_snippet": {…}, "erd_snippet": "CREATE TABLE …", "controller_text": "…핸들러 코드 발췌 또는 \"\"…",
 "controller_signals": {…}, "meta": {"label_source": "…", "source_locations": [{"file": "…", "start_line": 1, "end_line": 20}], "code_withheld": "(공개 사본에서 비운 경우만)", "code_ref": {…}}}
```

SFT 행은 `{id, source, condition(oas|oas_code), label, user, assistant, …}`이며 `assistant`는 `{"label","confidence","rationale","evidence_fields"}` 한 줄 JSON입니다. 필드 사전: [reports/data_dictionary.md](reports/data_dictionary.md).

## 라벨 7종

프롬프트 v3.0.1의 정의를 그대로 옮긴 요약입니다. 원문은 [training/data/prompts/policy_label_v3.0.1.md](training/data/prompts/policy_label_v3.0.1.md), 코드 검수 규약(G1~G8)은 DATA_CARD의 data-v4 절에 있습니다.

| label | 의미 |
|---|---|
| `public` | 인증 없이 누구나 접근 가능하다는 긍정 근거가 있다. 검사가 안 보인다는 이유만으로 선택하지 않는다. |
| `role_required` | 특정 역할(전역 역할, 또는 그룹 구성원 확인 뒤 그룹 안 역할) 보유가 실제 접근 조건이다. |
| `membership_required` | 요청자가 요청 대상 그룹·팀의 구성원이어야 한다. (requester, target_group) 구성원 조회가 근거다. 구독·플랜은 아니다. |
| `tenant_match` | 요청자 테넌트와 대상 자원의 테넌트가 같아야 한다(세션의 활성 조직·워크스페이스로 필터). |
| `owner_match` | 요청자가 대상 객체의 소유자 본인이거나, 처리 대상이 인증 사용자 본인으로 고정된다. |
| `owner_or_admin` | 소유자 허용 OR 관리자 우회가 실제 조건이다. |
| `manual_review_required` | 근거 부족·모순·독립 필수 조건의 AND 결합·인증만 확인 등으로 6종 중 하나를 고를 수 없다. 자동 적용 제외. |

## 공개 사본과 복원

`datasets/blade/processed/public/*_public.jsonl`은 동결 원본과 레코드 수·라벨이 같고, 아래 162건만 `controller_text`가 `""`이며 `meta.code_withheld`(사유)와 `meta.code_ref`(저장소·커밋·라이선스·원문 SHA-256·고정 링크)가 추가돼 있습니다. 나머지 줄은 원본과 바이트 동일합니다.

| 사유 | 건수 | 영향 파일 |
|---|---:|---|
| GPL-3.0 — snoopysecurity/dvws-node `eb6e2886` | 25 | test_public, test_v30_public, test_v30_inputs 사본(oas_code_user → null) |
| 라이선스 미선언 — RealWorld 구현 5개 저장소(data-v3 코드 쌍) | 28 | train_v3a/v3b/v31b/v4/v5_public, pairs_train_v3s1/v3s1b_public |
| GPL-3.0 — NodeBB `c3d8dc51` | 109 | train_v5_public, val_v5_public |

- `datasets/blade/processed/public/withheld_manifest.json`: 레코드별 출처와 **코드가 들어 있지 않은** 조립 규칙(줄 범위·공백 변환·생략 표시, 변형 레코드는 원본 줄 번호와 들여쓰기), 원본·사본 SHA-256.
- 복원: 해당 저장소를 기록된 커밋으로 클론한 뒤 실행합니다. 원본 10개 파일이 바이트 동일하게 복원되는지 SHA-256으로 확인합니다(2026-11-01 검증, 162/162).

```bash
git clone https://github.com/snoopysecurity/dvws-node datasets/blade/raw/vuln_apis/DVWS-node && git -C datasets/blade/raw/vuln_apis/DVWS-node checkout eb6e2886f2206b88bf709fe1fa311adc3ae3c34f
# NodeBB, RealWorld 5개 저장소도 withheld_manifest.json의 clones 항목대로 클론
python -X utf8 scripts/rebuild_from_public.py            # → .cache/rebuild_from_public/ 에 원본 복원 + 해시 대조
```

- SFT 공개 사본은 코드가 든 행을 제외했으므로 원본과 해시가 다릅니다. 학습 재현은 복원된 레코드 파일로 `training/lora/prepare_lora_v3_inputs.py` 계열 스크립트를 다시 실행합니다.
- test_v31_supp는 코드를 공개하지 않습니다(manifest의 저장소·커밋·파일·줄 링크로 확인). 공개 제외 원본 목록: `datasets/blade/processed/public/PUBLIC_EXCLUDE.txt`.

## 평가 방법

- 주지표: test_v30 oas_code 조건, 합성 제외 207건(eval-def v2) — `scripts/eval_v30.py --pred <predictions.jsonl>`. 구간 정의 `reports/eval_v30_redef/segments.json`.
- hold-out test_v5: `scripts/eval_test_v5.py --pred … --out …`, test_v31_supp: `scripts/eval_v31_supp.py`. 모델별 결과는 프로젝트 저장소 `reports/eval/lora_v5/`.

## 라이선스

- **라벨·rationale·메타데이터·합성 서비스·문서**: [CC BY 4.0](LICENSE). 출처 표기 예: "BLADE-dataset (HokagoSecurityTime), CC BY 4.0".
- **코드 발췌(`controller_text`, SFT user 메시지 안의 코드, `data/*/candidates.jsonl`, `datasets/blade/raw/*` fixture)**: 각 원 저장소의 라이선스를 그대로 따릅니다(MIT·Apache-2.0·MPL-2.0 등). 출처별 저장소·커밋·라이선스·링크는 [NOTICE.md](NOTICE.md)에 정리했습니다.
- GPL·상용·미선언 라이선스 출처의 코드 본문은 이 저장소에 포함하지 않았습니다(위 "공개 사본과 복원").

## 인용

```bibtex
@misc{blade_dataset_2026,
  title  = {BLADE-dataset: Authorization Policy Labels for REST Endpoints (BLADE)},
  author = {HokagoSecurityTime},
  year   = {2026},
  url    = {https://github.com/HokagoSecurityTime/BLADE-dataset},
  note   = {data-v5 (train 1,277 / val 180), test_v30 269, test_v31_supp 222, test_v5 283}
}
```

## 알려진 한계

- test_v5의 `membership_required` 33건 중 28건이 Rocket.Chat이고 `tenant_match` 정답은 0건입니다. test_v31_supp는 label이 프로젝트에 몰려 있습니다(membership 50/55 Chatwoot, tenant 52/55 Flowise, owner_or_admin 19/20 Chamilo).
- 학습 라벨은 APIs.guru 구간은 `gpt-4o-mini`(프롬프트 v3.0.1), 코드 구간은 코드 규칙 + 사람 표본 검수입니다. test_v5는 AI 1차 판정 후 사람 확인입니다. 상세와 Errata는 DATA_CARD를 보세요.
