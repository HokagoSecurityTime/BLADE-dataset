# C1 검수 시트 생성 보고 (2026-11-05, 작업 C′ / data-v6d — 생성 후 정지, 커밋 금지)

생성 `scripts/build_c1_review_sheet.py`(seed 42). 동결 파일(data-v5 train/val, SFT, test)은 해시 확인 후 읽기만 했다. xlsx는 커밋하지 않는다.

## 산출

- `review/c1_relabel_review.xlsx` SHA-256 `942512205457327e5f46345b397cc60752879214798de19476ce888bfe6bf2fb` — 시트 5개: 안내·검수 규약 / 무작위5%_블라인드 68 / 판정필요_코드 39 / 판정필요_OAS문구 22 / 변경예상_C2 46(결정적 초안 32 + review 1 + C2 전용 13).
- `reports/data_v6d/c1_draft_deterministic.jsonl` 32건 — 결정적 규칙 예측의 기계 적용 초안(label_draft + 템플릿 rationale_draft). 사람 확인 전이며 train_v5·SFT 파일은 수정하지 않았다.
- `reports/data_v6d/c1_audit_key.json` — 블라인드 표본 정답키(시트 밖). 사전 기록: 불일치율 > 5%면 한계로 기록, 전수 검수는 마감 후.

## 검수자 배분(A/B/C, 시트별 seed 42 셔플 후 순환)

| 시트 | 건수 | A | B | C |
|---|---:|---:|---:|---:|
| 무작위5%_블라인드 | 68 | 23 | 23 | 22 |
| 판정필요_코드 | 39 | 13 | 13 | 13 |
| 판정필요_OAS문구 | 22 | 8 | 7 | 7 |
| 변경예상_C2 | 46 | 16 | 15 | 15 |
| 합계 | 175 | 60 | 58 | 57 |

## 열과 규칙

- 공통 열: id · split · 프로젝트 · method · path · security_state · 입력 요약 · 코드/OAS 본문 · 현재 label · 현재 rationale(SFT) · 후보 규칙 · 예상 label(초안) · 예상 근거 · 초안 rationale(템플릿) · 기존 검수 label·검수자 · C2 재작성 대상 · 확정 label · 확정 근거(코드 줄·설명 문장) · 확정 rationale(자유문, 선택) · 검수 메모 · 검수자. 블라인드 시트는 현재 label·예상 label·rationale·후보 규칙·기존 검수 열을 뺀 id · split · 프로젝트 · method · path · security_state · 입력 요약 · 코드/OAS 본문 · 확정 label · 확정 근거(코드 줄·설명 문장) · 검수 메모 · 검수자.
- 결정적 초안 32건은 "확정 label" 열에 초안 label을 미리 채웠고(사람이 확인·수정), 나머지는 비어 있다. "초안 rationale(템플릿)"은 C2용 초안이며 확정이 아니다.
- C2 재작성 대상 열: Y(label 변경) 33 · Y(v3.0.1 문구) 13 · C1 결과에 따름 61. C2 출발점은 SFT assistant rationale("현재 rationale(SFT)" 열)이다.
- 기존 검수 label이 있는 행: 28건(기존 label 유지가 기본값, 변경 시 사유 기재).
- 안내 시트 첫 줄에 "블라인드 시트부터" 순서를 명시했다. 블라인드 표본은 C0 c0_audit_sample_ids.json(seed 42, 모집단 1,359)과 동일하며 다른 시트 행과 겹치지 않는다(assert).

## 다음 단계(승인 후)

검수 완료본 `review/c1_relabel_review_reviewed.xlsx` 수령 → 블라인드 불일치율 계산·보고 → 확정 label 반영 + C2 rationale 재작성(템플릿/LLM 초안 + 사람 확인) → 정합성 assert → data-v6d 동결(정지 지점) → C′ 학습은 별도 승인. 중단 규칙: 2026-11-08 12:00 KST까지 결과 없거나 미달이면 C′ 중단.
