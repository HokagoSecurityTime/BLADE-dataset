# policy_label_v3.0 — v2.9 대비 변경점

- v3.0 SHA-256: `d2dc8377c28830c7dfdefe297c63a0ff1623eb5036d1e3ae3c31b38e2dea2fc5` (10,036 bytes)
- v2.9 SHA-256: `f748510fea456603e2b2fbb77f99cff4fa583444968a301a430218b54731b518` (5,008 bytes)
- 작성일: 2026-10-21. 사람 교정 61건(human_corrections_v5.jsonl)은 어디에도 사용하지 않았다. v2.9 자체에 사람 교정 few-shot은 없었다(v2.6에만 존재).

| 항목 | v2.9 | v3.0 |
|---|---|---|
| 라벨 6종 정의 | 그룹 구성원 의미의 membership 등 | **동일 유지** |
| 판단 절차 6단계 | 있음 | **동일 유지** |
| 보안·근거 규칙(security_state, mutation 제한, schema 후보 해석) | 있음 | 동일 유지 + 코드가 description에 포함될 때의 해석 규칙(거부 분기의 부정 = 허용 조건, 코드에 없는 검사 가정 금지) 추가 |
| 구독·플랜·등급만 요구 | manual 정의 끝에 한 문장 | **"보류가 필수인 경우" 절로 독립, 1항** |
| OAS만으로 관계·조건 확인 불가 | 명시 없음(근거 부족 일반 규칙) | **2항 명시: 객체 ID·owner/tenant 필드·자원 이름만으로 추측 금지, 설명에 조건이 명시된 경우만 선택 가능** |
| 복합 AND 조건 | 판단 절차 4단계 | **3항으로 별도 명시(예시 포함)** |
| 코드·의도 충돌, 전면 거부·미확정 코드 | 절차 5단계 일부 | **4·5항 명시** |
| 예시(few-shot) | 없음 | **8개 추가** — 전부 train 전용 합성 서비스(orbit_tickets·copper_wallet·campus_records) 코드·OAS에서 작성. test 전용 합성(quill_blog·folio_wiki·beacon_iot) 미사용. 합성 intended_labels의 "premium plan" membership은 v3.0 정의에 따라 manual 예시로 변환 |
| 실험 버전 머리말("제출 설계 정렬 실험", v2.8 대비 해석 주의) | 있음 | 제거, v3.0 목적 문장으로 교체 |
| 출력 스키마·confidence 안내·근거 이름 목록 | 있음 | **동일 유지**(기존 Output 검증·evidence 검사 코드와 호환) |

주의: 합성 intended_labels.yaml의 `membership_required`(premium plan)는 v3.0 정의와 충돌한다. Q 단계 일치율은 원본 intended_labels 기준과 v3.0 정의 보정(subscription→manual) 기준을 함께 보고한다.
