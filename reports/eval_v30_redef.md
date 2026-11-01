# eval-def v2 재계산 — LoRA v1 4개 조합 (test_v30, 예측 파일 재사용, 추론 없음)

구간(reports/eval_v30_redef/segments.json): 전체 269 · 합성 58 · 취약 route_only 109 · 취약 repository_spec 102 · security declared 64 · oas 주지표(route_only 제외) 160. test_v30.jsonl은 불변. 정의 변경 내용은 AGENTS.md '평가 정의 eval-def v2'.

## 1. 구 정의(v1) vs 신 정의(v2) 비교

주지표 macro-F1은 support 있는 label 평균. 신 정의 oas 주지표는 route_only 109건 제외(160건), oas_code는 전체 265건(정답 변경 없음). "합성 제외"는 주지표에서 합성 58건을 뺀 값(oas 102건 = repository_spec, oas_code 207건). public 오판 신 정의 = declared ∧ 예측 public ∧ 정답≠public, 분모 declared ∧ 정답≠public(47건). 구체 응답 정밀도/재현율 = 정답이 구체 label인 건 중 구체로 답한 비율의 정확도 / 전체 대비 정답률.

| 조건 | 모델 | macro-F1 구(전체) | macro-F1 신(주지표) | 신·합성 제외 | 합성 58만 | manual 구 | manual 신(주지표) | public 오판 구 | public 오판 신 | 구체 P/R 구 | 구체 P/R 신 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| oas | base_v301 | 0.572 | 0.7078 | 0.2896 | 0.9539 | 28.6% | 13.8% | 27/64 | 13/47 | 0.5605 / 0.3465 (응답률 0.6181) | 0.6542 / 0.4795 (응답률 0.7329) |
| oas | lora_v1 | 0.5636 | 0.6889 | 0.3528 | 1.0 | 68.4% | 46.9% | 11/64 | 0/47 | 0.8353 / 0.2795 (응답률 0.3346) | 0.8353 / 0.4863 (응답률 0.5822) |
| oas_code | base_v301 | 0.6457 | 0.6457 | 0.1958 | 0.9543 | 9.4% | 9.4% | 33/64 | 18/47 | 0.4693 / 0.428 (응답률 0.912) | 0.4693 / 0.428 (응답률 0.912) |
| oas_code | lora_v1 | 0.5762 | 0.5762 | 0.2431 | 1.0 | 29.4% | 29.4% | 7/64 | 1/47 | 0.6022 / 0.448 (응답률 0.744) | 0.6022 / 0.448 (응답률 0.744) |

합성 58건 주석: test 합성 58건 중 56건이 train 합성과 같은 경로 템플릿, 43건은 정규화한 인가 검사 줄까지 동일(reports/data_v1_audit.md 4절). 합성 구간 수치는 일반화 근거로 쓰지 않는다.

## 2. oas 보조지표 — route_only 109건(명세 없음), manual 예측을 정답으로 인정

| 모델 | N | 정확도(manual 인정) | macro-F1(manual 인정) | manual 예측 비율 | 정확도(엄격, 구 정의) | macro-F1(엄격) |
|---|---:|---:|---:|---:|---:|---:|
| base_v301 | 109 | 67.0% | 0.3059 | 50.5% | 17.4% | 0.1044 |
| lora_v1 | 109 | 100.0% | 1.0 | 100.0% | 0.9% | 0.0036 |

## 3. public 오판 재정의 효과 — 구 정의로 잡힌 건 중 정답이 실제 public인 건

| 조건 | 모델 | 구 정의 건수 | 그중 정답이 public(오판 아님) | 신 정의 건수/분모 | 정답 public인 id |
|---|---|---:|---:|---:|---:|
| oas | base_v301 | 27 | 14 | 13/47 | 149fc53d41cf49d52bb9, 9a7d3d59efab53f32063, 860383f68102b772bb99, c085f5d6b9f87dd6d4a1, 324601a8dc9e9ea969bb, d72193f9a1b7d79700d0, 58e3df2930d0ce4c3175, 61f662463e13765b9478, be8b11cdbabe4486aeda, 7e3f8c20d798e8b34143, bb532c95786f45e07314, d553cdd9276767f1b1bc, beacon_iot_catalogue_0, beacon_iot_catalogue_1 |
| oas | lora_v1 | 11 | 11 | 0/47 | 149fc53d41cf49d52bb9, 9a7d3d59efab53f32063, 860383f68102b772bb99, 7a19e5a3a9eb0d5947f3, c085f5d6b9f87dd6d4a1, d72193f9a1b7d79700d0, 58e3df2930d0ce4c3175, bb532c95786f45e07314, d553cdd9276767f1b1bc, beacon_iot_catalogue_0, beacon_iot_catalogue_1 |
| oas_code | base_v301 | 33 | 15 | 18/47 | 149fc53d41cf49d52bb9, 9a7d3d59efab53f32063, 860383f68102b772bb99, c085f5d6b9f87dd6d4a1, 3dc50d2c3650a204001d, d72193f9a1b7d79700d0, bc1dce3621c7da44ddfe, 58e3df2930d0ce4c3175, 61f662463e13765b9478, be8b11cdbabe4486aeda, 7e3f8c20d798e8b34143, bb532c95786f45e07314, d553cdd9276767f1b1bc, beacon_iot_catalogue_0, beacon_iot_catalogue_1 |
| oas_code | lora_v1 | 7 | 6 | 1/47 | 149fc53d41cf49d52bb9, c085f5d6b9f87dd6d4a1, d72193f9a1b7d79700d0, 61f662463e13765b9478, beacon_iot_catalogue_0, beacon_iot_catalogue_1 |

신 정의 오판 id:

- oas / base_v301: 759eb32d69ab1820e44d, aae57acca0e9317e81c1, d93acb187b6c273464f0, 15af38ebe8faf15c930f, 6bca6097b26cf226f405, cdd3d3e140b0b509bcd3, af6e2ae1b29132ee1d77, dcc8f1be82d40ee3d5cf, fc9dac901542ca88d688, 5a72ac6384c12b441687, d8c5cf5eb0bfbd488219, 956a6feb1b1f65eb5a9a, 0b0918598294090d14c3
- oas / lora_v1: 없음
- oas_code / base_v301: 759eb32d69ab1820e44d, ff8c5eda79000fa6687f, b3906a959a0b669047ba, aae57acca0e9317e81c1, acdc8447219278841824, d93acb187b6c273464f0, d0afe4b052514b189dfa, 5928631c56d36ced026a, c3203410c4072686beaa, 15af38ebe8faf15c930f, 6bca6097b26cf226f405, dcc8f1be82d40ee3d5cf, c917e3e10dce94cc245c, fc9dac901542ca88d688, 5a72ac6384c12b441687, 4de2f44349d88f3d6b3a, d8c5cf5eb0bfbd488219, 0b0918598294090d14c3
- oas_code / lora_v1: d8c5cf5eb0bfbd488219

## 4. 신 정의 주지표 label별 P/R/F1 (support 포함)

### oas / base_v301 — 주지표 160건, macro-F1 0.7078 (7종)

| label | support | P | R | F1 |
|---|---:|---:|---:|---:|
| public | 42 | 0.5231 | 0.8095 | 0.6355 |
| role_required | 22 | 0.6 | 0.4091 | 0.4865 |
| membership_required | 4 | 1.0 | 1.0 | 1.0 |
| tenant_match | 8 | 1.0 | 1.0 | 1.0 |
| owner_match | 62 | 1.0 | 0.1452 | 0.2535 |
| owner_or_admin | 8 | 1.0 | 0.75 | 0.8571 |
| manual_review_required | 14 | 0.5909 | 0.9286 | 0.7222 |

### oas / lora_v1 — 주지표 160건, macro-F1 0.6889 (7종)

| label | support | P | R | F1 |
|---|---:|---:|---:|---:|
| public | 42 | 0.9583 | 0.5476 | 0.697 |
| role_required | 22 | 0.5263 | 0.4545 | 0.4878 |
| membership_required | 4 | 0.8 | 1.0 | 0.8889 |
| tenant_match | 8 | 1.0 | 1.0 | 1.0 |
| owner_match | 62 | 0.8571 | 0.2903 | 0.4337 |
| owner_or_admin | 8 | 1.0 | 1.0 | 1.0 |
| manual_review_required | 14 | 0.1867 | 1.0 | 0.3146 |

### oas_code / base_v301 — 주지표 265건, macro-F1 0.6457 (7종)

| label | support | P | R | F1 |
|---|---:|---:|---:|---:|
| public | 66 | 0.4296 | 0.8788 | 0.5771 |
| role_required | 47 | 0.2623 | 0.3404 | 0.2963 |
| membership_required | 4 | 1.0 | 1.0 | 1.0 |
| tenant_match | 8 | 1.0 | 1.0 | 1.0 |
| owner_match | 114 | 1.0 | 0.114 | 0.2047 |
| owner_or_admin | 11 | 1.0 | 0.7273 | 0.8421 |
| manual_review_required | 15 | 0.48 | 0.8 | 0.6 |

### oas_code / lora_v1 — 주지표 265건, macro-F1 0.5762 (7종)

| label | support | P | R | F1 |
|---|---:|---:|---:|---:|
| public | 66 | 0.7429 | 0.3939 | 0.5149 |
| role_required | 47 | 0.3099 | 0.4681 | 0.3729 |
| membership_required | 4 | 0.2857 | 1.0 | 0.4444 |
| tenant_match | 8 | 1.0 | 1.0 | 1.0 |
| owner_match | 114 | 0.88 | 0.386 | 0.5366 |
| owner_or_admin | 11 | 1.0 | 0.7273 | 0.8421 |
| manual_review_required | 15 | 0.1923 | 1.0 | 0.3226 |

## 5. 결론이 바뀌는 항목 (사실만)

- oas 주지표 macro-F1: 구 0.572 vs 0.5636 → 신 0.7078 vs 0.6889. 순위(베이스 > LoRA)는 유지되나 차이가 줄고, 합성을 제외하면 0.2896 vs 0.3528로 역전된다.
- oas manual 비율: LoRA 구 68.4% → 신(주지표) 46.9%. route_only 109건에서 LoRA는 전부 manual을 예측했고 보조지표(manual 인정) 정확도 100.0%, 베이스 67.0%.
- public 오판: 구 정의 베이스 27·LoRA 11(oas) 가운데 각각 14·11건은 정답이 public이라 오판이 아니었다. 신 정의로는 oas 베이스 13/47, LoRA 0/47; oas_code 베이스 18/47, LoRA 1/47.
- oas_code macro-F1은 정의 변경으로 바뀌지 않는다(0.6457 vs 0.5762); 합성 제외 시 0.1958 vs 0.2431.

원자료: reports/eval_v30_redef/scores.json, segments.json. 채점 스크립트 scripts/eval_v30.py (`--eval-def both --md`).
