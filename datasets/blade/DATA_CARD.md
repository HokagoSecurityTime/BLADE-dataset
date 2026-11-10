# BLADE 데이터셋 초안 — v2.5

## 출처와 라벨 방법

- APIs.guru: 설명을 복구한 공개 OAS 2,027건. OpenAI gpt-4o-mini + 고정 policy_label_v2.5로 생성. 사람 샘플 검수 완료 N=0건. 라벨은 구조·설명에서 제안한 인가 패턴이지 검증된 실제 정책이 아니다.
- 공개 취약 API: VAmPI·crAPI·Juice Shop·Pixi·DVWS-node 275건. 코드·문서 근거 제안이며 사람 확정 전이다. 전부 test 전용.
- 합성: FastAPI 2·Express 2·Spring 1·Django 1의 84건. intended_labels.yaml의 설계 의도를 사용하며 사람 확정이라고 주장하지 않는다. seed 42로 orbit_tickets·copper_wallet·campus_records의 42건을 train/val용으로 선택했다. quill_blog·folio_wiki·beacon_iot의 42건은 test 전용이다.

## v2.5 최초 분포 (2026-10-20 기계 필터 적용 전)

| label | API 전체 | train | val |
|---|---:|---:|---:|
| public | 162 | 134 | 12 |
| role_required | 63 | 63 | 6 |
| membership_required | 88 | 87 | 7 |
| tenant_match | 90 | 76 | 6 |
| owner_match | 228 | 196 | 26 |
| owner_or_admin | 12 | 17 | 1 |
| manual_review_required | 1384 | 191 | 19 |
| 합계 | 2027 | 764 | 77 |

train/val은 합성 42건을 포함한다. API confidence 분포: [0,0.5] 1,384건, (0.5,0.7) 82건, [0.7,0.9) 278건, [0.9,1] 283건. evidence_invalid 24건, flag_review 22건, label_error 0건.

사용량 5,030,138토큰(입력 4,934,620·출력 95,518), 캐시 입력 3,766,016토큰. 사용량 기반 예상 비용 $0.5150526이며 청구서 금액은 아니다. 파일럿과 교정 요청 포함. 입력·프롬프트·출력 해시와 모델은 processed/labeled_v5.manifest.json에 기록했다.

## 분할과 적격 기준

구체 label은 confidence>=0.6, evidence_invalid=false, flag_review=false를 모두 만족해야 한다. manual은 confidence 하한 없이 품질 플래그를 검사하고 seed 42로 샘플링한다. 합성은 intended_labels를 사용하며 confidence=1은 설계 의도 표시이지 모델 확률이 아니다. 학습 대상은 label+rationale이고 owner_lookup은 제외한다.

정렬한 service를 seed 42로 섞어 약 10%를 val에 배정한다. 이후 각 분할에서 API manual 수를 round_half_up(구체 label 수/3 - 합성 manual 수)로 선택한다. 양쪽 샘플 seed는 42다. 후보 service 배정은 9:1이며 샘플링 후 빈 service가 사라질 수 있다. 최종 train 231 services·val 24 services, 교차 0이다. train manual 191/764=25%, val 19/77=24.68%. 합성은 train 42건(5.50%), val 0건이다.

train 구성 코드는 선택한 합성 3개만 읽으며 test 전용 소스·데이터를 열지 않는다. demo_backend의 method/path 파라미터 이름을 정규화해 중복 5건을 제거했다. 사람 검수 오라벨률 >20%인 label의 0.6 구간 추가 제외는 N=0이므로 아직 적용하지 않았다. 모델 학습은 실행하지 않았다.

## 제외와 보존

API 중 train/val 사용 799건, 제외 1,228건. 우선순위에 따른 제외 사유는 demo 중복 5건, evidence_invalid 24건, flag_review 22건, manual 쿼터 미선택 1,177건이다.

apisguru_manual_pool.jsonl 1,180건 = 쿼터 미선택 1,177 + demo 중복 manual 3. apisguru_lowconf_pool.jsonl은 구체 label confidence<0.6이 없어 0건이다. 낮은 confidence 1,384건은 모두 manual이며 최신 사용자 승인에 따라 그중 204건은 train/val manual로 포함했다. 구체 label의 낮은 confidence 제외 규칙은 유지한다.

review_sample_v5.md는 train에서 label별 최대 20건, 구간별 우선 5건을 추출하고 부족분을 다른 구간에서 채웠다. owner_or_admin은 17건만 존재해 17건을 제공한다. 총 137건, 검수와 검수 사유는 빈칸이다.

## 공개 OAS 2,027건 중 68.28%는 명세만으로 인가 패턴 판정 불가

이는 모델의 manual_review_required 비율이며 사람이 확인한 객관적 불가능률은 아니다.

| 버전 | 보류율 | 문제·해석 |
|---|---:|---|
| v3 전체 | 8.29% | public·역할·관리자 우회 과대 판정 사례 발견 |
| v2.4 파일럿 | 77% | 엄격한 근거와 낮은 confidence 보류 지침으로 보류 집중 |
| v2.5 동일 파일럿 | 67% | 사후 변환 제거 후에도 모델이 직접 보류 반환 |
| v2.5 전체 | 68.28% | 불완전 명세와 고정 프롬프트에서 보류 지속 |

파일럿은 v3 라벨별 층화 표본 200건이므로 전체와 직접 동등하게 비교할 수 없다. v2.4의 154건은 사후 변환이 아니라 모델이 직접 manual을 반환한 결과다.

## 알려진 편향

공개 SaaS API 편중, API 입력 controller 신호 부재, 응답 스키마와 실제 DB ERD의 차이, LLM 라벨 오류, 미보정 confidence. manual 25% 샘플링은 실제 68.28% 분포를 바꾼다. 합성은 GET 전용·고정 토큰·메모리 데이터·공통 인가 템플릿이며 ERD는 공통 dataclass DDL이다. 합성 train/test 서비스가 달라도 생성 템플릿을 공유하므로 구조 유사성에 따른 낙관 편향이 남는다. val owner_or_admin은 1건이라 지표가 불안정하다.

## Test

2026-10-20 사용자 검수 반영 완료. review_test.xlsx에서 공개 취약 API 211건을 확정하고 64건을 제외했다. 합성 42건은 사용자의 별도 승인으로 intended_labels를 확정값으로 사용했다. test 총 253건이며 SHA-256은 `bd22c2580c2ddc2154974f76aa9e7aa2ca30bc6f8434e4960f3d3966093977fa`이다. 이후 수정하지 않는다.

| label | vuln | synthetic | 합계 |
|---|---:|---:|---:|
| public | 58 | 6 | 64 |
| owner_match | 106 | 6 | 112 |
| owner_or_admin | 3 | 6 | 9 |
| tenant_match | 0 | 6 | 6 |
| role_required | 43 | 6 | 49 |
| membership_required | 0 | 6 | 6 |
| manual_review_required | 1 | 6 | 7 |
| 합계 | 211 | 42 | 253 |

tenant_match와 membership_required는 합성에만 있다. 해당 label의 점수는 실제 공개 API 일반화의 증거가 아니다. 공개 API 211건은 ERD가 미확보이고 controller 원문은 207건 확보·4건 미확보다. 원문 확보와 런타임 controller 파서의 인식 여부는 다르다. 베이스라인은 실제 런타임의 lookup·confidence 검증을 유지하므로 입력 미확보에 따른 보류까지 포함하는 pipeline 평가다.

## v2.6 검수 반영 진행

실제 v5 검수는 137건 중 61건 수정(44.53%)이며 사용자가 요청의 138/62 대신 이 수치를 승인했다. seed 42로 few-shot 30건과 독립 검증 31건으로 분리한다. test 데이터는 v2.6 프롬프트와 train 구성에 사용하지 않는다. v2.6은 규칙 본문을 유지하고 가상 few-shot을 교정 사례로 교체한다. 검증 31건 일치율 60% 이상일 때만 전체 재실행한다.

| 원 label | 검수 | 수정 | 표본 오라벨률 |
|---|---:|---:|---:|
| public | 20 | 14 | 70% |
| role_required | 20 | 8 | 40% |
| membership_required | 20 | 11 | 55% |
| tenant_match | 20 | 1 | 5% |
| owner_match | 20 | 7 | 35% |
| owner_or_admin | 17 | 7 | 41.18% |
| manual_review_required | 20 | 13 | 65% |

검수는 confidence와 label을 층화한 작은 표본이며 전체 모집단 오라벨률의 불편 추정치가 아니다.

v2.0 베이스라인 a(gpt-4o-mini, RAG on, controller on)는 253건 완료: macro-F1 0.0903, manual 55.73%, 평균 추론 2,038ms, 출력 schema 오류 1건. ERD 미확보 211건, controller 원문은 있지만 현재 핸들러 미인식 212건, 인식 37건, 원문 미확보 4건이다. 상세 P/R/F1·confusion matrix와 Ollama 진행 결과는 reports/eval/baseline_summary.md를 참조한다.

### 즉시 적용한 train 기계 필터

기존 train 764건 중 public+declared 123건, membership+confidence<0.9 6건, APIs.guru owner_or_admin 11건: 세 조건은 총 140건이다. 전체 API 2,027건에서는 각각 154·6·12건, 총 172건이다. 검수 오라벨률 >20% 라벨의 0.6 구간 제외 규약까지 합치면 중복 제외 후 기존 train 177건·전체 API 216건이다. 수정 대상은 processed/apisguru_correction_pool.jsonl에 보존한다.

기존 train/val을 백업하고 필터와 manual 쿼터를 재적용한 현재 v5 구성은 train 512건·val 71건이며 train manual 128/512=25%이다. 합성은 두 분할 합계 42건으로 유지된다. 위 최초 분포표는 이전 결과이며 현재 세부 분포는 training/data/build_train_v5_filtered_report.json을 참조한다. v2.6 파일럿 통과 시에만 새 전체 라벨로 교체한다.

### v2.6 파일럿 결과 — 중단

200건 실행 완료. 독립 검증 31건 중 사람 라벨 일치 3건(9.68%; 같은 검증 표본의 v2.5는 0%). 기준 60% 미달로 전체 2,027건 재실행은 시작하지 않았다. v6 train/val·review_sample_v6은 생성하지 않았고, 기계 필터 적용된 v5 구성을 유지한다.

파일럿 분포: public 2, role_required 45, membership_required 12, tenant_match 2, owner_match 25, owner_or_admin 2, manual_review_required 112(56%). confidence 네 구간은 115/56/15/14건. evidence_invalid 1건, flag_review 0건, 요청 오류 0건. 총 2,263,890토큰, 사용량 기준 예상 비용 $0.23379855.

few-shot 30건과 검증 31건은 겹치지 않는다. 추가 169건은 검증 label/confidence 구간 내에서 선정했으나 일부 구간의 후보 부족으로 50건을 다른 검증 구간에서 보충했다. 상세 비교는 training/data/pilot_v6_report.md에 기록했다. 프롬프트 규칙은 추가 수정하지 않았다.

### 베이스라인 최종 결과

세 구성 모두 고정 test 253건을 완료했다.

| 구성 | macro-F1 | manual 비율 | 평균 추론 ms | 출력/통신 오류 |
|---|---:|---:|---:|---:|
| gpt-4o-mini, RAG on, controller on | 0.0903 | 55.73% | 2038.2 | 1 |
| qwen2.5:7b, RAG on, controller on | 0.1222 | 8.70% | 68159.3 | 0 |
| qwen2.5:7b, RAG off, controller off | 0.1874 | 3.16% | 12947.1 | 0 |

Ollama는 CPU에서 실행했다. 두 스위치를 함께 바꾼 비교이므로 RAG 단독 효과나 controller 단독 효과를 분리해 해석할 수 없다. ERD 미확보와 controller 파서 인식 한계를 포함한 pipeline 결과이며 순수 의미 분류 정확도가 아니다. 라벨별 P/R/F1과 confusion matrix는 reports/eval/baseline_summary.md에 있다.

## v3.0 섹션 (2026-10-21, 프롬프트 v3.0.1) — 기존 섹션은 수정하지 않음

### 프롬프트와 실행

- 프롬프트: training/data/prompts/policy_label_v3.0.1.md, SHA-256 `d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef` (v3.0 `d2dc8377…2fc5`에 인증 관련 두 문장 추가). v2.9의 라벨 정의·판단 절차를 유지하고, membership_required는 요청 대상 그룹·팀 구성원 관계, 구독·플랜·등급만 요구하면 manual_review_required, OAS만으로 관계·조건을 확인할 수 없으면 manual_review_required, 복합 AND 조건은 manual_review_required다.
- 사람 교정 61건(human_corrections_v5.jsonl)은 few-shot·검증 기준·학습 데이터 어디에도 사용하지 않았다. 이유: 사용자 지시(교정 데이터의 라벨 의미가 v2.5 기준이라 v3.0 정의와 섞이지 않도록). 예시 8개는 train 전용 합성 3개 서비스에서만 작성했다.
- Q 품질 확인(합성 train 전용 42건 × oas/oas_code, gpt-4o-mini): oas_code에서 v3.0 보정 일치 71.4%, 정상 구현 27/27 일치, 취약 변형 15건 중 public 오판 6건. 보고서 reports/eval/classification_quality/prompt_v301_q/report.md.
- 전체 재라벨링 F: APIs.guru 2,027건(apisguru_enriched_v2.jsonl, v2.5와 동일 입력), gpt-4o-mini temperature 0, 2,043회 응답, 입력 5,573,661·출력 137,031토큰, 사용량 기준 추정 $0.59(청구서 아님). 출력 datasets/blade/processed/apisguru_labeled_v301.jsonl SHA-256 `ac34bd1ec3c2eeafe584e09026a5dfd2dc0fbce9b4e045dd5e1e55326905b827`. 원시 응답은 git 미추적(reports/untracked_artifacts.md 6절).

### 전체 label 분포 (2,027건, 원본 apisguru_labeled_v301.jsonl)

| label | 건수 | 비율 |
|---|---:|---:|
| public | 173 | 8.5% |
| role_required | 124 | 6.1% |
| membership_required | 26 | 1.3% |
| tenant_match | 35 | 1.7% |
| owner_match | 138 | 6.8% |
| owner_or_admin | 1 | 0.0% |
| manual_review_required | 1,530 | 75.5% |

manual 75.48%는 v2.5의 68.28%보다 높다. 사용자가 70% 기준 초과를 확인하고 이번 train 구성 진행을 승인했다. 원인(reports/eval/classification_quality/prompt_v301_full/manual_analysis.md): security_state=unknown 754건은 96.7%가 manual(그중 description 비어 있음 262건은 259건 manual), declared 1,267건은 63.2%가 manual. manual rationale 주 유형은 객체 ID만 있음 25.8%, 요청자-객체 관계 미확인 23.1%, 인증만 확인·인가 조건 없음 19.0%, 접근 조건 미명시 9.0%, 설명 없음 8.0%, API 키만 요구 7.1%.

### override 규칙 (train 구성 시에만 적용, 원본 파일은 불변)

- public인데 security_state=declared인 150건과 비익명 mutation public(flag_review) 5건(중복 4) → 합계 151건을 manual_review_required로 바꿔 포함. meta.v30_override_reason="security_declared_public", meta.label_before_override="public". declared public 150건의 security 출처는 global(전역 선언만) 86건, operation 64건.
- 합성 subscription(premium plan) 6건은 intended membership_required를 manual_review_required로 바꿔 포함. meta.v30_relabel_reason 기록, intended_labels.yaml은 불변.
- v2.6 시기의 membership<0.9(10건)·owner_or_admin(1건) 기계 제외는 v2.5 의미 검수에서 나온 규칙이라 적용하지 않았다.

### train_v30 / val_v30 구성 (training/data/build_train_v30.py, seed 42)

- 적격: 구체 label confidence>=0.6, evidence_invalid=false(2건 제외), demo_backend 경로 중복 5건 제외. service 단위 9:1 분할, 각 분할에서 manual은 round_half_up(구체/3 − 합성 manual) 쿼터(25%), 미선택 manual 1,428건은 apisguru_manual_pool_v30.jsonl에 보존. 구체 label 저신뢰(<0.6)는 0건.
- train_v30.jsonl 441건(160 services) SHA-256 `76b675cdb84761b9a2b65206f4f4d1614a87077628ccd0274122c5b802613be0`, val_v30.jsonl 60건(26 services) SHA-256 `bfc24dc5fdce3131a6d8ce9920ec82db824dfefe6aa613efa6f964fef28390dd`. 기존 train.jsonl·val.jsonl·test.jsonl 해시 불변 확인. test 분할 서비스(합성 test 3개·공개 취약 API 5개)와 겹침 0.

| label | train (APIs.guru / 합성) | val |
|---|---:|---:|
| public | 25 (19 / 6) | 3 |
| role_required | 112 (106 / 6) | 18 |
| membership_required | 24 (24 / 0) | 2 |
| tenant_match | 35 (29 / 6) | 6 |
| owner_match | 128 (122 / 6) | 16 |
| owner_or_admin | 7 (1 / 6) | 0 |
| manual_review_required | 110 (98 / 12) | 15 |
| 합계 | 441 | 60 |

30건 미만 경고: public 25, membership_required 24, owner_or_admin 7. train에 포함된 override manual 9건, val 2건. 합성은 train 42건(9.5%), val 0건.

- 사람 검수 표본: training/data/review_sample_v30.md (membership_required 26건 전수, owner_or_admin 1건, tenant_match 15, override declared-public 20, 나머지 label 15건씩; 검수 열 비움, 상단에 v3.0.1 정의).

### 알려진 한계 (2026-10-21 사용자 확인)

1. 코드 입력 시 인증만 있고 인가 검사 없는 핸들러를 public으로 오판(Q 재실행 6/15). 인증이 핸들러 밖(데코레이터·의존성)에 있을 때 발생 추정. 프롬프트는 v3.0.1로 고정했다.
2. 프롬프트가 security 선언 시 public을 금지함에도 security_state=declared인 public 판정 150건이 남았다(global 86·operation 64). train 구성에서는 override로 manual 처리했고 원본 라벨은 보존했다.

### Test 참고

frozen test.jsonl(SHA `bd22c258…977fa`)의 membership_required 6건은 전부 "premium plan"(구독)이라 v3.0 정의와 불일치하며 tenant_match 6건은 일치한다(reports/eval/classification_quality/test_v30_check/report.md). test.jsonl은 수정하지 않는다. v3.0 기준 평가용 test_v30.jsonl은 별도 파일로 생성하며 해시는 AGENTS.md에 별도 항목으로 기록한다.

### 보강 (2026-10-21 후속): membership·owner_or_admin 합성 서비스 추가 후 재구성

- 신규 합성 서비스 2개(training/data/sources/synthetic_v30.py, FastAPI export OpenAPI): summit_club(test 전용, 16 엔드포인트: membership_required 4, 복합 tenant AND membership → manual 2, 나머지 label 2씩), relay_forum(train 전용, 18 엔드포인트: membership_required 4, owner_or_admin 4, 나머지 2씩). membership_required는 (caller_id, record.group_id) ∈ memberships 검사이며 구독·tenant와 무관하다. archive 변형은 인가 검사를 생략한 취약 변형이다. 배정은 training/data/synthetic_partition_v30.json에 고정했다.
- test_v30.jsonl 269건 SHA-256 `9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2`: frozen test 253건(구독 membership 6건만 manual로 relabel, 나머지 바이트 동일) + summit_club 16건. label: manual_review_required 15, membership_required 4, owner_match 114, owner_or_admin 11, public 66, role_required 51, tenant_match 8. membership_required 4건은 전부 합성 그룹 의미이며 사람 확정 전 설계 라벨(meta.label_source=intended_labels_v30_design)이다. test.jsonl은 불변.
- train_v30.jsonl 재구성 471건(177 services) SHA-256 `a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2`, val_v30.jsonl 52건(22 services) SHA-256 `62bdadb29cae7aaf814007ad8adec40115e8612d70f2911693219399c82b595c`. 서비스 수가 늘어 seed 42 분할의 val 서비스 집합이 바뀌었다. manual 비율 train 25.05%, val 25.00%. 합성 train 60건(42+18), val 0건. test 분할 서비스와 겹침 0.
- train label(APIs.guru+합성): public 19+8 / role_required 104+8 / membership_required 25+4 / tenant_match 32+8 / owner_match 126+8 / owner_or_admin 1+10 / manual_review_required 104+14. val: public 3+0 / role_required 20+0 / membership_required 1+0 / tenant_match 3+0 / owner_match 12+0 / owner_or_admin 0+0 / manual_review_required 13+0. 30건 미만: public, membership_required, owner_or_admin.
- 위 "train_v30 / val_v30 구성" 절의 441/60건·해시는 relay_forum 추가 전 1차 구성이며 이 보강 절의 값이 현재 파일이다.

## data-v1 동결 (2026-10-21)

- data-v1 = train_v30.jsonl(471건, SHA-256 `a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2`) + val_v30.jsonl(52건, `62bdadb29cae7aaf814007ad8adec40115e8612d70f2911693219399c82b595c`). 평가셋 test_v30.jsonl(269건, `9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2`). 프롬프트 v3.0.1(`d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef`) 고정. git tag `data-v1`. 이 파일들은 이후 수정하지 않는다.
- data-v2(목표 2026-10-26) = data-v1 + 취약 변형 샘플 + 프레임워크 다양화 합성 + 실제 오픈소스 프로젝트(Gitea 등, held-out 프로젝트 1개는 test 전용) + 확인 후 추가 취약 API.

## data-v2 수집 라이선스 고지 (2026-10-21)

- data-v2에서 추가 수집한 공개 취약 API 두 종은 GPL-3.0이다: vAPI(roottusk/vapi, 커밋 67152695b0acf13dd424905729080fbc80d5a593), Damn Vulnerable RESTaurant(theowni, 커밋 d32d09972aec7830f5f1d4a5d274cac7aae7eb82). 레코드별 meta.license·author·commit을 기록했다.
- **데이터셋 공개 시 GPL-3.0 코드 발췌(controller_text)를 포함하는 레코드는 라이선스 고지(원 저장소·저작자·GPL-3.0 전문 링크)가 필요하다.** 해당 레코드는 meta.license_notice_required=true로 표시한다. Gitea(MIT)·NetBox(Apache-2.0) 발췌는 각 라이선스 고지 조건(저작권 표시·NOTICE)을 따른다.
- 추가 취약 API 레코드는 test 전용이며 test_v30.jsonl에 합치지 않고 별도 파일(test_v2_extra*.jsonl)로 두고 해시를 기록한다.

## data-v2 (2026-10-23 동결)

- train_v2.jsonl 799건(SHA `f26c368d051e1ec2683a1f70ed52162808740d9b06540bbad1fe94988ed47ada`), val_v2.jsonl 98건(`d0e216dd1267ba7f46eb08e5db955473b11bbd049d875e33eb8032504c0f3ac0`), 쿼터 pool 22건. 평가 test_v30(불변) + eval-def v2. 프롬프트 v3.0.1(`d0913c27b5de185e…`).
- 출처별: train {'apisguru': 411, 'synthetic': 171, 'gitea': 217}, val {'apisguru': 52, 'gitea': 28, 'synthetic': 18} (val_v30 52건 그대로 + 코드 val 46건, 그룹 단위 분리).
- label 분포 train: {'public': 46, 'role_required': 162, 'membership_required': 55, 'tenant_match': 54, 'owner_match': 244, 'owner_or_admin': 38, 'manual_review_required': 200} / val: {'public': 10, 'role_required': 26, 'membership_required': 6, 'tenant_match': 5, 'owner_match': 14, 'owner_or_admin': 4, 'manual_review_required': 33}. 조건별 train oas 799·oas_code 388, val oas 98·oas_code 46. train manual 25.0%, 코드 있는 레코드 manual 24.7%.
- 적용 규칙: human_review_v2(52)·human_review_v2_fix(1)·human_review_v2_r3(4), R1'(SELF→owner_match, 검증 정밀도 100%), R2'(검증만, 적용 레코드 0), R4(인증·인가 없음→public), variant_intended_policy(authonly 19), VIS cap 1(시그니처당 1건, 제외 104 보존), 쿼터 25%(apply_reviews_v2 공식). 미적용: R3'(정밀도 78%).
- 라벨 기준(AGENTS.md data-v2 라벨 기준):
  - test_v30 정답은 "의도된 정책" 기준: 본인 리소스(/user/..., Doer 기준 처리)는 owner_match (test의 /user/dashboard·change-email 등과 동일)
  - 저장소 권한 레벨(쓰기·admin)은 role_required, org/팀 멤버십은 membership_required로 처리
  - 공개/비공개 저장소 분기(repoAssignment·reqRepoReader·reqAnyRepoReader)는 manual(VIS)
  - reqToken만 있고 객체가 없는 엔드포인트는 7종에 맞는 label이 없어 manual(AUTH_ANY)
  - VIS+SELF: 요청자가 데이터 범위(본인 star·watch·구독·stopwatch·알림)이면 owner_match, 요청자가 행위자(댓글·머지·리뷰·릴리스·이전·생성·실행)이면 manual
  - 인가 검사가 코드에서 빠졌어도 경로·스키마로 의도된 정책이 드러나면 그 정책을 label로 한다(test_v30 취약 API와 동일). 외부 인가처럼 의도를 코드로 확인할 수 없는 경우만 manual.
- 알려진 한계: VIS·AUTH_ANY는 manual로 둠(test_v30에 VIS 사례 거의 없어 검증 불가), extauth 변형은 manual 유지, Gitea 라벨 대부분은 LLM+규칙이며 사람 확정 아님, 합성 val은 train 합성과 템플릿 공유.

## data-v3a / data-v3b (2026-10-26 동결, 재동결)

- train_v3a.jsonl 930건(SHA `1f5d1055ac3d8d407e555c774183acf4c52ceb03ea508391ee5d508484446e66`), train_v3b.jsonl 787건(`723e3b3a784e624033379dce5e46b243c2c3444c34db7efb5032ea2436a696dd`), val_v3.jsonl 126건(`69536f8b10e99538673a1beaf96411aba2b18f341e04f9429f717d9d84cbc109`). 평가 test_v30(불변) + eval-def v2. 프롬프트 v3.0.1.
- 출처(train_v3a / train_v3b / val_v3): APIs.guru 411/338/52, Gitea 239/197/28, 합성 171/143/18, data-v3 코드 쌍 109(SFT 108)/109(108)/28. 코드 쌍은 실제 오픈소스 핸들러의 검사 유지 원본 + 검사 제거 변형(경로·스키마로 의도가 드러날 때만 변형 유지)이며 label은 검사 내용으로 규칙 결정(사람 검수 80쌍 반영, API 라벨링 없음).
- manual 비율: v3a 23.9%(후보 전부), v3b 10.0%. 쿼터 규칙: 구체 label 수/3(25%) 또는 /9(10%), 사람 검수 manual 우선, 나머지 출처별 비례(seed 42).
- 합성 정답 문장 중립화: 합성 description의 정책 문장(예: "Only the record owner may read it.")과 fixture·변형 해설 주석을 핸들러 발췌·OAS에서 제거(189건), 합성 변형 summary의 변형 종류 접미사 삭제(57건). test_v30 합성은 동결이라 그대로다.
- label–rationale 정합성: 구체 label인데 rationale에 보류 표현이 있던 레코드(98건) 등 242건을 템플릿 규칙으로 재작성(authonly 19 → "경로·리소스 구조상 … 코드에 검사는 없으나 의도된 정책은 <label>", Gitea 규칙 relabel → 학습 target과 같은 규칙 템플릿, 코드 쌍 원본 → 검사 내용 템플릿, 변형 → "검사 코드는 없으나 경로·리소스 의미상 …"). LLM 호출 없음. 목록 rationale_rewrites_v3.jsonl.
- 라벨 기준: AGENTS.md data-v2 라벨 기준 + data-v3 라벨 기준. 실험 규칙: AGENTS.md data-v3 실험 규칙.
- 알려진 한계: v3a manual이 25%에 못 미침(23.9%). 코드 쌍의 role_required는 전부 Java(petclinic), owner_or_admin은 Go·JS뿐이고 변형 없음. val 코드 쌍 28건(정상 확인용). 라이선스 미선언 저장소 5개(reports/data_v3/stage1b_report.md). 합성 변형의 경로·함수 이름에는 변형 종류(authonly·extauth·extguard)가 남음.

## data-v4 / test_v31_supp (2026-10-28 동결)

- data-v4 = data-v3.1b + 코드 규칙 라벨 추가분 216건(Zulip 12.3 Apache-2.0 커밋 b3198225, Label Studio 1.23.2 Apache-2.0 커밋 df96d791). train_v4.jsonl 981건(SHA `1729f79dd1c06408846e4083b2e82fdace113166c0f92fea32e293441791966c`), val_v4.jsonl 148건(`2b3362b6adcc6da13b0d1c71fcf671b9700f54fedcd57bb6f55010f3c63c9105`). 해시 전체 AGENTS.md 'data-v4 동결'.
- data-v3.1b = data-v3b에서 학습 target(rationale)의 검수 메타 문구(검수 시트명·분류 태그·규칙 ID·파일:줄)를 템플릿으로 치환(train SFT 86건, val 5건, 잔존 0). label·입력 불변, LLM 없음.
- 라벨 방법: 코드 규칙(training/data/rule_label_v4.py) — 관리자 데코레이터 → role_required, 활성 조직 범위 → tenant_match, 경로 조직 + 구성원 행 → membership_required, 봇·초대 소유자 OR 관리자 → owner_or_admin, 본인 고정 → owner_match, 조건 없는 익명 → public, OR 분기 접근 함수·조직 설정 의존·인증만 → manual_review_required. 검수: **AI 보조 검수 + 사람 표본 확인**(AI 검수 71건과 일치 69·불일치 0; 사람 표본 시트 review/v4_rule_label_sample.xlsx).
- test_v31_supp(평가 추가분, 학습 미사용): 222건 = Chatwoot 79(MIT, v4.19.1), Chamilo 58(GPL-3.0, v2.0.0-RC.2, advisory 수정 커밋 근거), Flowise 60(flowise@3.0.13, GHSA-3prp-9gf7-4rxx 등), multitenant lab 4, Generic University 21. 제외 41건(의도 불명확·경계, 목록 test_v31_supp_excluded.jsonl). 검수: **AI 보조 검수 + 사람 표본 확인**(Claude가 근거 열로 확정, 사람 표본 시트 test_v31_supp_spotcheck.xlsx).
- **공개 시 코드 본문 제외, 링크·커밋만 제공.** Flowise 발췌 다수에 packages/server/src/enterprise/(FlowiseAI 상용 라이선스, 배포 금지) 코드가 있고, multitenant lab·Generic University는 라이선스 미선언이다. 해당 test 파일은 .gitignore이며 test_v31_supp_manifest.json(id·저장소·커밋·고정 링크·label)만 추적한다.
- 알려진 한계: test_v31_supp의 목표 label이 한 프로젝트에 몰려 있다(membership 50/55 Chatwoot, tenant 52/55 Flowise, owner_or_admin 19/20 Chamilo) — 프로젝트별 정확도를 함께 보고한다. 일부 취약 앱 발췌에 원본 취약점 주석(예: "No admin role check")이 남아 있다. 학습 추가분의 membership_required는 5건뿐이다.


## data-v5 (2026-10-31 동결)

- 출처: Dendrite v0.13.8(Apache-2.0, 커밋 763c79f1), NodeBB v4.16.5(GPL-3.0, 커밋 c3d8dc51), Taiga 6.10.2(MPL-2.0, 커밋 4b023d84). 코드 규칙 라벨(training/data/rule_label_v5.py, 검수 규약 G1~G7 + 정지 지점 1·3 결정)이며 LLM 라벨 없음. test_v5 출처(Rocket.Chat·Ghost·Umami)와 포크는 학습에 쓰지 않는다.
- 선정 328건(프로젝트당 150 이하, 한 label 50% 이하, manual 쿼터 10%, Taiga 댓글 계열 자원당 2건) → train 296 / val 32(핸들러 그룹 분리). data-v5 = data-v4 + 보강분: train_v5.jsonl 1,277건(SHA `528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344`), val_v5.jsonl 180건(`43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9`), SFT train 1274(manual 12.79%) / val 179, data_v5_hashes.json `39c302c5fb33d1b1506487678cd15f40cc83ffd59435449522786388554753ac`. 해시 전체 AGENTS.md 'data-v5 동결'. 검수 일치율: 수정 전 규칙 0.956(86/90), 불일치 4건은 규칙 수정으로 해소, 수정 후 88/88. test_v5 label 미참조(후보 키 겹침 0건).
- **NodeBB(GPL-3.0) 발췌(controller_text)가 든 파일은 공개하지 않는다. 공개는 링크·커밋만 제공한다**: candidates_train_v5.jsonl, train_v5_rule_labeled.jsonl, train_v5_selected.jsonl, train_v5_pool.jsonl, train_v5.jsonl, val_v5.jsonl, train_sft_v5.jsonl, val_sft_v5.jsonl, review/v5_train_review*.xlsx, data/raw_v5_train/nodebb/candidates.jsonl은 .gitignore이며 data_v5/train_v5_manifest.json(id·저장소·커밋·고정 링크·label·split)만 추적한다. NodeBB 레코드는 meta.license_notice_required=true.

## test_v5 (2026-10-31 동결, hold-out 평가셋 — 별도 조건)

- 출처: Rocket.Chat 8.9.0(MIT, 커밋 057a927d) 157건, Ghost v6.73.0(MIT, 커밋 5794cfd8) 69건, Umami v3.4.1(MIT, 커밋 559e3c60) 57건 = 283건(제외 13건, G8, data_v5/test_v5_excluded.jsonl). label: role_required 111 · manual_review_required 65 · owner_match 34 · membership_required 33 · owner_or_admin 21 · public 19 (tenant_match 0). 세 출처 모두 MIT라 코드 발췌(controller_text)를 포함해 공개한다. 출처·추출 범위는 data/raw_v5/<project>/SOURCE.md.
- 라벨링: 프롬프트 v3.0.1 정의 + 검수 규약 G1~G8. **AI(Claude) 1차 판정(초안) + 사람 확인**(검수 시트 review/test_v5_review_reviewed.xlsx, 초안 대비 변경 5건). 사람 확인의 범위(전수/표본)는 사용자가 별도로 알려주면 여기와 lora_v5_report.md 6절에 기재한다. v5 예측 생성 전에 동결했고 data-v5·test_v30·test_v31_supp와 (서비스, method, 정규화 path) 겹침 0.
- 파일: datasets/blade/processed/test_v5.jsonl(SHA `7b8e4a940967ec474e0d5dbf6dcdbd6b7e04be439599c2a684664d6b9393fd9c`), manifest data_v5/test_v5_manifest.json(`57fd384f…`, 평가 스크립트의 해시 게이트), training/lora/data_v5/test_v5_inputs.jsonl(`9103cd3d…`). 수정·재생성 금지.
- 용도: eval-def v2의 별도 조건(주지표 test_v30 207건은 불변). 학습(data-v5) 출처로 test_v5 프로젝트와 포크를 쓰지 않는다. 한계: membership_required 33건 중 28건 Rocket.Chat, tenant_match 0건, owner_or_admin support 21.

## 공개 배포 사본과 라이선스 처리 (2026-11-01 사용자 승인, 적용 완료)

- 동결 파일은 수정하지 않는다(해시 불변, scripts/build_public_copies.py가 실행 전후 assert). 공개 배포에는 `datasets/blade/processed/public/*_public.jsonl`, `training/lora/public/*_public.jsonl`, `datasets/blade/processed/public/withheld_manifest.json`을 쓰고, 원본 목록 `public/PUBLIC_EXCLUDE.txt`는 공개 대상에서 제외한다.
- 코드 본문(controller_text)을 뺀 레코드 162건: (1) test.jsonl·test_v30.jsonl의 **DVWS-node(GPL-3.0, snoopysecurity/dvws-node `eb6e2886`) 25건**, (2) data-v3 코드 쌍 가운데 **라이선스 미선언 저장소 5개 28건**(아래), (3) data-v5 **NodeBB(GPL-3.0) 109건**(train 98·val 11, 기존 정책과 동일). 레코드·라벨·OAS·rationale·meta는 유지하고 `meta.code_withheld`·`meta.code_ref`(저장소·커밋·라이선스·고정 링크·원문 SHA-256)를 넣는다. test_v30_inputs 공개 사본은 DVWS 25건의 oas_code_user만 비운다. SFT 공개 사본은 user 메시지에 코드가 들어 있어 해당 행을 제외한다(train_sft_v3a·v3b·v31b·v4 각 28행, train_sft_v5 126행, val_sft_v5 11행 제외).
- 복원: `withheld_manifest.json`은 코드가 아닌 조립 규칙(줄 범위·들여쓰기 변환·생략 표시·변형의 줄 번호)만 담는다. `scripts/rebuild_from_public.py`가 로컬 클론(고정 커밋)과 manifest로 원본 10개 파일(test·test_v30·train_v3a·v3b·v31b·v4·v5·val_v5·pairs_train_v3s1·v3s1b)을 바이트 동일하게 복원함을 확인했다(162/162 레코드, SHA-256 일치, 2026-11-01).
- **라이선스 미선언 출처의 학습 사용(한계).** data-v3 코드 쌍 가운데 라이선스를 선언하지 않은 저장소 5개 — gothinkster/node-express-realworld-example-app `30b68e1e`, gothinkster/rails-realworld-example-app `a2ae4fff`, adr1enbe4udou1n/nestjs-realworld-example-app `d4ddf3fd`, gothinkster/kotlin-spring-realworld-example-app `848c29e3`, gothinkster/koa-knex-realworld-example `602e2341` — 의 핸들러 발췌 28건(원본 14·검사 제거 변형 14, 전부 owner_match)을 data-v3a·v3b·v3.1b·v4·v5의 train과 SFT에 사용했다(val·test에는 없음). reports/data_v3/stage1b_report.md(2026-10-26)가 "학습 투입 전 확인 필요"로 기록했으나 확인 없이 투입됐다. 공개 배포본에서는 이 28건의 코드 본문을 제외하고 저장소·커밋·줄 범위만 제공한다. 검수 시트 reports/data_v3/review_pairs_v3s1*.xlsx 4개도 발췌가 들어 있어 공개 대상에서 제외한다.
- DVWS-node 25건은 공개 사본에서 코드를 제외하는 방식(방안 1)을 택했다. GPL-3.0 고지만 하고 발췌를 유지하는 방안 2는 쓰지 않는다. 처리 기록: reports/presentation_support/F_license_release_plan.md.

## Errata

- **data-v5 Dendrite meta.tag 오기 (2026-11-01 발견, 데이터 미수정).** Dendrite 레코드의 `meta.tag`는 `v0.13.8`이어야 하나 추출 스크립트(data/raw_v5_train/dendrite/extract_dendrite.py)에서 전역 상수 `TAG`가 342행에서 파일 경로 약어로 재정의돼, 그 뒤에 추가된 레코드의 tag 필드(110행)에 `clientapi/routing/room_tagging.go`가 들어갔다. 영향: train_v5.jsonl 74/95건, val_v5.jsonl 8/10건, data_v5/train_v5_manifest.json 91/126건(train 74·val 8·pool 9), data/raw_v5_train/dendrite/candidates.jsonl 93/136건. 커밋 `763c79f1421200c3fd74401fd68298bc00ecefbc`·저장소·source_locations·고정 링크는 정확하며 라벨·코드·SFT 입력에는 tag가 쓰이지 않는다. 동결 해시를 유지하기 위해 파일은 수정하지 않으며, 태그는 이 errata와 data/raw_v5_train/dendrite/SOURCE.md(`v0.13.8`)를 따른다. 재추출 시 상수 이름 충돌을 고쳐야 한다(런타임 코드 아님, 이번에는 수정하지 않음).


## data-v6d (2026-11-05 동결, 작업 C′ — 학습 정답만 교정)

- data-v6d = data-v5 SFT(train 1,274 / val 179)에서 **C1 재판정으로 확정된 label 36건과 rationale 42건만** 바꾼 것. user 입력·행 순서·나머지 행은 data-v5와 바이트 동일. 프롬프트 v3.0.1, 출력 순서(label 먼저) 불변. 변경은 전부 gitea(data-v2 출처) 행이며 v3.1 라벨 정의(G3-a 그룹 안 역할 → role_required 등)에 맞춘 것: owner_match->role_required 23, manual_review_required->role_required 5, membership_required->manual_review_required 2, manual_review_required->owner_match 2, manual_review_required->owner_or_admin 1, owner_match->manual_review_required 1, role_required->public 1, membership_required->owner_match 1. SFT manual 비율 train 12.8% → 12.6%, val 23.5% → 21.8%.
- 검수: review/c1_relabel_review_reviewed.xlsx(`d9f8299f…`), **검수자 Claude(AI), 사람 확인 전**. 시트 5개(블라인드 68 / 판정필요_코드 39 / 판정필요_OAS문구 22 / 변경예상_C2 46). OAS-only 행은 사용자 결정으로 현행 label 유지(AI 의견 manual 21건은 reports/data_v6d/oas_relabel_candidates_post_deadline.jsonl에 보존, 마감 후 일괄 점검 후보). 확정 rationale의 소스 파일 경로 참조 4건은 입력에 없는 정보라 제거.
- **블라인드 감사(안 바뀐 행 5% 표본 68건) 불일치율 41.2%(코드 행 25.5%, OAS-only 76.2%; 불일치 28 중 24가 → manual)로 사전 기준 5%를 넘어 한계로 기록한다.** 안 바뀐 행 전수 검수는 마감(2026-11-08 12:00 KST) 후. 블라인드 판정은 데이터에 반영하지 않았다. 이 수치는 AI 재판정과 기존 라벨(APIs.guru LLM 라벨·규칙 라벨·사람 검수)의 불일치이며 기존 라벨 오류율로 바로 읽지 않는다.
- 정합성(빌드 assert): 구체 label에 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, 토큰 최대 4085(4096 초과 0). Errata: data-v5 SFT `tokens` 필드는 gitea 69행에서 최대 24 어긋남(data-v3.1 메타 정리 전 값; 학습 코드는 자체 토큰화).
- 파일: datasets/blade/processed/train_v6d.jsonl 1,277(`aed2b275a76fa684e426a656fb04b1c934a29bc987f45a146fe1c244ced4d372`), val_v6d.jsonl 180(`159e01780eb2d8aa1710146d2c06533c20c81920a828a60b889ec6db221361cf`), training/lora/data_v6d/train_sft_v6d.jsonl 1,274(`63c1768949a0e8c7f0747712c6a55e4fb492e1d03baeddfa111884f31ff65b98`), val_sft_v6d.jsonl 179(`1a421c836032ff3c611f3a74380b519374393deb44519c1772db8049d7d671ee`), data_v6d_hashes.json(`82efda868e7bde511d0838e10bf0e8a5cc3e6aae577c68b15fcbf370a9d94b53`). 변경 내역 reports/data_v6d/c1_changes.jsonl, 보고 reports/data_v6d/stop_c1_c2_data_v6d.md. NodeBB 코드 본문이 든 파일은 data-v5와 같이 비공개(.gitignore).
- 평가: test_v30(eval-def v2, 주지표 불변) + test_v31_supp + test_v5(dev). test_v6 미사용. 베이스는 S8(14B) 불채택으로 7B. 학습은 아직 실행하지 않았다.

## test_v6 (2026-11-08 동결, S9 최종 판정용 hold-out — 별도 조건)

- 출처: seahub v14.0.9-server(Apache-2.0, 커밋 0841826c) 88건, Redash v26.9.0(BSD-2-Clause, 42fdf9d4) 72건, GlitchTip v6.2.6(MIT, gitlab.com, d3039088) 70건, Penpot 2.18.5(MPL-2.0, f4456696) 55건 = 289건(후보 302, 제외 13 = 4.3%, data_v6/test_v6_excluded.jsonl 사유 포함). label: role_required 65 · owner_match 59 · manual_review_required 52 · tenant_match 38 · membership_required 37 · public 21 · owner_or_admin 17. 추출 범위 data/raw_v6/<project>/SOURCE.md. S9 전까지 어떤 모델도 추론하지 않았다(scripts/testv6_guard.py).
- **라벨링(A안, 2026-11-08 사용자 결정, 마감 사유)**: 프롬프트 v3.0.1 정의 + 검수 규약 G1~G8 + test_v6 보충 규약 1~8. AI(Claude) 1차 확정(2026-11-04) + 독립 AI 2차 검수(Claude: 블라인드 감사 41건 + 우선확인 44건 의견) + 불일치·저확신 건 사람 확정. 레코드별 `meta.label_status`: **human_confirmed 5 · ai_double_confirmed 67 · ai_single 217**. 블라인드 감사 41건의 AI 1차 vs AI 2차 일치 38/41(92.7%) — **사람 대비 정확도가 아니다.** 사람 판정은 7건(label 변경 4: EXCLUDE 전환 2·해제 2). 기존 프로토콜(우선확인 44건 사람 판정 필수, 감사 ≤5% 규칙)은 A안으로 대체. 상세 reports/data_v6/stop3_test_v6_freeze.md, audit41_compare.md, human_check_apply.json.
- 파일: datasets/blade/processed/test_v6.jsonl(SHA `872675957276d15777acde947ab99b6e4b9112941a8bedef404ffac9e20bc765`), data_v6/test_v6_manifest.json(`a9ca4fca05ee3e59226411c08c9f102440d5f36b2d4b45dc870bd74e346f3edc`, S9 스크립트 해시 게이트), training/lora/data_v6/test_v6_inputs.jsonl(`33d1aecdbd1a685416523eddf73722e105c2c761154a6bf95403fe1431435741`), 검수 반영본 review/test_v6_review_final.xlsx(`0bf36fb5…`, 미커밋). 수정·재생성 금지.
- 용도: eval-def v2의 별도 조건(주지표 test_v30 207건 불변). data-v7 채택 판정 기준 (1)의 판정셋. 한계: (a) 정답의 75%가 AI 단독 판정; (b) tenant_match 38 중 Redash 27, membership_required 37 중 GlitchTip 27, owner_or_admin 17 중 Redash 13, Penpot은 tenant·membership·owner_or_admin 0; (c) Redash G1-b 경계 18건 전부 포함(data_v6/redash_g1b_boundary_ids.json, S9 별도 집계); (d) test_v5(tenant 0)와 label 구성이 다름; (e) 익명 operation 전역 security 보정 26건(빌드 assert).

## data-v7 (2026-11-07 동결, LoRA v7 학습 데이터 — 최종 모델)

- data-v7 = data-v6d SFT 행(LLM 라벨 615행을 G1~G8·v3.1 정의로 AI 재판정 — B안: label 변경 45건 반영, OAS-only에서 새로 manual이 된 256행은 학습 제외·`data_v7/train_v7_oas_manual_pool.jsonl` 보존) + **test_v31_supp 221행 + test_v5 281행을 train에 추가**(확정 정답, 4096 토큰 초과 3건 제외; 추가 행의 rationale은 검수 근거 기반 템플릿으로 입력에 있는 식별자·코드 인용만 사용). test_v30은 학습에 넣지 않았다(회귀·안전 지표). train 1,540(manual 17.1%) / val 159(manual 22.6%). 프롬프트 v3.0.1, 출력 순서(label 먼저)·하이퍼파라미터는 v5와 동일.
- 파일·SHA-256: `datasets/blade/processed/train_v7.jsonl` 1,540(`662b16405d5775c0ecfceb8361c53953751b554390c5f1f63e30bfdfbffa32db`), `val_v7.jsonl` 159(`cf04b4b3b8928985377a53a69905d0e1a343f705850e8694bc3f38286b9da325`), `training/lora/data_v7/train_sft_v7.jsonl` 1,540(`6654f79afb8cc984b42944cf3b246111c06d7704b02809577fa85cd5630b6178`), `val_sft_v7.jsonl` 159(`2173171ed412b2b3949c1d21f29fec69bcdd5b7e4732e67ace4fb84bc2e57087`), `data_v7_hashes.json`(`bd33f1bcf0f68ab5fe5b96195c0da3cf6affbb3486fb85bef542b3f77e88ba73`). 재판정 안내문 `data_v7/rejudge/REJUDGE_GUIDE.md`(`d734ce9a…`), 변경 내역 reports/data_v7/v7_changes.jsonl(45), 추가 행 rationale reports/data_v7/added_rows_rationale.jsonl(505), 보고 reports/data_v7/stop2_rejudge_report.md·stop5_build_report.md·freeze_report.json.
- train label 분포: public 88 · role_required 425 · membership_required 138 · tenant_match 111 · owner_match 382 · owner_or_admin 132 · manual_review_required 264. val: 14 · 46 · 6 · 6 · 38 · 13 · 36. train 프로젝트별: gitea 197 · rocketchat 155 · synthetic 143 · zulip 132 · data_v3_pairs 108 · taiga 103 · apisguru 102 · nodebb 98 · dendrite 95 · chatwoot 78 · ghost 69 · label_studio 60 · flowise 60 · chamilo 58 · umami 57 · generic_university 21.
- **test_v5·test_v31_supp는 data-v7 학습에 들어갔으므로 LoRA v7 평가에 쓰지 않는다**(평가 스크립트가 해당 입력을 거부). v7 평가는 test_v30(회귀) + test_v6(hold-out)만.
- 한계: (a) 재판정은 AI(Claude) 판정이며 사람 확인 시트 review/data_v7_human_check.xlsx(변경 45 · 블라인드 31 · 추가행 rationale 50)는 **미회수** — 마감 압축 실행으로 학습을 막지 않았다. (b) data-v6d C1 블라인드 감사 불일치 41.2%(위 절)는 그대로 한계로 남는다. (c) 코드 본문 비공개 출처(NodeBB GPL-3.0, Flowise enterprise, Chamilo GPL-3.0-or-later, Generic University·multitenant lab 미선언)가 train_v7에 269행 들어 있어 train_v7.jsonl·val_v7.jsonl·SFT v7 파일은 .gitignore이고 공개는 아래 "공개 배포 사본 v7 확장"의 사본으로만 한다.

## LoRA v7 최종 모델·가중치 공개 (2026-11-09 채택, 2026-11-11 공개)

- 최종 모델 **LoRA v7** = data-v7로 학습한 QLoRA(베이스 unsloth/Qwen2.5-7B-Instruct-bnb-4bit, r16·α16, 3 epoch, lr 2e-4, batch 2×4, cosine, adamw_8bit, max_seq_len 4096, 프롬프트 v3.0.1, completion-only 마스킹, seed 42·43·44). 채택 근거(사전 등록 기준, v5 대비): test_v6 oas_code macro-F1 0.586 ± 0.006 → 0.650 ± 0.016(+0.064 ≥ 0.016), test_v30 207 구체 정밀도 0.796 → 0.824(하락 ≤ 0.025 충족), test_v30 207 public 오판(/35) 평균 2.0 → 1.33(≤ 2.0). 보고 reports/eval/lora_v7/report.md(1단계), s9/report.md(S9), 발표 표 presentation_numbers_v7.md.
- 중간 실험 S4(문맥 보강)·S5(v3.1 프롬프트 + 토큰 확률 confidence, v6a)·S8(14B 베이스, v6c)·C′(학습 정답 36건 교정, v6d)는 모두 사전 기준 미달로 불채택(reports/eval/{context_aug_v5,lora_v6a,lora_v6c,lora_v6d}/report.md).
- **가중치 공개 위치**: 프로젝트 저장소 GitHub Release `lora-v7`(https://github.com/HokagoSecurityTime/BLADE/releases/tag/lora-v7) — seed 42·43·44 어댑터 tar.gz 3개(SHA-256 `9dc03740…`, `850793b2…`, `63d842ed…`; reports/eval/lora_v7/SHA256SUMS_blade_v7)와 배포용 GGUF Q4_K_M(s42 fp16 병합, llama.cpp b11693; SHA-256 `1dd24dcdff60619d055277591b134f133a24a4cd62a9b51f3cec8abcdc88144d`, 4,683,073,504 bytes; GitHub 자산 2 GiB 제한 때문에 3개 조각으로 나눠 올리고 이어 붙이는 명령과 해시를 함께 둔다). 베이스 모델 Qwen2.5-7B-Instruct는 Apache-2.0(Qwen 저작권 고지 포함).
- **평가는 HF 어댑터 기준, 배포는 s42 Q4_K_M GGUF**(Ollama blade-qwen-lora-v7, MIN_CONFIDENCE 0.9). 배포 GGUF는 같은 어댑터 HF s42 대비 test_v30 207 구체 정밀도 −0.03·public 오판 +2(crAPI owner_match 2건)로 사전 허용 폭을 벗어났고 사용자 조건부 수용(2026-11-10). GGUF 경로 confidence는 265건 중 261건이 0.9 고정이라 문턱이 실질적으로 거르는 행은 0건이다(reports/eval/lora_v7_gguf/equivalence_check.md).
- test_v6 정답 한계(위 test_v6 절)와 함께 읽어야 한다: 289건 중 사람 확정 5 · AI 이중 확정 67 · AI 단독 217. Redash G1-b 경계 18건은 Base·v5·v7 모두 0/18.

## 공개 배포 사본 v7 확장 (2026-11-11)

- `scripts/build_public_copies.py`를 data-v7로 확장했다. 새 사본: `public/train_v7_public.jsonl` 1,540(코드 본문 제외 **269** = NodeBB 98 · Flowise 60 · Chamilo 58 · Generic University 21 · multitenant lab 4 · 미선언 RealWorld 5개 저장소 28), `public/val_v7_public.jsonl` 159(제외 11, NodeBB), `training/lora/public/data_v7_train_sft_v7_public.jsonl` 1,271(269행 제외), `data_v7_val_sft_v7_public.jsonl` 148(11행 제외), `data_v7_test_v30_inputs_public.jsonl`(DVWS 25건 oas_code_user null). 기존 사본 10개는 바이트 동일(재빌드 확인). 보류 레코드 합계 162 → **305**(withheld_manifest.json summary.by_reason).
- test_v31_supp에서 train_v7로 들어간 Flowise·Chamilo·Generic University·multitenant lab 행은 동결 test_v31_supp 파일과 같은 "링크만" 정책을 따른다. Chatwoot(MIT, enterprise/ 제외 추출) 78행과 test_v5 출처(Rocket.Chat·Ghost·Umami, MIT) 281행은 코드 포함 공개.
- 복원: `scripts/rebuild_from_public.py`로 305건 중 **204건** 복원·원본 10개 + val_v7 바이트 동일 확인(2026-11-11). **train_v7의 101건(Flowise 50 · Chamilo 49 · Generic University 1 · multitenant lab 1)은 발췌 조립 형식이 slices 규칙과 달라 자동 복원 규칙이 없고 고정 링크·원문 SHA-256만 제공한다**(`recipe.kind = sha_only`; test_v31_supp 정책이 원래 복원을 약속하지 않음). 따라서 train_v7.jsonl은 공개 사본만으로 바이트 복원되지 않는다.
- PUBLIC_EXCLUDE.txt에 train_v7·val_v7·SFT v7·data_v7 test_v30_inputs·test_v31_supp 원본(.gitignore 상태 포함)을 추가했다.

## Errata (추가)

- **test_v6 프로젝트별 건수 오기(2026-11-11 발견, 데이터 미수정).** 위 test_v6 절과 AGENTS.md의 "seahub 88"은 **92**가 맞다(후보 94 − 제외 2). Redash 72 · GlitchTip 70 · Penpot 55는 그대로이며 합계 289와 label 분포·해시는 정확하다(reports/eval/lora_v7/presentation_numbers_v7.json project_n).
