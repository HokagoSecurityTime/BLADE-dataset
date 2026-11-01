# Gitea v28.2.0 라벨링 결과 — gpt-4o-mini + 프롬프트 v3.0.1 + oas_code, 455건

프롬프트 SHA `d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef`, 입력 SHA `3e28db6d3a93a5085149b7e3b72735328f3aef64c428ed8f2f47c289b7fa9a0a`, 출력 `gitea_v28.2.0_labeled_v301.jsonl` SHA `3aac8843315d30dc473bae38409f83866b7c077aa0591ab6285470d335e274fc`. 응답 462회, 입력 1,443,823(캐시 799,232)·출력 33,220토큰, 추정 $0.17656(청구서 아님). 평균 1633.1 ms, 출력 오류 0.

라벨은 LLM 제안이며 사람 확정 전이다(data-v2 train 후보). 모든 레코드가 OAS 전역 security 때문에 security_state=declared다.

## label 분포

| label | 건수 | 비율 |
|---|---:|---:|
| public | 61 | 13.4% |
| role_required | 37 | 8.1% |
| membership_required | 9 | 2.0% |
| tenant_match | 2 | 0.4% |
| owner_match | 36 | 7.9% |
| owner_or_admin | 85 | 18.7% |
| manual_review_required | 225 | 49.5% |

## public_candidate (미들웨어·핸들러 모두에 인증·인가 없음) 28건의 모델 label

| label | 건수 |
|---|---:|
| public | 15 |
| role_required | 1 |
| manual_review_required | 12 |

## visibility_dependent (저장소·조직 공개 여부에 따라 접근이 달라짐, 인증 미들웨어 없음) 96건의 모델 label

원칙: 조건부 접근이므로 사람 검수 기준은 manual_review_required.

| label | 건수 |
|---|---:|
| public | 49 |
| membership_required | 1 |
| tenant_match | 2 |
| owner_or_admin | 1 |
| manual_review_required | 43 |

## 패키지별 label

| 패키지 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|
| admin | 0 | 33 | 0 | 0 | 0 | 0 | 0 |
| misc | 4 | 0 | 0 | 0 | 0 | 0 | 10 |
| notify | 1 | 0 | 0 | 0 | 0 | 0 | 6 |
| org | 1 | 0 | 9 | 0 | 23 | 0 | 17 |
| packages | 0 | 0 | 0 | 0 | 0 | 2 | 7 |
| repo | 53 | 3 | 0 | 2 | 0 | 81 | 120 |
| settings | 0 | 1 | 0 | 0 | 0 | 0 | 3 |
| shared | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| token | 0 | 0 | 0 | 0 | 0 | 0 | 2 |
| user | 2 | 0 | 0 | 0 | 13 | 2 | 59 |

confidence 구간: {'[0,0.5]': 0, '(0.5,0.7)': 0, '[0.7,0.9)': 226, '[0.9,1]': 229}

원자료: gitea_v28.2.0_labeled_v301.jsonl, gitea_label/{usage.jsonl,metrics.json,manifest.json}; raw_responses.jsonl은 git 미추적.
