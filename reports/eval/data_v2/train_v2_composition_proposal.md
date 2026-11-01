# data-v2 train 구성 제안 — Gitea 비중과 층화 상한 (적용은 승인 후)

## 현재 후보 구성 (2026-10-21)

| 출처 | 건수 | 비중 |
|---|---:|---:|
| train_v30 (data-v1, APIs.guru 411 + 합성 60) | 471 | 44.6% |
| data-v2 합성 보강 (변형 57 + 신규 4종 72) | 129 | 12.2% |
| Gitea v28.2.0 (LLM 라벨, 사람 확정 전) | 455 | **43.1%** |
| 합계 | 1,055 | |

한 프로젝트(Gitea)가 40%를 넘으므로 아래 상한안을 제안한다. 라벨 분포(합계, 상한 전): public 96 · role_required 161 · membership_required 56 · tenant_match 54 · owner_match 182 · owner_or_admin 117 · manual 389(36.9%).

## 상한안 A (권장): Gitea 40% 상한, label 비율 유지 층화 샘플링

- 상한 건수 = 0.40 × (471 + 129) / 0.60 = **400건** (455 중 55건 제외, 제외분은 `gitea_train_pool_v2.jsonl`에 보존).
- 층화 목표(현재 Gitea label 비율 유지, seed 42): public 54 · role_required 33 · membership_required 8 · tenant_match 2 · owner_match 32 · owner_or_admin 75 · manual 198 (반올림 조정으로 합 400).
- 사람 검수(review_sample_gitea 86건)에서 교정된 라벨은 샘플링 전에 반영한다. visibility_dependent 96건은 검수 기준이 manual이므로 검수 전까지 train 포함을 보류하는 선택지(안 A')도 가능: 그 경우 Gitea 후보 359건이라 상한에 걸리지 않는다.

## 상한안 B: 35% 상한

- 상한 = 0.35 × 600 / 0.65 = 323건. 소수 label(tenant_match 2, membership 9)은 전량 유지하고 manual·owner_or_admin에서 줄인다.

## 공통 규칙

- data-v1 레코드는 그대로 둔다. manual 쿼터 25% 규칙은 data-v2 전체에 다시 적용할지 사용자 결정 사항(현재 합계 36.9%).
- 서비스 단위 분할 유지: Gitea·합성은 train 전용, val은 val_v30(52) 유지 또는 Gitea 일부를 val로 보낼지 결정 필요(권장: Gitea 라우트는 모두 train, val_v30 유지).
- held-out 실제 프로젝트는 NetBox(test 전용), 추가 취약 API(vAPI·DVRestaurant)는 test 전용.
