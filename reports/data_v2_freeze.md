# data-v2 동결 보고 — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl a99d30da2d29907e…, val_v30.jsonl 62bdadb29cae7aaf…, test_v30.jsonl 9bd47216575afc60…, policy_label_v3.0.1.md d0913c27b5de185e…. 입력 train_v2_draft_r3.jsonl(867, SHA `e520a0fdece4ac39…`, 불변). 프롬프트 v3.0.1 해시 확인. test_v30 불변.

## 1. val_v2 분리 (쿼터 전)

코드 있는 레코드 456건(Gitea 267 · 합성 189) → 목표 10% = 46건. 그룹 키: Gitea = 경로 첫 두 세그먼트 + 미들웨어 시그니처, 합성 = 서비스명(variants는 원 서비스로 합침). 그룹 125개 중 사람 검수 포함 그룹 36개는 train 고정. 선택 그룹 29개 → val 코드 46건. label 7종 val 포함 전부 충족.

| label | val 코드(신규) | val_v30(APIs.guru, 그대로) | val_v2 |
|---|---:|---:|---:|
| public | 7 | 3 | 10 |
| role_required | 6 | 20 | 26 |
| membership_required | 5 | 1 | 6 |
| tenant_match | 2 | 3 | 5 |
| owner_match | 2 | 12 | 14 |
| owner_or_admin | 4 | 0 | 4 |
| manual_review_required | 20 | 13 | 33 |
| 합계 | 46 | 52 | 98 |

val_v2 조건별: oas 98건, oas_code 46건. 선택 그룹: gitea|signing-key.pub|, gitea|settings/ui|, gitea|user/teams|contextAuthenticatedUser,rejectPublicOnly,reqToken, syn|atlas_leases, gitea|admin/orgs|reqSiteAdmin,reqToken, gitea|admin/packages|reqSiteAdmin,reqToken, gitea|licenses/{name}|, gitea|licenses|, gitea|markup|reqToken, gitea|orgs/{org}|orgAssignment, gitea|orgs/{org}|orgAssignment,reqOrgMembership,reqOrgOwnership,reqToken, gitea|orgs/{org}|orgAssignment,reqOrgVisible, gitea|orgs/{org}|orgAssignment,reqToken, gitea|orgs|reqToken, gitea|repos/issues|, gitea|repos/migrate|rejectPublicOnly,reqToken, gitea|repos/search|, gitea|repos/{owner}|context.ReferencesGitRepo,context.RepoRefForAPI,repoAssignment,reqRepoReader, gitea|repos/{owner}|context.ReferencesGitRepo,mustAllowPulls,mustNotBeArchived,repoAssignment,reqRepoReader,reqToken, gitea|repos/{owner}|context.ReferencesGitRepo,mustAllowPulls,repoAssignment,reqRepoReader, gitea|repos/{owner}|context.ReferencesGitRepo,mustNotBeArchived,repoAssignment,reqRepoReader,reqRepoWriter,reqToken, gitea|repos/{owner}|context.ReferencesGitRepo,repoAssignment,reqAdmin,reqGitHook,reqToken, gitea|repos/{owner}|mustEnableEditor,repo.ReqChangeRepoFileOptionsAndCheck,repoAssignment,reqToken, gitea|repos/{owner}|mustEnableIssuesOrPulls,mustNotBeArchived,repoAssignment,reqRepoReader,reqToken, gitea|repos/{owner}|mustEnableIssuesOrPulls,repoAssignment,reqRepoReader, gitea|repos/{owner}|mustEnableWiki,repoAssignment, gitea|repos/{owner}|mustNotBeArchived,repoAssignment,reqRepoWriter,reqToken, gitea|repos/{owner}|repoAssignment, gitea|repos/{owner}|repoAssignment,reqAnyRepoReader

## 2. manual 쿼터 25% (train 부분)

| 항목 | 값 |
|---|---:|
| 구체 label | 599 |
| manual 목표 round_half_up(C/3) | 200 |
| 고정 manual(APIs.guru + 합성 + 검수 Gitea) | 162 |
|   └ APIs.guru | 104 |
|   └ 합성 | 39 |
|   └ 검수 Gitea | 19 |
| 비검수 Gitea manual | 60 |
| 남은 자리 → 선택 | 38 |
| pool로 제외 | 22 |
| 규칙 | slots 38 filled from free Gitea manual 60 by tag {'AUTH_ANY': 8, 'VIS': 29, '복합': 1} |

선택된 비검수 Gitea manual 태그: {'AUTH_ANY': 8, 'VIS': 29, '복합': 1}; pool 태그: {'AUTH_ANY': 5, 'VIS': 16, '복합': 1}.

## 3. 동결 결과

| label | train_v2 | 비율 | train 코드 있음 | val_v2 | val 코드 있음 |
|---|---:|---:|---:|---:|---:|
| public | 46 | 5.8% | 27 | 10 | 7 |
| role_required | 162 | 20.3% | 58 | 26 | 6 |
| membership_required | 55 | 6.9% | 30 | 6 | 5 |
| tenant_match | 54 | 6.8% | 22 | 5 | 2 |
| owner_match | 244 | 30.5% | 118 | 14 | 2 |
| owner_or_admin | 38 | 4.8% | 37 | 4 | 4 |
| manual_review_required | 200 | 25.0% | 96 | 33 | 20 |
| 합계 | 799 | 100% | 388 | 98 | 46 |

train_v2 출처: {'apisguru': 411, 'synthetic': 171, 'gitea': 217}; val_v2 출처: {'apisguru': 52, 'gitea': 28, 'synthetic': 18}. 조건별 train: oas 799 / oas_code 388; val: oas 98 / oas_code 46.

**train 전체 manual 비율 25.0%, 코드 있는 레코드 manual 비율 24.7%** (참고 test_v30 코드 있음 5.7%).

적용 규칙(train+val 레코드의 meta.v2_relabel): human_review_v2 34, human_review_v2_fix 1, human_review_v2_r3 4, R1_self_owner 30, R1_self_split 8, R4_noauth_public 14, variant_intended_policy 19; VIS cap 1(제외 104, r3 파일), 쿼터 25%(pool 22).

## 4. 해시

| 파일 | SHA-256 |
|---|---:|
| train_v2.jsonl | f26c368d051e1ec2683a1f70ed52162808740d9b06540bbad1fe94988ed47ada |
| val_v2.jsonl | d0e216dd1267ba7f46eb08e5db955473b11bbd049d875e33eb8032504c0f3ac0 |
| train_v2_manual_pool.jsonl | 32e23716422f43dcb77b97bed03acdca5ec1fff9ece93c7794934d987798b32a |
| test_v30.jsonl | 9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2 |
| policy_label_v3.0.1.md | d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef |
| source_train_v2_draft_r3.jsonl | e520a0fdece4ac39454db264cd65f6ddcdeac18c8a48bd040f8d50c69d124bdf |

## 5. 라벨 기준 (AGENTS.md data-v2 라벨 기준)

- test_v30 정답은 "의도된 정책" 기준: 본인 리소스(/user/..., Doer 기준 처리)는 owner_match (test의 /user/dashboard·change-email 등과 동일)
- 저장소 권한 레벨(쓰기·admin)은 role_required, org/팀 멤버십은 membership_required로 처리
- 공개/비공개 저장소 분기(repoAssignment·reqRepoReader·reqAnyRepoReader)는 manual(VIS)
- reqToken만 있고 객체가 없는 엔드포인트는 7종에 맞는 label이 없어 manual(AUTH_ANY)
- VIS+SELF: 요청자가 데이터 범위(본인 star·watch·구독·stopwatch·알림)이면 owner_match, 요청자가 행위자(댓글·머지·리뷰·릴리스·이전·생성·실행)이면 manual
- 인가 검사가 코드에서 빠졌어도 경로·스키마로 의도된 정책이 드러나면 그 정책을 label로 한다(test_v30 취약 API와 동일). 외부 인가처럼 의도를 코드로 확인할 수 없는 경우만 manual.

## 6. 알려진 한계

- VIS(공개/비공개 분기)·AUTH_ANY(인증만, 객체 없음)는 manual로 두었다. test_v30에는 VIS 사례가 거의 없어(취약 API 코드는 단일 저장소) 이 보류의 정답률은 test로 측정되지 않는다.
- extauth 변형(외부 인가 호출) 19건은 manual 유지. 의도 정책이 코드로 확인되지 않는다는 설계 가정이다.
- Gitea 라벨은 사람 검수 56건(52+4) 외에는 LLM 라벨 + 규칙(R1'·R4·variant_intended_policy)이며 사람 확정이 아니다. VIS cap으로 Gitea manual을 시그니처당 1건으로 줄여 Gitea 분포가 실제 API 분포와 다르다.
- val_v2의 코드 부분은 그룹 분리했지만 합성은 train 합성과 생성 템플릿을 공유한다.

## 7. LoRA v2 Colab 패키지

- 입력(training/lora/data_v2/, 생성 training/lora/prepare_lora_v2_inputs.py): train_sft 799건(4096 토큰 초과 제외 0건, 최대 4050·중앙값 3115 토큰), val_sft 98건(oas 52 / oas_code 46, 최대 4015 토큰), test_v30_inputs 269(v1과 동일), 프롬프트 사본, data_v2_hashes.json(원본·생성 파일 SHA-256).
- assistant rationale 출처: {"R1_self_owner": 30, "R1_self_split": 8, "R4_noauth_public": 9, "human_review_v2": 34, "human_review_v2_fix": 1, "human_review_v2_r3": 4, "intended_labels": 146, "model_v301": 523, "rule_security_declared_public": 7, "rule_subscription_relabel": 6, "rule_variant_intended_policy": 19, "rule_visibility_dependent": 12} (규칙 relabel 레코드는 규칙 사유 문장으로 대체, 원본 데이터 불변).
- 생성 파일 SHA-256: {"train_sft.jsonl": "aa903c54af37296458d2741a6162fca7f7bda16cd13b5fdbc134bb8947d51691", "val_sft.jsonl": "73f820580ad6e37596ae80f3a7240f7cdb63e64f898dfd0c3e7f951ff4c69eb8", "test_v30_inputs.jsonl": "d65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a", "policy_label_v3.0.1.md": "d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef"}
- 노트북 training/lora/lora_v2.ipynb(8셀, 문법 검사 통과; GPU 실행 검증은 사용자 Colab에서): v1 하이퍼파라미터 동일, seed 42·43·44 반복, eval/save 30 step, val loss 조건별(eval_oas_loss·eval_oas_code_loss), 체크포인트 전부 Drive 보존, 평가 = seed별 최종 + 조건별 val loss 최저 체크포인트 + 베이스 1회, 예측 파일 형식 v1과 동일 → scripts/eval_v30.py로 채점.
- 업로드 목록·실행 순서·회수 방법: training/lora/README_colab_v2.md.
