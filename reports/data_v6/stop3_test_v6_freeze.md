# test_v6 동결 보고 — 정지 지점 3 (2026-11-08, A안: AI 이중 검수 + 경계 사례만 사람 확정, 커밋 없음)

사전 기록 AGENTS.md "작업 S0"(후보 302건, AI 1차 검수·사람 확인 프로토콜)와 "test_v6 동결 방식 변경 — A안"(2026-11-08, S9 전·test_v6 예측 미열람). 마감 일정상 전체 사람 검수가 불가해 **정답 출처를 세 등급으로 나누어 레코드별 meta.label_status에 기록**했다. S9 전까지 어떤 모델도 test_v6을 추론하지 않았다(scripts/testv6_guard.py: manifest 해시 + BLADE_TESTV6_STAGE=S9 게이트).

## 1. 동결 파일 (이후 수정·재생성 금지)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/test_v6.jsonl | 289 | `872675957276d15777acde947ab99b6e4b9112941a8bedef404ffac9e20bc765` |
| datasets/blade/processed/data_v6/test_v6_excluded.jsonl | 13 | `b66e8ac3a40a68e8252ac058bf26dc71190dcc969e150a7e6992d1e8de005136` |
| training/lora/data_v6/test_v6_inputs.jsonl | 289 | `33d1aecdbd1a685416523eddf73722e105c2c761154a6bf95403fe1431435741` |
| datasets/blade/processed/data_v6/test_v6_manifest.json | - | `a9ca4fca05ee3e59226411c08c9f102440d5f36b2d4b45dc870bd74e346f3edc` (= run_train_v7.py TESTV6 sha) |
| review/test_v6_review_final.xlsx (.gitignore) | 302행 | `0bf36fb58d9bd8d087651797f32007d6e5063f8661027a0334a6683a5d2197b0` |

제외율 13/302 = 4.3%(기준 10% 이하). 후보 302 → 확정 289. 출처: seahub v14.0.9-server(`0841826c`, Apache-2.0) 88 · Redash v26.9.0(`42fdf9d4`, BSD-2-Clause) 72 · GlitchTip v6.2.6(`d3039088`, MIT) 70 · Penpot 2.18.5(`f4456696`, MPL-2.0) 55. data-v1~v7·test_v30·test_v31_supp·test_v5와 (서비스, method, 정규화 path) 겹침 0(assemble 단계 assert). data-v7 train(test_v5·supp 포함)과도 출처 프로젝트가 다르다.

## 2. 정답 출처 (A안)

| label_status | 건수 | 정의 |
|---|---:|---|
| human_confirmed | 5 | 우선확인 44건 중 AI 확정 ≠ Claude 2차 의견 3건 + 저확신 1건, 블라인드 감사 41건 중 Claude 판정 ≠ AI 확정 3건 → 사용자가 사람 판정으로 확정(7건, 그중 EXCLUDE 2) |
| ai_double_confirmed | 67 | 우선확인 44건 중 AI 확정 = Claude 의견 40건(EXCLUDE 11 제외 → 29) + 감사 41건 중 일치 38건 |
| ai_single | 217 | 나머지: AI 1차 확정(Claude, review/test_v6_review_reviewed.xlsx 2026-11-04)만 |

- 2차 검수(Claude)는 1차 확정·근거를 보지 않은 독립 판정이다(감사 41건은 블라인드 시트; 우선확인 44건은 AI 확정 열이 보이는 상태에서의 동의 여부 'Claude AI동의' 열).
- **블라인드 감사 41건: Claude 2차 vs AI 1차 일치 38/41 = 92.7%**(seahub 14/14, Redash 9/9, GlitchTip 9/10, Penpot 6/8; AI label별 manual 5/7, role 9/10, 나머지 5종 24/24). **이 수치는 AI 1차 vs AI 2차 일치율이며 사람 대비 정확도가 아니다.** reports/data_v6/audit41_compare.md(+.json).
- 사람 판정 7건(2026-11-08 사용자): penpot-0366cd50c0 delete-team manual → **EXCLUDE**(설정 의존 조직 소유자 OR 경로, 보충 규약 5); redash-e8133c143b EXCLUDE → **tenant_match**; seahub-5569330cd5 EXCLUDE → **public**; redash-c89e256edf tenant_match 유지(Claude 확신 하); glitchtip-196fbf241d POST /api/embed/error-page/ **manual** 유지(G7-b 조건부 익명, DSN 키 소지; Claude는 EXCLUDE); penpot-30c4fcfc6a delete-file-snapshot **manual** 유지(편집 역할 AND (무잠금 OR 잠금자 본인) = 보류 3; Claude는 role_required); penpot-05b0504832 create-team-invitations role_required → **EXCLUDE**(플래그 의존 조직 설정 경로, delete-team과 일관; Claude는 manual). label 변경 4(EXCLUDE 전환 2, EXCLUDE 해제 2), AI 확정 유지 3.
- 반영 스크립트 scripts/apply_test_v6_human_check.py(audit / apply), 반영 기록 reports/data_v6/human_check_apply.json. AI 확정본 test_v6_review_reviewed.xlsx는 그대로 두고 반영본 test_v6_review_final.xlsx('정답 출처'·'사람 판정 label'·'Claude 2차 label' 열 추가)를 동결 입력으로 썼다(build_test_v6.py freeze --sheet, 정답 출처 → meta.label_status).

## 3. label 분포

| label | 합 | seahub | Redash | GlitchTip | Penpot |
|---|---:|---:|---:|---:|---:|
| role_required | 65 | 22 | 2 | 16 | 25 |
| owner_match | 59 | 23 | 8 | 12 | 16 |
| manual_review_required | 52 | 21 | 16 | 9 | 6 |
| tenant_match | 38 | 11 | 27 | 0 | 0 |
| membership_required | 37 | 8 | 2 | 27 | 0 |
| public | 21 | 4 | 4 | 5 | 8 |
| owner_or_admin | 17 | 3 | 13 | 1 | 0 |
| 합 | 289 | 88 | 72 | 70 | 55 |

security_state: declared 265 · explicitly_anonymous 24(익명 operation 전역 security 보정이 적용된 레코드 18건, 후보 단계 26건 중 8건은 제외/다른 상태). public 오판 분모(declared ∧ 정답 ≠ public) = 265 − (declared ∧ public) — S9 채점 시 산출.

## 4. 제외 13건 (G8·보충 규약, 사유는 test_v6_excluded.jsonl)

Penpot 6(logout·get-profile 익명 스텁/본인 경계, get-error-reports 토큰 스코프, create-team 본인 생성/플래그 정책, delete-team·create-team-invitations 플래그 의존 조직 설정) · GlitchTip 3(wizard-set-token 해시 소지, status-page organization_slug 미사용, 대표 소유자 OR OWNER 역할) · Redash 2(GET /api/groups 범위 분기, GET /api/alerts 권한·데이터소스 그룹 결합) · seahub 2(revert commit·repo-api-tokens의 소유자/부서 관리자 경계). 사용자 판정 EXCLUDE 2건 포함.

## 5. 한계 (DATA_CARD 동일 기재)

1. **정답의 75%(217/289)는 AI 1차 판정 단독**, 23%(67)는 AI 둘의 일치, 사람 확정은 5건이다. 감사 일치율 92.7%는 AI 간 일치이며 사람 정확도 추정이 아니다. S9 결과 해석 시 label 정답 오류가 양 모델에 같은 방향으로 작용한다고 가정할 수 없다.
2. label 편중: tenant_match 38 중 Redash 27(71%), membership_required 37 중 GlitchTip 27(73%), owner_or_admin 17 중 Redash 13; Penpot에 tenant·membership·owner_or_admin 0.
3. Redash G1-b 경계(`@require_admin` + `current_org` → tenant_match) 18건 전부 확정본에 포함(datasets/blade/processed/data_v6/redash_g1b_boundary_ids.json; S9에서 따로 집계).
4. test_v5 대비 label 구성이 다르다(test_v5 tenant 0, test_v6 tenant 38). test_v6 익명 operation 입력 보정 26건(빌드 assert, anonymous_fix).
5. 기존 사전 기록 "우선확인 44건 사람 판정 필수 / 감사 ≤ 5% 규칙"은 A안으로 대체됐다(마감 사유). 전체 사람 검수는 마감 후 과제.

## 6. 다음 (S9)

같은 Pod(kufx154dteqn1b, v7 학습 Pod)·같은 라이브러리에서 v5 어댑터 3개 + v7 어댑터 3개를 test_v6(oas·oas_code)으로 한 번에 추론(runpod/run_s9.sh, TESTV6 해시 게이트; 번들 export/blade_s9_test_v6_20261108.tgz SHA-256 `fa7b93f430a224fb7deb1ec9746db5e12acd15cb8ba17ea1f37045383031353b` + 별도 blade_v5_adapters.tar.gz `db6abe46…`). 채택 기준(AGENTS.md 작업 data-v7): (1) test_v6 oas_code macro-F1 ≥ v5 + 0.016, (2) test_v30 207 구체 정밀도 하락 ≤ 0.025(충족, +0.028), (3) test_v30 207 public 오판 평균 ≤ 2.0(충족, 1.33). S9 보고에 프로젝트별 정확도·label별 F1·G1-b 18건 집계·label_status별 정확도를 넣는다. 마감 2026-11-09 18:00 KST, 미달이면 v5 유지. 커밋 없음.
