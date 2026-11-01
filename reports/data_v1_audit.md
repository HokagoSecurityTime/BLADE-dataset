# data-v1 / data-v2 초안 라벨·피처 분포 점검 (분석 전용, 2026-10-23)

data-v1 해시 assert 통과(hashes.json ↔ AGENTS.md): train_v30.jsonl `a99d30da2d29907e…`, val_v30.jsonl `62bdadb29cae7aaf…`, test_v30.jsonl `9bd47216575afc60…`, policy_label_v3.0.1.md `d0913c27b5de185e…`. 모든 파일 읽기 전용. data-v2 초안 = `train_v2_draft.jsonl`(build_train_v2.py, 안 A' 변형, 검수 반영 전·manual 쿼터 미적용).

## 1. label 분포

| label | train_v1 | train_v1 비율 | val_v1 | val_v1 비율 | test_v30 | test_v30 비율 | train_v2_draft | train_v2_draft 비율 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| public | 27 | 5.7% | 3 | 5.8% | 66 | 24.5% | 47 | 4.8% |
| role_required | 112 | 23.8% | 20 | 38.5% | 51 | 19.0% | 161 | 16.6% |
| membership_required | 29 | 6.2% | 1 | 1.9% | 4 | 1.5% | 55 | 5.7% |
| tenant_match | 40 | 8.5% | 3 | 5.8% | 8 | 3.0% | 52 | 5.4% |
| owner_match | 134 | 28.5% | 12 | 23.1% | 114 | 42.4% | 182 | 18.7% |
| owner_or_admin | 11 | 2.3% | 0 | 0.0% | 11 | 4.1% | 32 | 3.3% |
| manual_review_required | 118 | 25.1% | 13 | 25.0% | 15 | 5.6% | 442 | 45.5% |
| 합계 | 471 | 100% | 52 | 100% | 269 | 100% | 971 | 100% |


manual 비율: train_v1 25.1%(쿼터 25% 적용), val_v1 25.0%, **test_v30 5.6%**(사람 확정·설계 라벨 실제 비율), train_v2_draft 45.5%(쿼터 미적용; apply_reviews_v2 적용 시 25%).

### 1-1. 출처 × label (split별)

| split | 출처 | N | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | manual 비율 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| train_v1 | apisguru | 411 | 19 | 104 | 25 | 32 | 126 | 1 | 104 | 25.3% |
| train_v1 | synthetic | 60 | 8 | 8 | 4 | 8 | 8 | 10 | 14 | 23.3% |
| val_v1 | apisguru | 52 | 3 | 20 | 1 | 3 | 12 | 0 | 13 | 25.0% |
| test_v30 | synthetic | 58 | 8 | 8 | 4 | 8 | 8 | 8 | 14 | 24.1% |
| test_v30 | vuln_repository_spec | 102 | 34 | 14 | 0 | 0 | 54 | 0 | 0 | 0.0% |
| test_v30 | vuln_route_only | 109 | 24 | 29 | 0 | 0 | 52 | 3 | 1 | 0.9% |
| train_v2_draft | apisguru | 411 | 19 | 104 | 25 | 32 | 126 | 1 | 104 | 25.3% |
| train_v2_draft | gitea | 371 | 12 | 37 | 8 | 0 | 36 | 0 | 278 | 74.9% |
| train_v2_draft | synthetic | 60 | 8 | 8 | 4 | 8 | 8 | 10 | 14 | 23.3% |
| train_v2_draft | synthetic_v2 | 129 | 8 | 12 | 18 | 12 | 12 | 21 | 46 | 35.7% |


### 1-2. 코드(핸들러 원문) 유무 × label (split별)

train/val: controller_signals.raw_snippet, test: controller_text. oas 조건은 모든 레코드, oas_code 조건은 코드 있는 레코드만 해당.

| split | 코드 | N | 비율 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | manual 비율 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| train_v1 | 코드 있음 | 60 | 12.7% | 8 | 8 | 4 | 8 | 8 | 10 | 14 | 23.3% |
| train_v1 | 코드 없음 | 411 | 87.3% | 19 | 104 | 25 | 32 | 126 | 1 | 104 | 25.3% |
| val_v1 | 코드 없음 | 52 | 100.0% | 3 | 20 | 1 | 3 | 12 | 0 | 13 | 25.0% |
| test_v30 | 코드 있음 | 265 | 98.5% | 66 | 47 | 4 | 8 | 114 | 11 | 15 | 5.7% |
| test_v30 | 코드 없음 | 4 | 1.5% | 0 | 4 | 0 | 0 | 0 | 0 | 0 | 0.0% |
| train_v2_draft | 코드 있음 | 560 | 57.7% | 28 | 57 | 30 | 20 | 56 | 31 | 338 | 60.4% |
| train_v2_draft | 코드 없음 | 411 | 42.3% | 19 | 104 | 25 | 32 | 126 | 1 | 104 | 25.3% |


## 2. manual_review_required 사유 분해 (train_v1 · val_v1 · train_v2_draft)

근거 필드: meta.v30_override_reason / meta.v30_relabel_reason(규칙 플래그), 합성 intended rationale(설계 사유), APIs.guru·Gitea는 모델 rationale 문장의 정규식 일치(reports/eval/.../manual_analysis.md와 같은 패턴). 모델 문장 기반 분류는 근사치이며 패턴 미일치는 "분류불가"로 둔다. (가)=정보 부족 보류, (나)=실제 판단 불가(복합·구독·충돌·조건부 접근).

**train_v1** manual 118건: (가) 102 · (나) 16 · 분류불가 0

| 구분 | 세부 사유 | 건수 |
|---|---|---:|
| 가 | 요청자-객체 관계 미확인 | 66 |
| 가 | 접근 조건 미명시(일반) | 15 |
| 나 | 합성: 복합/충돌 조건(설계 manual) | 8 |
| 가 | override: security 선언 public→manual | 7 |
| 나 | relabel: 합성 subscription(구독 조건) | 6 |
| 가 | 인증만 확인·인가 조건 없음 | 6 |
| 가 | 객체 ID만 있음 | 4 |
| 가 | API 키만 요구 | 2 |
| 가 | 설명 없음·비어 있음 | 2 |
| 나 | 복합 조건(AND)·단일 라벨 불가 | 1 |
| 나 | 구독·플랜·등급 조건 | 1 |


**val_v1** manual 13건: (가) 11 · (나) 1 · 분류불가 1

| 구분 | 세부 사유 | 건수 |
|---|---|---:|
| 가 | 요청자-객체 관계 미확인 | 10 |
| 가 | 접근 조건 미명시(일반) | 1 |
| 나 | 역할·권한 조건 불명확 | 1 |
| 분류불가 | 패턴 미일치 | 1 |


**train_v2_draft** manual 442건: (가) 220 · (나) 220 · 분류불가 2

| 구분 | 세부 사유 | 건수 |
|---|---|---:|
| 나 | override: visibility_dependent(조건부 접근) | 96 |
| 가 | 요청자-객체 관계 미확인 | 89 |
| 나 | 복합 조건(AND)·단일 라벨 불가 | 86 |
| 가 | 인증만 확인·인가 조건 없음 | 59 |
| 가 | 합성 변형: 인증만·인가 제거(설계 manual) | 38 |
| 가 | 접근 조건 미명시(일반) | 19 |
| 나 | 합성: 복합/충돌 조건(설계 manual) | 16 |
| 나 | 역할·권한 조건 불명확 | 14 |
| 가 | override: security 선언 public→manual | 7 |
| 나 | relabel: 합성 subscription(구독 조건) | 6 |
| 가 | 객체 ID만 있음 | 4 |
| 가 | API 키만 요구 | 2 |
| 가 | 설명 없음·비어 있음 | 2 |
| 나 | 구독·플랜·등급 조건 | 2 |
| 분류불가 | 패턴 미일치 | 2 |


### 2-1. (가) 정보 부족 보류 건의 원천 구체 label (확인 가능한 경우만)

APIs.guru 레코드는 코드·정답 소스가 없어 원천 구체 label을 확인할 수 없다(확인 불가). 확인 가능한 것은 규칙 override로 manual이 된 건의 원래 모델 label(label_before_override), 합성 변형의 설계 base label뿐이다.

| split | (가) 건수 | 원천 label 확인 불가 | 확인 가능한 원천 label 분포 |
|---|---:|---:|---:|
| train_v1 | 102 | 95 | public 7 |
| val_v1 | 11 | 11 |  |
| train_v2_draft | 220 | 175 | variant base:owner_or_admin 10 / variant base:owner_match 8 / variant base:tenant_match 8 / variant base:role_required 8 / public 7 / variant base:membership_required 4 |


### 2-2. test_v30에서 같은 성격의 입력이 갖는 정답 (대조표)

train의 (가) 규칙("OAS만으로 관계·조건 확인 불가 → manual")이 test에서 어떻게 채점되는지: 명세가 없는 route_only 109건과 security unknown 건의 정답 분포.

| test 구간 | N | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | manual 정답 비율 | 코드 있음 비율 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| vuln route_only(명세 없음) | 109 | 24 | 29 | 0 | 0 | 52 | 3 | 1 | 0.9% | 100.0% |
| vuln repository_spec | 102 | 34 | 14 | 0 | 0 | 54 | 0 | 0 | 0.0% | 96.1% |
| synthetic(설명=설계 사유 포함) | 58 | 8 | 8 | 4 | 8 | 8 | 8 | 14 | 24.1% | 100.0% |
| security_state=unknown 전체 | 205 | 49 | 43 | 4 | 6 | 83 | 9 | 11 | 5.4% | 98.0% |
| description 비어 있음 전체 | 142 | 32 | 32 | 0 | 0 | 74 | 3 | 1 | 0.7% | 100.0% |


train 쪽 같은 성격(명세 정보 부족) 레코드의 라벨(쿼터 적용 후 train에 남은 건 기준):

| split | 구간 | N | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required | manual 비율 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| train_v1 | APIs.guru description 비어 있음 | 112 | 1 | 27 | 2 | 6 | 47 | 0 | 29 | 25.9% |
| train_v1 | APIs.guru security_state=unknown | 68 | 15 | 2 | 0 | 0 | 4 | 0 | 47 | 69.1% |
| val_v1 | APIs.guru description 비어 있음 | 6 | 0 | 1 | 0 | 0 | 1 | 0 | 4 | 66.7% |
| val_v1 | APIs.guru security_state=unknown | 12 | 1 | 2 | 0 | 0 | 0 | 0 | 9 | 75.0% |


**결론(수치)**: train 라벨 생성(v3.0.1, APIs.guru 2,027건)에서 security_state=unknown 754건은 manual 96.7%로 라벨됐지만, test_v30의 명세 없는 route_only 109건의 사람 정답은 manual 1건(0.9%)이고 구체 label이 108건이다. 같은 성격의 입력에 train은 '보류', test는 '코드 기준 구체 label'을 부여하므로 **train과 test의 라벨 기준은 다르다**(test 정답은 코드 발췌가 있는 상태에서 확정됐고 oas 조건 채점에도 그대로 쓰인다).

## 3. security_state × label (split별)

| split | security_state | N | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| train_v1 | declared | 339 | 0 | 102 | 25 | 32 | 122 | 1 | 57 |
| train_v1 | explicitly_anonymous | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| train_v1 | unknown | 128 | 23 | 10 | 4 | 8 | 12 | 10 | 61 |
| val_v1 | declared | 38 | 0 | 18 | 1 | 3 | 12 | 0 | 4 |
| val_v1 | explicitly_anonymous | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| val_v1 | unknown | 12 | 1 | 2 | 0 | 0 | 0 | 0 | 9 |
| test_v30 | declared | 64 | 17 | 8 | 0 | 2 | 31 | 2 | 4 |
| test_v30 | unknown | 205 | 49 | 43 | 4 | 6 | 83 | 9 | 11 |
| train_v2_draft | declared | 710 | 12 | 139 | 33 | 32 | 158 | 1 | 335 |
| train_v2_draft | explicitly_anonymous | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| train_v2_draft | unknown | 257 | 31 | 22 | 22 | 20 | 24 | 31 | 107 |


security_state=declared 이면서 label=public인 건:

- train_v1: 0건
- val_v1: 0건
- test_v30: 17건 — 149fc53d41cf49d52bb9, 9a7d3d59efab53f32063, 860383f68102b772bb99, 7a19e5a3a9eb0d5947f3, c085f5d6b9f87dd6d4a1, 324601a8dc9e9ea969bb, 3dc50d2c3650a204001d, d72193f9a1b7d79700d0, bc1dce3621c7da44ddfe, 58e3df2930d0ce4c3175, 61f662463e13765b9478, be8b11cdbabe4486aeda, 7e3f8c20d798e8b34143, bb532c95786f45e07314, d553cdd9276767f1b1bc, beacon_iot_catalogue_0, beacon_iot_catalogue_1
- train_v2_draft: 12건 — gitea:post:/markdown, gitea:get:/gitignore/templates, gitea:get:/users/{username}/keys, gitea:get:/user/keys, gitea:get:/repos/{owner}/{repo}/actions/workflows/{workflow_id}, gitea:get:/repos/{owner}/{repo}/collaborators, gitea:get:/repos/{owner}/{repo}/teams, gitea:get:/repos/{owner}/{repo}/keys, gitea:get:/repos/{owner}/{repo}/times, gitea:get:/repos/{owner}/{repo}/notifications, gitea:get:/orgs, gitea:get:/topics/search

(train_v1은 build_train_v30.py의 security_declared_public override로 0건. train_v2_draft의 declared∧public은 전부 Gitea 레코드다: build_train_v2.py/apply_reviews_v2.py에는 Gitea에 대한 security_declared_public override가 없고 visibility_dependent override만 있다. Gitea는 OAS 전역 security 때문에 455건 전부 declared이므로 data-v1 규칙을 그대로 적용하면 Gitea public 전부가 manual이 된다. test_v30 synthetic은 security 선언 없이 Authorization 헤더 파라미터만 있어 unknown, 취약 API는 전역/operation security로 declared.)

## 4. 합성 데이터 편중·누수

| split | public (합성/전체) | role_required (합성/전체) | membership_required (합성/전체) | tenant_match (합성/전체) | owner_match (합성/전체) | owner_or_admin (합성/전체) | manual_review_required (합성/전체) |
|---|---:|---:|---:|---:|---:|---:|---:|
| train_v1 | 8/27 (29.6%) | 8/112 (7.1%) | 4/29 (13.8%) | 8/40 (20.0%) | 8/134 (6.0%) | 10/11 (90.9%) | 14/118 (11.9%) |
| val_v1 | 0/3 (0.0%) | 0/20 (0.0%) | 0/1 (0.0%) | 0/3 (0.0%) | 0/12 (0.0%) | 0/0 (-) | 0/13 (0.0%) |
| test_v30 | 8/66 (12.1%) | 8/51 (15.7%) | 4/4 (100.0%) | 8/8 (100.0%) | 8/114 (7.0%) | 8/11 (72.7%) | 14/15 (93.3%) |
| train_v2_draft | 16/47 (34.0%) | 20/161 (12.4%) | 22/55 (40.0%) | 20/52 (38.5%) | 20/182 (11.0%) | 31/32 (96.9%) | 60/442 (13.6%) |


- 서비스 단위 중복(train∪val∪v2 ∩ test): 0건 .
- test 합성 58건 중 **경로 템플릿(섹션/라벨) 동일**한 train 합성 사례가 있는 건: 56건(96.6%). 같은 생성 템플릿(catalogue/drafts/shared/… 섹션, 동일 인가 검사 코드)을 공유하므로 서비스명만 다른 near-duplicate다.
- test 합성 중 **정규화한 인가 검사 줄이 train 합성과 바이트 동일**한 건: 43건(74.1%).
- 취약 API(vuln) 211건과 Gitea·APIs.guru 사이의 경로 패턴(파라미터 정규화) 교집합: 0건.

## 5. 토큰 길이 (Qwen2.5 토크나이저, 프롬프트 v3.0.1 적용, chat template 포함)

시스템 프롬프트 단독 2699 토큰(chat template 제외). 학습 입력은 system+user+assistant, 평가 입력은 system+user(+generation prompt).

| split | 조건 | N | 중앙값 | 평균 | p95 | 최대 | >4096 | >3584 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| test_v30 | oas | 269 | 2809 | 2817 | 2865 | 2976 | 0 | 0 |
| test_v30 | oas_code | 265 | 2999 | 3039 | 3296 | 3841 | 0 | 5 |
| train_v1 | oas(학습 입력) | 411 | 3040 | 3086 | 3382 | 4050 | 0 | 5 |
| train_v1 | oas_code(학습 입력) | 60 | 3012 | 3015 | 3057 | 3075 | 0 | 0 |
| train_v2_draft | oas | 411 | 3040 | 3086 | 3382 | 4050 | 0 | 5 |
| train_v2_draft | oas_code | 560 | 3322 | 3314 | 3698 | 4098 | 1 | 70 |
| val_v1 | oas(학습 입력) | 52 | 3049 | 3125 | 3490 | 3817 | 0 | 3 |


max_seq_len 4096 초과:

| split | 조건 | id | 토큰 | 핸들러 원문 토큰 |
|---|---|---|---:|---:|
| train_v2_draft | oas_code | gitea:post:/repos/{owner}/{repo}/pulls/{index}/merge | 4098 | 962 |


초과분은 모두 핸들러 원문(description에 포함된 코드)이 길어서 생긴 것이며, 잘릴 때 뒤쪽(코드 끝부분과 assistant 응답 쪽)이 먼저 잘린다. 학습 입력에서 assistant가 잘리면 해당 샘플은 학습 신호가 사라진다.

## 6. data-v2 초안: 라벨링 규칙·쿼터 동일성과 신규분 분포

- 라벨 규칙: Gitea 455건은 gpt-4o-mini + 프롬프트 v3.0.1(SHA `d0913c27b5de185e…`, data-v1과 동일 파일) + oas_code 조건으로 라벨(reports/eval/data_v2/gitea_label/manifest.json). data-v1 APIs.guru는 같은 프롬프트의 oas 조건. 합성 보강 129건은 intended_labels(설계 라벨)이며 LLM 라벨이 아니다.
- 추가 규칙(train_v2 빌드, build_train_v2.py/apply_reviews_v2.py): visibility_dependent 96건 → manual override, Gitea owner_or_admin 84건 → pool. data-v1에는 없던 규칙.
- manual 쿼터: data-v1 25%(build_train_v30.py, round_half_up(C/3)). train_v2_draft는 쿼터 미적용(manual 45.5%); apply_reviews_v2.py가 같은 공식으로 25%를 적용하며 dry-run 기준 705건(Gitea 105건, visibility manual 12건만 포함).

합성 보강 129건 중 train_v2_draft에 포함된 건: 129.

| data-v2 신규분 | N | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Gitea 라벨 원본 455 | 455 | 61 | 37 | 9 | 2 | 36 | 85 | 225 |
| Gitea train_v2_draft 포함 371(visibility override·owner_or_admin pool 후) | 371 | 12 | 37 | 8 | 0 | 36 | 0 | 278 |
| Gitea 구체 label(draft 내) | 93 | 12 | 37 | 8 | 0 | 36 | 0 | 0 |
| 합성 보강 129(변형 57 + 신규 4종 72) | 129 | 8 | 12 | 18 | 12 | 12 | 21 | 46 |
|   └ 변형 authonly/extauth(manual 설계) | 38 | 0 | 0 | 0 | 0 | 0 | 0 | 38 |
|   └ 변형 extguard(구체 대조군) | 19 | 0 | 4 | 2 | 4 | 4 | 5 | 0 |
|   └ 신규 4종(Django/Nest/Gin/Rails) | 72 | 8 | 8 | 16 | 8 | 8 | 16 | 8 |


## 7. 핵심 수치 요약

1. manual 비율: train_v1 25.1%(쿼터) vs test_v30 5.6%; 코드 있는 레코드: train_v1 60/471(12.7%) vs test_v30 265/269(98.5%).
2. train_v1 manual 118건 중 (가) 정보 부족 보류 102건, (나) 실제 판단 불가 16건, 분류불가 0건; (가)의 원천 구체 label은 APIs.guru 특성상 확인 불가.
3. test_v30 route_only 109건(명세 없음)의 정답: manual 1건, 구체 108건; 전체 라벨링에서 security unknown 754건은 manual 96.7%.
4. declared∧public: train_v1 0, val_v1 0, test_v30 17, train_v2_draft 12. 합성 비중: membership_required train_v1 4/29, tenant_match 8/40, owner_or_admin 10/11; test 합성 58건 중 템플릿 중복 56건.
5. 토큰: 4096 초과 1건(상세 5절); train_v2_draft Gitea oas_code 입력이 가장 길다.

## 8. 라벨 기준 불일치 판정

**확정**. 근거: (i) 명세가 없는 입력에 대해 train 라벨 규칙은 보류(전체 라벨링 security unknown 754건 manual 96.7%)인데 test_v30 route_only 109건의 사람 정답은 구체 label 99.1%; (ii) test 정답은 코드 발췌를 보고 확정됐지만 oas 조건 채점에도 같은 정답을 쓰므로, oas 조건에서 v3.0.1 규칙대로 보류한 모델은 구조적으로 틀린 것으로 채점된다; (iii) train의 코드 있는 레코드 12.7% vs test 98.5%로 입력 조건 자체가 다르다.

## 9. 선택지별 사실 정리 (권고 없음)

**(A) test를 조건별 정답으로 재정의 — oas 조건에서 정보 부족 시 manual을 정답으로 인정, 프롬프트 v3.0.1 유지**
- 바꿔야 하는 파일: test_v30.jsonl은 동결이므로 불변. 새 파일로 `test_v30_oas_truth.jsonl`(또는 조건별 정답 열)을 만들어 oas 조건 전용 정답을 둔다. 평가 코드(노트북 셀 7~8, 향후 eval 스크립트)가 조건별 정답을 읽도록 변경.
- 재정의 대상 건수: route_only 109건(명세 없음)이 1차 대상, security unknown 전체 205건·description 비어 있음 142건이 검토 범위. '정보 부족' 판정 규칙(어떤 OAS 필드가 없으면 manual 인정인지)을 먼저 문서화해야 하며 이는 사람 결정이다. oas_code 조건 정답은 그대로.
- 프롬프트 v3.0.1 영향: 없음(유지). train 라벨·LoRA 재학습 불필요. 영향은 평가 해석에만 미치며, oas 조건의 모델 간 비교 수치는 모두 다시 계산된다(기존 lora_v1_report의 oas 열은 구 정답 기준으로 남긴다).

**(B) train 라벨을 코드 기준 구체 label로 변경, 프롬프트 v3.1로 개정**
- 바꿔야 하는 파일: 프롬프트 신규 `policy_label_v3.1.md`(보류 필수 2항 'OAS만으로 확인 불가 → manual' 완화 또는 삭제; 예시 8 재작성), APIs.guru 2,027건 재라벨(gpt-4o-mini, 약 $0.6~1.0, 새 파일 apisguru_labeled_v31.jsonl), train/val 재구성(train_v31/val_v31; data-v1은 불변), DATA_CARD·AGENTS 추가 절, LoRA 재학습(data-v1.1 또는 v2).
- 재라벨 대상 건수: APIs.guru 2,027건 전부(코드가 없어 '코드 기준' 구체 label 자체를 만들 수 없는 레코드 — 명세 설명만으로 구체 label을 붙이게 되므로 v2.5 시절의 과대 판정 위험이 돌아온다). 코드가 있는 train 레코드는 합성 60건(+data-v2 Gitea 371, 변형 129)뿐이다. train_v1 manual 118건 중 (가) 102건이 직접 영향 범위.
- 프롬프트 v3.0.1 영향: 고정 결정을 철회하고 v3.1로 개정. Q 단계(합성 train 42건 × 2조건)와 F 단계를 다시 수행해야 하며, Gitea 455건·NetBox·test_v2_extra 참고 라벨도 v3.1 기준과 어긋나므로 재라벨 대상이 된다(Gitea 약 $0.18, NetBox 185 약 $0.07, extra 약 $0.02). test_v30 정답은 이미 코드 기준이라 변경 없음.

출력: reports/data_v1_audit.md, reports/data_v1_audit/*.csv (label_dist, source_label, code_label, manual_reasons_summary/detail, info_gap_origin, test_specless_truth, train_specless_labels, security_label, declared_public_ids, synthetic_share, synthetic_near_duplicates, token_lengths(+detail), v2_new_records). 스크립트 scripts/audit_data_v1.py.
