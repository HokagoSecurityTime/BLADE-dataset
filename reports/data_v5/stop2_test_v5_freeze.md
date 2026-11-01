# 작업 C 정지 지점 2 — test_v5 동결 (2026-10-31)

사용자 검수 완료본 `review/test_v5_review_reviewed.xlsx`(SHA-256 `6a6e1405b7de39c9dec1382594ec0fedda05a82ce0bf796eabee456e12a0c54f`)로 `scripts/build_test_v5.py freeze`를 실행했다. 동결은 **v5 예측 생성 전**에 이뤄졌다(순서 변경 강제 (a)): 1단계 export에 test_v5 예측 파일이 없고, 06:17 UTC의 2단계 시도는 TESTV5 게이트가 7개 항목을 모두 거부했다(reports/eval/lora_v5/lora_v5_report.md 4절). 커밋·태그 없음.

## 동결 결과

| 항목 | 값 |
|---|---|
| 시트 행 | 296 (담당자 열 검수자A 99 · B 99 · C 98 — 시트의 배정 이름 그대로, 사람 확정) |
| 확정(test_v5) | **283건** |
| 제외(EXCLUDE, G8) | 13건 (사유는 test_v5_excluded.jsonl) |
| 초안 대비 변경 | 5건 |
| 확정 근거 빈칸 | 0 |
| security_state | declared 277 · explicitly_anonymous 6 |
| 출처 | Rocket.Chat 8.9.0 `057a927d` (MIT) · Ghost v6.73.0 `5794cfd8` (MIT) · Umami v3.4.1 `559e3c60` (MIT) |

### label × project

| label | rocketchat | ghost | umami | 합계 |
|---|---:|---:|---:|---:|
| role_required | 54 | 44 | 13 | 111 |
| manual_review_required | 39 | 8 | 18 | 65 |
| owner_match | 21 | 2 | 11 | 34 |
| membership_required | 28 | 0 | 5 | 33 |
| owner_or_admin | 9 | 8 | 4 | 21 |
| public | 6 | 7 | 6 | 19 |
| 합계 | 157 | 69 | 57 | 283 |

### 해시 (동결, 이후 수정·재생성 금지)

| 파일 | 건수 | SHA-256 |
|---|---:|---|
| datasets/blade/processed/test_v5.jsonl | 283 | `7b8e4a940967ec474e0d5dbf6dcdbd6b7e04be439599c2a684664d6b9393fd9c` |
| datasets/blade/processed/data_v5/test_v5_excluded.jsonl | 13 | `56161a35cda3c7d487eecc16266a185a6f0cf9c09ac4c62e6542ca29488a839f` |
| datasets/blade/processed/data_v5/test_v5_manifest.json | - | `57fd384f46e89e905209e627a7ff7fb9f312e22a7bed222639e91a80bd05fccd` (= run_train.py `TESTV5['sha']`) |
| training/lora/data_v5/test_v5_inputs.jsonl | 283 | `9103cd3d5276ab425f577a2866291bf8e27e7a06a18bd725701989673dbe5d82` |
| review/test_v5_review_reviewed.xlsx | 296행 | `6a6e1405b7de39c9dec1382594ec0fedda05a82ce0bf796eabee456e12a0c54f` |

### 제외 13건 (G8: 경계·근거 부족은 manual로 넣지 않고 제외)

| project | method path | 사유 |
|---|---|---|
| ghost | DELETE /ghost/api/admin/session/ | 객체 없는 본인 세션 로그아웃 — owner_match(G4)/manual(G6) 경계 |
| ghost | POST /ghost/api/admin/pages/ | 생성 요청, 기존 객체 없음 (정지 지점 1 통일 판단) |
| ghost | POST /ghost/api/admin/posts/ | 생성 요청, 기존 객체 없음 (정지 지점 1 통일 판단) |
| ghost | POST /ghost/api/admin/authentication/setup/ | 사이트 설정 완료 여부에 따른 조건부 익명 허용 — public/manual 경계 |
| rocketchat | GET /api/v1/groups.members | broadcast 방에서만 권한이 AND로 추가 — 방 종류별 조건 분기 경계 |
| rocketchat | POST /api/v1/users.generatePersonalAccessToken | 본인 고정 + 기능 권한 결합 — owner_match/role_required 경계 |
| rocketchat | GET /api/v1/users.getPersonalAccessTokens | 본인 고정 + permissionsRequired 결합 — owner_match/role_required 경계 |
| rocketchat | GET /api/v1/chat.ignoreUser | 본인 구독 플래그이나 대상 사용자와 같은 방 구성원이어야 함 — owner_match/membership 경계 |
| rocketchat | POST /api/v1/im.setTopic | DM에서 edit-room 기본 부여 여부 미확인 — role_required/membership 경계 |
| rocketchat | POST /api/v1/rooms.createDiscussion | 기본 user 권한 + 설정 의존 + 상위 방 접근 검사 발췌 밖 — 근거 부족 |
| umami | POST /api/teams/join | 인증 + 비밀 초대 코드 소지만 조건 — 6종 표현 경계 |
| umami | DELETE /api/teams/{teamId}/users/{userId} | 관리자 OR 본인 탈퇴 OR 팀 역할 — "역할 OR 본인" 구조(학습 데이터 Dendrite kick·NodeBB 추방 제외와 동일 처리) |
| umami | POST /api/auth/logout | 객체 없는 본인 세션 로그아웃 — owner_match/manual 경계 |

### 초안 대비 변경 5건

| id | method path | 초안 → 확정 |
|---|---|---|
| v5t-rocketchat-b0265eaedd | POST /api/v1/rooms.saveDraft | owner_match → membership_required |
| v5t-rocketchat-e274608cda | POST /api/v1/subscriptions.read | owner_match → membership_required |
| v5t-rocketchat-e880661365 | POST /api/v1/rooms.saveNotification | owner_match → membership_required |
| v5t-rocketchat-23a530da4b | POST /api/v1/users.resetAvatar | owner_or_admin → manual_review_required |
| v5t-rocketchat-8289184b61 | POST /api/v1/users.setAvatar | owner_or_admin → manual_review_required |

정지 지점 1 통일 판단(시트 '검수 규약' 탭)대로: Rocket.Chat 본인 구독 변경은 방 비구성원 거부 시 membership_required, canAccessRoom 계열 manual(G6), Ghost POST /posts·/pages EXCLUDE, Umami 팀 관리 role_required(G3)·웹사이트 수정·삭제 manual.

## 격리 확인 (동결 시 재확인)

- (service, method, 정규화 path) 키 겹침: train_v5 0 · val_v5 0 · train_v5_rule_labeled 0 · train_v5_pool 0 · test_v30 0 · test_v31_supp 0.
- test_v5 service(Rocket.Chat·Ghost·Umami)는 train_v5 service 집합과 교집합 없음. 출처 저장소·포크는 data-v5 보강분(Dendrite·NodeBB·Taiga)에 쓰지 않았다.
- data-v5 동결본은 test_v5 label을 읽지 않았다(빌드 코드는 키 겹침 검사만).

## 한계 (보고서 한계 절에 기록)

- membership_required 33건 중 Rocket.Chat 28건(85%). 정지 지점 1 예상(26/31)보다 편중이 조금 더 크다. tenant_match는 0건이라 test_v5에서 tenant_match F1은 정의되지 않는다.
- owner_or_admin 21건(Rocket.Chat 9 · Ghost 8 · Umami 4)으로 support가 작아 seed 표준편차가 클 수 있다. 사전 기준(owner_or_admin·membership F1이 v4보다 표준편차 이상 상승)은 이 support 그대로 적용한다.
- 검수자 열은 시트의 배정 이름(검수자A/B/C)이다. 사람 확인 목록 탭(75건)은 검수 과정의 확인 대상 기록이며 label 확정 자료는 '확정 label' 열이다.

## 평가 반영

- eval-def v2의 별도 조건으로만 추가한다. 주지표(test_v30 oas_code 합성 제외 207건)는 바뀌지 않는다. 채점기 scripts/eval_test_v5.py는 manifest 해시가 맞을 때만 동작한다.
- run_train.py `TESTV5['sha']`에 manifest SHA-256을 기입했다. Pod에는 `data_v5/test_v5_inputs.jsonl`·`data_v5/test_v5_manifest.json`·`runpod/run_train.py`·`runpod/export_results.sh`(경로 수정본)를 올린다.
- 2단계 명령(GGUF_SEED=42 포함, 사용자 결정): README_runpod_rerun.md 4.5절.
