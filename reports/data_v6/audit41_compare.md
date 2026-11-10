# test_v6 블라인드 감사 41건 — Claude 2차 판정 vs AI 1차 확정 (2026-11-08)

일치 38/41 = 92.7%, 불일치 3건(7.3%). 입력 `test_v6_감사41_Claude판정_비교용.xlsx`(SHA-256 `b52241341d623dc6…`), 정답키 human_check_audit_key.json(`0fa0f0e76035ca0e…`). 일치율은 AI 1차 확정 vs 독립 AI 2차(Claude) 판정의 일치율이며 사람 대비 정확도가 아니다(A안). 불일치 건은 사용자가 사람 판정으로 확정한다.

| project | n | 일치 |
|---|---:|---:|
| glitchtip | 10 | 9 |
| penpot | 8 | 6 |
| redash | 9 | 9 |
| seahub | 14 | 14 |

| AI 1차 label | n | 일치 |
|---|---:|---:|
| manual_review_required | 7 | 5 |
| membership_required | 6 | 6 |
| owner_match | 8 | 8 |
| owner_or_admin | 3 | 3 |
| public | 4 | 4 |
| role_required | 10 | 9 |
| tenant_match | 3 | 3 |

## 불일치 건(사용자 판정 대상)

| id | project | method path | AI 1차 (conf) | Claude 2차 (확신) | Claude 근거 |
|---|---|---|---|---|---|
| v6t-glitchtip-196fbf241d | glitchtip | POST /api/embed/error-page/ | manual_review_required (0.8) | EXCLUDE (중) | embed_auth가 DSN 공개키·project_id 일치만 확인해 public(G7)과 키 기반 인증 사이 경계라 제외(G8). |
| v6t-penpot-30c4fcfc6a | penpot | POST /api/rpc/command/delete-file-snapshot | manual_review_required (0.7) | role_required (중) | check-edition-permissions!가 팀·프로젝트·파일 구성원 행의 can_edit(편집자 이상 역할)를 요구하는 그룹 내 역할 조건(G3); 잠금 검사는 부가 조건. |
| v6t-penpot-05b0504832 | penpot | POST /api/rpc/command/create-team-invitations | role_required (0.8) | manual_review_required (하) | 팀 :is-admin 요구에 더해 :admin-console 플래그·조직 정책(cto/allowed?)에 따라 허용 주체가 바뀌는 설정 의존 조건(G6, v3.1 보류5). |
