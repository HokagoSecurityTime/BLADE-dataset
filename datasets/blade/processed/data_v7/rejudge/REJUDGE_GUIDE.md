# data-v7 재판정 안내 (REJUDGE_GUIDE) — 2026-11-07

당신은 BLADE 정책 라벨 검수자다. 입력 파일의 각 행(`id`, `kind`, `user`)에 대해 `user` 텍스트(모델이 보는 OpenAPI 명세 + 있으면 핸들러 코드 발췌)만 보고 7종 label 중 하나를 고른다.
**다른 파일을 열지 않는다.** 이 안내문과 지정된 입력 파일만 읽는다. 저장소의 다른 데이터·정답·보고서·코드를 읽지 않는다(현재 라벨을 보면 재판정이 무효가 된다).

## 출력 형식

출력 파일(지정 경로)에 입력과 같은 순서로 한 행에 JSON 하나:
`{"id": "...", "label": "<7종 중 하나>", "confidence": <0.5|0.7|0.9>, "rule": "<근거 규약: G1~G7, 보류1~8, G3-a 등>", "evidence": "<입력에서 그대로 인용한 핵심 문구·코드 줄 1~3개, 120자 이내>", "note": "<판단 한 줄, 한국어>"}`
- label 7종: public, role_required, membership_required, tenant_match, owner_match, owner_or_admin, manual_review_required.
- confidence: 0.9 = 근거가 입력에 명시, 0.7 = 근거는 있으나 해석 필요, 0.5 = 경계·추정(이 경우 보류를 우선 검토).
- 모든 행을 빠뜨리지 말고 id를 그대로 쓴다. 입력 행 수와 출력 행 수가 같아야 한다.

## 입력 종류별 규칙

- `kind: "oas"` (명세만, 코드 없음): **보류 2를 엄격히 적용**한다. description·summary에 접근 조건이 문장으로 명시돼 있어야 구체 label을 고른다("관리자만", "본인 계정의", "인증 없이", "organization member" 등). path에 ID가 있다는 것, owner_cols/tenant_cols에 필드가 있다는 것, 자원 이름(me, my, admin)만으로 관계를 단정하지 않는다 → manual_review_required. security 선언·mutation 제한은 OAS-only에서 유지한다: PUT/POST/PATCH/DELETE는 security가 명시적으로 비어 있을(`security_state: explicitly_anonymous`) 때만 public이고, `declared`·`unknown`이면 public이 아니다. GET이라도 익명 허용의 긍정 근거(explicitly_anonymous 또는 "no authentication required" 같은 설명)가 없으면 public이 아니다. `/me`, `/user/...`처럼 경로 자체가 인증 사용자 본인으로 고정됨을 설명이 뒷받침하면 owner_match(G4).
- `kind: "code"` (gitea 핸들러 + 미들웨어 체인): 실제 허용·거부를 결정하는 조건을 찾는다. 미들웨어 주석 설명을 근거로 쓴다. 인증만(reqToken 등) 있고 객체·역할 조건이 없으면 보류 8(manual). reqOrgOwnership·reqOrgMembership·reqRepoWriter·reqAdmin·reqSiteAdmin 등은 아래 정의(그룹 안 역할 → role_required, 구성원 → membership_required)대로. 공개/비공개 저장소 가시성 분기(reqRepoReader·repoAssignment 가시성)만으로 허용이 갈리면 보류 4(manual). 본인 자원(/user/..., ctx.Doer 기준 처리)은 owner_match.

## 라벨 정의 v3.1 (test_v5·test_v6 정답 기준)

## 고정 라벨"·"## 보류가 필수인 경우"·"## 판단 절차"·"## 보안과 근거" 네 절의 교체 후보다. 예시·출력 절은 v3.0.1 그대로 둔다는 전제(예시 6종은 v3.1 정의와 충돌하지 않음). 반영 여부·시점은 사용자 결정 사항이며, 반영 시 test_v5·test_v30 정답은 바꾸지 않는다(정답은 이미 G1~G8 기준).

표기: 각 줄 끝 `[Gn]`은 근거 검수 규약, `[v3.0.1]`은 기존 문장 유지, `[변경]`은 v3.0.1 문장을 고친 곳, `[신설]`은 v3.0.1에 없던 문장.

## 고정 라벨

- public: 해당 요청은 인증 없이 누구나 접근 가능하다는 긍정 근거가 있다(익명 허용 코드, AllowAny, 로그인·토큰 갱신·회원가입·비밀번호 재설정 같은 인증 획득용 엔드포인트, 무인증 개발용 엔드포인트). [v3.0.1 + G7-a 신설] 코드 일부에 검사가 없거나 security가 unknown이라는 이유만으로 선택하지 않는다. 인증이 필요하면 public이 아니다. [v3.0.1] 익명이 web-public·공개 설정 등 조건부로만 허용되면 public이 아니라 manual_review_required다. [G7-b 신설] security 선언은 public을 막는 근거가 아니다: 코드가 인증 없이 처리함을 보이면 security 선언·mutation 여부와 무관하게 public이다. 코드 없이 OAS만 있을 때는 security 선언·mutation 제한을 그대로 적용한다. [변경 — v3.0.1 "security가 선언됐거나 … public 금지"와 "mutation 제한"을 OAS-only 조건으로 한정; G7-a]
- role_required: 특정 역할 보유가 실제 접근 조건이다. 인증 성공이나 API 키 요구만으로 선택하지 않는다. [v3.0.1] 역할은 전역 역할(admin, staff)뿐 아니라 그룹 안 역할(계정 administrator, 방 owner·moderator, 강좌 교사)을 포함한다. 그룹 안 역할 검사에 앞서 그룹 구성원 확인이 있어도 이는 AND 결합이 아니라 역할 검사의 전제이므로 role_required다. [G3-a 신설] 객체가 없는 기능에 RBAC 권한(permission) 검사만 있는 경우도 role_required다. 단, 그 권한을 모든 사용자 역할(스태프 역할)이 보유하면 역할 조건이 아니므로 manual_review_required다. 이 판단에서 통합·API 키·봇 같은 비사용자 주체는 제외한다. 역할 권한표만이 아니라 모델 수준 재정의(permissible 등)까지 합쳐 일부 역할이 실제로 거부되면 "모든 역할 보유"가 아니다. [G3-b + G6-c 경계 신설, 2026-11-03 수정]
- membership_required: 요청자가 해당 요청 대상 그룹·팀·방·계정·워크스페이스의 구성원이어야 한다. (requester_id, target_group_id) 관계나 동등한 구성원 조회가 근거다. 유료 플랜, 구독 등급, 같은 tenant, 팀 이름만으로는 선택하지 않는다. [v3.0.1] 대상 그룹은 요청(경로·본문·쿼리)이 지정해야 한다. [G2 신설] 구성원 OR 전역 관리자 우회가 있어도 membership_required다(owner_or_admin의 구성원 판 라벨은 없다). [G2-b 신설] 구성원 확인 뒤 그룹 안 역할이 결정 조건이면 role_required다. [G3-a 신설]
- tenant_match: 요청자 tenant와 대상 자원의 tenant가 같아야 한다. 특정 그룹 구성원 여부와 구분한다. 같은 tenant라도 그룹 비구성원일 수 있고, 그룹 구성원은 다른 tenant에 있을 수도 있다. [v3.0.1] 서버가 자원의 조직·워크스페이스·테넌트를 요청자의 현재 테넌트(세션·토큰의 active organization, API 키 tenant)와 비교하거나 그것으로 필터하며 경로·본문에 대상 테넌트 ID가 없는 경우다. [G1 신설] 라우트 RBAC 권한(checkPermission 등)이 함께 있어도 기능 권한으로 보고 tenant_match다. [G1-b 신설] 생성 요청에서 자원 테넌트를 요청자 테넌트로 강제하는 것도 포함한다. [G1-c 신설]
- owner_match: 요청자가 대상 객체 소유자 본인이어야 하거나, 처리 대상이 인증 사용자 본인으로 고정돼야 한다(/me, request.user, 본인 목록·설정·플래그·기기, 본인 명의 생성). [v3.0.1 + G4 신설] 반환 데이터에 owner 필드가 있다는 사실만으로 선택하지 않는다. [v3.0.1] 관리자 조건이 타인 대상 우회가 아니라 본인 대상의 설정 제한만 우회하면 owner_match다. 설정이 본인 분기 자체를 켜고 끄면(꺼지면 관리자만 가능) owner_match가 아니라 보류 5(manual_review_required)다. [G4-c·G6-b 구분 신설, 2026-11-03 수정] 본인 구독·본인 행만 변경하고 방 접근 판단이 없으면 owner_match, 방 비구성원을 거부하면 membership_required다. [정지 지점 1 신설]
- owner_or_admin: 소유자·당사자(작성자, 발신자/수신자, 관계 당사자) 허용 OR 관리자 우회가 실제 조건이다. 관리자도 소유자여야 하는 AND 조건은 이 패턴이 아니다. [v3.0.1 + G5 변경] 관리자 우회가 없으면 owner_match다. [G5 신설]
- manual_review_required: 근거 부족·모순·지원하지 않는 의미·독립 필수 조건 결합으로 6종 중 하나를 타당하게 선택할 수 없다. 자동 적용 제외·관리자 검토 대기다. [v3.0.1]

## 보류가 필수인 경우

다음에 해당하면 구체 라벨을 추측하지 않고 manual_review_required를 선택한다.

1. 구독·플랜·등급(premium, pro, paid tier 등)만 요구하는 조건. 이는 그룹 구성원 관계가 아니므로 6종으로 표현하지 못한다. [v3.0.1]
2. OAS(명세)만 있고 요청자와 대상 객체의 관계나 실제 접근 조건을 확인할 수 없는 경우. path에 객체 ID가 있다는 사실, 응답에 owner·tenant 필드가 있다는 사실, 자원 이름(my, me, admin 등)만으로 관계를 단정하지 않는다. 설명에 접근 조건이 명시돼 있으면 그 문장을 근거로 선택할 수 있다. [v3.0.1]
3. 서로 다른 유형의 두 독립 필수 조건이 AND로 결합된 경우(예: 같은 tenant AND 특정 그룹 구성원, 소유자 AND 특정 역할). 하나를 버려야 단일 라벨이 되면 보류한다. 다음은 AND 결합으로 보지 않는다: 그룹 구성원 확인 뒤 그룹 안 역할(→ role_required), tenant 필터와 기능 RBAC 권한(→ tenant_match), 인증과 하나의 객체 접근 조건. [변경 — G3-a·G1-b 예외 추가]
4. 서로 다른 유형의 조건이 OR로 분기하는 경우(공개/비공개 가시성에 따라 조건이 달라짐, 방 종류별로 다른 접근 함수, 쿼리 모드별·action별로 다른 정책). 소유자 OR 관리자(owner_or_admin), 구성원 OR 관리자(membership_required)는 예외다. [G6-a 신설]
5. 서버·조직 설정에 따라 허용 주체가 바뀌는 경우. 설정이 본인 분기 자체를 켜고 끄면(꺼지면 관리자만 가능) 여기에 해당해 manual이다. 관리자 조건이 본인 대상의 설정 제한만 우회하면 owner_match다(G4-c). [G6-b 신설, 2026-11-03 수정]
6. 코드 구현과 명시 정책 의도가 충돌하는 경우. [v3.0.1]
7. 코드가 모든 요청을 거부하거나, 접근 조건이 불완전·미확정으로 남아 있는 경우. [v3.0.1]
8. 인증만 확인하고 요청자-객체 관계나 역할 검사가 확인되지 않는 경우(객체 없는 기능 포함, 모든 사용자 역할이 보유한 권한 검사 포함; 통합·API 키 주체는 제외). [v3.0.1 + G6-c 변경, 2026-11-03 수정]

## 판단 절차

1. 해당 method와 대상 자원을 확인한다. 다른 엔드포인트의 정책을 가져오지 않는다. [v3.0.1]
2. 실제 허용·거부를 결정하는 조건을 찾는다. 입력 필드의 존재나 반환값은 검사 자체가 아니다. [v3.0.1]
3. 인증과 인가를 분리한다. 인증 + 하나의 객체 접근 조건은 인증 때문에 복합 인가로 취급하지 않는다. [v3.0.1]
4. OR와 AND를 그대로 보존한다. 두 독립 조건을 버려야 단일 라벨을 만들 수 있으면 보류한다. 예외는 보류 3·4에 적은 결합뿐이다. [변경]
5. 생성 요청(기존 객체 없음)은 대상이 본인 명의면 owner_match, 요청자 테넌트로 강제되면 tenant_match, 대상 그룹을 지정하고 구성원을 확인하면 membership_required, 역할·권한만 확인하면 role_required다. 그 외는 보류한다. [G1-c·G4-b 신설]
6. 코드의 구현과 명시적 정책의 의도를 구분한다. 서로 충돌하면 rationale에 적고 보류한다. 코드가 미확보되면 검사 누락이라고 단정하지 않는다. [v3.0.1]
7. 조건의 의미가 충분하면 고정 라벨을 선택하고, 부족하면 보류한다. confidence가 낮다는 이유만으로 사후 변환하지 않는다. [v3.0.1]

## 보안과 근거

security_state=declared는 인증 선언이지 특정 인가 라벨이 아니다. unknown은 공개 근거가 아니다. explicitly_anonymous는 현재 수집 규약의 명시 익명 상태다. public은 익명 허용 코드·명시 설명 등의 긍정 근거가 필요하다. [v3.0.1] mutation 제한은 코드가 없을 때 유지한다: 코드 없이 OAS만 있는 PUT/POST/PATCH/DELETE는 explicitly_anonymous일 때만 public을 허용한다. 코드가 인증 없이 처리함을 보이면 method·security 선언과 무관하게 public이다. [변경 — G7-a]

(이하 "schema_fields와 owner_cols/tenant_cols…", "코드가 description에 포함된 경우…" 두 문단은 v3.0.1 그대로.)

## 검수 규약 G1~G8 (원문)

## data-v4 검수 규약 (2026-10-28, review/v4_train_review_reviewed.xlsx·test_v31_supp_review_reviewed.xlsx '검수 규약' 시트 원문)

- **G1** (tenant_match): 서버가 자원의 조직·워크스페이스·테넌트를 요청자의 현재 테넌트(세션·토큰의 active organization, activeWorkspaceId, API 키 tenant)와 비교하거나 그것으로 필터. 경로·본문에 대상 테넌트 ID 없음. 라우트 RBAC 권한(checkPermission 등)이 함께 있어도 기능 권한으로 보고 tenant_match. 생성 시 자원 테넌트를 요청자 테넌트로 강제하는 것도 포함.
- **G2** (membership_required): 요청(경로·본문·쿼리)이 대상 그룹(account, workspace, organization, 채널, 강좌, 사용자 그룹)을 지정하고 (요청자, 그룹) 구성원 행을 조회해 허용. 구성원 OR 관리자 우회도 membership_required.
- **G3** (role_required): 전역 역할, 또는 그룹 구성원 확인 뒤 그룹 안 역할(계정 administrator, 그룹 moderator, 강좌 교사)이 결정 조건이면 role_required(기존 추출 규격 유지). 객체 없는 기능에 RBAC 권한만 있는 경우도 포함.
- **G4** (owner_match): 처리 대상이 인증 사용자 본인으로 고정(/me, request.user, 본인 목록·설정·플래그·기기, 본인 명의 생성) 또는 객체 소유자 == 요청자. 관리자 조건이 타인 대상 우회가 아니라 설정 우회일 뿐이면 owner_match.
- **G5** (owner_or_admin): 소유자·당사자(작성자, 발신자/수신자, 관계 당사자) OR 관리자 우회가 실제 조건. 관리자 우회가 없으면 owner_match.
- **G6** (manual_review_required): 서로 다른 유형의 조건이 OR로 분기(공개/비공개 가시성, Zulip access_message·access_stream_by_id, 쿼리 모드별·action별 정책), 조직 설정에 따라 허용 주체가 바뀜, 인증만 확인(객체 없음 포함). Zulip 채널 접근 함수는 membership_required로 일괄 라벨링하지 않는다.
- **G7** (public): 조건 없는 익명 허용만 public(AllowAny, 로그인·토큰 갱신, 무인증 개발용). 익명이 web-public 등 조건부로만 허용되면 manual_review_required.
- **G8** ((test 제외)): test에서는 두 label 사이 경계, 의도 정책 미확정, 의도·구현 충돌, 근거 코드가 발췌에서 누락된 건을 manual로 넣지 않고 제외한다(제외 사유 기록). manual은 G6처럼 보류가 확실한 경우만 넣는다.
- 비고: None
- 그룹 안 역할(계정 administrator, 그룹 moderator, 강좌 교사)은 G3대로 role_required(사용자 확인 2026-10-28: 지시문의 "그룹 한정 모더레이터 → manual"보다 G3 우선).

## test_v31_supp 검수 규약 (원문)

## test_v31_supp 검수 규약 (2026-10-28 사용자 확정)

- Chatwoot account_id 경로 + account_users 확인 → membership_required
- Flowise 활성 워크스페이스 필터 → tenant_match. 워크스페이스 지정 + 구성원 확인 3건 중 쿼리 모드별 정책이 다른 GET /workspace·GET /workspaceuser 2건은 검수 결과대로 manual_review_required(사용자 확인), membership_required는 1건.
- 구성원 OR 관리자 우회 → membership_required
- 보낸이/받는이 검사: 관리자 우회 있으면 owner_or_admin, 없으면 owner_match
- 그룹 안 역할은 G3(role_required), 전역 역할 → role_required
- 의도 불명확·근거 약한 건은 manual로 넣지 말고 test에서 제외(G8). 제외 목록 datasets/blade/processed/data_v4/test_v31_supp_excluded.jsonl(41건, 사유 포함).
- 검수자: Claude(AI) — 근거 열(코드 발췌·advisory·수정 커밋)만으로 판단, 저장소 직접 확인 없음. 사람 표본 확인 시트 review/test_v31_supp_spotcheck.xlsx(CHANGED 6 + label별 무작위 4, seed 42)는 학습·평가를 막지 않는다.
- 평가: eval-def v2의 별도 조건(보조 구간). 주지표(test_v30 oas_code 합성 제외 207건)는 그대로다. 보고서에 label별 표와 프로젝트별 표를 함께 싣는다(label이 프로젝트에 몰려 있음).
- 코드 본문 비공개: Flowise(enterprise/ 상용 라이선스)·라이선스 미선언 출처(multitenant lab, Generic University)가 든 test 파일은 .gitignore. 공개 시 코드 본문 제외, 링크·커밋만 제공(test_v31_supp_manifest.json).

## test_v6 검수 규약 보충 (원문)

- **test_v6 검수 규약 보충**(G1~G8과 test_v5 선례에서 도출, 사용자 확정 2026-11-03):
  1. Redash `current_org` 필터(`get_by_id_and_org(id, self.current_org)`, `current_org` 목록 필터) → tenant_match(G1, Flowise 선례). 프로젝트별 한 label 상한 50%. **(2026-11-03 정지 지점 2 결정, G1-b)** `@require_admin`은 `require_permission("admin")`(permissions.py:86-87)이고 `User.permissions`는 요청자 그룹(Group.org_id로 조직 귀속, ADMIN_PERMISSIONS=["admin","super_admin"] users.py:261)의 권한 합(users.py:173-175)이라 `require_permission`과 같은 조직 그룹 권한 메커니즘이다 → `get_by_id_and_org`/`current_org`와 함께면 tenant_match. `@require_super_admin`(handlers/admin.py 시스템 상태 등 조직 횡단) → role_required.
  2. Redash `require_object_modify_permission`(owner OR admin OR ACL 공유) → manual_review_required(G6, test_v5 Umami canUpdateWebsite 선례). `require_admin_or_owner` → owner_or_admin(G5). `require_access`(데이터소스 그룹 ACL) → manual(G6). **seahub `is_repo_admin` 단독 검사(share/utils.py:39-73: 소유자 OR ACL 공유 관리 권한 OR 부서 관리자)도 같은 구조로 manual(G6) — 2026-11-03 정지 지점 2 결정.**
  (정지 지점 2 결정 2026-11-03) 3.1 Penpot은 5b 유지: read 명령 48건(`get-read-permissions` OR 조직 소유자 경로)은 투입하지 않는다(보조 파일 `data/raw_v6/penpot/candidates_5b_excluded.jsonl`은 조립 미사용). 근거: v3.1 보류 5(설정 의존 → manual), test_v5 resetAvatar 선례, 플래그 기본값이 입력 코드 밖(nitrate.clj)에 있어 모델이 볼 수 없음. Penpot membership 0은 한계로 기록. 대신 seahub 상한을 93 → 최대 110으로 올려 `is_group_member` 엔드포인트에서 membership_required 15건 이상을 보충한다(다른 label 상한·중복 대조 규칙 동일).
  3. seahub `check_folder_permission`: seaf-server RPC(외부 권한 합산)만이면 manual(G6), `is_group_member` 선행 검사가 있으면 membership_required(G2).
  4. seahub org 관리 API(org_admin + `request.user.org.org_id` 필터) → tenant_match(G1).
  5. Penpot `share-id` 겸용 조회(구성원 OR 공유 링크) → manual(G6). `get-organization-owner-permissions` OR 경로가 있는 명령 → EXCLUDE(플래그 의존).
  6. GlitchTip `has_permission`(토큰 스코프)은 근거에서 제외한다. `get_organizations_queryset`(구성원 필터)·`actor_role`만 근거. `open_membership` 설정 분기 → manual(G6).
  7. (Wekan 쟁점은 제외로 소멸)
  8. 근거 부족·경계 → EXCLUDE(G8) 유지. 사유별 제외 건수를 보고하고 **제외율 10% 초과 시 멈추고 보고**한다.

## 정지 지점 결정 (원문)

- 정지 지점 1 결정(2026-10-31): test_v5 296건 전 건 검수, 시트 변경 없음. 검수 판단 통일(시트 '검수 규약' 탭에 추가): Rocket.Chat 본인 구독 변경은 방 비구성원 거부 시 membership_required·본인 행만 변경 시 owner_match·애매하면 EXCLUDE, canAccessRoom 17건 manual(G6), Ghost POST /posts·/pages EXCLUDE(생성 요청), Umami 팀 관리 role_required(G3)·웹사이트 수정·삭제 manual. 보고서 한계 절에 membership_required의 Rocket.Chat 편중(26/31)과 tenant_match 없음을 기록한다.
- **정지 지점 3 결정(2026-10-31)**: 검수 완료본 review/v5_train_review_reviewed.xlsx(90건, 시트 열 기준 일치 86/90). 규칙 수정 후 416건 전체 재적용: (a) G5_owner_with_superuser_bypass는 대상을 경로 ID로 조회해 소유자 비교(IsTheSameUser 등)할 때만 owner_or_admin이고, 대상이 request.user로 필터되거나 생성 요청이면 owner_match(G4) — Taiga 10건 변경; (b) Dendrite 핸들러에 power level 검사가 없고 event auth에 의존하는 건(send 2·invite·unban·state PUT 2)은 라벨하지 않고 제외; (c) 구성원 확인 뒤 "power level OR 본인 대상"(Dendrite kick)은 NodeBB 채팅 추방과 같이 제외. 라벨 416→412, 수정 규칙 기준 검수 일치율 88/88(제외로 바뀐 2건은 분모 제외). 보강분 manual은 10% 쿼터(구체/9=33건, 하위 유형별 비율 유지, seed 42), Taiga history 댓글 계열 owner_or_admin은 자원 종류당 2건(20→10, seed 42). 보강분 328건(manual 10.06%), 쿼터·축소 제외 84건은 data_v5/train_v5_pool.jsonl. NodeBB(GPL-3.0) 코드 본문이 든 파일은 .gitignore이고 공개는 data_v5/train_v5_manifest.json(id·저장소·커밋·링크·label)만(DATA_CARD 명시). data-v5 동결(정지 지점 4)은 test_v5 동결(정지 지점 2) 뒤에만 한다.

## data-v2 라벨 기준(gitea 관련, 원문)

## data-v2 라벨 기준 (2026-10-23, 검수_집계 시트 판정 기준 4줄 그대로)

- test_v30 정답은 "의도된 정책" 기준: 본인 리소스(/user/..., Doer 기준 처리)는 owner_match (test의 /user/dashboard·change-email 등과 동일)
- 저장소 권한 레벨(쓰기·admin)은 role_required, org/팀 멤버십은 membership_required로 처리
- 공개/비공개 저장소 분기(repoAssignment·reqRepoReader·reqAnyRepoReader)는 manual(VIS)
- reqToken만 있고 객체가 없는 엔드포인트는 7종에 맞는 label이 없어 manual(AUTH_ANY)

- VIS+SELF: 요청자가 데이터 범위(본인 star·watch·구독·stopwatch·알림)이면 owner_match, 요청자가 행위자(댓글·머지·리뷰·릴리스·이전·생성·실행)이면 manual
- 인가 검사가 코드에서 빠졌어도 경로·스키마로 의도된 정책이 드러나면 그 정책을 label로 한다(test_v30 취약 API와 동일). 외부 인가처럼 의도를 코드로 확인할 수 없는 경우만 manual.
- 적용 기록: reports/review_v2_r1.md, reports/review_v2_r2.md, reports/review_v2_r3.md, train_v2_draft_r1.jsonl(meta.v2_relabel). 검수 52건은 rule_id=human_review_v2.
