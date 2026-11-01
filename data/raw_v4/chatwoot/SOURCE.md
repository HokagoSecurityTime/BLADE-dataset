# chatwoot — test_v31_supp 추출 출처

- 저장소: https://github.com/chatwoot/chatwoot
- 고정 태그/커밋: `v4.19.1` (GitHub latest release, 2026-10-24 게시) / `caab07a8f00032d5205b5a5d7e2eb0ba2f3d2d82`
- 로컬 clone: `datasets/blade/raw/opensource/chatwoot_chatwoot/` (`git clone --depth 1 --filter=blob:none --branch v4.19.1`, git 추적 대상 아님)
- 분석 방식: 정적 읽기만 했다. 빌드·실행·의존성 설치·테스트 실행 없음. LLM API 호출 없음.

## 라이선스

- SPDX: `MIT` (enterprise/ 밖 코드). LICENSE 요지: "Copyright (c) 2017-2026 Chatwoot Inc." `enterprise/` 아래 코드는 `enterprise/LICENSE`(별도 상용 라이선스)를 따르고, 제3자 구성요소는 각자의 라이선스를 따른다. 그 밖의 코드는 MIT Expat이다.
- `enterprise/` 아래 코드는 읽지도 인용하지도 않았다. 모든 발췌는 MIT 범위(`app/`, `config/routes.rb`, `swagger/`)에서 가져왔다.

## 추출 범위

- 명세: `swagger/swagger.json`(OpenAPI 3.1.0, `servers: https://app.chatwoot.com/`). 명세에 있는 operation은 `oas_status=repository_spec`(63건)이다. path·path 수준 parameters의 `$ref`는 풀었고, 요청·응답 본문은 원문 그대로(`$ref` 포함) 두었다. `response_schema_fields`는 200/201 응답 schema의 최상위 properties다(`$ref`, `allOf`, array items를 따라감). 명세에 전역 `security`가 없어서 `oas_global_security=[]`이고, operation마다 security를 선언한다.
- 명세에 없는 엔드포인트는 `config/routes.rb`와 컨트롤러 코드로 operation을 만들었다(`oas_status=generated`, 23건). 인증 요구는 Api::BaseController를 근거로 `userBearerAuth`/`userApiKey`로 적었다.
- 코드: `app/controllers/api/v1/accounts/**`, `app/controllers/api/v1/{accounts,profiles}_controller.rb`, `app/controllers/api/v2/accounts/{reports,summary_reports}_controller.rb`, `app/controllers/platform*`, `app/controllers/public/api/v1/**`, `app/controllers/concerns/{ensure_current_account_helper,label_concern}.rb`, `app/policies/**`, 그리고 인가 범위를 정하는 모델·서비스 메서드(`User#assigned_inboxes`, `Macro.with_visibility`, `Conversations::PermissionFilterService`, `ConversationFinder#set_inboxes/find_all_conversations`, `SearchService` 일부, `NotificationFinder#initialize`)다.

## 인증·인가 구조

- 인증: `ApplicationController`(DeviseTokenAuth `SetUserByToken`, Pundit), `Api::BaseController`(`authenticate_access_token!`/`validate_bot_access_token!`은 access token일 때, 그 밖에는 `authenticate_user!`).
- 계정 범위: `Api::V1::Accounts::BaseController`의 `before_action :current_account`에서 `EnsureCurrentAccountHelper#ensure_current_account`를 호출한다. 이 메서드는 path의 `account_id`로 `Account.find`를 하고 `account_accessible_for_user?`에서 `account.account_users.find_by(user_id: current_user.id)`를 조회한다. 행이 없으면 401이다. 조회한 행은 `Current.account_user`로 저장된다. agent bot 토큰이면 `account_accessible_for_bot?`(bot.account_id 일치 또는 agent_bot_inboxes)를 쓴다. 토큰 호출이면 `validate_token_api_access`(계정의 API 사용 기능 플래그)도 검사한다.
- Pundit: `pundit_user = {user, account, account_user}`. `Api::BaseController#check_authorization`은 `authorize(controller_name.classify)`, `check_admin_authorization?`는 `Current.account_user.administrator?`다. OSS 계정 역할은 `administrator`와 `agent` 두 가지다. 정책 클래스: AccountPolicy, UserPolicy, AgentBotPolicy, ContactPolicy, ConversationPolicy, InboxPolicy, LabelPolicy, TeamPolicy, TeamMemberPolicy, CustomFilterPolicy, CustomAttributeDefinitionPolicy, MacroPolicy, PortalPolicy, ArticlePolicy, CategoryPolicy, WebhookPolicy, HookPolicy, ReportPolicy, CampaignPolicy, CsatSurveyResponsePolicy, DashboardAppPolicy, DataImportPolicy, AutomationRulePolicy 등.
- 대화 접근: `ConversationPolicy#show? = administrator? || agent_bot? || inbox_access? || team_access?`. `inbox_access?`는 `user.inboxes`(inbox_members), `team_access?`는 `user.teams`(team_members)다. inbox 접근은 `InboxPolicy#show?`가 `Current.user.assigned_inboxes.include?`로 검사하며, `assigned_inboxes`는 administrator면 계정의 모든 inbox, agent면 자신이 구성원인 inbox다.
- Platform API: `PlatformController`가 `set_platform_app`(토큰 소유자가 PlatformApp인지)과 `validate_platform_app_permissible`(`platform_app_permissibles`에 대상 자원이 있는지)을 검사한다.
- Public client API: `PublicController`는 사용자 인증이 없다. inbox `identifier`와 contact `source_id`로 대상을 찾고, inbox 설정에 따라 HMAC을 검증한다.
- 여러 정책·컨트롤러가 `prepend_mod_with`로 enterprise 확장(custom role 등)을 붙인다. enterprise 코드는 범위 밖이라 OSS 동작 기준으로 라벨을 붙였다. enterprise 전용 라우트(`if ChatwootApp.enterprise?`: reporting_events, audit_logs, captain, sla, custom_roles 등)는 명세에 있어도 제외했다.

## 라벨 판단 규칙 (일관 적용)

1. **membership_required**: `/api/v1/accounts/{account_id}/...`에서 거부를 결정하는 조건이 path 계정의 구성원 관계 `(user_id, account_id) ∈ account_users`이고 정책이 계정 안 역할을 가리지 않는 경우다. 정책 값이 `true`이거나 `administrator || agent`(OSS의 두 역할 전부)인 경우가 여기에 든다. 사용자는 여러 계정에 속할 수 있고 path로 대상 계정을 고르므로, 이것은 "요청자에게 고정된 tenant와 자원 tenant의 비교"(tenant_match)가 아니라 대상 그룹 구성원 조회로 판단했다. `Current.account.<연관>.find`로 범위를 좁히는 것은 같은 계정 경계의 결과로 보고 별도 조건으로 세지 않았다. agent에게 inbox·team 구성원 관계가 결정 조건인 엔드포인트(대화 단건·하위 자원, inbox show 등)도 membership_required로 했다. 다만 administrator 우회(OR)가 있어 confidence를 0.6~0.75로 낮췄다.
2. **role_required**: 계정 구성원 확인 뒤 정책이 `@account_user.administrator?`를 요구하는 경우다. 규격의 "그룹 안 역할이 핵심이면 role_required"를 따랐다.
3. **owner_match**: `Current.user`/`current_user` 범위로만 조회하는 경우(custom_filters, notifications, notification_settings, profile)다. Platform/Public 일부도 낮은 confidence로 owner_match를 붙였다.
4. **manual_review_required**: 매크로처럼 global/personal 공개 범위에 따라 조건이 갈리는 경우다.
5. **tenant_match**: 위 1번 규칙 때문에 0건이다. Chatwoot OSS에는 "요청자가 한 테넌트에 고정되고 자원 tenant 키와 비교"하는 구조가 계정 API에 없다. `DataImportPolicy#show?`의 `record.account_id == account.id`가 유일하게 명시된 tenant 비교인데, administrator 조건과 AND로 묶여 있어 role_required(0.7)로 두고 검수를 요청했다.
6. **owner_or_admin**: 0건이다. OSS 정책 중 "작성자 OR 관리자"를 OR로 구현한 곳이 없다. MacroPolicy는 global이면 관리자, personal이면 작성자만 허용하는 분기 구조여서 OR가 아니다. contact notes와 messages 삭제는 작성자 검사가 아예 없다.

## Advisory 확인

`gh api repos/chatwoot/chatwoot/security-advisories`(공개 advisory 4건)로 확인했다.
- GHSA-x288-jh8j-348c (CVE-2026-72719, medium): account_id 파라미터로 Portal·Automation Rule·Macro·Twilio 채널을 다른 계정에 이전할 수 있었음. 4.9.0에서 패치.
- GHSA-8qxm-4p4p-cfhm (CVE-2026-44707): 미확인 계정의 OAuth 사전 탈취. 4.13.0에서 패치.
- GHSA-9pgm-75gg-6948 (CVE-2026-44706, high): Conversation/Contact filter 커스텀 속성 SQLi. 4.11.2에서 패치.
- GHSA-g8f9-hh83-rcq9 (CVE-2025-21628, critical): filter blind SQLi. 3.16.0에서 패치.

모두 고정 태그 v4.19.1 이전에 패치됐으므로 전 후보 `known_vulnerable=false`, `advisory=null`이다. GHSA-x288은 관련 엔드포인트(PATCH automation_rules/portals)의 evidence에 참고로 넣었다.

## 제외한 범위와 이유

- `enterprise/` 전체: 라이선스가 다르고 작업 지시상 제외 대상이다. enterprise 전용 라우트도 같은 이유로 뺐다.
- Super Admin(`/super_admin`), devise 인증 라우트, webhook 수신(`/webhooks/*`), widget API(`/api/v1/widget`), OAuth 콜백 컨트롤러: 계정 인가 패턴과 관련이 적거나, 외부 서명·토큰 검증이 중심이다.
- 같은 정책 메서드를 공유해 중복이 되는 변형 중 일부(role_required 다수, 대화 하위 POST 일부)는 목표 건수(60~90)에 맞추려고 뺐다. membership_required/owner 계열을 우선 남겼다.

## 건수

- 후보 86건: repository_spec 63, generated 23.
- draft_label: membership_required 50, role_required 14, owner_match 16, manual_review_required 5, public 1, tenant_match 0, owner_or_admin 0.
