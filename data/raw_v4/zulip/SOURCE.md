# Zulip (zulip/zulip) — data-v4 학습용 후보 추출

- 저장소: https://github.com/zulip/zulip
- 고정 태그/커밋: `12.3` / `b31982251ff82d0b02e59f63ad21f19204e37aea` (커밋 일자 2026-09-22; `gh api repos/zulip/zulip/releases/latest` = 12.3)
- 로컬 clone: `datasets/blade/raw/opensource/zulip_zulip` (`--depth 1 --filter=blob:none --sparse`, non-cone sparse: 루트 파일 + `zproject/`, `zerver/`(tests·webhooks 제외), `zilencer/`(tests 제외)). git 추적 대상 아님.
- 라이선스: Apache-2.0 (SPDX `Apache-2.0`). `LICENSE` = Apache License 2.0 원문. `NOTICE`: "Copyright 2012–2015 Dropbox, Inc., 2015–2021 Kandra Labs, Inc., and contributors"; 제3자 저작물은 각자 라이선스(docs/THIRDPARTY). Mattermost(AGPL) 대체 프로젝트.
- 용도: 학습 데이터(data-v4) 후보. draft_label / draft_confidence / evidence / draft_reason / known_vulnerable / advisory / fix_commit은 넣지 않았다(이후 별도 LLM 라벨링 단계).

## 추출 방법

`data/raw_v4/zulip/extract_zulip.py`(정적 분석만: `yaml.safe_load` + `ast`; clone 코드 import·실행 없음, LLM 호출 없음).

1. OAS: `zerver/openapi/zulip.yaml`의 모든 operation(161개). 명세 path는 `/api/v1` 기준 상대 경로라 실제 요청 경로 `/api/v1` + path로 기록. `oas_operation`에는 operationId, summary, description(원문), tags, parameters(`$ref` 해석 후 name/in/required/schema type), requestBody(콘텐츠 타입별 속성 이름·타입·required), responses(코드별 description), `x-requires-administrator`/`x-requires-owner` 확장 플래그(있는 경우)를 넣었다. 전역 security `[{"basicAuth": []}]`와 `components.securitySchemes`(`BasicAuth`: email + API key)는 `oas_global_security`/`oas_security_schemes`에 그대로 넣었다(명세 원문의 대소문자 불일치 그대로).
2. `permission_doc`: operation description 중 권한·역할·구독·조직 설정·인증 관련 문장(원문 그대로). `**Changes**` 단락과 링크 정의 줄은 제외. 해당 문장이 없으면 "".
3. 라우트: `zproject/urls.py`(`v1_api_and_json_patterns`는 `/api/v1/`와 `/json/` 둘 다에 마운트, `v1_api_mobile_patterns`, uploads/avatar 블록), `zproject/tornado_urls.py`(events), `zproject/dev_urls.py`(dev_fetch_api_key, dev_list_users), `zilencer/urls.py`(remote_server_path)를 AST로 읽어 method → view 함수를 매핑.
4. `controller_text`: 라우트 정의 블록 + view 함수(데코레이터 포함) + view가 호출하는 인가 헬퍼 본문(access_*, check_*can/permission/..., validate_*, can_*, has_*permission/access, user_has_permission_for_group_setting, require_* 데코레이터 본문, UserProfile 메서드 등; import를 따라 정의를 찾고 최대 3단계까지) + 같은 views 모듈의 하위 view(`*_backend`) + `user_profile`을 받는 lib/actions 함수(소유자 범위 쿼리 근거, 최대 4개). `allow_anonymous_user_web` 플래그 라우트에는 `zerver/lib/rest.py` `rest_dispatch`의 익명 분기 발췌를 함께 넣었다. 블록 사이 빈 줄 하나, 경로·줄 번호·설명 주석을 새로 쓰지 않음(위치는 `source_locations`).
   - 3,000자 상한. 길면 문장(AST statement) 단위로 인가 관련 문장(raise, access_/check_/can_/permission, is_realm_admin/owner/moderator/guest, realm 범위, Subscription 조회 등)과 그 상위 블록 헤더(if/for/try/with)를 남기고 나머지를 `...`로 줄였다. 단계(전체 → AUTH → STRICT → VSTRICT → ULTRA)를 두고, view를 최소 단계로 넣은 뒤 헬퍼를 우선순위(access_/require_ > check_/validate_/can_ > 기타 > get_) 순으로 넣고 남는 길이로 다시 덜 줄인 단계로 올린다.
   - 길이 분포: 최소 275, 최대 3,000, 평균 약 2,080자.
5. `auth_summary`: 사람용 한 줄 요약(자동 생성: 데코레이터, 호출한 인가 헬퍼, 코드 안 검사 토큰 — is_realm_admin/is_realm_owner/bot_owner/can_admin_user/realm scoping/query scoped to requester 등, OAS x-requires-*). 정답 라벨이 아니다.
6. `response_schema_fields`: 2xx 응답 JSON 스키마의 최상위 속성 이름(allOf/oneOf 병합).

## 인증·인가 구조 요약

- 인증: 모든 REST 경로는 `rest_path` → `zerver/lib/rest.py::rest_dispatch`. `/api/...`는 HTTP Basic(email:API key, `authenticated_rest_api_view`), `/json/...`는 세션(`authenticated_json_view` + CSRF). 그 외는 `MissingAuthenticationError`. `allow_anonymous_user_web` 플래그가 있는 view만 `/json`, `/avatar`, `/user_uploads`, `/thumbnail` 경로에서 익명(spectator, `public_json_view`) 허용 — **`/api/v1` 경로에서는 익명 불가**(코드 주석 "TODO: Allow /api calls"). 익명 허용 view는 보통 `realm.allow_web_public_streams_access()`와 web-public 채널로 범위를 제한한다.
- 테넌트: 사용자(UserProfile)는 한 realm(조직, 서브도메인)에 속하고, 대부분의 조회가 `user_profile.realm`으로 필터된다(`get_stream_by_id_in_realm`, `get_user_profile_by_id_in_realm`, `access_stream_common`의 realm_id 비교 등).
- 역할 데코레이터(`zerver/decorator.py`): `require_realm_admin`, `require_realm_owner`, `require_non_guest_user`, `require_human_non_guest_user`, `require_user_group_create_permission`, `check_if_user_can_manage_default_streams`, `require_bot_user`, `human_users_only`, `require_billing_access`.
- 채널(stream) 접근: `zerver/lib/streams.py` `access_stream_by_id`/`access_stream_by_name` → `access_stream_common` → `check_basic_stream_access`(구독 여부, 공개/비공개·history 정책, 관리자 메타데이터 접근, 그룹 기반 권한 can_administer_channel_group/can_add_subscribers_group/can_subscribe_group). 메시지: `zerver/lib/message.py` `access_message` → `has_message_access`; 편집/삭제는 `validate_user_can_edit_message`(작성자), `check_stream_topic_edit_permissions`, `validate_can_delete_message`(작성자 + 조직 정책 / can_delete_any_message 그룹).
- 사용자·봇: `zerver/lib/users.py` `access_user_by_id`(같은 realm, `for_admin`이면 `can_admin_user`), `access_bot_by_id`(`can_admin_user` = 봇 소유자 또는 realm 관리자; can_create_users 봇은 owner 필요), `check_can_access_user`(can_access_all_users_group).
- 사용자 그룹: `zerver/lib/user_groups.py` `access_user_group_for_update`(can_manage_all_groups 또는 그룹별 can_manage_group/can_add_members_group/can_join_group 등 그룹 설정), `access_user_group_to_read_membership`.
- 그룹 기반 권한 설정: `user_has_permission_for_group_setting`, `UserProfile.has_permission(<realm 그룹 설정>)`(can_invite_users_group, can_create_public_channel_group 등). 구독(subscription)은 채널 구성원 관계다.
- push bouncer(`zilencer`): `remote_server_path` → `authenticated_remote_server_view`(원격 Zulip 서버 UUID + API key).

## 범위와 제외

- 후보 193건 = 명세(repository_spec) 158건 + 라우트에서 생성(generated) 35건.
- 명세 operation 161개 중 제외 3개(실제 엔드포인트 아님):
  - `POST /real-time`: 실시간 이벤트 API 개요용 문서 pseudo path(operationId 없음, 라우트 없음).
  - `POST /rest-error-handling`: 공통 오류 응답 설명용 문서 pseudo path.
  - `POST /zulip-outgoing-webhook`: Zulip이 outgoing webhook 봇에 보내는 payload 설명(Zulip이 서비스하는 엔드포인트 아님).
- 이벤트 큐(`GET /events`, `DELETE /events`)는 큐 소유자 검사(`access_client_descriptor`)가 있어 포함. `GET /api/v1/events/internal`, `api/internal/*`(Tornado·tusd 내부 통신)은 OAS에 없고 공유 비밀 기반 내부 API라 제외.
- generated(명세에 없는 `rest_path`): `PATCH /api/v1/realm`, realm icon/logo, realm profile_fields/{field_id}, realm/deactivate, bots(목록·생성·수정·비활성화), zcommand, messages/summary, submessage, users/me/avatar, users/me/onboarding_steps, default_stream_groups/*, calls/zoom/create, export/realm/{export_id}, 그리고 api prefix 없는 `/user_uploads/...`, `/thumbnail`, `/avatar/...`, `/json/fetch_api_key`. 이들의 `oas_operation`은 view 함수 이름·docstring·경로 파라미터로만 구성(parameters 외 requestBody/responses 없음).
- generated에서 제외: `PATCH /api/v1/settings/display`, `PATCH /api/v1/settings/notifications`(`intentionally_undocumented` 별칭; `PATCH /settings`와 같은 view), `/json/self-hosted-billing`(corporate 결제), zilencer의 나머지 bouncer API(서버 간 통신, 명세에 없음), HTML 페이지·로그인·가입·OAuth·웹훅(`path()` 기반, REST 아님), dev 전용 HTML 도구.
- 문서화된 `path()` 기반 엔드포인트(`/fetch_api_key`, `/jwt/fetch_api_key`, `/dev_fetch_api_key`, `/dev_list_users`, `/server_settings`)는 rest_dispatch 인증 없이 동작하는 로그인·서버 정보 API라 포함(view 본문만 발췌).

## 알려진 한계

- `PATCH /api/v1/realm`(update_realm, 원본 약 21,000자)과 `PATCH /api/v1/streams/{stream_id}`(update_stream_backend, 약 10,800자)는 가장 강하게 줄여도 3,000자를 넘어 줄 경계에서 잘랐다(끝 `...`). 뒤쪽 인가 줄 일부가 빠졌다. 두 건은 선정 시 주의.
- `POST /api/v1/messages`, `PATCH /api/v1/messages/{message_id}`처럼 인가가 깊은 action 함수(`check_message`, `check_update_message`)에 있는 경우 일부 하위 헬퍼(예: `access_stream_for_send_message`, `check_can_send_direct_message`)가 길이 때문에 빠졌다.
- `auth_summary`는 규칙 기반 자동 요약이라 잡음이 있다("authenticated user only ... no explicit authorization check found in view"는 view 본문에 명시 검사가 보이지 않는다는 뜻이며, lib 함수의 `user_profile=` 필터는 `query scoped to requester`로 표시).
- Zulip API는 같은 view가 `/api/v1`와 `/json` 양쪽에 있다. 후보는 `/api/v1` 경로만 기록했다(익명 허용 플래그는 `/json`에서만 효과).

## 건수(대략적 auth_summary 분류, 자동)

| 분류 | 건수 |
|---|---:|
| admin-only (require_realm_admin/owner, x-requires-*, default stream 관리) | 42 |
| subscription/membership (access_stream_*, 사용자 그룹 접근, 구독) | 19 |
| sender-or-admin / message access (access_message, 편집·삭제·반응) | 13 |
| owner-or-admin (봇 소유자 또는 관리자, can_admin_user) | 17 |
| self (/users/me, drafts, saved_snippets, reminders, scheduled_messages 등) | 50 |
| anonymous/public (allow_anonymous_user_web, 로그인 API) | 18 |
| role/org-setting (그룹 기반 조직 설정) | 7 |
| other | 27 |
| 합계 | 193 |

## 산출 파일

- `candidates.jsonl` — 193줄(EXTRACTION_SPEC 필드).
- `SOURCE.md` — 이 문서.
- `extract_zulip.py` — 추출 스크립트(인자: 커밋 SHA, 태그).
- `_extract_log.json`, `_candidates_debug.jsonl` — 보조 기록(제외 목록, 매핑된 view, 포함/생략 헬퍼, 자동 분류). 학습 입력 아님.
