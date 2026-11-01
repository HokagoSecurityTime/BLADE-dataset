# data-v4 / test_v31_supp 추출 규격 (2026-10-27)

모든 프로젝트 추출 에이전트가 같은 형식으로 `data/raw_v4/<project>/`에 산출한다. 조립(중복 제거·레코드화·라벨링·검수 시트)은 별도 스크립트가 한다.

## 공통 제약

- 저장소는 `datasets/blade/raw/opensource/<owner>_<repo>/`에 얕게 clone(`--depth 1 --filter=blob:none`, 필요하면 sparse-checkout)하고 고정 커밋 SHA를 기록한다. 이 폴더는 git 추적 대상이 아니다.
- 저장소 코드는 **읽기만** 한다. 수정·빌드·실행·의존성 설치·테스트 실행 금지(정적 분석만).
- 네트워크는 git clone, GitHub API(`gh api`), advisory·커밋 페이지 조회만 쓴다. LLM API(OpenAI 등) 호출 금지.
- 자기 프로젝트 외 다른 프로젝트 폴더, `datasets/blade/processed/`의 test 파일(test_v30 등)은 읽지 않는다. (중복 대조는 조립 단계에서 한다.)
- BLADE 저장소의 다른 파일을 수정하지 않는다. 쓰기는 `data/raw_v4/<project>/`와 clone 폴더만.

## 산출 파일

1. `data/raw_v4/<project>/candidates.jsonl` — 엔드포인트(OAS operation) 1건 = 1줄.
2. `data/raw_v4/<project>/SOURCE.md` — 저장소 URL, 고정 커밋/태그, 라이선스(SPDX와 LICENSE 파일 요지), 추출 범위, 인증·인가 구조 요약(미들웨어·정책 클래스·권한 함수 이름), 제외한 범위와 이유, 건수.

## candidates.jsonl 필드

```json
{
  "project": "chatwoot",                       // 폴더 이름과 같은 키
  "service": "Chatwoot",                       // 서비스 표시 이름
  "repository": "https://github.com/chatwoot/chatwoot",
  "commit": "<40자리 SHA>", "tag": "<태그 또는 null>", "license": "MIT",
  "method": "GET",
  "path": "/api/v1/accounts/{account_id}/conversations/{conversation_id}",   // OAS 형식 {param}, 서버 prefix 포함한 실제 요청 경로
  "oas_status": "repository_spec" | "generated",   // 저장소 명세에서 왔으면 repository_spec, 라우트·코드에서 만들었으면 generated
  "oas_operation": { "operationId": "...", "summary": "...", "description": "...",
                      "parameters": [{"name": "account_id", "in": "path", "required": true, "schema": {"type": "integer"}}],
                      "requestBody": {...선택...}, "responses": {"200": {"description": "..."}}, "security": [...선택...] },
  "oas_global_security": [{"userApiKey": []}],   // 명세 전역 security(없으면 [])
  "oas_security_schemes": {...},                 // components.securitySchemes(없으면 {})
  "response_schema_fields": ["id", "account_id", "assignee_id"],   // 응답 스키마 최상위 필드 이름(있으면)
  "controller_text": "...",                     // 아래 '코드 발췌' 규칙
  "source_locations": [{"file": "app/controllers/...rb", "start_line": 10, "end_line": 42}],
  "auth_summary": "before_action :check_authorization → ConversationPolicy#show? (inbox member 또는 administrator)",   // 사람용 요약
  "permission_doc": "...",                      // 문서·명세에 적힌 권한 문구 원문(있으면, 없으면 "")
  // ---- 평가 추가분(test)만 ----
  "draft_label": "membership_required", "draft_confidence": 0.8,
  "evidence": [{"type": "code" | "doc_permissions" | "advisory" | "fix_commit", "text": "인용 원문", "location": "파일:줄 또는 URL"}],
  "draft_reason": "사람 검수용 설명(한국어). 학습 target에 쓰지 않는다.",
  "known_vulnerable": false, "advisory": null, "fix_commit": null
}
```

## 코드 발췌(controller_text) 규칙

- 해당 엔드포인트의 라우트 정의(미들웨어/데코레이터/before_action 체인) + 핸들러 함수 본문 + 핸들러가 호출하는 인가 함수·정책 메서드 본문을 원문 그대로 이어 붙인다. 블록 사이는 빈 줄 하나.
- 파일 경로·줄 번호·설명 주석을 발췌 안에 새로 쓰지 않는다(위치는 source_locations에). 원문에 있던 주석은 그대로 둔다.
- 길이 500~2,000자 권장, 최대 3,000자. 길면 인가와 무관한 본문(직렬화·응답 조립 등)을 `...`로 줄인다. 인가 관련 줄은 절대 자르지 않는다.
- 인가가 전역 미들웨어·베이스 클래스에 있으면 그 부분을 함께 넣는다.

## 라벨 정의 (프롬프트 v3.0.1과 BLADE 규약, 요약)

정의 원문: `training/data/prompts/policy_label_v3.0.1.md`의 '고정 라벨'·'보류가 필수인 경우' 절을 먼저 읽는다. 추가 규약(AGENTS.md):

- `public`: 익명 접근 허용이 긍정적으로 드러남. 인증만 있고 인가가 없으면 public이 아니다(그 경우 보통 manual 또는 경로 의미상의 정책).
- `role_required`: 역할·전역 권한(관리자, 저장소 쓰기/관리 권한 레벨 등) 보유가 접근 조건.
- `membership_required`: 요청 대상 그룹·팀·채널·워크스페이스·계정의 **구성원 관계** (caller_id, target_group_id) ∈ memberships. 구독·요금제 등급은 해당 없음.
- `tenant_match`: 요청자의 테넌트(조직)와 대상 자원의 테넌트가 같아야 함. 요청자가 한 테넌트에 속하고(현재 조직·realm·active organization 등) 자원이 테넌트 키로 필터링되는 구조.
- `owner_match`: 요청자 본인 소유 자원만(관리자 우회 없음). 본인 리소스(/me, /user/...)는 owner_match.
- `owner_or_admin`: 소유자 본인 또는 관리자.
- `manual_review_required`: 위 하나로 표현 안 됨(여러 독립 조건 결합, 공개/비공개 분기, 외부 인가 등).
- 인가 검사가 코드에서 빠졌어도(취약 버전) 경로·스키마·수정 커밋으로 **의도된 정책**이 드러나면 그 정책을 label로 한다. 의도를 확인할 수 없으면 manual.
- 그룹 구성원이면서 그룹 안 역할(그룹 관리자 등)까지 필요하면: 그룹 안 역할이 핵심이면 role_required, 구성원 여부가 핵심이면 membership_required. 판단이 갈리면 draft_reason에 적고 confidence를 낮춘다.

## 선정 우선순위

membership_required, tenant_match, owner_or_admin이 될 엔드포인트를 우선 모은다. 나머지 label은 자연히 섞이는 만큼만. 프로젝트별 목표 건수는 각 작업 지시를 따른다.
