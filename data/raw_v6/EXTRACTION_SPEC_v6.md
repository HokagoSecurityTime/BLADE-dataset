# test_v6 추출 규격 보충 (2026-11-03)

공통 형식은 `data/raw_v4/EXTRACTION_SPEC.md`를 그대로 따른다(필드, controller_text 규칙, 라벨 정의). 이 문서는 test_v6에서 더해지는 조건이다. 스타일 참고 구현: `data/raw_v5/umami/extract_umami.py`(block/ev 헬퍼, `add()` 한 건 = 한 레코드). 실행은 `python -I data/raw_v6/<project>/extract_<project>.py`이며 산출은 같은 폴더의 `candidates.jsonl`과 `SOURCE.md`.

## 프로젝트·목표 건수 (A안, 사용자 승인)

| project 키 | service | 클론 경로(읽기 전용) | 태그 · 커밋 | 라이선스 | 목표 |
|---|---|---|---|---|---:|
| `seahub` | Seafile seahub | `datasets/blade/raw/opensource/test_v6_candidates/seahub` | `v14.0.9-server` · `0841826c7ce738caf92121d94d7741ba0f2373d5` | Apache-2.0 (`LICENSE.txt`) | 90 |
| `redash` | Redash | `.../test_v6_candidates/redash` | `v26.9.0` · `42fdf9d4a0fdb83841130ab78f69899a224f281b` | BSD-2-Clause (`LICENSE`) | 70 |
| `glitchtip` | GlitchTip | `.../test_v6_candidates/glitchtip-backend` | `v6.2.6` · `d3039088e913a591a8e6544a2d2fffc865a9711a` (repository `https://gitlab.com/glitchtip/glitchtip-backend`, 고정 링크 `.../-/blob/<commit>/<file>#L<a>-<b>`) | MIT (`LICENSE`) | 70 |
| `penpot` | Penpot | `.../test_v6_candidates/penpot` (백엔드 `backend/src/app/`) | `2.18.5` · `f44566963daf61fce4d8608e7c5e8c27c5853a88` | MPL-2.0 (`LICENSE`) | 60 |

- 목표 ±5건 허용. (method, path)는 프로젝트 안에서 유일.
- 선정 우선순위: membership_required · owner_or_admin · tenant_match 후보를 먼저 모두 모으고, 그 다음 role_required · owner_match · public · manual을 자연 비율로 섞는다. **한 프로젝트에서 한 draft_label이 50%를 넘지 않게** 한다(초과분은 동형 조건 중복을 줄여 조정하고 SOURCE.md에 적는다).
- 동형 조건(같은 권한 함수·같은 베이스 클래스) 엔드포인트는 대표 2~4건만 넣고 나머지는 SOURCE.md '제외한 범위'에 열거한다.

## 경로 표기

- seahub: 실제 요청 경로 그대로 `/api/v2.1/...`, `/api2/...` (`seahub/urls.py`, `seahub/api2/urls.py` 정규식의 `(?P<name>...)`는 `{name}`으로).
- Redash: `/api/...` (`redash/handlers/api.py`의 `add_org_resource`/`add_resource` 첫 URL; `<org_slug>` 접두 변형은 넣지 않고 SOURCE.md에 설명).
- GlitchTip: `/api/0/...` (`glitchtip/api/api.py`의 `add_router("0", ...)` 접두 + 라우터 경로; `{slug:organization_slug}` → `{organization_slug}`). 인제스트 `api/{project_id}/envelope/` 등은 `/api/...`.
- Penpot: 모든 RPC 명령은 `POST /api/rpc/command/{명령 이름}`을 **리터럴 경로**로 쓴다(예: `/api/rpc/command/get-team-members`). 요청 본문 스키마는 `::sm/params`(`[:map ...]`)에서 키를 뽑아 requestBody로 만든다. `::rpc/auth false` 명령은 security `[]`(익명).

## 라벨링 기준 (프롬프트 v3.0.1 + AGENTS.md G1~G8 + test_v6 보충 규약)

AGENTS.md "data-v4 검수 규약"(G1~G8)과 "작업 S0" 절의 **test_v6 검수 규약 보충 1~8**을 그대로 적용한다. 요약:

- 그룹(조직·팀·그룹·보드) 지정 + (요청자, 그룹) 구성원 행 조회 → membership_required. 구성원 OR 관리자 우회도 membership_required.
- 구성원 확인 뒤 그룹 안 역할(owner/admin/manager, can_edit 플래그 등)이 결정 조건 → role_required(G3). 전역 관리자(is_staff, is_superuser, isAdmin) → role_required. Redash `@require_admin`은 조직 그룹 권한 메커니즘이라 `current_org`와 함께면 tenant_match(G1-b, 정지 지점 2 결정 2026-11-03), `@require_super_admin`은 role_required.
- 대상이 request.user·/me·본인 목록으로 고정, 또는 객체 소유자 == 요청자(관리자 우회 없음) → owner_match. 소유자 OR 관리자(전역 관리자 또는 그룹 관리자) 우회가 실제 조건 → owner_or_admin.
- 요청자의 현재 테넌트(org, current_org, request.user.org)로 자원을 필터·고정하고 경로·본문에 대상 테넌트 ID가 없음 → tenant_match(G1). RBAC 권한이 함께 있어도 tenant_match.
- 서로 다른 유형의 OR 분기(공개/비공개, 구성원 OR 공유 링크, owner OR admin OR ACL), 외부 인가(RPC·ACL 합산), 설정값에 따라 허용 주체가 바뀜, 인증만 확인(객체 없음) → manual_review_required.
- 조건 없는 익명 허용만 public(로그인·토큰·헬스·공개 임베드). 조건부 익명은 manual.
- 보충 규약: Redash `current_org`만 → tenant_match, `require_admin_or_owner` → owner_or_admin, `require_object_modify_permission`·`require_access` → manual. seahub `check_folder_permission`만 → manual, `is_group_member` 선행 → membership_required, org 관리 API → tenant_match. Penpot share-id 겸용 조회 → manual, `get-organization-owner-permissions`가 OR로 붙는 명령은 **추출하지 않고** SOURCE.md 제외 목록에 적는다. GlitchTip `has_permission`은 근거로 쓰지 않고 `get_organizations_queryset`·`actor_role`만, `open_membership` 분기 → manual.
- 경계·근거 부족 건은 draft_label에 가장 가까운 값을 적고 `draft_reason` 첫머리에 `EXCLUDE 후보:`와 사유를 쓴다(검수자가 G8 판단). confidence는 0.5 이하.
- `draft_confidence`: 코드 한 줄로 결정되면 0.85~0.95, 해석이 필요하면 0.6~0.8, 대안 label이 있으면 0.5~0.6.
- `evidence`는 인가 결정 줄을 원문 그대로 2~4개(`파일:줄`). `draft_reason`·`auth_summary`는 한국어.

## 금지·범위

- 클론은 읽기만(수정·빌드·실행·의존성 설치 금지). LLM API 호출 금지. 모델(Ollama·LoRA) 추론 금지.
- `datasets/blade/processed/`의 test·train 파일, `reports/eval/`, 다른 프로젝트의 `data/raw_*` 폴더를 읽지 않는다(중복 대조는 조립 단계).
- 쓰기는 `data/raw_v6/<project>/`만. 커밋 금지.
- controller_text는 최대 3,000자(초과 레코드는 조립에서 버려진다). 500자 미만이면 SOURCE.md에 사유를 적는다.

## SOURCE.md 필수 항목

저장소·태그·커밋·라이선스(LICENSE 요지), 추출 범위와 방법, 인증·인가 구조(권한 함수·데코레이터·베이스 클래스 목록), 제외한 범위와 이유(동형 중복·규약상 EXCLUDE·외부 인가 등, **사유별 건수**), draft_label 건수표, 불확실한 엔드포인트 목록(검수 주의), test_v5와 달리 tenant_match가 포함된다는 점(seahub·Redash).
