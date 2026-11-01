[작업] 검수 반영 → data-v4 규칙 라벨 → 동결 → LoRA v4 학습 → 평가

## 0. 입력과 전제
- 검수 완료 파일(사용자가 review/ 에 넣음):
  - review/v4_train_review_reviewed.xlsx — '검수 label'·'검수 사유' 열, '검수 규약' 시트(G1~G8)
  - review/test_v31_supp_review_reviewed.xlsx — '확정 label'·'확정 근거'·'비고' 열, '검수 규약' 시트
- 검수자는 Claude(AI)다. 근거 열만으로 판단했고 저장소를 직접 열지 않았다. DATA_CARD에 "AI 보조 검수 + 사람 표본 확인"으로 기록할 것.
- AGENTS.md 규칙·label 정의 변경 금지. test_v30·data-v1~v3·data-v3.1b 동결본은 해시 확인 후 읽기만 한다.

## 1. 검수 규약 기록
- '검수 규약' 시트의 G1~G8을 AGENTS.md의 data-v4 규약 절에 그대로 옮긴다(문구 수정 금지).
- 특히 G6: Zulip access_message·access_stream_by_id·check_can_access_user·validate_attachment_request는 membership_required로 일괄 라벨링하지 않는다.

## 2. test_v31_supp 확정·동결
- 비고 = EXCLUDE 41건은 제외하고 목록을 datasets/blade/processed/data_v4/test_v31_supp_excluded.jsonl에 사유와 함께 저장.
- 나머지 222건을 '확정 label'로 test_v31_supp.jsonl 생성. 입력 문자열은 후보 파일 그대로.
- 보고: label × 프로젝트 분포표. (예상: membership 55 중 Chatwoot 50, tenant 55 중 Flowise 52, owner_or_admin 20 중 Chamilo 19)
- 사람 표본 확인 시트 review/test_v31_supp_spotcheck.xlsx 생성: 비고 = CHANGED 6건 + label별 층화 무작위 각 4건(seed 42). 학습·평가 진행을 막지 않는다.
- SHA256 기록 후 동결. eval-def v2에는 별도 조건(보조 구간)으로만 추가하고 주지표(test_v30 oas_code 합성 제외)는 그대로 둔다.
- Flowise(enterprise/ 코드 포함)·라이선스 미선언 출처(multitenant lab, Generic University)가 든 test 파일은 .gitignore에 넣고 DATA_CARD에 "공개 시 코드 본문 제외, 링크·커밋만 제공" 명시.

## 3. 학습용 규칙 라벨(data-v4 추가분)
- 대상: candidates_train_v4.jsonl 440건(Zulip 187 + Label Studio 253). LLM 1차 라벨은 사용하지 않는다(검수 표본 41건 중 일치 20건).
- 규칙은 Zulip·Label Studio 코드와 검수 규약 G1~G7에서만 도출한다. test·supp 파일과 test 오류 목록은 참조 금지.
- 규칙 초안(검수 결과 기반):
  - Label Studio
    - project.has_permission / queryset의 active_organization 필터 / storage·export·annotation 등 → project 조직 소속 → tenant_match (G1)
    - target fixed to request.user, pk를 무시하고 request.user만 변경 → owner_match (G4)
    - 경로 pk 조직 + OrganizationMember(user, org) 조회 → membership_required (G2)
    - AllowAny, simplejwt 토큰 뷰 → public (G7)
    - 객체 없음 + is_authenticated뿐 → manual_review_required (G6)
    - 생성 시 본문 project/task의 조직 검증이 발췌에서 확인 안 됨 → 규칙 미적용
  - Zulip
    - @require_realm_admin, x-requires-administrator, 관리자 관리 함수 → role_required (G3)
    - query scoped to requester, users/me, 본인 목록·설정·플래그·기기 대상 → owner_match (G4)
    - access_bot_by_id, access_invite_by_id(소유자 OR 관리자) → owner_or_admin (G5)
    - access_message, access_stream_by_id, check_can_access_user, validate_attachment_request, 조직 설정 의존 권한, 대상별 설정 그룹(can_manage_group) → manual_review_required (G6)
    - allow_anonymous_user_web(조건부 익명) → manual_review_required (G7)
    - 무인증 로그인·API 키 발급 → public (G7)
- 규칙이 걸리지 않거나 두 규칙이 충돌하는 건은 학습에서 제외한다(LLM 라벨로 채우지 않음). 제외 수 보고.
- 검증: 규칙 라벨을 검수 완료 71건(v4_train_review 41 + 선정 제외 manual 표본 30)과 비교해 일치율·불일치 목록 보고. 불일치는 규칙을 고쳐 해소한다(같은 학습 프로젝트라 허용). 최종 일치율 95% 미만이면 학습 전에 멈추고 보고.
- rationale: label별 기존 템플릿 문장 + 근거 함수·데코레이터 이름만. 파일 경로·시트명·규칙 ID(G1 등)·검수 문구 금지.
- 선정: 프로젝트당 최대 150, 프로젝트 안 한 label 50% 이하, 목표 label(membership·tenant·owner_or_admin) 우선, seed 42. membership이 적게 나와도 합성·LLM으로 채우지 말고 실제 수를 보고.

## 4. data-v4 동결
- data-v4 = data-v3.1b(manual 쿼터 10%) + 3의 선정분. val도 같은 규칙으로 분리(프로젝트 단위 누수 없게).
- 정합성 점검: 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, test_v30·test_v31_supp와 (서비스, method, 정규화 path) 겹침 0. 해시 기록 후 동결.

## 5. RunPod 실행 (하이퍼파라미터는 LoRA v2와 동일)
- LoRA v4: data-v4, seed 42·43·44
- 기준점: data-v2 seed 43·44 (아직 돌리지 않았다면. 기존 s42와 합쳐 3 seed)
- 마지막에 runpodctl로 Pod 정지. 정지가 안 되면 로그 마지막 줄에 명확히 남긴다.

## 6. 평가 (final 어댑터만, 체크포인트 선택·문턱 조정 금지)
- 주지표: test_v30 oas_code 합성 제외 207건 — 베이스, v2(3 seed), v3b(3 seed), v4(3 seed)
- 별도 조건: test_v31_supp 222건 — 같은 모델 전부. label별 F1, macro-F1(support>0 label), 혼동표, **프로젝트별 정확도 표**(label이 프로젝트에 몰려 있으므로 label별 표와 함께 제시).
- 보조: support 충분 label 평균 F1, 정확도, manual 비율, 출력 오류 수, 검수 메타 문구 출력 수.

## 7. 보고
- reports/eval/lora_v4/lora_v4_report.md
- 판정은 seed 표준편차보다 큰 차이만 인정.
- 답할 질문: (1) data-v3가 v2보다 나은가(같은 RunPod 3 seed) (2) v4가 v3b보다 나은가(주지표·supp 각각) (3) supp에서 membership·tenant·owner_or_admin 성능과 프로젝트별 편차
- 커밋하지 말고 보고 후 대기.
