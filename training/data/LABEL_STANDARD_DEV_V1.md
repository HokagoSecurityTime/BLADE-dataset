# 개발용 라벨 기준 v1 — 사용자 승인본

적용 범위: 이후 별도 개발 실험과 검수. 기존 데이터·프롬프트·AGENTS.md·고정 test를 소급 수정하지 않는다. 이 문서는 분류 의미를 정의하며 실행 가능한 정책 생성 규약을 대체하지 않는다.

| label | 판단 기준 | 충분하지 않은 근거 |
|---|---|---|
| owner_match | 요청자와 대상 리소스 소유자의 일치가 접근 조건 | 일반적인 write/edit 권한, 콘텐츠 ID만 존재 |
| owner_or_admin | 소유자 허용과 관리자 예외/대안 허용이 명시됨 | 소유 필드와 admin 단어의 단순 공존 |
| tenant_match | 요청자와 대상 리소스의 조직·테넌트 일치가 접근 조건 | project/team 경로명만 존재 |
| role_required | admin/moderator/staff 등 특정 역할이 접근 조건 | API 키·JWT·OAuth 인증, 일반 write scope |
| membership_required | 플랜·구독·회원 등급에 따른 이용 자격이 접근 조건 | 팀·저장소 협업 멤버십만 존재 |
| public | 익명 접근 허용 또는 공개 데이터라는 근거가 있음 | security 선언 누락, 단순 GET |
| manual_review_required | 근거 부족·모순 또는 ACL·복합 조건으로 다른 6종 중 하나를 타당하게 선택하기 어려움 | 객체 ID나 설명이 있다는 이유로 보류를 금지하지 않음 |

## 복수 조건

실제 접근 허용·거부를 결정하는 조건을 대표 라벨로 선택하고 이유를 남긴다. 여러 조건이 독립적으로 필수이며 하나로 표현하면 의미가 달라지면 보류한다. 고정 우선순위는 사용하지 않는다. 계정 owner를 개인 객체 소유자로 자동 해석하지 않는다.

## 근거와 confidence

- 해당 method/endpoint에 적용되는 근거를 사용한다. 변경 요청의 설명을 조회 요청의 정책으로 전용하지 않는다.
- ACL 편집 권한을 소유권 또는 역할로 자동 변환하지 않는다.
- 낮은 confidence 자체를 보류 사유로 삼지 않는다. 패턴을 선택할 근거가 부족하면 confidence와 별개로 보류할 수 있다.
- 일반 설명, 서비스 이름, 보안 scheme의 존재만으로 정책을 확정하지 않는다.
- 기존 31건은 이미 분석한 진단 표본이다. 전체 macro-F1, 구체 선택률, 구체 선택 정확도를 함께 보고하며 미사용 사람 검수 표본을 독립 평가에 사용한다.

## 승인된 9건 처리 방향

- Microsoft 2건 및 GererMesAffaires 1건: 기존 보류 유지.
- AppCenter·Bitbucket·Circuit 3건: 협업 멤버십만으로 membership_required를 부여하지 않는다. 다른 정책 근거를 확인하지 못하면 보류한다.
- Appwrite 파일·Shutterstock 2건: ACL만으로 owner_match를 확정하지 않는다. 추가 소유권 근거가 없으면 보류로 교정한다.
- Zoom 1건: GET 자체의 역할·플랜 조건을 추가 확인할 때까지 확정 라벨을 비운다.

상태와 근거는 reports/eval/classification_quality/label_decisions_dev_v1.jsonl 및 .md에 별도로 기록한다. 조건부 항목을 사람 확정 완료로 취급하지 않는다. 이 승인으로 모델 학습·전체 재라벨링·런타임 변경은 실행하지 않는다.
