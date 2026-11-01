# review_summit_club — test_v30의 summit_club 16건 (test 정답 확정용)

용도: test 정답(설계 라벨 확정). 건수 16. 검수 열은 비워 두었다. 라벨 기준은 프롬프트 v3.0.1 정의 전문(아래)을 따른다.

**추가 기준**: visibility_dependent(저장소·조직·설정의 공개 여부에 따라 접근이 달라지는 조건부 접근)와 ACL(관리자가 배포별로 설정하는 객체 권한·역할 목록)은 원칙적으로 manual_review_required. 인증만 있고 인가 검사가 없으면 manual_review_required. 구독·플랜·등급만 요구하면 manual_review_required.

## v3.0.1 라벨 정의(전문)

- public: 해당 요청은 인증 없이 누구나 접근 가능하다는 긍정 근거가 있다. 코드 일부에 검사가 없거나 security가 unknown이라는 이유만으로 선택하지 않는다. 인증이 필요하면 public이 아니다. security가 선언됐거나 인증 후 반환하는 경우 public 금지.
- role_required: 특정 역할 보유가 실제 접근 조건이다. 인증 성공이나 API 키 요구만으로 선택하지 않는다.
- membership_required: 요청자가 해당 요청 대상 그룹·팀의 구성원이어야 한다. (requester_id, target_group_id) 관계나 동등한 구성원 조회가 근거다. 유료 플랜, 구독 등급, 같은 tenant, 팀 이름만으로는 선택하지 않는다.
- tenant_match: 요청자 tenant와 대상 자원의 tenant가 같아야 한다. 특정 그룹 구성원 여부와 구분한다. 같은 tenant라도 그룹 비구성원일 수 있고, 그룹 구성원은 다른 tenant에 있을 수도 있다.
- owner_match: 요청자가 대상 객체 소유자 본인이어야 하거나, 처리 대상이 인증 사용자 본인으로 고정돼야 한다. 반환 데이터에 owner 필드가 있다는 사실만으로 선택하지 않는다.
- owner_or_admin: 소유자 허용 OR 관리자 우회가 실제 조건이다. 관리자도 소유자여야 하는 AND 조건은 이 패턴이 아니다.
- manual_review_required: 근거 부족·모순·지원하지 않는 의미·독립 필수 조건 결합으로 6종 중 하나를 타당하게 선택할 수 없다. 자동 적용 제외·관리자 검토 대기다.

## 보류가 필수인 경우

다음에 해당하면 구체 라벨을 추측하지 않고 manual_review_required를 선택한다.

1. 구독·플랜·등급(premium, pro, paid tier 등)만 요구하는 조건. 이는 그룹 구성원 관계가 아니므로 6종으로 표현하지 못한다.
2. OAS(명세)만 있고 요청자와 대상 객체의 관계나 실제 접근 조건을 확인할 수 없는 경우. path에 객체 ID가 있다는 사실, 응답에 owner·tenant 필드가 있다는 사실, 자원 이름(my, me, admin 등)만으로 관계를 단정하지 않는다. 설명에 접근 조건이 명시돼 있으면 그 문장을 근거로 선택할 수 있다.
3. 두 개 이상의 독립 필수 조건이 AND로 결합된 경우(예: 같은 tenant AND 그룹 구성원, 소유자 AND 특정 역할). 하나를 버려야 단일 라벨이 되면 보류한다.
4. 코드 구현과 명시 정책 의도가 충돌하는 경우.
5. 코드가 모든 요청을 거부하거나, 접근 조건이 불완전·미확정으로 남아 있는 경우.
6. 인증만 확인하고 요청자-객체 관계나 역할 검사가 확인되지 않으면 manual_review_required.

## 보류가 필수인 경우(전문)

다음에 해당하면 구체 라벨을 추측하지 않고 manual_review_required를 선택한다.

1. 구독·플랜·등급(premium, pro, paid tier 등)만 요구하는 조건. 이는 그룹 구성원 관계가 아니므로 6종으로 표현하지 못한다.
2. OAS(명세)만 있고 요청자와 대상 객체의 관계나 실제 접근 조건을 확인할 수 없는 경우. path에 객체 ID가 있다는 사실, 응답에 owner·tenant 필드가 있다는 사실, 자원 이름(my, me, admin 등)만으로 관계를 단정하지 않는다. 설명에 접근 조건이 명시돼 있으면 그 문장을 근거로 선택할 수 있다.
3. 두 개 이상의 독립 필수 조건이 AND로 결합된 경우(예: 같은 tenant AND 그룹 구성원, 소유자 AND 특정 역할). 하나를 버려야 단일 라벨이 되면 보류한다.
4. 코드 구현과 명시 정책 의도가 충돌하는 경우.
5. 코드가 모든 요청을 거부하거나, 접근 조건이 불완전·미확정으로 남아 있는 경우.
6. 인증만 확인하고 요청자-객체 관계나 역할 검사가 확인되지 않으면 manual_review_required.

## 표본

| id | method | path | 설계 label(제안) | vulnerable | 코드 발췌 | 정답 | 사유 | 검수자 |
|---|---|---|---|---|---|---|---|---|
| summit_club_catalogue_0 | GET | /fixtures/summit_club/expeditions/catalogue/current/{item_id} | public | False | if obj is None: raise HTTPException(404)<br>    return obj | | | |
| summit_club_catalogue_1 | GET | /fixtures/summit_club/expeditions/catalogue/archive/{item_id} | public | False | if obj is None: raise HTTPException(404)<br>    return obj | | | |
| summit_club_drafts_0 | GET | /fixtures/summit_club/expeditions/drafts/current/{item_id} | owner_match | False | if principal["id"] != obj["owner_id"]: raise HTTPException(403)<br>    return obj | | | |
| summit_club_drafts_1 | GET | /fixtures/summit_club/expeditions/drafts/archive/{item_id} | owner_match | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_shared_0 | GET | /fixtures/summit_club/expeditions/shared/current/{item_id} | owner_or_admin | False | if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)<br>    return obj | | | |
| summit_club_shared_1 | GET | /fixtures/summit_club/expeditions/shared/archive/{item_id} | owner_or_admin | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_workspace_0 | GET | /fixtures/summit_club/expeditions/workspace/current/{item_id} | tenant_match | False | if principal["tenant_id"] != obj["tenant_id"]: raise HTTPException(403)<br>    return obj | | | |
| summit_club_workspace_1 | GET | /fixtures/summit_club/expeditions/workspace/archive/{item_id} | tenant_match | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_audit_0 | GET | /fixtures/summit_club/expeditions/audit/current/{item_id} | role_required | False | if principal["role"] != "admin": raise HTTPException(403)<br>    return obj | | | |
| summit_club_audit_1 | GET | /fixtures/summit_club/expeditions/audit/archive/{item_id} | role_required | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_roster_0 | GET | /fixtures/summit_club/expeditions/roster/current/{item_id} | membership_required | False | if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)<br>    return obj | | | |
| summit_club_roster_1 | GET | /fixtures/summit_club/expeditions/roster/archive/{item_id} | membership_required | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_gear_0 | GET | /fixtures/summit_club/expeditions/gear/current/{item_id} | membership_required | False | if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)<br>    return obj | | | |
| summit_club_gear_1 | GET | /fixtures/summit_club/expeditions/gear/archive/{item_id} | membership_required | True | # Deliberate fixture: object authorization check omitted.<br>    return obj | | | |
| summit_club_council_0 | GET | /fixtures/summit_club/expeditions/council/current/{item_id} | manual_review_required | False | if principal["tenant_id"] != obj["tenant_id"] or (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)<br>    return obj | | | |
| summit_club_council_1 | GET | /fixtures/summit_club/expeditions/council/archive/{item_id} | manual_review_required | False | if principal["tenant_id"] != obj["tenant_id"] or (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)<br>    return obj | | | |
