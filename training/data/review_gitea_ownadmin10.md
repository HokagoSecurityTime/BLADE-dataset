# review_gitea_ownadmin10 — Gitea owner_or_admin LLM 라벨 10건 (train 포함 여부 결정용)

용도: train 품질. reqAdmin은 저장소 단위 관리자 ACL이라 BLADE owner_or_admin(객체 소유자 OR 시스템 관리자)과 다를 수 있다. 이 10건의 검수 결과로 pool의 owner_or_admin 84건 포함 여부를 재결정한다. 건수 10. 검수 열은 비워 두었다. 라벨 기준은 프롬프트 v3.0.1 정의 전문(아래)을 따른다.

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

| 그룹 | id | 미들웨어 체인 | 핸들러 | public_candidate | visibility_dependent | LLM label | confidence | rationale | 검수 | 검수 사유 |
|---|---|---|---|---|---|---|---:|---|---|---|
| owner_or_admin 10 | gitea:delete:/repos/{owner}/{repo}/actions/runs/{run} | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqRepoReader(unit.TypeActions), reqToken(), reqRepoWriter(unit.TypeActions) | repo.DeleteActionRun | False | False | owner_or_admin | 0.9 | description: 요청자가 레포지토리의 작성자이거나 관리자여야 함; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:post:/repos/{owner}/{repo}/push_mirrors | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqAdmin(), reqToken(), mustNotBeArchived | repo.AddPushMirror | False | False | owner_or_admin | 0.9 | description: 요청자가 소유자 또는 관리자여야 하며, 관리자 권한이 없으면 403; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:delete:/repos/{owner}/{repo}/tag_protections/{id} | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqAdmin() | repo.DeleteTagProtection | False | False | owner_or_admin | 0.9 | description: 요청자가 소유자 또는 관리자여야 하며, 관리자 권한이 없으면 403; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:post:/repos/{owner}/{repo}/keys/tokens | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqAdmin() | repo.CreateDeployToken | False | False | owner_or_admin | 0.9 | description: 요청자가 소유자 또는 관리자여야 하며, 인증 후 권한 검사를 통해 403을 반환; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:patch:/repos/{owner}/{repo}/releases/{id} | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqRepoReader(unit.TypeReleases), reqToken(), reqRepoWriter(unit.TypeReleases), context.ReferencesGitRepo() | repo.EditRelease | False | False | owner_or_admin | 0.9 | description: 요청자가 리포지토리의 작성자이거나 관리자여야 함; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:delete:/repos/{owner}/{repo}/topics/{topic} | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqAnyRepoReader(), reqAdmin(), reqToken(), mustNotBeArchived | repo.DeleteTopic | False | False | owner_or_admin | 0.9 | description: 요청자가 레포지토리의 관리자이거나 소유자여야 함; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:post:/repos/{owner}/{repo}/actions/runs/{run}/approve | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqRepoReader(unit.TypeActions), reqToken(), reqRepoWriter(unit.TypeActions) | repo.ApproveWorkflowRun | False | False | owner_or_admin | 0.9 | description: 요청자가 특정 권한을 가져야 하며, 소유자 또는 관리자여야 함; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:post:/repos/{owner}/{repo}/tag_protections | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqAdmin(), mustNotBeArchived | repo.CreateTagProtection | False | False | owner_or_admin | 0.9 | description: 요청자가 레포지토리의 소유자이거나 관리자여야 함; 판단: 소유자 또는 관리자 조건이 명시되어 있으므로 owner_or_admin 선택 | | |
| owner_or_admin 10 | gitea:get:/repos/{owner}/{repo}/collaborators/{collaborator}/permission | sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken() | repo.GetRepoPermissions | False | False | owner_or_admin | 0.9 | description: 요청자가 관리자이거나, 협력자 본인 또는 레포지토리 관리자여야만 접근 가능; 판단: 소유자 또는 관리자 조건이므로 owner_or_admin | | |
| owner_or_admin 10 | gitea:delete:/packages/{owner}/{type}/{name} | sudo(), reqToken(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryPackage), context.UserAssignmentAPI(), context.PackageAssignmentAPI(), reqPackageAccess(perm.AccessModeRead), checkTokenPublicOnly(), reqPackageAccess(perm.AccessModeWrite) | packages.DeletePackage | False | False | owner_or_admin | 0.9 | description: 사용자가 특정 권한을 가져야 하거나 사이트 관리자가 아니면 403; 판단: 소유자 또는 관리자 조건이므로 owner_or_admin | | |
