# review_overlap20 — 교차 검수용 겹침 셋 20건 (test 정답 파일에서 층화 추출: summit_club 3, vAPI 4, DVRestaurant 3, NetBox 1순위 5·2순위 3·3순위 2)

용도: 검수자 2명 일치율(Cohen's kappa) 측정. 각자 자기 열만 채운다. 건수 20. 검수 열은 비워 두었다. 라벨 기준은 프롬프트 v3.0.1 정의 전문(아래)을 따른다.

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

| id | 출처 | 핵심 코드 줄 | 검수자A label | 검수자A 사유 | 검수자B label | 검수자B 사유 |
|---|---|---|---|---|---|---|
| summit_club_catalogue_1 | summit_club |  | | | | |
| summit_club_audit_0 | summit_club | if principal["role"] != "admin": raise HTTPException(403) | | | | |
| summit_club_roster_1 | summit_club |  | | | | |
| vapi:post:/api2/user/login | vAPI | return response(json_encode(array("success"=>"false","cause"=>"usernameOrPasswordIncorrect")), 401) | | | | |
| vapi:get:/stickynotes | vAPI | return response(json_encode(array("success"=>"false","cause"=>"format param not set properly")), 403) | | | | |
| vapi:get:/serversurfer | vAPI | return response(json_encode(array("success"=>"false","msg"=>"Whoa!!! Not Allowed!!")), 403) / return response(json_encode(array("success"=>"false","cause"=>"url param not set")), 403) | | | | |
| vapi:get:/api7/user/key | vAPI | return response(json_encode(array("success"=>"false","cause"=>"usernameOrPasswordIncorrect")), 403) / return response(json_encode(array("success"=>"false","cause"=>"usernameOrPasswordIncorrect")), 403) / return response(json_encode(array("success"=>"false","cause"=>"userNotLoggedIn")), 403) | | | | |
| dvrestaurant:put:/users/update_role | DVRestaurant | # app/apis/users/services/update_user_role_service.py: @router.put("/users/update_role") / // apis/auth/utils/jwt_auth.py get_current_user: decodes the Bearer JWT (signature verification disabled in this fixture / // apis/auth/utils/roles_based_auth_checker.py: / from apis.auth.utils import get_current_user / required_roles, / self.required_roles = required_roles / def __call__(self, user: User = Depends(get_current_user)): / if user.role not in self.required_roles: / raise HTTPException(status_code=403, detail="Unauthorized") / async def update_user_role( / current_user: Annotated[models.User | | | | |
| dvrestaurant:get:/debug | DVRestaurant | // apis/auth/utils/jwt_auth.py get_current_user: decodes the Bearer JWT (signature verification disabled in this fixture / // apis/auth/utils/roles_based_auth_checker.py: / from apis.auth.utils import get_current_user / required_roles, / self.required_roles = required_roles / def __call__(self, user: User = Depends(get_current_user)): / if user.role not in self.required_roles: / raise HTTPException(status_code=403, detail="Unauthorized") | | | | |
| dvrestaurant:put:/menu/{item_id} | DVRestaurant | // apis/auth/utils/jwt_auth.py get_current_user: decodes the Bearer JWT (signature verification disabled in this fixture / // apis/auth/utils/roles_based_auth_checker.py: / from apis.auth.utils import get_current_user / required_roles, / self.required_roles = required_roles / def __call__(self, user: User = Depends(get_current_user)): / if user.role not in self.required_roles: / raise HTTPException(status_code=403, detail="Unauthorized") / current_user: Annotated[User, Depends(get_current_user)], | | | | |
| netbox:post:/api/users/tokens/provision/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj / permission_classes = [] | | | | |
| netbox:post:/api/dcim/devices/{id}/render-config/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
| netbox:get:/api/core/object-types/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj / permission_classes = [IsAuthenticatedOrLoginNotRequired] / Override initial() to skip the restrict() call since ObjectType (a ContentType proxy) / # which would try to call restrict() on the queryset | | | | |
| netbox:post:/api/extras/config-templates/{id}/render/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj / # Override restrict() on the default queryset to enforce the render & view actions / self.queryset = self.queryset.model.objects.restrict(request.user, 'render').restrict(request.user, 'view') | | | | |
| netbox:get:/api/users/config/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj / permission_classes = [IsAuthenticated] / return UserConfig.objects.filter(user=self.request.user) | | | | |
| netbox:delete:/api/users/owner-groups/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
| netbox:delete:/api/users/groups/{id}/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
| netbox:delete:/api/users/owners/{id}/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
| netbox:get:/api/ipam/prefixes/{id}/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
| netbox:get:/api/tenancy/tenants/{id}/ | netbox | # BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> Restric / #   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the Obj | | | | |
