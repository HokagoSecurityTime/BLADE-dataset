# label_studio — data-v4 학습 후보 추출 출처

- 저장소: https://github.com/HumanSignal/label-studio
- 고정 태그/커밋: `1.23.2` (GitHub latest release, 2026-09-29) / `df96d79183156e556d91825d15fa7721f1145e1a`
- clone: `datasets/blade/raw/opensource/HumanSignal_label-studio/` (`--depth 1 --filter=blob:none --sparse --branch 1.23.2`, sparse-checkout `label_studio/`, 루트 파일 포함). git 추적 대상 아님.
- 라이선스: Apache-2.0. `LICENSE` = Apache License Version 2.0 전문. `NOTICE`: "Label Studio (TM) Copyright (c) 2019-2021 Heartex, Inc. ... Source code in this repository is licensed under the Apache License Version 2.0".
- 용도: data-v4 **학습** 후보(Plane(AGPL) 대체). 조직(organization) → 프로젝트(project) 구조가 Plane의 workspace_slug/project_id 역할을 한다. 라벨 필드(draft_label 등)는 채우지 않았다. 라벨은 이후 별도 LLM 라벨링 단계에서 만든다.

## 추출 범위와 방법

- 정적 OpenAPI/swagger 파일은 저장소에 없다(drf-spectacular가 런타임에 생성). 그래서 `oas_status=generated`다.
- 라우트 목록은 `label_studio/core/all_urls.json`(저장소에 커밋된 URLconf 덤프)의 `/api/` 항목을 쓰고, 각 항목을 `label_studio/*/urls.py`의 `path()`/`router.register()` 호출과 대조했다. DRF format suffix 변형(`\.<format>`)과 `APIRootView`는 제외했다.
- HTTP 메서드: 뷰 클래스 MRO(프로젝트 내부 베이스 클래스는 import를 따라 해석)의 `get/post/put/patch/delete` 정의 + DRF generics 기본 메서드(`ListCreateAPIView` → GET/POST 등) + ViewSet 액션(`ModelViewSet` list/create/retrieve/update/partial_update/destroy, `@action`). `http_method_names` 제한을 적용했다. OPTIONS/HEAD는 제외했다.
- 경로: 실제 요청 경로(`/api/...`), Django 변환기 `<int:pk>` → `{pk}`. Router ViewSet 상세 경로는 drf-spectacular와 같이 `{id}`로 적었다(URL kwarg는 `pk`).
- oas_operation: `@extend_schema` / `@method_decorator(name=..., decorator=extend_schema(...))`의 summary·description·parameters·request·responses·tags를 정적으로 읽었다(literal이 아니면 `x-source`에 원문). `extend_schema(exclude=True)` 연산(42건, 주로 PUT)은 스키마에서 숨겨졌지만 실제 라우트이므로 `x-excluded-from-schema: true`로 포함했다. extend_schema가 없으면 summary는 빈 문자열, description은 클래스/메서드 docstring이다. requestBody가 없으면 serializer_class 이름을 `x-source`로 넣었다.
- response_schema_fields: 응답 serializer(또는 serializer_class)의 선언 필드 + `Meta.fields`가 literal인 경우의 필드 이름.
- oas_global_security / oas_security_schemes: 정적 명세가 없어 `[]`, `{}`. 인증 방식은 아래 요약과 controller_text의 DEFAULT 설정 블록에 있다.
- permission_doc: extend_schema description과 핸들러/클래스 docstring 중 권한·접근·조직·소유자 관련 문장 원문(있을 때만, 30건).

## controller_text 구성

블록 순서: URL 패턴(`path()`/`router.register()` + 상위 `include()` 줄) → 뷰 클래스 헤더와 클래스 속성(permission_required, permission_classes, queryset, parent_queryset, http_method_names 등) → 해당 메서드 핸들러와 `get_queryset`/`filter_queryset`/`get_object`/`permission_classes`/`perform_*` 등(베이스 클래스 정의면 그 클래스 헤더 줄과 함께) → 핸들러가 부르는 인가 관련 self 메서드(1단계) → 전역 `REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES']`와 `HasObjectPermission`(기본 권한을 쓰는 뷰만) → `make_perm(..., rules.is_authenticated)` 루프(permission_required가 있는 뷰) → 객체 검사에 쓰이는 모델 `has_permission` 체인(예: Task → TaskMixin → ProjectMixin), `.objects.for_user()` 매니저 정의, `validate_storage_instance`의 권한 부분, organizations 앱의 `HasObjectPermission = load_func(settings.MEMBER_PERM)`·`MEMBER_PERM`·`MemberHasOwnerPermission`.

- 원문만 이어 붙였고 새 주석·경로·줄 번호를 넣지 않았다. `extend_schema` 문서 데코레이터는 oas_operation으로 옮기고 코드에서는 뺐다. 다른 데코레이터(`@api_webhook` 등)는 남겼다.
- 3,000자를 넘으면 인가와 무관한 줄(직렬화·응답 조립·로그)을 `...`로 줄였다. 인가 키워드(permission, organization, request.user, get_object, check_object_permissions, PermissionDenied, NotFound, for_user, created_by 등)가 있는 줄과 그 상위 블록 헤더는 남겼다. 그래도 넘치면 규칙 루프 블록과 항상 True를 반환하는 `TaskMixin/AnnotationMixin.has_permission`을 뺐다. 최종 길이 249~2,998자(중앙값 약 1,985자).
- source_locations: 블록마다 저장소 루트 기준 파일과 줄 범위(생략한 메서드도 전체 범위). 모델 has_permission은 클래스 줄과 메서드 범위를 따로 기록했다.

## 인증·인가 구조 요약 (OSS 1.23.2)

- 인증: `REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES` = `jwt_auth.auth.TokenAuthenticationPhaseout`, `SessionAuthentication`. 미들웨어 `XApiKeySupportMiddleware`, `JWTAuthenticationMiddleware`.
- 기본 권한: `DEFAULT_PERMISSION_CLASSES` = `core.api_permissions.HasObjectPermission`(`obj.has_permission(request.user)`) + `IsAuthenticated`. 객체 검사는 `get_object()`·`check_object_permissions()`·`GetParentObjectMixin._get_parent_object()`가 호출될 때만 돈다.
- `permission_required` / `ViewClassPermission` / `all_permissions`(core/permissions.py): OSS는 모든 권한 이름을 `rules.is_authenticated`로 등록한다. OSS 코드에는 클래스 속성 permission_required를 집행하는 곳이 없다(LSE용 훅으로 보인다). 그래서 auth_summary에 "(OSS rules: is_authenticated)"로 적었다.
- 테넌트(조직) 경계: `request.user.active_organization`로 queryset을 거른다(`Project.objects.filter(organization=...)`, `project__organization=...`, `Project.objects.for_user(user)` → `organization=user.active_organization`). 모델 `has_permission`: Project(ProjectMixin) = 조직 멤버십이 취소되지 않음(주석: "LSO always runs a single organization"); Organization = 활성 OrganizationMember 존재; View·Label·OrganizationMember = `user.active_organization` 일치; Task/Annotation/Prediction/Draft/Storage/MLBackend/FileUpload/Export = project.has_permission으로 위임; Webhook = organization.has_user AND project.has_permission.
- 역할성 검사: `MemberHasOwnerPermission`(비안전 메서드는 `request.user.own_organization` 필요) — 조직 멤버 삭제 DELETE에만 적용된다.
- 익명: `LabelConfigValidateAPI`(AllowAny), `WebhookInfoAPI`(AllowAny), `/api/version/`(함수 뷰). simplejwt `TokenRefreshView`/`TokenViewBase` 기반 `/api/token/refresh/`·`/api/token/blacklist/`는 베이스 클래스(외부 코드)가 authentication_classes=()·permission_classes=()로 두고 요청 본문의 refresh token을 자격으로 쓴다(외부 코드라 발췌에 없다).
- 참고: `FileUploadAPI`(`/api/import/file-upload/{pk}`)는 permission_classes=(IsAuthenticated,)이고 queryset이 전체라 객체 검사가 없다. `AnnotationDraftListAPI` 목록은 task_id로만 거른다. 의도된 정책 판단은 라벨링 단계에 맡긴다.

## 건수

- 후보 253건(GET 100, POST 75, DELETE 29, PATCH 26, PUT 23). 뷰 모듈 앱별: io_storages 99(S3·GCS·Azure·Redis·LocalFiles 5종이 같은 베이스 클래스를 써서 코드가 거의 같다), tasks 29, projects 25, users 15, data_manager 13, labels_manager 13, organizations 10, data_import 10, data_export 10, ml 10, webhooks 7, jwt_auth 7, fsm 2, session_policy 2, core 1.
- auth_summary 기준 대략 분류(추출 스크립트의 휴리스틱, 라벨 아님): organization-scoped 195, authenticated-only 37, owner/creator 12, other 5, anonymous 3, admin/role 1.

## 제외한 범위와 이유

- `/api/`가 아닌 라우트: 템플릿 페이지(`/projects/`, `/user/login/` 등), 저장소 URI 해석(`/tasks/{id}/resolve/`, `/projects/{id}/presign/`), `/data/upload/...`, `/storage-data/uploaded/`, `/data/local-files/`, Django admin, django-rq, `/docs/api/schema/*`, 정적 파일. 지시 범위(/api/ operation)가 아니다.
- DRF format suffix 변형과 Router `APIRootView`(`/api/`, `/api/dm/`).
- `ml_models`, `ml_model_providers` 앱은 OSS URLconf에 등록되지 않아 /api/ 라우트가 없다.
- LocalFiles 스토리지 라우트는 `ENABLE_LOCAL_FILES_STORAGE`(기본 True) 조건부지만 포함했다.
- 코드는 읽기만 했고 빌드·실행·설치·테스트를 하지 않았다. LLM API 호출 없음.
