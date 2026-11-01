# NetBox 엔드포인트 발췌 규칙 (Django REST 적응판 R1'~R5') — held-out test 전용

대상: netbox-community/netbox v4.7.3, 커밋 `3cd2c1d6469caed6c50e80eddd4cde863e0e2cf5`, Apache-2.0(LICENSE.txt·NOTICE). 클론 `datasets/blade/raw/opensource/netbox/`(git 미추적). 정적 분석만, 수정·실행 없음. **프로젝트 단위 held-out: NetBox 레코드는 어떤 버전의 train·val·프롬프트 예시에도 쓰지 않는다.** 라벨은 사람 확정 정답이며, LLM 라벨은 `llm_reference_label` 참고 열에만 둔다.

## Gitea 규칙과의 대응

| Gitea(R1~R5) | NetBox(R1'~R5') |
|---|---|
| R1 api.go 라우트 트리 파싱 | R1' 저장소 생성 OpenAPI(`contrib/openapi.json`, drf-spectacular) 1,256 operation을 출처로 삼고, operationId `<app>_<basename>_<action>`과 `<app>/api/urls.py`의 `router.register(prefix, ViewSet)`·`path(..., View.as_view())`로 ViewSet을 해석한다. 비표준 경로(`{id}/elevation/` 등)는 경로 꼬리를 action 이름으로 쓴다 |
| R2 METHOD+경로 정규화 매칭 | R2' OAS가 출처이므로 매칭 단계 없음. 레코드 id = `netbox:<method>:<path>` |
| R3 미들웨어 정의 + 핸들러 발췌 | R3' (a) 프레임워크 고정 주석: `TokenPermissions`(메서드별 Django 모델 권한 view/add/change/delete, 토큰 write 플래그, LOGIN_REQUIRED 시 익명 읽기 불가) + `BaseViewSet.initial()`의 `queryset.restrict(user, action)`(관리자가 설정한 ObjectPermission 제약으로 객체 필터링, superuser 우회) (b) ViewSet 클래스 헤더·클래스 속성(queryset, serializer_class, filterset_class, permission_classes, authentication_classes) (c) 해당 action이 커스텀 @action이면 그 메서드, get_queryset/get_object/perform_* 오버라이드가 있으면 그 메서드. 60줄 상한 |
| R4 bind·기능 플래그는 이름만 | R4' meta에 app, viewset, action, permission_override, custom_action, bases 기록 |
| R5 헬퍼 등록 라우트 제외 | R5' 해결 불가 3건(`/api/authentication-check/`, `/api/schema/`, `/api/status/`: urls.py 밖의 특수 뷰)은 controller_status=unresolved로 남긴다 |

## 결과 (v4.7.3)

| 항목 | 값 |
|---|---|
| OAS operation = 레코드 | 1,256 (dcim 481, extras 180, ipam 172, circuits 101, vpn 90, virtualization 64, users 56, tenancy 54, core 28, wireless 27, 기타 3) |
| 해석된 ViewSet | 145 |
| 미해결 | 3 |
| 출력 | `datasets/blade/processed/opensource/netbox_v4.7.3_endpoints.jsonl`, manifest |

표준 CRUD 9 action(list/create/retrieve/update/partial_update/destroy/bulk_*)은 ViewSet마다 동일한 프레임워크 권한 패턴(모델 권한 + 객체 제약)을 따르므로 코드 발췌가 ViewSet 단위로 반복된다. 사람 정답도 ViewSet×action 단위로 결정하면 된다.

## held-out 검수 범위 제안 (R5', `meta.heldout_subset_proposed=true`, 185건)

| 선정 이유 | 건수 |
|---|---:|
| 비표준 경로(커스텀 @action: trace/paths/elevation/sync/render/enqueue 등, 특수 뷰) | 43 |
| permission_classes 명시 오버라이드(IsSuperuser, IsAuthenticated, [] 등) | 10 |
| users 앱 전체(users/groups/tokens/permissions/owners/config) | 56 |
| 앱별 대표 모델 1개의 표준 CRUD(dcim devices, ipam prefixes, circuits, virtual-machines, tunnels, wireless-lans, tenants, journal-entries, data-sources) | 97 |

(합계 185건은 이유 중복 제거 후. 나머지 1,071건은 ViewSet 단위 패턴이 같으므로 검수 범위에서 제외하되 레코드는 보존.) 이 범위와 LLM 참고 라벨링(185건, gpt-4o-mini + v3.0.1 + oas_code, 예상 $0.10 이하)은 사용자 승인 후 진행한다.

## 라벨 기준 메모(검수자용)

- 표준 CRUD는 "모델 권한 보유 + 관리자 설정 객체 제약"이 실제 조건이다. 6종 중 어느 하나로 단정하기 어려우면(제약이 배포별 설정) v3.0 규칙상 manual_review_required가 기본이며, `permission_classes=[IsSuperuser]`는 role_required, `[]`(토큰 발급 등)는 설명에 따라 public/manual, `IsAuthenticated`만 있으면 manual(인증만)이다.
- LOGIN_REQUIRED=False 배포에서는 GET이 익명 허용이므로 visibility/설정 의존(조건부 접근)이다. 이 역시 manual 기준으로 검수한다.
