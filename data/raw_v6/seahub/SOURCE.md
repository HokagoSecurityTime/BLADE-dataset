# Seafile seahub — test_v6 hold-out 후보 추출 (data/raw_v6/seahub)

## 저장소

- URL: https://github.com/haiwen/seahub
- 태그: `v14.0.9-server` (같은 커밋에 `v14.0.8-server` 태그도 붙어 있어 `git describe`는 v14.0.8-server를 보인다; `git tag --points-at HEAD`로 v14.0.9-server 확인)
- 커밋 SHA: `0841826c7ce738caf92121d94d7741ba0f2373d5`
- clone: `datasets/blade/raw/opensource/test_v6_candidates/seahub/` 읽기 전용. 수정·빌드·실행·의존성 설치 없음.
- 라이선스: Apache-2.0. `LICENSE.txt` 요지: "Copyright (c) 2016 Seafile Ltd. / Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. ... Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND ..."
- 추출 도구: `extract_seahub.py` (정적 추출, `python -I data/raw_v6/seahub/extract_seahub.py`). LLM API 호출·모델 추론 없음. 라벨은 전부 초안이며 사람이 확정한다.

## 산출

- `candidates.jsonl`: 94건 (method, path 유일; 상한 93→110 사용자 결정 2026-11-03, 2차 갱신 2026-11-03: membership_required 보충 +1, `is_repo_admin` 단독 3건 owner_or_admin → manual_review_required). `oas_status: "generated"` (저장소에 OpenAPI 명세 없음). 경로는 `seahub/urls.py`·`seahub/api2/urls.py`·`seahub/organizations/api_urls.py` 정규식을 `/api/v2.1/...`, `/api2/...`로 그대로 옮기고 `(?P<name>...)`·`<int:name>`은 `{name}`으로, 끝 슬래시는 정규식대로 유지했다. 파라미터는 URL 그룹 + `request.GET.get(...)`, requestBody는 `request.data.get(...)`/`request.POST.get(...)`/`request.FILES` 키에서 만들었다.
- security: 인증 뷰는 `[{"tokenAuth": []}]` (scheme: apiKey, header `Authorization: Token <api-token>`, `seahub.api2.authentication.TokenAuthentication` 또는 세션 쿠키). 익명 가능 뷰 5건은 `security: []` (public 4 + 조건부 익명 share-link dirents 1).
- 모든 레코드에 `draft_label`, `draft_confidence`, `evidence`(원문 2~4줄, `파일:줄`; 스크립트가 파일 재독으로 일치 검증), `draft_reason`·`auth_summary`(한국어), `known_vulnerable: false`, `advisory: null`, `fix_commit: null`. `permission_doc`은 전부 "" (엔드포인트별 권한 문서 없음; 핸들러 docstring의 'Permission checking:' 문구는 controller_text 안에 원문으로 포함).
- controller_text 길이: 최소 532자, 중앙값 1,443자, 최대 2,985자. 500자 미만 0건, 3,000자 초과 0건.
- 검증(스크립트 `validate()`): 건수 85~110(상한 93→110 사용자 결정 2026-11-03), (method, path) 유일, label 7종, label별 50% 이하, evidence 2~4개와 원문 일치, `EXCLUDE 후보`는 confidence ≤ 0.5.

## 추출 범위와 방법

- 대상: DRF `APIView` 핸들러. `seahub/api2/views.py`(api2 레거시), `seahub/api2/endpoints/*.py`·`endpoints/admin/*.py`·`endpoints/address_book/*.py`(api/v2.1), `seahub/organizations/api/**`(api/v2.1/org). URL 수: api2 73 라우트, api/v2.1 356 라우트(그중 admin 125), org 52 라우트.
- controller_text = 뷰 클래스 헤더(`class`, `authentication_classes`, `permission_classes`, `throttle_classes`) + 데코레이터 포함 메서드 본문(직렬화·응답 조립·예외 처리는 `...`로 축약, 인가 줄은 자르지 않음) + 호출하는 권한 헬퍼·permission class 원문. Python 블록 끝은 들여쓰기 기준으로 계산(`func_end`).
- 선정: membership_required·owner_or_admin·tenant_match 후보를 먼저 전부 모으고(아래 '불확실' 절의 한계 참조), role_required·owner_match·public·manual은 동형 조건별 대표 2~4건. 한 label 최대 23/94(24.5%).

## 인증·인가 구조

- 인증: `seahub/api2/authentication.py:39-140` `TokenAuthentication` (`Authorization: Token <key>`; TokenV2 → Token v1 순, MULTI_TENANCY면 `user.org` 부착) + DRF `SessionAuthentication`. `settings.REST_FRAMEWORK`(`seahub/settings.py:558-570`)에는 DEFAULT_PERMISSION_CLASSES/DEFAULT_AUTHENTICATION_CLASSES가 없어 클래스 미지정 뷰는 DRF 기본(AllowAny, Session+Basic)으로 동작한다.
- permission classes (`seahub/api2/permissions.py`): `IsRepoWritable`(16-30), `IsRepoAccessible`(32-40, `check_permission(repo_id, user)`), `IsRepoOwner`(42-50), `IsGroupMember`(53-60), `CanInviteGuest`(63-68, `ENABLE_GUEST_INVITATION and permissions.can_invite_guest()`), `CanGenerateShareLink`(71-75), `CanGenerateUploadLink`(78-82), `CanSendShareLinkMail`(84-88), `IsProVersion`(90-96), `IsOrgAdminUser`(98-105, `request.user.org.is_staff and org.org_id == view.kwargs['org_id']`). DRF 기본 `IsAuthenticated`, `IsAdminUser`(`request.user.is_staff`). 조직: `seahub/organizations/api/permissions.py:3-12` `IsOrgAdmin`(`request.user.org.is_staff`), 데코레이터 `check_org_admin`(`organizations/api/utils.py:5-19`, org.is_staff AND 경로 org_id == 요청자 org).
- 시스템 관리자 API: `permission_classes = (IsAdminUser,)` + 핸들러 첫 줄 `request.user.admin_permissions.can_manage_user|can_manage_library|can_manage_group|can_view_system_info|can_config_system|can_view_user_log|can_view_statistic|other_permission()` (관리자 역할별 권한, `seahub/role_permissions`). admin 폴더 185개 permission_classes 선언이 모두 IsAdminUser.
- 그룹 헬퍼 (`seahub/group/utils.py`): `is_group_member`(57-72, `ccnet_api.is_group_user`), `is_group_admin`(74-75, `ccnet_api.check_group_staff`), `is_group_owner`(77-82, `group.creator_name == email`), `is_group_admin_or_owner`(84-89). 데코레이터 `api_check_group`(`api2/endpoints/utils.py:34-53`, 그룹 존재만 확인), `api_group_check`(`api2/utils.py:113-149`, 구성원 → 통과, 시스템 is_staff → 통과, 아니면 403).
- 저장소 헬퍼: `check_folder_permission(request, repo_id, path)`(`seahub/views/__init__.py:121-143`) = `seafile_api.check_permission_by_path`(seaf-server RPC; 소유·개인/그룹/공개 공유·폴더 권한 합산, 외부 인가). `get_repo_owner`/`is_repo_owner`(`seahub/utils/repo.py:128-141`), `is_group_repo_staff`(350-359, 부서 소유 저장소의 부서 staff), `is_repo_admin`(`seahub/share/utils.py:39-73`: admin 권한 공유 사용자 OR admin 권한 공유 그룹의 그룹 관리자 OR **저장소 소유자** OR 부서 저장소의 부서 관리자), `permission_check_admin_owner`(`seahub/repo_api_tokens/utils.py:24-37` = is_repo_owner OR is_group_repo_staff). 링크 소유: `FileShare.is_owner`/`UploadLinkShare.is_owner`(`seahub/share/models.py:408-409, 561-562`).
- 역할 기능 권한: `request.user.permissions.can_add_repo|can_add_group|can_share_repo|can_create_wiki|can_generate_share_link|can_use_global_address_book()` (사용자 role별, `seahub/role_permissions`). 라벨링에서는 G1·G3 취지대로 '기능 권한'으로 보고 객체 관계 조건을 우선했으며, AND 결합인 경우 draft_reason에 적고 confidence를 낮췄다.
- 익명 뷰: `Ping`(api2/views.py:158-171), `ObtainAuthToken`(187-247, `permission_classes = ()`), `ServerInfoView`(views_misc.py:10-59), `GroupMembersImportExample`(group_members.py:570-594). 조건부 익명: `ShareLinkDirents`·`ShareLinkUpload`·`ShareLinkUploadDone` 등 share-link 토큰 뷰(`SHARE_LINK_LOGIN_REQUIRED` 설정, 링크 비밀번호 세션, scope 검사).

## 제외한 범위와 이유 (사유별 건수)

| 사유 | 제외 규모 | 내용 |
|---|---:|---|
| 동형 중복 — 시스템 관리자 API (`IsAdminUser` + `admin_permissions.*`) | 라우트 125 중 114 제외 (+ api2 `accounts/{email}`, `two-factor-auth/{email}`) | 대표 11건만 수집(users GET, libraries GET/DELETE, groups GET, sysinfo, organizations GET, share-links GET, license POST, web-settings GET, api2 accounts GET, api2 organization POST). 제외: admin users/{email}/*, ldap-users, user-list, admin-users, devices, device-errors/trusted-ip, libraries/{id}/history·dirents·dirent·history-limit, system-library, default-library, trash-libraries, groups/{id}/*, departments, shares, logs/*, admin-logs, share-links/{token}/*, upload-links/*, admin-role, organizations/{id}/*, institutions/*, logo·favicon·login-background-image, invitations, wikis, address-book/groups, file-scan-records, virus-files, notifications, sys-notifications, sys-user-notifications, terms-and-conditions, work-weixin/*, dingtalk/*, statistics/*, abuse-reports, generate-user-auth-token, revision-tags, user-activities, logs/login·file-audit·file-update·perm-audit·export-excel. |
| 동형 중복 — 조직 관리 API (`IsOrgAdminUser`/`IsOrgAdmin`) | 라우트 52 중 41 제외 | 대표 11건(info GET/PUT, links GET/DELETE, logs/file-access, {org_id}/users GET, users/{email} GET, groups GET, repos GET, devices GET, groups/{gid}/members GET). 제외: statistics/*, saml-config, verify-domain, delete-org, logo, devices-errors, address-book/groups*, search-group, groups/{gid} GET/PUT/DELETE, groups/{gid}/libraries*, group-to-department, move-department, group-owned-libraries*, groups/{gid}/members/{email}, users POST/PUT/DELETE, import-users, invite-users, search-user, set-password, users/{email}/repos·beshared-repos, repos/{id} PUT, trash-libraries*, web-settings, logs/file-update·repo-permission·repo-transfer·group-member-audit, logs/export-excel, admin/log/export-excel(함수 뷰). |
| 동형 중복 — `check_folder_permission`만 쓰는 저장소·파일·폴더 작업(외부 인가 → manual) | endpoints 모듈 37개 + api2/views.py 호출 48곳 중 대표 8 메서드만 수집 | 수집: api2 `repos/{id}` GET, `repos/{id}/dir` GET, `repos/{id}/file` GET, v2.1 `repos/{id}/dir` GET, `file/history`, `trash` GET, `repo-notification-jwt-token`, `smart-link`. 제외: api2 FileView POST/PUT/DELETE, DirView POST/DELETE, file/dir metadata·detail·revision·revert, thumbnail, upload/update-link, blks, starredfiles POST/DELETE, repo-tokens, repo history; v2.1 file.py POST/PUT/DELETE, dir.py POST/DELETE, dir/detail, file/access-log, new_history, commits/{id}·commits/{id}/dir, trash POST, trash2*, repo history, repo-tags*, file-tags*, tagged-files, tags/*, file participants, related-users, zip-task, file-uploaded-bytes, share-info, image-rotate, office-suite, file comments*, repo share-links POST, upload-links POST, copy-move-task, move-folder-merge, monitored-repos(check_permission_by_path), repo set-password POST, starred-items POST, repo-folder-share-info, group-owned-libraries user-share-in-libraries DELETE, smart-links/{token}. |
| 동형 중복 — 그룹 안 역할(`is_group_admin*`/`is_group_owner`) | 약 35 메서드 | 수집 13건(members POST, members/{email} PUT, group PUT/DELETE, members/bulk, invite-links GET, group-owned-libraries POST/PUT/transfer, user-folder-permission GET, address-book sub-groups 등). 제외: invite-links POST, invite-links/{token} DELETE, members/import, address-book search-member, group-owned-libraries/{id} DELETE, user/group-folder-permission POST/PUT/DELETE, user-share·group-share GET/POST/PUT/DELETE, api2 groups PUT(생성, can_add_group)/DELETE/POST, api2 groups/{id}/members PUT/DELETE, wikis2 POST(그룹 위키는 is_group_admin). |
| 동형 중복 — 본인 자원(`request.user.username` 고정, 관리자 우회 없음) | 약 22 메서드 | 수집 23건. 제외: api2 starredfiles GET, api2 groups GET, api2 shared-links GET/DELETE, api2 account/info PUT, api2 devices DELETE, api2 shared-repos GET, api2 beshared-repos GET, upload-links GET·{token} DELETE·clean-invalid, share-links clean-invalid·{token} GET/PUT, starred-items DELETE, notifications PUT/DELETE, sdoc-notifications*, all-notifications, sys-user-notifications/unseen, deleted-repos DELETE, invitations GET/POST·batch, invitations/{token} GET·revoke, webdav-secret GET, user-list, user/convert-to-team, shareable-groups, all-groups, search-group, wikis GET, wikis/{id} PUT/DELETE/POST(wiki.username == 본인), abuse-reports POST. |
| 규약상 추출 제외 — 별도 인증 체계·외부 서비스·내부 API | 약 60 라우트 | `via-repo-token/*` 25(저장소 API 토큰 인증, `RepoAPITokens` 권한), `internal/*` 9(내부 서비스 JWT), share-link 토큰 하위 11 중 10(upload·upload/done·save-file/items-to-repo·online-office-lock·repo-tags·tagged-files·user-auth·email-auth; dirents 1건만 조건부 익명 manual 대표로 수집), upload-links/{token}/upload 1, `ocm/*` 7(OCM 연합 공유), `wopi/`, `two-factor-auth/{email}`, `client-sso-link*`, `device-wiped`, `regdevice`, `logout-device`, `client-login`, `seadoc/`·`exdraw/`·`ai/`·`repos/{id}/metadata/` include(별도 앱, 미조사), `search`/`items-search`/`search-file`/`published-repo-search`(IsProVersion + 외부 검색 서비스), `subscription/plans`·`logs`(수집한 `subscription` GET과 동형). |
| 복합 조건(서로 다른 유형 AND·분기)로 manual 동형 또는 추출 제외 | 약 45 메서드 | 수집: `beshared-repos/{id}` DELETE(share_type별 분기), api2 `dir/shared_items` PUT(소유자/admin AND 그룹 구성원·부서 관리자). 제외: `repos/batch*` 11(저장소별 owner OR admin AND 대상 그룹 구성원), `wiki2/*` 22(`check_wiki_permission` RPC + `is_group_wiki` 분기 + 공개 설정), `multi-share-links*` 3, `share-links` POST(생성, 폴더 권한·역할 분기), `batch-lock-file`/`batch-unlock-file`(파일별 잠금 소유자 OR 저장소 admin), `repo-folder-share-info`, `custom-share-permissions*`(is_repo_admin 동형), `shared/invitations*`, `revision-tags/*`, `repos/{id}/repo-api-tokens/{app_name}` PUT/DELETE·`repo-api-tokens` POST·`set-password` PUT·`send-new-password`·api2 `history-limit` GET/PUT(수집한 revert·repo-api-tokens GET과 같은 '소유자 OR 부서 관리자' 패턴). |
| 생성 요청·객체 없음(의도 불명) | 약 8 메서드 | api2 `repos` POST·`repos/public` GET/POST·`default-repo`, v2.1 `repos` GET/POST(`ReposView`, 조회 모드별 목록), `groups` POST(can_add_group), `markdown-lint`, `query-zip-progress`·`cancel-zip-task`·`query-copy-move-progress`·`query-io-status`(토큰·작업 id 기반), `abuse-reports` POST(인증 선택). |

- 50% 상한 조정은 필요 없었다(최대 owner_match 23/94).

## draft_label 건수 (94)

| label | 건수 | 1차(93) 대비 |
|---|---:|---|
| owner_match | 23 | - |
| role_required | 22 | - |
| manual_review_required | 17 | +3 (B: is_repo_admin 단독 relabel) |
| tenant_match | 11 | - |
| owner_or_admin | 9 | −3 (B) |
| membership_required | 8 | +1 (A: POST `/api2/groups/{group_id}/repos/`) |
| public | 4 | - |

- membership_required (8): GET `/api/v2.1/groups/{group_id}/`, `.../members/`, `.../search-member/`, `.../members/{email}/`, `.../libraries/`(모두 `is_group_member`만), POST `.../libraries/`(can_add_repo AND is_group_member, 0.6), GET `/api2/groups/{group_id}/repos/`(`api_group_check`: 구성원 OR 시스템 is_staff, 0.8), **POST `/api2/groups/{group_id}/repos/`**(2차 추가, `api_group_check`만, 0.7). **목표 15에 미달(8)**: 아래 'membership_required 보충 결과' 절.
- owner_or_admin (9): 그룹 구성원 DELETE(본인 탈퇴 OR 그룹 owner/admin), 그룹 저장소 공유 해제 2건(그룹 admin OR `repo_owner == username` OR is_repo_admin — 명시적 소유자 비교가 OR로 있어 유지), shared-repos DELETE 2건(is_staff OR 소유자), dir shared_items POST(`repo_owner == username` OR is_repo_admin — 명시적 소유자 비교 있어 유지), '소유자 OR 부서 관리자' 패턴 3건(revert, repo-api-tokens GET, wikis POST — 전부 `EXCLUDE 후보`). `is_repo_admin`만 쓰던 webhooks GET·auto-delete PUT·trash DELETE 3건은 manual로 옮겼다(아래 'B' 절).

## 2차 갱신 (2026-11-03, 사용자 결정 — 상한 93→110)

### A. membership_required 보충 결과: +1 (8/15, 목표 미달 — 실제 수가 그만큼이다)

클론의 `is_group_member` 호출 전수(`grep -rn "is_group_member("`: api2/views.py, api2/utils.py, api2/permissions.py, organizations/api/group_members.py, views/file.py, views/ajax.py, group/views.py, group/utils.py, endpoints/{group_owned_libraries, group_members, group_libraries, groups, dir_shared_items, departments, repos_batch}.py, endpoints/admin/{account, groups, group_members}.py)와 `api_group_check`·`IsGroupMember`·`ccnet_api.is_group_user` 사용처를 모두 확인했다. 구성원 조회가 **결정 조건**인 DRF 엔드포인트는 기존 7건 + 아래 1건이 전부다.

| 추가 | 근거 | label·conf |
|---|---|---|
| POST `/api2/groups/{group_id}/repos/` (`GroupRepos.post`, `seahub/api2/views.py:4807-4808`) | `@api_group_check`(`seahub/api2/utils.py:132-147`: `is_group_member` → 통과, `request.user.is_staff` → 통과, 그 외 403)만. 본문에 역할·소유자·can_add_repo 검사 없음. | membership_required 0.7 (생성 요청이라 EXCLUDE 대안 적음) |

- 같은 뷰 클래스 `GroupRepos`의 GET과 POST 두 메서드를 모두 넣었다(규격의 '같은 view class 두 엔드포인트' 명시).
- 검토했으나 membership으로 넣지 않은 것(사유):
  - `is_group_member(group_id, email)`에서 `email`이 요청자가 아닌 **대상 사용자**인 검사 — group_members.py:109(추가 대상)·185/212/240(대상 구성원 여부)·354/513(import·bulk 대상), groups.py:345(새 소유자), organizations/api/group_members.py 130/198/250, admin/*: 요청자-그룹 관계가 아니라 대상 검증.
  - `GroupOwnedLibraryTransferView` PUT(group_owned_libraries.py:1465·1485): `is_group_admin(현재 그룹)`이 결정 조건, 이전 대상 부서 구성원은 추가 조건 → role_required 유지.
  - `ReposBatchView` POST `/api/v2.1/repos/batch/` share_type=group(repos_batch.py:262): 저장소별 소유자/admin AND 대상 그룹 구성원(서로 다른 유형 AND) → 기존 제외 유지(manual 동형).
  - `DirSharedItemsEndpoint` PUT(dir_shared_items.py:464): 소유자/admin AND 설정에 따른 구성원·부서 관리자 → manual(기존).
  - `Group` PUT owner 변경(groups.py:331-348): `is_group_owner`(역할)가 결정 조건.
  - `GET /api/v2.1/departments/`(departments.py:66): 대상 그룹 지정 없이 본인 소속 부서 필터 → owner_match 0.65 유지(membership 대안 기재).
  - `IsGroupMember` permission class(api2/permissions.py:53-60): 정의만 있고 사용하는 뷰 없음.
  - `seahub/views/file.py:573`·`seahub/views/ajax.py:112`(`convert_repo_path_when_can_not_view_*`): 라우트가 없는 내부 헬퍼(`view_lib_file`이 `check_folder_permission` 실패 시 호출)이고, `group_id`가 변환 결과에 있을 때만 `is_group_member` → `check_folder_permission` 순서로 검사(조건부). DRF API가 아니며 조건부 분기라 제외.
  - `seahub/group/views.py:99` `group_check` 데코레이터: 사용하는 뷰 없음(`group/urls.py`는 `group_remove`만). `seahub/avatar/views.py` 그룹 아바타: `check_group_staff`(역할)이고 Django 폼 뷰.
  - `AddressBookDepartmentMembers` GET(address_book/departments.py:91-109): 조직 컨텍스트면 부서가 요청자 조직 소속인지(테넌트), 아니면 인증만 → 구성원 조회 아님(조건부 tenant/인증만, 추출 안 함).
  - wiki2(`check_wiki_permission` = seaf-server RPC, 그룹 위키 생성·관리는 `is_group_admin`), multi-share-links(사용자 그룹 목록은 폴더 권한 금지 여부 확인용 필터), shareable-groups·all-groups(본인/전체 목록) → 구성원 결정 조건 아님.
- 결론: seahub에서 "(요청자, 그룹) 구성원이면 허용"으로 끝나는 API는 그룹 정보·구성원·그룹 저장소 조회/생성 계열 8건이 전부다. 나머지 그룹 API는 그룹 안 역할(G3)이고, 저장소·파일 접근은 `check_folder_permission`(외부 인가)이다. 수를 맞추기 위한 중복 투입은 하지 않았다.

### B. `is_repo_admin` 단독 → manual_review_required (보충 규약 2 seahub 동일 적용)

`is_repo_admin(username, repo_id)`(`seahub/share/utils.py:39-73`) = 저장소 소유자 OR ACL 공유 관리 권한(admin 권한으로 공유받은 사용자·admin 권한으로 공유된 그룹의 그룹 관리자) OR 부서 관리자 — 서로 다른 유형의 OR(G6). 핸들러에 **별도의 명시적 소유자 비교가 없고** is_repo_admin만 결정하는 레코드를 manual로 바꿨다.

| 레코드 | 핸들러 조건 | 전 | 후 |
|---|---|---|---|
| GET `/api/v2.1/repos/{repo_id}/webhooks/` (webhook.py:38-40) | `is_repo_admin`만 | owner_or_admin 0.7 | manual_review_required 0.8 |
| PUT `/api/v2.1/repos/{repo_id}/auto-delete/` (repo_auto_delete.py:77-80) | `is_repo_admin`만 | owner_or_admin 0.7 | manual_review_required 0.8 |
| DELETE `/api/v2.1/repos/{repo_id}/trash/` (repo_trash.py:231-246) | ENABLE_USER_CLEAN_TRASH AND `is_repo_admin` AND NOT org DISABLE_ORG_USER_CLEAN_TRASH | owner_or_admin 0.6 | manual_review_required 0.8 (설정 게이트도 manual 근거) |

유지(명시적 `repo_owner == username` 비교가 is_repo_admin과 OR로 함께 있음 → owner_or_admin 그대로): DELETE `/api/v2.1/groups/{group_id}/libraries/{repo_id}/`(group_libraries.py:300-308 `is_group_admin OR repo_owner == username OR is_repo_admin`), DELETE `/api2/groups/{group_id}/repos/{repo_id}/`(api2/views.py:4985 `group.is_staff OR repo_owner == username OR is_repo_admin`), POST `/api2/repos/{repo_id}/dir/shared_items/`(dir_shared_items.py:246-248 `repo_owner == username OR is_repo_admin`). 다른 이유로 이미 manual·role인 레코드는 건드리지 않았다. 제외 목록의 `custom-share-permissions*`·`repo-folder-share-info`(is_repo_admin 단독 동형)는 수집하지 않은 상태 그대로다.
- tenant_match (11): 경로에 org_id가 없는 `/api/v2.1/org/admin/{info GET/PUT, links GET, links/{token} DELETE, logs/file-access}` 5건(`IsOrgAdmin` + `request.user.org` 고정, 0.85), 경로에 org_id가 있는 `/api/v2.1/org/{org_id}/admin/{users, users/{email}, groups, repos, devices, groups/{gid}/members}` 6건(`IsOrgAdminUser`/`check_org_admin`이 요청자 org == 경로 org 비교, 0.75~0.8). 보충 규약 4에 따라 조직 관리자 역할은 기능 권한으로 보았다.
- role_required (22): 시스템 관리자 11(IsAdminUser + admin_permissions), 그룹 안 역할 11(is_group_admin_or_owner / is_group_owner / is_group_admin; group-owned-libraries POST는 can_add_repo AND is_group_admin 0.75, transfer는 부서 이전 시 구성원 추가 조건 0.75).
- owner_match (23): 본인 프로필·비밀번호·아바타·WebDAV 비밀·즐겨찾기·기기·알림·활동·그룹 목록·공유 목록·삭제된 저장소·공유 링크(CanGenerateShareLink 기능 권한 병존 0.75~0.85)·초대, 저장소 소유자 전용 3건(api2 repos DELETE, owner GET/PUT), shared-repos PUT(can_share_repo AND 소유자 0.7), departments GET(본인 소속 부서 필터 0.65).
- public (4): api2 ping, auth-token, server-info, group-members-import-example — 전부 permission class 미지정 또는 `()`로 DRF 기본 AllowAny.
- manual_review_required (17): `check_folder_permission`만인 저장소·파일 조회 8건(외부 인가, 보충 3), share_type별 분기 1(beshared-repos DELETE), 소유자/admin AND 그룹 구성원·부서 관리자 1(dir shared_items PUT), 인증만·객체 없음 2(auth/ping, search-user), 조건부 익명 1(share-links/{token}/dirents), 컨텍스트별 허용 주체 변경·구독 1(subscription GET), **`is_repo_admin` 단독 3건**(webhooks GET, auto-delete PUT, trash DELETE — 소유자 OR ACL admin 공유 OR 부서 관리자의 OR 유형 상이, 보충 규약 2 seahub 동일 적용).

## 불확실한 엔드포인트 (검수 시 주의)

- **`EXCLUDE 후보` 3건** (confidence 0.5, 라벨 owner_or_admin): POST `/api/v2.1/repos/{repo_id}/commits/{commit_id}/revert/`, GET `/api/v2.1/repos/{repo_id}/repo-api-tokens/` — 둘 다 "is_repo_owner OR (저장소 소유자가 `<id>@seafile_group` 부서면 그 부서의 is_group_admin/check_group_staff)". 부서 관리자를 그룹 소유 저장소의 소유자 대리(G4 owner_match)로 볼지 관리자 우회(G5)로 볼지 경계. POST `/api/v2.1/wikis/` — can_create_wiki AND can_generate_share_link(역할 기능 권한 2개) AND (소유자 OR is_repo_admin OR is_group_repo_staff); 기능 권한 AND를 독립 조건으로 보면 manual(보류 3).
- `is_repo_admin` 계열: 단독 3건(webhooks GET, auto-delete PUT, trash DELETE)은 2차 갱신에서 manual 0.8로 확정(위 'B' 절). 명시적 소유자 비교가 OR로 함께 있는 3건(그룹 저장소 공유 해제 2건, dir shared_items POST; 0.7~0.8)은 owner_or_admin 유지 — 다만 OR 안에 is_repo_admin(ACL admin 공유·부서 관리자)이 섞여 있어 검수자가 B와 같은 논리로 manual로 볼 여지가 있다.
- POST `/api2/groups/{group_id}/repos/` (membership_required 0.7, 2차 추가): `api_group_check`(구성원 OR 시스템 is_staff)만. 생성 요청이지만 대상 그룹이 경로에 있어 Ghost POST /posts(객체 없음) 선례와 다르다고 보았다. 생성 요청으로 EXCLUDE할 수도 있다.
- POST `/api/v2.1/groups/{group_id}/libraries/` (membership_required 0.6): can_add_repo(전역 역할 기능 권한) AND is_group_member. G1의 '기능 권한 병존' 취지로 membership을 택했으나 보류 3(독립 조건 AND) 적용 시 manual.
- 기능 권한 AND 패턴 공통: DELETE `/api/v2.1/shared-repos/{repo_id}/`(can_share_repo AND (is_staff OR owner), owner_or_admin 0.7), PUT `/api/v2.1/shared-repos/{repo_id}/`(can_share_repo AND owner, owner_match 0.7), POST `/api/v2.1/groups/{group_id}/group-owned-libraries/`(can_add_repo AND is_group_admin, role_required 0.75), GET `/api/v2.1/share-links/`·DELETE `/api/v2.1/share-links/{token}/`(CanGenerateShareLink, owner_match), DELETE `/api/v2.1/invitations/{token}/`(CanInviteGuest = 설정 AND 역할 권한, owner_match 0.85).
- tenant_match 6건(`/api/v2.1/org/{org_id}/admin/...`, 0.75~0.8): 경로에 대상 org_id가 있어 G1 문구("경로·본문에 대상 테넌트 ID 없음")와 다르지만 보충 규약 4(org 관리 API → tenant_match)와 `IsOrgAdminUser`의 '요청자 org == 경로 org' 비교를 근거로 tenant_match. 역할(org.is_staff)을 결정 조건으로 보면 role_required.
- GET `/api2/groups/{group_id}/repos/` (membership_required 0.8): `api_group_check`가 구성원 OR 시스템 관리자(`request.user.is_staff`)를 허용. G2 "구성원 OR 관리자 우회도 membership_required" 적용.
- GET `/api/v2.1/departments/` (owner_match 0.65): 대상 그룹 지정 없이 본인이 구성원인 부서만 필터. membership_required 대안.
- GET `/api/v2.1/subscription/` (manual 0.7): 조직 컨텍스트면 org.is_staff, 개인이면 인증만. owner_match(개인)/role_required(조직) 대안.
- DELETE `/api/v2.1/groups/{group_id}/members/{email}/` (owner_or_admin 0.85): 본인 탈퇴 OR 그룹 owner/admin. 지시문 패턴이지만 '관리자'가 전역 아닌 그룹 안 역할이다.
- public 4건: `settings.REST_FRAMEWORK`에 DEFAULT_PERMISSION_CLASSES가 없다는 점(DRF 기본 AllowAny)을 근거로 했다. `group-members-import-example`(0.8)은 같은 파일의 다른 뷰가 모두 IsAuthenticated를 선언해 의도적 익명으로 보았으나 누락 가능성은 검수 대상.

## test_v5와의 차이

- test_v6 seahub 분량은 **tenant_match 11건을 포함**한다(test_v5는 tenant_match 0건). 조직(org) 관리 API의 `IsOrgAdmin`/`IsOrgAdminUser` + `request.user.org` 필터 구조를 보충 규약 4에 따라 tenant_match로 라벨링했다. 조립 시 SOURCE.md·DATA_CARD에 이 점을 명시해야 한다.
- membership_required는 2차 보충 후 8건으로 목표(15)에 미달하며 전부 그룹 정보·구성원·그룹 저장소 조회/생성 계열이다. 클론 전수 확인 결과 구성원 조회가 결정 조건인 API가 그만큼이라 수를 채우지 않았다(위 '2차 갱신 A' 절).
