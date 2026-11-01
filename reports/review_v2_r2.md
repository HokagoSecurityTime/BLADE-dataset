# data-v2 r2 — 규칙 수정·재적용 + VIS 중복 축소 시뮬레이션 (동결 전) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl a99d30da2d29907e…, val_v30.jsonl 62bdadb29cae7aaf…, test_v30.jsonl 9bd47216575afc60…, policy_label_v3.0.1.md d0913c27b5de185e…. 입력 train_v2_draft_r1.jsonl(불변) → 출력 train_v2_draft_r2.jsonl(971). 검수 정정 1건(rule_id=human_review_v2_fix): gitea:get:/repos/{owner}/{repo}/issues/{index}/subscriptions/check manual_review_required → owner_match.

규칙 적용 순서: 사람 검수(정정 포함) > R2'(쓰기 메서드 + 쓰기 권한 미들웨어 → role_required) > R3'(public 재판정: SELF(데이터 범위) → admin → VIS → AUTH_ANY; public 유지는 reqToken 없음 AND 가시성 미들웨어 없음) > R1'(SELF 분리: 데이터 범위 → owner_match, 행위자 → manual) > R4(인증·인가 미들웨어 없음 → public). 데이터 범위 함수명 상수 DATA_SCOPE_FN=('Star', 'Watch', 'Subscription', 'Subscribe', 'Stopwatch', 'Notification', 'FindNotificationOptions', 'TrackedTime'), 행위자 접두사 ACTOR_PREFIX=('Create', 'Update', 'Submit', 'Merge', 'Transfer', 'Generate', 'Dispatch', 'Edit', 'Delete', 'Add', 'Remove').

## 1. 재검증 (검수 52건, 정정 반영, 사람 라벨 가림, draft 원본 상태에 적용)

| 규칙 | 발동 | 일치 | 정밀도 | 판정 |
|---|---:|---:|---:|---:|
| R1_self_split | 15 | 15 | 1.0 | 적용 |
| R2_write_mw | 1 | 1 | 1.0 | 적용 |
| R3_public_order | 9 | 7 | 0.7778 | 미적용(후보만) |
| R4_noauth_public | 1 | 1 | 1.0 | 적용 |

R1_self_split 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:post:/user/emails | owner_match | owner_match | ○ | SELF routers/api/v1/user/email.go:43 "AddEmailAddresses(ctx, ctx.Doer," |
| gitea:get:/user/blocks/{username} | owner_match | owner_match | ○ | SELF routers/api/v1/user/block.go:33 "CheckUserBlock(ctx, ctx.Doer)" |
| gitea:get:/user/actions/runners/{runner_id} | owner_match | owner_match | ○ | SELF routers/api/v1/user/runners.go:52 "shared.GetRunner(ctx, ctx.Doer.ID" |
| gitea:patch:/user/actions/runners/{runner_id} | owner_match | owner_match | ○ | SELF routers/api/v1/user/runners.go:98 "shared.UpdateRunner(ctx, ctx.Doer.ID" |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/subscriptions/check | owner_match | owner_match | ○ | VIS+SELF data-scope routers/api/v1/repo/issue_subscription.go:157 "CheckIssueWatch(ctx, ctx.Doer," |
| gitea:get:/user/following | owner_match | owner_match | ○ | SELF routers/api/v1/user/follower.go:106 "listUserFollowing(ctx, ctx.Doer)" |
| gitea:post:/user/hooks | owner_match | owner_match | ○ | SELF routers/api/v1/user/hook.go:79 "AddOwnerHook(
		ctx,
		ctx.Doer," |
| gitea:patch:/user/hooks/{id} | owner_match | owner_match | ○ | SELF routers/api/v1/user/hook.go:105 "EditOwnerHook(
		ctx,
		ctx.Doer," |
| gitea:delete:/user/blocks/{username} | owner_match | owner_match | ○ | SELF routers/api/v1/user/block.go:77 "UnblockUser(ctx, ctx.Doer," |
| gitea:get:/user/orgs | owner_match | owner_match | ○ | SELF routers/api/v1/org/org.go:63 "listUserOrgs(ctx, ctx.Doer)" |
| gitea:put:/repos/{owner}/{repo}/notifications | owner_match | owner_match | ○ | VIS+SELF data-scope routers/api/v1/notify/repo.go:135 "UserID:            ctx.Doer.ID" |
| gitea:post:/user/avatar | owner_match | owner_match | ○ | SELF routers/api/v1/user/avatar.go:17 "UploadAvatar(ctx, ctx.Doer," |
| gitea:get:/notifications/new | owner_match | owner_match | ○ | SELF routers/api/v1/notify/notifications.go:18 "UserID: ctx.Doer.ID" |
| gitea:put:/user/blocks/{username} | owner_match | owner_match | ○ | SELF routers/api/v1/user/block.go:52 "BlockUser(ctx, ctx.Doer)" |
| gitea:get:/user/gpg_keys | owner_match | owner_match | ○ | SELF routers/api/v1/user/gpg_key.go:76 "listGPGKeys(ctx, ctx.Doer.ID," |

R2_write_mw 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:delete:/repos/{owner}/{repo}/actions/artifacts/{artifact_id} | role_required | role_required | ○ | write DELETE + ['reqRepoWriter'] -> role_required (no restore) |

R3_public_order 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:get:/repos/{owner}/{repo}/actions/workflows/{workflow_id} | manual_review_required | manual_review_required | ○ | VIS ['repoAssignment', 'reqRepoReader'] |
| gitea:get:/repos/{owner}/{repo}/collaborators | manual_review_required | manual_review_required | ○ | VIS ['repoAssignment', 'reqAnyRepoReader'] |
| gitea:get:/repos/{owner}/{repo}/keys | role_required | role_required | ○ | ['reqAdmin'] |
| gitea:get:/repos/{owner}/{repo}/notifications | manual_review_required | owner_match | ✗ | VIS ['repoAssignment'] |
| gitea:get:/repos/{owner}/{repo}/teams | manual_review_required | manual_review_required | ○ | VIS ['repoAssignment', 'reqAnyRepoReader'] |
| gitea:get:/repos/{owner}/{repo}/times | manual_review_required | owner_or_admin | ✗ | VIS ['repoAssignment'] |
| gitea:get:/user/keys | owner_match | owner_match | ○ | SELF routers/api/v1/user/key.go:102 "listPublicKeys(ctx, ctx.Doer)" |
| gitea:get:/users/{username}/keys | manual_review_required | manual_review_required | ○ | AUTH_ANY: reqToken without authorization middleware |
| gitea:post:/markdown | manual_review_required | manual_review_required | ○ | AUTH_ANY: reqToken without authorization middleware |

R4_noauth_public 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:get:/settings/attachment | public | public | ○ | chain ['sudo']: no authn/authz middleware |

## 2. 적용 건수 (r1 이후 추가 변경)

| rule_id | 변경 건수 |
|---|---:|
| human_review_v2_fix | 1 |
| R1_self_split | 8 |
| R2_write_mw | 0 |
| R3_public_order | 0 |
| R4_noauth_public | 0 |

### R2_write_mw 변경 없이 목록만 (1건)

| id | 사유 |
|---|---:|
| gitea:post:/repos/{owner}/{repo}/file-contents | write POST without write-permission middleware; chain ['sudo', 'tokenRequiresScopes', 'repoAssignment', 'checkTokenPubli |

### R1_self_split 변경 없이 목록만 (9건)

| id | 사유 |
|---|---:|
| gitea:post:/repos/{template_owner}/{template_repo}/generate | VIS+SELF actor "GenerateRepository(ctx, ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches | VIS+SELF actor "DispatchActionWorkflow(ctx, ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/releases | VIS+SELF actor "UpdateRelease(ctx, ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/merge | VIS+SELF other "CheckPullMergeable(ctx, ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/reviews | VIS+SELF actor "CreateCodeComment(ctx,
			ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/reviews/{id} | VIS+SELF actor "SubmitReview(ctx, ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/comments/{id}/replies | VIS+SELF actor "CreateCodeComment(ctx,
		ctx.Doer," |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/comments | VIS+SELF actor "CreateIssueComment(ctx, ctx.Doer," |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/timeline | VIS+SELF other "isXRefCommentAccessible(ctx, ctx.Doer," |

## 3. 변경 전후 label 분포 (r1 → r2)

| label | 전체 r1 | 전체 r2 | 코드 있음 r1 | 코드 있음 r2 | Gitea r1 | Gitea r2 |
|---|---:|---:|---:|---:|---:|---:|
| public | 53 | 53 | 34 | 34 | 18 | 18 |
| role_required | 164 | 164 | 60 | 60 | 40 | 40 |
| membership_required | 58 | 58 | 33 | 33 | 11 | 11 |
| tenant_match | 52 | 52 | 20 | 20 | 0 | 0 |
| owner_match | 231 | 240 | 105 | 114 | 85 | 94 |
| owner_or_admin | 35 | 35 | 34 | 34 | 3 | 3 |
| manual_review_required | 378 | 369 | 274 | 265 | 214 | 205 |
| 합계 | 971 | 971 | 560 | 560 | 371 | 371 |

코드 있는 레코드 manual 비율: 48.9% → 47.3%. Gitea manual 214 → 205.

## 4. 남은 Gitea manual 사유 분포

| 사유 | 건수 |
|---|---:|
| VIS | 147 |
| VIS(검수) | 16 |
| AUTH_ANY(객체 경로 있음) | 12 |
| 기타 | 10 |
| AUTH_ANY | 8 |
| 복합(VIS+SELF actor) | 7 |
| AUTH_ANY(검수) | 3 |
| 복합(VIS+SELF other) | 2 |

## 5. VIS 중복 축소 시뮬레이션 (라벨 변경·적용 없음)

대상: 남은 Gitea manual 중 VIS·VIS(검수)·복합 172건. 시그니처 = HTTP 메서드 + 정규화한 미들웨어 이름 집합(sudo·tokenRequiresScopes·checkTokenPublicOnly 제외). 그룹 53개.

| 메서드 | 미들웨어 시그니처 | 건수 |
|---|---:|---:|
| GET | context.ReferencesGitRepo, repoAssignment, reqRepoReader | 20 |
| GET | repoAssignment, reqRepoReader | 19 |
| GET | mustEnableIssuesOrPulls, repoAssignment | 13 |
| GET | context.ReferencesGitRepo, mustAllowPulls, repoAssignment, reqRepoReader | 11 |
| GET | repoAssignment | 10 |
| GET | repoAssignment, reqAnyRepoReader, reqToken | 6 |
| POST | context.ReferencesGitRepo, mustAllowPulls, repoAssignment, reqRepoReader, reqToken | 6 |
| DELETE | mustEnableIssuesOrPulls, repoAssignment, reqToken | 6 |
| POST | context.ReferencesGitRepo, mustAllowPulls, mustNotBeArchived, repoAssignment, reqRepoReader, reqToken | 5 |
| POST | mustEnableIssuesOrPulls, repoAssignment, reqToken | 5 |
| GET | mustEnableAttachments, mustEnableIssuesOrPulls, repoAssignment | 4 |
| POST | mustEnableIssuesOrPulls, mustNotBeArchived, repoAssignment, reqToken | 4 |
| GET | context.ReferencesGitRepo, repoAssignment, reqRepoReader, reqToken | 3 |
| GET | context.ReferencesGitRepo, context.RepoRefForAPI, repoAssignment, reqRepoReader | 3 |
| GET | mustEnableWiki, repoAssignment | 3 |
| GET | orgAssignment | 3 |
| GET | orgAssignment, reqOrgVisible | 3 |
| GET | repoAssignment, reqAnyRepoReader | 2 |
| POST | repoAssignment, reqRepoReader, reqToken | 2 |
| POST | context.ReferencesGitRepo, repoAssignment, reqRepoReader, reqRepoWriter, reqToken | 2 |
| GET | repoAssignment, reqAdmin, reqToken, reqWebhooksEnabled | 2 |
| GET | repoAssignment, reqAdmin, reqToken | 2 |
| POST | context.ReferencesGitRepo, mustEnableEditor, repo.ReqChangeRepoFileOptionsAndCheck, repoAssignment, reqRepoReader, reqToken | 2 |
| POST | mustEnableAttachments, mustEnableIssuesOrPulls, mustNotBeArchived, repoAssignment, reqToken | 2 |
| PATCH | mustEnableAttachments, mustEnableIssuesOrPulls, mustNotBeArchived, repoAssignment, reqToken | 2 |

(상위 25개 그룹만 표시; 나머지 28개 그룹)

| 안 | 남는 VIS | 제외 | 전체 건수 | 코드 있음 manual | 전체 manual | label 분포 |
|---|---:|---:|---:|---:|---:|---:|
| 축소 없음(현재 r2) | 172 | 0 | 971 | 47.3% | 38.0% | public 53 / role_r 164 / member 58 / tenant 52 / owner_ 240 / owner_ 35 / manual 369 |
| 시그니처당 최대 1건 | 53 | 119 | 852 | 33.1% | 29.3% | public 53 / role_r 164 / member 58 / tenant 52 / owner_ 240 / owner_ 35 / manual 250 |
| 시그니처당 최대 2건 | 82 | 90 | 881 | 37.2% | 31.7% | public 53 / role_r 164 / member 58 / tenant 52 / owner_ 240 / owner_ 35 / manual 279 |
| 시그니처당 최대 3건 | 99 | 73 | 898 | 39.4% | 33.0% | public 53 / role_r 164 / member 58 / tenant 52 / owner_ 240 / owner_ 35 / manual 296 |
| 참고: test_v30 코드 있음 | - | - | 265 | 5.7% | 5.6% | - |

## 6. '기타' 10건 (라벨 변경 없음, 사용자 확인용)

| id | method | 미들웨어 체인 | 핸들러 핵심 줄 |
|---|---:|---:|---:|
| gitea:get:/users/search | GET | sudo, tokenRequiresScopes, reqExploreSignIn, reqUsersExploreEnabled | Actor:         ctx.Doer, / "data": convert.ToUsers(ctx, ctx.Doer, users), |
| gitea:get:/users/{username} | GET | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, reqExploreSignIn | if !user_model.IsUserVisibleToViewer(ctx, ctx.ContextUser, ctx.Doer) { / ctx.JSON(http.StatusOK, convert.ToUser(ctx, ctx.ContextUser, ctx.Doer)) |
| gitea:get:/users/{username}/repos | GET | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, tokenRequiresScopes, reqExploreSignIn | listUserRepos(ctx, ctx.ContextUser, ctx.IsSigned) |
| gitea:get:/users/{username}/projects | GET | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, tokenRequiresScopes, reqExploreSignIn, reqProjectsUnitAccess | if err := project_service.LoadIssueNumbersForProjects(ctx, projects, ctx.Doer); err != nil { / ctx.JSON(http.StatusOK, convert.ToProjectList(ctx, projects, ctx.Doer)) |
| gitea:post:/users/{username}/tokens | POST | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, reqSelfOrAdmin, reqBasicOrRevProxyAuth, reqToken | hasScope, err := apiTokenScope.CanCreateChildScope(scope) / ctx.APIError(http.StatusForbidden, "cannot create an access token with a broader scope than the authenticating token") |
| gitea:get:/packages/{owner}/{type}/{name} | GET | sudo, reqToken, tokenRequiresScopes, context.UserAssignmentAPI, context.PackageAssignmentAPI, reqPackageAccess, checkTokenPublicOnly | // ---- handler packages.ListPackageVersions (routers/api/v1/packages/package.go:237-290) |
| gitea:get:/packages/{owner}/{type}/{name}/{version} | GET | sudo, reqToken, tokenRequiresScopes, context.UserAssignmentAPI, context.PackageAssignmentAPI, reqPackageAccess, checkTokenPublicOnly | apiPackage, err := convert.ToPackage(ctx, ctx.Package.Descriptor, ctx.Doer) |
| gitea:get:/packages/{owner}/{type}/{name}/-/latest | GET | sudo, reqToken, tokenRequiresScopes, context.UserAssignmentAPI, context.PackageAssignmentAPI, reqPackageAccess, checkTokenPublicOnly | apiPackage, err := convert.ToPackage(ctx, pd, ctx.Doer) |
| gitea:post:/packages/{owner}/{type}/{name}/-/link/{repo_name} | POST | sudo, reqToken, tokenRequiresScopes, context.UserAssignmentAPI, context.PackageAssignmentAPI, reqPackageAccess, checkTokenPublicOnly, reqPackageAccess | err = packages_service.LinkToRepository(ctx, pkg, repo, ctx.Doer) / case errors.Is(err, util.ErrPermissionDenied): / ctx.APIError(http.StatusForbidden, err.Error()) |
| gitea:post:/packages/{owner}/{type}/{name}/-/unlink | POST | sudo, reqToken, tokenRequiresScopes, context.UserAssignmentAPI, context.PackageAssignmentAPI, reqPackageAccess, checkTokenPublicOnly, reqPackageAccess | err = packages_service.UnlinkFromRepository(ctx, pkg, ctx.Doer) / case errors.Is(err, util.ErrPermissionDenied): / ctx.APIError(http.StatusForbidden, err.Error()) |

## 7. 'AUTH_ANY(객체 경로 있음)' 12건 (라벨 변경 없음)

| id | method | 미들웨어 체인 | 핸들러 핵심 줄 |
|---|---:|---:|---:|
| gitea:patch:/notifications/threads/{id} | PATCH | sudo, tokenRequiresScopes, rejectPublicOnly, reqToken | notif, err := notifications.SetNotificationStatus(ctx, n.ID, ctx.Doer, targetStatus) |
| gitea:get:/users/{username}/gpg_keys | GET | sudo, tokenRequiresScopes, reqToken, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker | // ---- handler user.ListGPGKeys (routers/api/v1/user/gpg_key.go:46-73) |
| gitea:get:/users/{username}/followers | GET | sudo, tokenRequiresScopes, reqToken, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker | // ---- handler user.ListFollowers (routers/api/v1/user/follower.go:63-90) |
| gitea:get:/users/{username}/following | GET | sudo, tokenRequiresScopes, reqToken, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker | // ---- handler user.ListFollowing (routers/api/v1/user/follower.go:129-156) |
| gitea:get:/users/{username}/following/{target} | GET | sudo, tokenRequiresScopes, reqToken, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker | // ---- handler user.CheckFollowing (routers/api/v1/user/follower.go:187-213) |
| gitea:get:/users/{username}/subscriptions | GET | sudo, tokenRequiresScopes, reqToken, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker | private := ctx.ContextUser.ID == ctx.Doer.ID |
| gitea:post:/user/actions/variables/{variablename} | POST | sudo, tokenRequiresScopes, reqToken, contextAuthenticatedUser, checkTokenPublicOnly, rejectPublicOnly | ownerID := ctx.Doer.ID |
| gitea:get:/user/keys/{id} | GET | sudo, tokenRequiresScopes, reqToken, contextAuthenticatedUser, checkTokenPublicOnly, rejectPublicOnly | if ctx.Doer.IsAdmin &#124;&#124; ctx.Doer.ID == key.OwnerID { / apiKey, _ = appendPrivateInformation(ctx, apiKey, key, ctx.Doer) |
| gitea:delete:/user/applications/oauth2/{id} | DELETE | sudo, tokenRequiresScopes, reqToken, contextAuthenticatedUser, checkTokenPublicOnly, rejectPublicOnly | if err := auth_model.DeleteOAuth2Application(ctx, appID, ctx.Doer.ID); err != nil { / audit.Record(ctx, audit_model.UserOAuth2ApplicationRemove, ctx.Doer, "oauth2_application", app.Name) |
| gitea:get:/repositories/{id} | GET | sudo, reqToken, tokenRequiresScopes | permission, err := access_model.GetDoerRepoPermission(ctx, repo, ctx.Doer) |
| gitea:get:/users/{username}/orgs | GET | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, reqToken | // ---- handler org.ListUserOrgs (routers/api/v1/org/org.go:88-115) |
| gitea:get:/users/{username}/orgs/{org}/permissions | GET | sudo, tokenRequiresScopes, context.UserAssignmentAPI, checkTokenPublicOnly, individualPermsChecker, reqToken | // ---- handler org.GetUserOrgsPermissions (routers/api/v1/org/org.go:118-189) / func GetUserOrgsPermissions(ctx *context.APIContext) { / op := api.OrganizationPermissions{} |

## 8. AGENTS.md 추가 기준

- VIS+SELF: 요청자가 데이터 범위(본인 star·watch·구독·stopwatch·알림)이면 owner_match, 요청자가 행위자(댓글·머지·리뷰·릴리스·이전·생성·실행)이면 manual

원자료: train_v2_draft_r2.jsonl(meta.v2_relabel), scripts/apply_review_v2_r2.py.
