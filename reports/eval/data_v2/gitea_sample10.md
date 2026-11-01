# Gitea v28.2.0 발췌 표본 10건 (seed 42, 패키지별 층화) — 라벨 전 검토용

커밋 829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1, MIT. 추출 규칙 R1~R5는 gitea_extraction_rules.md. 통계: 라우트 481, OAS operation 537, 매칭 레코드 455, 미매칭 라우트 26, 핸들러 미해결 0, 라우트 미들웨어에 인증 341, 라우트 인가 미들웨어 보유 265, 핸들러 내부 인가 idiom 1줄 이상 251.

## gitea:post:/repos/{owner}/{repo}/branch_protections

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqAdmin(), mustNotBeArchived` | 핸들러: `repo.CreateBranchProtection` | 인가 idiom 줄 수: 6
- OAS summary: Create a branch protections for a repository

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqAdmin(), mustNotBeArchived

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// repoAssignment() (api.go): resolves {username}/{reponame}; computes ctx.Repo.Permission = access_model.GetUserRepoPermission(doer, repo); anonymous or unauthorized doer on a private repo -> 404; public repo readable by anyone.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

func reqAdmin() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.IsUserRepoAdmin() && !ctx.IsUserSiteAdmin() {
			ctx.APIError(http.StatusForbidden, "user should be an owner or a collaborator with admin write of a repository")
			return
		}
	}
}

// mustNotBeArchived: 403 when the repository is archived (feature state, not a caller check).

// ---- handler repo.CreateBranchProtection (routers/api/v1/repo/branch.go:622-838)
func CreateBranchProtection(ctx *context.APIContext) {

	form := web.GetForm[*api.CreateBranchProtectionOption](ctx)
	repo := ctx.Repo.Repository

	ruleName := form.RuleName
	if ruleName == "" {
		ruleName = form.BranchName //nolint:staticcheck // deprecated field
	}
	if len(ruleName) == 0 {
		ctx.APIError(http.StatusBadRequest, "both rule_name and branch_name are empty")
		return
	}

	protectBranch, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, ruleName)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	} else if protectBranch != nil {
		ctx.APIError(http.StatusForbidden, "Branch protection already exist")
		return
	}
	// ...
	var whitelistTeams, forcePushAllowlistTeams, mergeWhitelistTeams, approvalsWhitelistTeams, bypassAllowlistTeams []int64
	if repo.Owner.IsOrganization() {
		whitelistTeams, err = organization.GetTeamIDsByNames(ctx, repo.OwnerID, form.PushWhitelistTeams, false)
		if err != nil {
			if organization.IsErrTeamNotExist(err) {
	// ...
			return
		}
		forcePushAllowlistTeams, err = organization.GetTeamIDsByNames(ctx, repo.OwnerID, form.ForcePushAllowlistTeams, false)
		if err != nil {
			if organization.IsErrTeamNotExist(err) {
	// ...
			return
		}
		mergeWhitelistTeams, err = organization.GetTeamIDsByNames(ctx, repo.OwnerID, form.MergeWhitelistTeams, false)
		if err != nil {
			if organization.IsErrTeamNotExist(err) {
	// ...
			return
		}
		approvalsWhitelistTeams, err = organization.GetTeamIDsByNames(ctx, repo.OwnerID, form.ApprovalsWhitelistTeams, false)
		if err != nil {
			if organization.IsErrTeamNotExist(err) {
	// ...
		}
		if form.EnableBypassAllowlist {
			bypassAllowlistTeams, err = organization.GetTeamIDsByNames(ctx, repo.OwnerID, form.BypassAllowlistTeams, false)
			if err != nil {
				if organization.IsErrTeamNotExist(err) {
	// ...
}
```

## gitea:post:/repos/{owner}/{repo}/transfer

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqRepoDangerZone()` | 핸들러: `repo.Transfer` | 인가 idiom 줄 수: 7
- OAS summary: Transfer a repo ownership

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), reqToken(), reqRepoDangerZone()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// repoAssignment() (api.go): resolves {username}/{reponame}; computes ctx.Repo.Permission = access_model.GetUserRepoPermission(doer, repo); anonymous or unauthorized doer on a private repo -> 404; public repo readable by anyone.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

func reqRepoDangerZone() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !access_model.CanDoerManageRepoDangerZone(ctx, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission) {
			ctx.APIError(http.StatusForbidden, "user has no permission to manage the danger zone")
			return
		}
	}
}

// ---- handler repo.Transfer (routers/api/v1/repo/transfer.go:26-134)
func Transfer(ctx *context.APIContext) {

	opts := web.GetForm[*api.TransferRepoOption](ctx)

	newOwner, err := user_model.GetUserByName(ctx, opts.NewOwner)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			ctx.APIError(http.StatusNotFound, "The new owner does not exist or cannot be found")
			return
		}
		ctx.APIErrorInternal(err)
		return
	}

	if newOwner.Type == user_model.UserTypeOrganization {
		if !ctx.Doer.IsAdmin && newOwner.Visibility == api.VisibleTypePrivate && !organization.OrgFromUser(newOwner).HasMemberWithUserID(ctx, ctx.Doer.ID) {
	// ...
			ctx.APIError(http.StatusNotFound, "The new owner does not exist or cannot be found")
			return
		}
	}

	// ...

			if team.OrgID != org.ID {
				ctx.APIError(http.StatusForbidden, fmt.Sprintf("team %d belongs not to org %d", tID, org.ID))
				return
			}
	// ...
	oldFullname := ctx.Repo.Repository.FullName()

	if err := repo_service.StartRepositoryTransfer(ctx, ctx.Doer, newOwner, ctx.Repo.Repository, teams); err != nil {
		switch {
		case repo_model.IsErrRepoTransferInProgress(err):
	// ...
			ctx.APIError(http.StatusUnprocessableEntity, err.Error())
		case repo_service.IsRepositoryLimitReached(err):
			ctx.APIError(http.StatusForbidden, err.Error())
		case errors.Is(err, user_model.ErrBlockedUser):
			ctx.APIError(http.StatusForbidden, err.Error())
		default:
			ctx.APIErrorInternal(err)
	// ...
	if ctx.Repo.Repository.Status == repo_model.RepositoryPendingTransfer {
		log.Trace("Repository transfer initiated: %s -> %s", oldFullname, ctx.Repo.Repository.FullName())
		ctx.JSON(http.StatusCreated, convert.ToRepo(ctx, ctx.Repo.Repository, access_model.Permission{AccessMode: perm.AccessModeAdmin}))
		return
	}

	log.Trace("Repository transferred: %s -> %s", oldFullname, ctx.Repo.Repository.FullName())
	ctx.JSON(http.StatusAccepted, convert.ToRepo(ctx, ctx.Repo.Repository, access_model.Permission{AccessMode: perm.AccessModeAdmin}))
}
```

## gitea:get:/repos/{owner}/{repo}/pulls/{index}/reviews/{id}

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), mustAllowPulls, reqRepoReader(unit.TypeCode), context.ReferencesGitRepo()` | 핸들러: `repo.GetPullReview` | 인가 idiom 줄 수: 1
- OAS summary: Get a specific review for a pull request

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), mustAllowPulls, reqRepoReader(unit.TypeCode), context.ReferencesGitRepo()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// repoAssignment() (api.go): resolves {username}/{reponame}; computes ctx.Repo.Permission = access_model.GetUserRepoPermission(doer, repo); anonymous or unauthorized doer on a private repo -> 404; public repo readable by anyone.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// mustAllowPulls: feature/unit enabled check (404 when the unit is disabled); not a caller check.

func reqRepoReader(unitType unit.Type) func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.Repo.Permission.CanRead(unitType) && !ctx.IsUserRepoAdmin() && !ctx.IsUserSiteAdmin() {
			ctx.APIError(http.StatusForbidden, "user should have specific read permission or be a repo admin or a site admin")
			return
		}
	}
}

// context.ReferencesGitRepo(): opens the git repository for ctx.Repo; no authorization.

// ---- handler repo.GetPullReview (routers/api/v1/repo/pull_review.go:108-155)
func GetPullReview(ctx *context.APIContext) {

	review, _, statusSet := prepareSingleReview(ctx)
	if statusSet {
		return
	}

	apiReview, err := convert.ToPullReview(ctx, review, ctx.Doer)
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	ctx.JSON(http.StatusOK, apiReview)
}
```

## gitea:post:/repos/{owner}/{repo}/pulls

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), mustAllowPulls, reqRepoReader(unit.TypeCode), context.ReferencesGitRepo(), reqToken(), mustNotBeArchived` | 핸들러: `repo.CreatePullRequest` | 인가 idiom 줄 수: 8
- OAS summary: Create a pull request

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryRepository), repoAssignment(), checkTokenPublicOnly(), mustAllowPulls, reqRepoReader(unit.TypeCode), context.ReferencesGitRepo(), reqToken(), mustNotBeArchived

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// repoAssignment() (api.go): resolves {username}/{reponame}; computes ctx.Repo.Permission = access_model.GetUserRepoPermission(doer, repo); anonymous or unauthorized doer on a private repo -> 404; public repo readable by anyone.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// mustAllowPulls: feature/unit enabled check (404 when the unit is disabled); not a caller check.

func reqRepoReader(unitType unit.Type) func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.Repo.Permission.CanRead(unitType) && !ctx.IsUserRepoAdmin() && !ctx.IsUserSiteAdmin() {
			ctx.APIError(http.StatusForbidden, "user should have specific read permission or be a repo admin or a site admin")
			return
		}
	}
}

// context.ReferencesGitRepo(): opens the git repository for ctx.Repo; no authorization.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

// mustNotBeArchived: 403 when the repository is archived (feature state, not a caller check).

// ---- handler repo.CreatePullRequest (routers/api/v1/repo/pull.go:369-584)
func CreatePullRequest(ctx *context.APIContext) {

	form := *web.GetForm[*api.CreatePullRequestOption](ctx)
	if form.Head == form.Base {
		ctx.APIError(http.StatusUnprocessableEntity, "Invalid PullRequest: There are no changes between the head and the base")
		return
	}

	var (
		repo        = ctx.Repo.Repository
		labelIDs    []int64
		milestoneID int64
	)

	// ...
	compareResult, closer := parseCompareInfo(ctx, form.Base+".."+form.Head)
	if ctx.Written() {
		return
	}
	defer closer()

	if !compareResult.BaseRef.IsBranch() || !compareResult.HeadRef.IsBranch() {
	// ...
	}

	unitPullRequest, err := ctx.Repo.Repository.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		ctx.APIErrorInternal(err)
	// ...
		RepoID:       repo.ID,
		Title:        form.Title,
		PosterID:     ctx.Doer.ID,
		Poster:       ctx.Doer,
		MilestoneID:  milestoneID,
		IsPull:       true,
	// ...
		}

		valid, err := access_model.CanBeAssigned(ctx, assignee, repo)
		if err != nil {
			ctx.APIErrorInternal(err)
	// ...
			ctx.APIError(http.StatusBadRequest, err.Error())
		} else if errors.Is(err, user_model.ErrBlockedUser) {
			ctx.APIError(http.StatusForbidden, err.Error())
		} else if errors.Is(err, issues_model.ErrMustCollaborator) {
			ctx.APIError(http.StatusForbidden, err.Error())
		} else {
			ctx.APIErrorInternal(err)
	// ...

	log.Trace("Pull request created: %d/%d", repo.ID, prIssue.ID)
	ctx.JSON(http.StatusCreated, convert.ToAPIPullRequest(ctx, pr, ctx.Doer))
}
```

## gitea:get:/user/actions/runners

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), contextAuthenticatedUser(), checkTokenPublicOnly(), rejectPublicOnly(), reqToken()` | 핸들러: `user.ListRunners` | 인가 idiom 줄 수: 1
- OAS summary: Get user-level runners

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), contextAuthenticatedUser(), checkTokenPublicOnly(), rejectPublicOnly(), reqToken()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

// contextAuthenticatedUser(): sets ctx.ContextUser = ctx.Doer (the authenticated user itself).

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// rejectPublicOnly(): public-only tokens are rejected (403).

// ---- handler user.ListRunners (routers/api/v1/user/runners.go:29-49)
func ListRunners(ctx *context.APIContext) {
	shared.ListRunners(ctx, ctx.Doer.ID, 0)
}
```

## gitea:patch:/user/settings

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), contextAuthenticatedUser(), checkTokenPublicOnly(), rejectPublicOnly()` | 핸들러: `user.UpdateUserSettings` | 인가 idiom 줄 수: 2
- OAS summary: Update user settings

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryUser), reqToken(), contextAuthenticatedUser(), checkTokenPublicOnly(), rejectPublicOnly()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

// contextAuthenticatedUser(): sets ctx.ContextUser = ctx.Doer (the authenticated user itself).

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// rejectPublicOnly(): public-only tokens are rejected (403).

// ---- handler user.UpdateUserSettings (routers/api/v1/user/settings.go:31-65)
func UpdateUserSettings(ctx *context.APIContext) {

	form := web.GetForm[*api.UserSettingsOptions](ctx)

	opts := &user_service.UpdateOptions{
		FullName:            optional.FromPtr(form.FullName),
		Description:         optional.FromPtr(form.Description),
		Website:             optional.FromPtr(form.Website),
		Location:            optional.FromPtr(form.Location),
		Language:            optional.FromPtr(form.Language),
		Theme:               optional.FromPtr(form.Theme),
		DiffViewStyle:       optional.FromPtr(form.DiffViewStyle),
		KeepEmailPrivate:    optional.FromPtr(form.HideEmail),
		KeepActivityPrivate: optional.FromPtr(form.HideActivity),
	}
	if err := user_service.UpdateUser(ctx, ctx.Doer, opts); err != nil {
		ctx.APIErrorInternal(err)
		return
	}

	ctx.JSON(http.StatusOK, convert.User2UserSettings(ctx.Doer))
}
```

## gitea:delete:/teams/{id}/members/{username}

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryOrganization), orgAssignment(false, true), reqToken(), checkTokenPublicOnly(), reqToken(), reqOrgOwnership()` | 핸들러: `org.RemoveTeamMember` | 인가 idiom 줄 수: 0
- OAS summary: Remove a team member

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryOrganization), orgAssignment(false, true), reqToken(), checkTokenPublicOnly(), reqToken(), reqOrgOwnership()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// orgAssignment() (api.go): resolves {org} (and optional team) into ctx.Org; no authorization by itself.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

func reqOrgOwnership() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if ctx.IsUserSiteAdmin() {
			return
		}

		var orgID int64
		if ctx.Org.Organization != nil {
			orgID = ctx.Org.Organization.ID
		} else if ctx.Org.Team != nil {
			orgID = ctx.Org.Team.OrgID
		} else {
			setting.PanicInDevOrTesting("reqOrgOwnership: unprepared context")
			ctx.APIErrorInternal(errors.New("reqOrgOwnership: unprepared context"))
			return
		}

		isOwner, err := organization.IsOrganizationOwner(ctx, orgID, ctx.Doer.ID)
		if err != nil {
			ctx.APIErrorInternal(err)
			return
		} else if !isOwner {
			if ctx.Org.Organization != nil {
				ctx.APIError(http.StatusForbidden, "Must be an organization owner")
			} else {
				ctx.APIErrorNotFound()
			}
			return
		}
	}
// ... (truncated)

// ---- handler org.RemoveTeamMember (routers/api/v1/org/team.go:481-515)
func RemoveTeamMember(ctx *context.APIContext) {

	u := user.GetContextUserByPathParam(ctx)
	if ctx.Written() {
		return
	}

	if err := org_service.RemoveTeamMember(ctx, ctx.Org.Team, u); err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	ctx.Status(http.StatusNoContent)
}
```

## gitea:get:/orgs/{org}

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryOrganization), orgAssignment(true), checkTokenPublicOnly()` | 핸들러: `org.Get` | 인가 idiom 줄 수: 2
- OAS summary: Get an organization

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryOrganization), orgAssignment(true), checkTokenPublicOnly()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// orgAssignment() (api.go): resolves {org} (and optional team) into ctx.Org; no authorization by itself.

// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.

// ---- handler org.Get (routers/api/v1/org/org.go:307-338)
func Get(ctx *context.APIContext) {

	if !organization.HasOrgOrUserVisible(ctx, ctx.Org.Organization.AsUser(), ctx.Doer) {
		ctx.APIErrorNotFound()
		return
	}

	org := convert.ToOrganization(ctx, ctx.Org.Organization)

	// ...
	if ctx.Doer == nil {
		org.Email = ""
	}

	ctx.JSON(http.StatusOK, org)
}
```

## gitea:post:/admin/users

- 미들웨어: `sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryAdmin), reqToken(), reqSiteAdmin()` | 핸들러: `admin.CreateUser` | 인가 idiom 줄 수: 5
- OAS summary: Create a user

```go
// ---- route middleware chain (api.go): sudo(), tokenRequiresScopes(auth_model.AccessTokenScopeCategoryAdmin), reqToken(), reqSiteAdmin()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.

// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.

func reqSiteAdmin() func(ctx *context.APIContext) {
	return func(ctx *context.APIContext) {
		if !ctx.IsUserSiteAdmin() {
			ctx.APIError(http.StatusForbidden, "user should be the site admin")
			return
		}
	}
}

// ---- handler admin.CreateUser (routers/api/v1/admin/user.go:57-158)
func CreateUser(ctx *context.APIContext) {

	form := web.GetForm[*api.CreateUserOption](ctx)

	u := &user_model.User{
		Name:               form.Username,
		FullName:           form.FullName,
		Email:              form.Email,
		Passwd:             form.Password,
		MustChangePassword: true,
		LoginType:          auth.Plain,
		LoginName:          form.LoginName,
	}
	if form.MustChangePassword != nil {
		u.MustChangePassword = *form.MustChangePassword
	}

	parseAuthSource(ctx, u, form.SourceID)
	if ctx.Written() {
		return
	}
	// ...
	}

	if form.Visibility != "" {
		visibility := api.VisibilityModes[form.Visibility]
		overwriteDefault.Visibility = &visibility
	}

	// ...
	audit.Record(ctx, audit_model.UserCreate, u)

	log.Trace("Account created by admin (%s): %s", ctx.Doer.Name, u.Name)

	// ...
		mailer.SendRegisterNotifyMail(u)
	}
	ctx.JSON(http.StatusCreated, convert.ToUser(ctx, u, ctx.Doer))
}
```

## gitea:get:/licenses/{name}

- 미들웨어: `sudo()` | 핸들러: `misc.GetLicenseTemplateInfo` | 인가 idiom 줄 수: 0
- OAS summary: Returns information about a license template

```go
// ---- route middleware chain (api.go): sudo()

// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.

// ---- handler misc.GetLicenseTemplateInfo (routers/api/v1/misc/licenses.go:40-75)
func GetLicenseTemplateInfo(ctx *context.APIContext) {
	name := util.PathJoinRelX(ctx.PathParam("name"))

	text, err := options.License(name)
	if err != nil {
		ctx.APIErrorNotFound()
		return
	}

	response := api.LicenseTemplateInfo{
		Key:  name,
		Name: name,
		URL:  fmt.Sprintf("%sapi/v1/licenses/%s", setting.AppURL, url.PathEscape(name)),
		Body: string(text),
	// ...
		Implementation: "Create a text file (typically named LICENSE or LICENSE.txt) in the root of your source code and copy the text of the license into the file",
	}

	ctx.JSON(http.StatusOK, response)
}
```

