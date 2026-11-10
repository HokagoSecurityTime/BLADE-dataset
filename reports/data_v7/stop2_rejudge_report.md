# data-v7 2단계 보고 — LLM 라벨 615행 재판정 집계 (2026-11-07, 정지 지점 — 사용자 승인 대기)

사전 기록 AGENTS.md "작업 data-v7". 대상 = data-v6d SFT 1,453행 중 라벨 출처가 LLM(gpt-4o-mini, v3.0.1)인 615행(gitea 코드 225 + APIs.guru OAS-only 390; train 535·val 80). 재판정자 Claude(AI) 서브에이전트 19개 청크(코드 25행·OAS 45행 단위), 입력은 SFT user 필드(코드/명세)만이며 현재 label·rationale은 키 파일에 분리해 집계에서만 읽었다. 기준: G1~G8 + v3.1 정의 + test_v6 보충 규약 + 정지 지점 결정, OAS-only는 보류 2 엄격 적용(data_v7/rejudge/REJUDGE_GUIDE.md). 학습·추론·LLM API 호출 없음, 커밋 없음. 판정 원본 data_v7/rejudge/out/*.jsonl, 변경 행 목록 reports/data_v7/rejudge_changes.jsonl.

## 1. 요약

- 615행 중 label 변경 **301건(48.9%)**: 코드(gitea) 21/225(9.3%), OAS-only 280/390(71.8%). 구체 → manual 269건, manual → 구체 7건, 구체 → 다른 구체 25건.
- 학습셋 전체(SFT) manual 비율: train 12.6% → **31.9%** ⚠️ 20% 초과 경고, val 21.8% → 31.3%, 전체 13.8% → 31.8%.
- C′ 블라인드 불일치 28건 중 규칙 라벨러 행 10건(615와 별도 집계): 변경 5, → manual 4. 이 행들은 data-v7 변경에 자동 반영하지 않는다(3단계 사람 확인 대상 후보).
- 확신도 분포(615): {'0.7': 288, '0.5': 17, '0.9': 310}; 변경 행 {'0.7': 179, '0.5': 16, '0.9': 106}. 상위 근거 규약: 보류2 274, G4 106, G3 71, 보류4 38, G7 26, G3-a 26, 보류8 25, G3-b 13, G2 9, 보류7 9.

## 2. 전이표 (현재 label 행 → 새 label 열)

### 전체 615

- n 615, 변경 301(48.9%), → manual 269, manual → 구체 7, manual 94 → 356; 확신도 {'0.7': 288, '0.5': 17, '0.9': 310}(변경 행 {'0.7': 179, '0.5': 16, '0.9': 106})

| 현재 \ 새 | public | role | member | tenant | owner | own+adm | manual | 합 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **public** | **25** | 0 | 0 | 0 | 0 | 0 | 16 | 41 |
| **role** | 0 | **97** | 0 | 1 | 4 | 0 | 89 | 191 |
| **member** | 0 | 5 | **9** | 2 | 2 | 0 | 16 | 34 |
| **tenant** | 0 | 3 | 0 | **1** | 2 | 0 | 29 | 35 |
| **owner** | 0 | 1 | 0 | 2 | **94** | 0 | 116 | 213 |
| **own+adm** | 0 | 0 | 0 | 0 | 3 | **1** | 3 | 7 |
| **manual** | 1 | 4 | 0 | 0 | 2 | 0 | **87** | 94 |

### gitea 코드 225

- n 225, 변경 21(9.3%), → manual 13, manual → 구체 6, manual 50 → 57; 확신도 {'0.9': 160, '0.7': 62, '0.5': 3}(변경 행 {'0.7': 19, '0.5': 2})

| 현재 \ 새 | public | role | member | tenant | owner | own+adm | manual | 합 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **public** | **17** | 0 | 0 | 0 | 0 | 0 | 2 | 19 |
| **role** | 0 | **66** | 0 | 0 | 0 | 0 | 1 | 67 |
| **member** | 0 | 0 | **4** | 0 | 0 | 0 | 4 | 8 |
| **owner** | 0 | 0 | 0 | 0 | **72** | 0 | 3 | 75 |
| **own+adm** | 0 | 0 | 0 | 0 | 2 | **1** | 3 | 6 |
| **manual** | 1 | 4 | 0 | 0 | 1 | 0 | **44** | 50 |

### APIs.guru OAS-only 390

- n 390, 변경 280(71.8%), → manual 256, manual → 구체 1, manual 44 → 299; 확신도 {'0.7': 226, '0.5': 14, '0.9': 150}(변경 행 {'0.7': 160, '0.5': 14, '0.9': 106})

| 현재 \ 새 | public | role | member | tenant | owner | own+adm | manual | 합 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **public** | **8** | 0 | 0 | 0 | 0 | 0 | 14 | 22 |
| **role** | 0 | **31** | 0 | 1 | 4 | 0 | 88 | 124 |
| **member** | 0 | 5 | **5** | 2 | 2 | 0 | 12 | 26 |
| **tenant** | 0 | 3 | 0 | **1** | 2 | 0 | 29 | 35 |
| **owner** | 0 | 1 | 0 | 2 | **22** | 0 | 113 | 138 |
| **own+adm** | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 |
| **manual** | 0 | 0 | 0 | 0 | 1 | 0 | **43** | 44 |

### split별

| split | n | 변경 | → manual | manual → 구체 | manual 전 → 후 |
|---|---:|---:|---:|---:|---|
| train | 535 | 278 | 249 | 4 | 66 → 311 |
| val | 80 | 23 | 20 | 3 | 28 → 45 |

### C′ 블라인드 불일치 중 규칙 라벨러 행(별도)

- n 10, 변경 5(50.0%), → manual 4, manual → 구체 1, manual 1 → 4; 확신도 {'0.7': 7, '0.9': 3}(변경 행 {'0.7': 3, '0.9': 2})

| 현재 \ 새 | public | role | member | tenant | owner | own+adm | manual | 합 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **tenant** | 0 | 0 | 0 | 0 | 0 | 0 | 3 | 3 |
| **owner** | 0 | 0 | 0 | 0 | **3** | 0 | 0 | 3 |
| **own+adm** | 0 | 0 | 0 | 0 | 0 | **2** | 1 | 3 |
| **manual** | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |

## 3. 프로젝트·서비스별

| 프로젝트 | n | 변경 | → manual | manual 전 → 후 |
|---|---:|---:|---:|---|
| apisguru | 390 | 280 | 256 | 44 → 299 |
| gitea | 225 | 21 | 13 | 50 → 57 |

OAS-only 서비스 중 변경 많은 순(상위 25):

| service | n | 변경 | → manual |
|---|---:|---:|---:|
| slmonitor.com | 13 | 9 | 0 |
| ably.net | 7 | 7 | 7 |
| flat.io | 7 | 7 | 7 |
| illumidesk.com | 7 | 7 | 7 |
| webflow.com | 7 | 7 | 7 |
| bitbucket.org | 6 | 6 | 6 |
| circuitsandbox.net | 11 | 6 | 5 |
| openbanking.org.uk | 7 | 6 | 6 |
| stripe.com | 8 | 6 | 6 |
| visma.com | 6 | 6 | 5 |
| googleapis.com | 5 | 5 | 5 |
| mastodon.local | 5 | 5 | 3 |
| onsched.com | 5 | 5 | 5 |
| vimeo.com | 5 | 5 | 5 |
| avaza.com | 4 | 4 | 4 |
| collegefootballdata.com | 4 | 4 | 4 |
| evetech.net | 7 | 4 | 4 |
| openbankingproject.ch | 4 | 4 | 4 |
| shop-pro.jp | 4 | 4 | 4 |
| telnyx.com | 4 | 4 | 4 |
| visma.net | 4 | 4 | 4 |
| impala.travel | 4 | 4 | 4 |
| salesforce.local | 4 | 4 | 4 |
| appwrite.io | 4 | 3 | 2 |
| box.com | 4 | 3 | 3 |

## 4. 학습셋 전체 label 분포 변화 (SFT, 615행 재판정 반영 가정; 별도 집계 행은 미반영)

| 구간 | n | public | role | member | tenant | owner | own+adm | manual | manual 비율 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| train 현재 | 1274 | 82 | 351 | 75 | 83 | 425 | 97 | 161 | 12.6% |
| train 재판정 후 | 1274 | 67 | 276 | 51 | 56 | 327 | 91 | 406 | 31.9% |
| val 현재 | 179 | 14 | 52 | 7 | 8 | 46 | 13 | 39 | 21.8% |
| val 재판정 후 | 179 | 14 | 46 | 6 | 6 | 38 | 13 | 56 | 31.3% |
| 전체 현재 | 1453 | 96 | 403 | 82 | 91 | 471 | 110 | 200 | 13.8% |
| 전체 재판정 후 | 1453 | 81 | 322 | 57 | 62 | 365 | 104 | 462 | 31.8% |

**경고: train manual 비율이 20%를 넘는다.** 사전 기록대로 보고하고 멈춘다. 3단계 진행 여부(manual 쿼터 적용·OAS-only manual 행 일부 제외 등)는 사용자 결정.

## 5. 변경 행 예시 (전이 유형별 최대 3건, 전체는 rejudge_changes.jsonl)

### owner → manual (116건)

- `apisguru:ably.net:get:/accounts/{account_id}/apps` [oas, conf 0.7, 보류2] OAS만 있고 요청자와 account_id의 관계(구성원·소유·테넌트)가 설명에 없어 보류한다. — 근거: `"List all applications for the specified account ID." / "security_state": "declared"`
- `apisguru:ably.net:patch:/apps/{id}` [oas, conf 0.7, 보류2] accountId 필드 존재만으로 tenant·owner 관계를 단정하지 않고 보류한다. — 근거: `"Updates the application with the specified application ID." / "security_state": "declared"`
- `apisguru:ably.net:post:/accounts/{account_id}/apps` [oas, conf 0.7, 보류2] 생성 요청의 대상 account에 대한 요청자 조건이 설명에 없어 보류한다. — 근거: `"Creates an application with the specified properties." / "security_state": "declared"`

### role → manual (89건)

- `apisguru:adyen.com:get:/balanceAccounts/{id}/paymentInstruments` [oas, conf 0.7, 보류2] API 키·BasicAuth 선언만 있고 balance account에 대한 요청자 관계가 없어 보류한다. — 근거: `"Returns a paginated list of the payment instruments associated with a balance account."`
- `apisguru:apideck.com:get:/accounting/invoice-items/{id}` [oas, conf 0.7, 보류2] created_by 필드 존재만으로 소유 관계를 단정하지 않으며 접근 조건 문장이 없어 보류한다. — 근거: `"description": "Get Invoice Item" / "owner_cols": ["created_by"]`
- `apisguru:appcenter.ms:get:/v0.1/apps/{owner_name}/{app_name}/crash_groups/{crash_group_id}/crashes` [oas, conf 0.7, 보류2] 경로의 owner_name은 앱 소유자 식별자일 뿐 요청자 조건이 아니며 설명에 접근 조건이 없어 보류한다. — 근거: `"Gets all crashes of a group." / "security": [{"APIToken": []}]`

### tenant → manual (29건)

- `apisguru:ably.net:get:/apps/{app_id}/rules` [oas, conf 0.7, 보류2] 인증 선언만 있고 app_id에 대한 접근 조건 문장이 없어 보류한다. — 근거: `"Lists the rules for the application specified by the application ID." / "security_state": "declared"`
- `apisguru:ably.net:get:/apps/{app_id}/rules/{rule_id}` [oas, conf 0.7, 보류2] 경로 ID와 인증 선언만으로는 요청자-객체 관계를 단정할 수 없어 보류한다. — 근거: `"Returns the rule specified by the rule ID, for the application specified by application ID."`
- `apisguru:ably.net:patch:/apps/{app_id}/rules/{rule_id}` [oas, conf 0.7, 보류2] 설명이 비어 있고 declared PATCH라 public도 아니며 접근 조건을 알 수 없어 보류한다. — 근거: `"summary": "Updates a Reactor rule", "description": "" / "security_state": "declared"`

### member → manual (16건)

- `apisguru:appwrite.io:post:/teams/{teamId}/memberships` [oas, conf 0.5, 보류2] 'your team'이 관계를 암시하지만 구성원인지 팀 owner 역할인지 설명에 명시되지 않아 보류한다. — 근거: `"Use this endpoint to invite a new member to join your team."`
- `apisguru:daniweb.com:patch:/conversations/{ID}/statuses` [oas, conf 0.5, 보류2] 요청자가 대화 당사자여야 함이 암시되나 명시되지 않고 same bubble 조건도 결합돼 있어 보류한다. — 근거: `"Archive or unarchive a conversation that is with a user who exists within the same bubble."`
- `apisguru:flat.io:get:/scores/{score}` [oas, conf 0.7, 보류2] ACL 읽기 권한(소유·협업자·공유키 등 여러 경로) 조건은 6종 라벨로 표현되지 않아 보류한다. — 근거: `"The currently authenticated user must have at least a read access to the document"; sharingKey`

### public → manual (16건)

- `apisguru:asuarez.dev:get:/similarity/by_song` [oas, conf 0.7, 보류2] security가 unknown이고 무인증 허용을 긍정하는 설명이 없어 public으로 보지 않고 보류한다. — 근거: `"security": null / "security_state": "unknown" / "Endpoint for an end-user client"`
- `apisguru:flickr.com:get:/rest?method=flickr.favorites.getList` [oas, conf 0.7, 보류4] 사진별 가시성 권한에 따라 결과가 갈리고 user_id로 타인 목록도 조회하므로 단일 라벨로 확정할 수 없다. — 근거: `"Only photos which the calling user has permission to see are returned."; "security_state": "unknown"`
- `apisguru:flickr.com:get:/rest?method=flickr.photos.getInfo` [oas, conf 0.7, 보류2] 익명 허용의 긍정 근거가 없고 사진 가시성 조건도 설명에 없어 보류한다. — 근거: `"description": "Returns a photo"; "security": null; "security_state": "unknown"`

### member → role (5건)

- `apisguru:slmonitor.com:get:/api/v2.1/companies/{companyId}/users` [oas, conf 0.7, G3] security 요구사항이 CompanyAdministrator·CompanyMonitor 역할을 명시하므로 role_required로 보되, Pin 스킴의 조건이 비어 있어 해석이 필요하다. — 근거: `security: EmailLogin [CompanyAdministrator, CompanyMonitor]; This operation gets all the users' profiles.`
- `apisguru:slmonitor.com:post:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin` [oas, conf 0.7, G3] 지정 작업자 체크인에 CompanyMonitor 역할이 명시되어 role_required로 본다. — 근거: `security: EmailLogin [CompanyMonitor]; This operation checks the worker in`
- `apisguru:slmonitor.com:post:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin-text` [oas, conf 0.7, G3] CompanyMonitor 역할 요구가 명시된 작업자 체크인이라 role_required다. — 근거: `security: EmailLogin [CompanyMonitor]; summary: Check in with a text report`

### role → owner (4건)

- `apisguru:linode.com:put:/account/oauth-clients/{clientId}` [oas, conf 0.7, G4] 요청자 자신의 Account에 속한 클라이언트로 대상이 고정된다고 설명해 본인 자원으로 본다(계정이 다중 사용자 테넌트일 가능성은 설명에 없음). — 근거: `"Update information about an OAuth Client on your Account."`
- `apisguru:mastodon.local:post:/api/v1/accounts/{id}/follow` [oas, conf 0.7, G4] 요청자 본인의 팔로우 관계·알림 설정을 만드는 본인 명의 요청이라 owner_match. — 근거: `Follow the given account. Can also be used to update whether to show reblogs or enable notifications.`
- `apisguru:netatmo.net:get:/getstationsdata` [oas, conf 0.7, G4] 사용자 위임 OAuth 토큰으로 '사용자의' 기상 관측소 데이터를 반환한다고 적혀 본인 기기 범위로 해석. — 근거: `Returns data from a user's Weather Stations; code_oauth/password_oauth: read_station`

### manual → role (4건)

- `gitea:post:/repos/{owner}/{repo}/transfer` [code, conf 0.7, G3] reqRepoDangerZone이 저장소 권한 레벨(danger zone 관리 권한)을 결정 조건으로 삼으므로 저장소 권한 레벨 규칙에 따라 role_required. — 근거: `if !access_model.CanDoerManageRepoDangerZone(ctx, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission)`
- `gitea:post:/packages/{owner}/{type}/{name}/-/unlink` [code, conf 0.7, G3] 패키지 소유자 범위의 쓰기 권한 레벨(또는 사이트 관리자)이 조건이라 저장소 쓰기 권한과 같이 role_required로 본다. — 근거: `reqPackageAccess(perm.AccessModeWrite) | if ctx.Package.AccessMode < accessMode && !ctx.IsUserSiteAdmin() { 403 }`
- `gitea:post:/repos/{owner}/{repo}/contents/{filepath}` [code, conf 0.7, G3] 저장소 파일 생성은 쓰기 권한이 의도된 정책이며 체인 끝 ReqChangeRepoFileOptionsAndCheck가 그 검사로 보이지만 본문 미해석이라 0.7. — 근거: `reqRepoReader(unit.TypeCode), ... repo.ReqChangeRepoFileOptionsAndCheck | files_service.ChangeRepoFiles(...)`

### own+adm → owner (3건)

- `apisguru:instagram.com:delete:/media/{media-id}/comments/{comment-id}` [oas, conf 0.7, G4] 미디어 소유자 또는 댓글 작성자 본인만 삭제할 수 있고 관리자 우회가 없어 당사자 조건인 owner_match로 본다. — 근거: `"Remove a comment either on the authenticated user's media object or authored by the authenticated user."`
- `gitea:get:/notifications/threads/{id}` [code, conf 0.7, G4] 본인 알림 스레드 조회(VIS+SELF의 알림 범위)로 의도된 정책은 owner_match이나 getThread의 소유자 비교 본문은 발췌에 없다. — 근거: `Get notification thread by ID | reqToken() | n := getThread(ctx)`
- `gitea:patch:/notifications/threads/{id}` [code, conf 0.7, G4] 본인 알림 스레드를 ctx.Doer 기준으로 읽음 처리하는 본인 데이터 범위 작업이라 owner_match이나 getThread 본문이 발췌에 없어 해석이 필요하다. — 근거: `notifications.SetNotificationStatus(ctx, n.ID, ctx.Doer, targetStatus) | rejectPublicOnly(), reqToken()`

### tenant → role (3건)

- `apisguru:slmonitor.com:get:/api/v2.1/companies/{companyId}/users/{uniqueUserId}` [oas, conf 0.7, G3] 타인 프로필 조회에 CompanyAdministrator·CompanyMonitor 역할이 요구되어 role_required로 본다. — 근거: `security: EmailLogin [CompanyAdministrator, CompanyMonitor]; gets the specified user's profile.`
- `apisguru:slmonitor.com:put:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/itinerary` [oas, conf 0.7, G3] 지정 작업자 일정 수정에 CompanyMonitor 역할이 요구되어 role_required로 본다. — 근거: `security: EmailLogin [CompanyMonitor]; This operation updates the worker's itinerary.`
- `apisguru:slmonitor.com:put:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/itinerary-file` [oas, conf 0.7, G3] CompanyMonitor 역할 요구가 명시되어 role_required다. — 근거: `security: EmailLogin [CompanyMonitor]; summary: Update the itinerary file`

### own+adm → manual (3건)

- `gitea:get:/repos/{owner}/{repo}/times` [code, conf 0.7, 보류4] user 쿼리 없으면 본인 기록, 타인 지정은 저장소 writer·관리자만 허용되는 쿼리 모드별 정책 분기라 보류. — 근거: `cantSetUser := !ctx.Doer.IsAdmin && opts.UserID != ctx.Doer.ID && !ctx.IsUserRepoWriter; query by user not allowed`
- `gitea:patch:/repos/{owner}/{repo}/issues/comments/{id}` [code, conf 0.7, 보류8] 체인에는 저장소 가시성 분기와 인증만 있고 실제 작성자·권한 검사는 발췌에 없는 editIssueComment 안에 있어 요청자-객체 관계를 확인할 수 없다(댓글 행위자 계열은 manual). — 근거: `repoAssignment(), checkTokenPublicOnly(), mustNotBeArchived, reqToken() | editIssueComment(ctx, *form)`
- `gitea:get:/repos/{owner}/{repo}/issues/{index}/times` [code, conf 0.7, 보류4] user 쿼리 유무에 따라 본인 기록은 누구나, 타인 기록은 저장소 writer·관리자만 허용되는 쿼리 모드별 정책 분기라 보류. — 근거: `cantSetUser := !ctx.Doer.IsAdmin && opts.UserID != ctx.Doer.ID && !ctx.IsUserRepoWriter; opts.UserID = ctx.Doer.ID`

### member → owner (2건)

- `apisguru:circuitsandbox.net:post:/conversations/community/{convId}/join` [oas, conf 0.7, G4] 처리 대상이 인증 사용자 본인으로 고정된 본인 명의 구독 생성이며, 비구성원 조건은 상태 전제일 뿐 별도 인가 조건이 아니라고 해석했다. — 근거: `"Adds the authenticated user to the given community"; "can only be performed by a user who is not yet a member"`
- `apisguru:daniweb.com:post:/audiences/{ID}/memberships` [oas, conf 0.7, G4] 인증 사용자 본인 명의의 구성원 기록 생성으로 처리 대상이 본인으로 고정된다. — 근거: `"Create a membership record for the OAuth'ed end-user based on the current audience segment/bubble combination."`

### tenant → owner (2건)

- `apisguru:figshare.com:get:/account/articles/export` [oas, conf 0.9, G4] 설명이 대상 계정을 OAuth 자격증명의 계정(인증 사용자 본인)으로 고정한다고 명시한다. — 근거: `"Return status on all reports generated for the account from the oauth credentials"`
- `apisguru:slmonitor.com:get:/api/v2.1/companies/{companyId}/me` [oas, conf 0.9, G4] 경로 /me와 설명이 처리 대상을 인증 사용자 본인으로 고정하므로 owner_match다. — 근거: `summary: Get the authenticated user; This operation gets the authenticated user's profile.`

### member → tenant (2건)

- `apisguru:kumpeapps.com:get:/kkid/allowance` [oas, conf 0.7, G1] 대상 사용자가 인증 사용자의 masterID 계정 안에 있어야 한다고 명시하고 대상 계정 ID는 요청에 없어 테넌트 일치 조건으로 본다. — 근거: `"provided that they are within the masterID account of the authenticated user"`
- `apisguru:kumpeapps.com:get:/kkid/userlist` [oas, conf 0.7, G1] 인증 사용자의 master account로 목록을 한정하므로 요청자 테넌트 필터로 본다. — 근거: `"search for users within the authenticated user's master account"`

### manual → owner (2건)

- `apisguru:mastodon.local:post:/api/v1/accounts/{id}/block` [oas, conf 0.7, G4] 요청자 본인의 차단 관계를 생성하는 본인 명의 요청(응답도 요청자-대상 관계)이라 owner_match. — 근거: `Block the given account.; blocked_by, blocking, following, muting`
- `gitea:post:/orgs` [code, conf 0.7, G4-b] 요청자 본인 명의로 조직을 생성하며 CanCreateOrganization은 본인 계정의 생성 허용 플래그라 본인 명의 생성(owner_match)으로 판단. — 근거: `if !ctx.Doer.CanCreateOrganization() { 403 } | organization.CreateOrganization(ctx, org, ctx.Doer)`

### owner → tenant (2건)

- `apisguru:viator.com:get:/booking/pastbooking` [oas, conf 0.7, G1] 예약의 생성 API 키와 요청 API 키가 같아야 한다는 명시 조건은 API 키 단위(파트너 계정) 필터이므로 tenant_match로 보되 owner_match 해석도 가능하다. — 근거: `"this service will only return past bookings that were made with the same API key that was used to make the booking"`
- `apisguru:vonage.com:get:/accounts/{account_id}/call-logs` [oas, conf 0.7, G1] 설명이 요청자 본인 계정 범위를 명시하고 계정이 다수 사용자를 포함하는 조직 단위라 tenant_match로 보되, 경로에 account_id가 있어 owner_match·보류 해석도 가능하다. — 근거: `"Retrieve call logs for your account"; path_params: ["account_id"]; "source_user", "destination_user"`

### owner → role (1건)

- `apisguru:appwrite.io:put:/teams/{teamId}` [oas, conf 0.7, G3-a] 대상 팀 안의 owner 역할 보유가 명시된 접근 조건이므로 그룹 안 역할로 보아 role_required로 본다. — 근거: `"Only team owners have write access for this resource."`

### role → tenant (1건)

- `apisguru:visma.com:get:/v1/bankaccounts` [oas, conf 0.7, G1] 경로에 조직 ID 없이 요청자의 현재 조직 범위로 목록을 필터한다고 명시해 tenant_match로 보되, 서버 측 비교 방식은 해석이다. — 근거: `"Get all bank accounts for current organization."; tenant_cols: ["company"]; path_params: []`

### manual → public (1건)

- `gitea:get:/orgs/{org}/repos` [code, conf 0.7, G7] reqToken·reqOrgVisible 없이 익명도 핸들러에 도달해 접근 가능한 저장소만 필터해 반환하므로 요청 허용 자체는 무조건이라고 보았다. — 근거: `orgAssignment(true), checkTokenPublicOnly() | listUserRepos(ctx, ctx.Org.Organization.AsUser(), ctx.IsSigned)`

## 6. 다음 단계 (승인 후, 사전 기록 3단계)

- 사람 확인 시트: manual로 바뀐 행 전부 269 + 그 외 변경 행 30%(10) + 안 바뀐 행 10% 블라인드(31) ≈ 310행, seed 42. 검수자 A/B/C 균등.
- 바뀐 행 rationale 재작성(SFT 형식, 입력 근거만, 규칙 ID·경로·메타 문구 금지) → 정합성 assert → data-v7 동결 → 학습 번들(v5 설정, 7B). 중단 규칙 2026-11-09 18:00 KST.
- 한계: 재판정자는 사람이 아니라 Claude(AI)이며 OAS-only 보류 2 엄격 적용은 data-v5의 gpt-4o-mini 라벨(confidence ≥ 0.6 포함)과 기준이 다르다. 변경 수가 많다면 그 차이가 주 원인이다. gitea 코드 행은 C′에서 36건이 이미 교정됐고 이번은 그 위에서 다시 판정한 결과다.

## 7. manual 20% 초과에 대한 선택지(계산만, 결정은 사용자)

| 선택지 | train n / manual / 비율 | val n / manual / 비율 | 비고 |
|---|---|---|---|
| A. 재판정 전부 반영 | 1274 / 406 / 31.9% | 179 / 56 / 31.3% | 경고 초과. v5(12.8%)·data-v3 쿼터 규칙(10~25%)과 어긋남 |
| B. 반영 + OAS-only에서 새로 manual이 된 256행 제외 | 1038 / 170 / 16.4% | 159 / 36 / 22.6% | 보류 2로 근거 없다고 판정된 OAS 행을 학습에서 빼는 것(manual pool 보존) |
| C. 반영 + OAS-only manual 전부(299행) 제외 | 1008 / 140 / 13.9% | 146 / 23 / 15.8% | OAS-only 학습 행은 구체 label 91행만 남음 |
| D. 반영 + manual 쿼터(data-v3 규칙: 구체/3 = 25%, seed 42) | train 구체 868 → manual 목표 289(25%) 또는 96(10%) | - | 초과 manual은 pool 파일로 보존 |

어느 선택지든 사람 확인 시트(3단계) 범위는 같다: manual로 바뀐 행 전부(269) + 그 외 변경 행 30% + 안 바뀐 행 10% 블라인드. B·C·D는 학습셋 구성만 바꾸고 재판정 결과 자체는 바꾸지 않는다. 계산 reports/data_v7/stop2_options.json.
