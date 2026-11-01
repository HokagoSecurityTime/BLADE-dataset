# data-v2 검수 반영 + Gitea 재라벨 규칙 적용 (r1, 동결 전) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl a99d30da2d29907e…, val_v30.jsonl 62bdadb29cae7aaf…, test_v30.jsonl 9bd47216575afc60…, policy_label_v3.0.1.md d0913c27b5de185e…. 입력 train_v2_draft.jsonl(971, 불변) → 출력 train_v2_draft_r1.jsonl(971). 검수 파일 reports/review_v2_sample/review_sheet_reviewed.xlsx(52건, mid 포함 전부 확정). 라벨을 바꾼 레코드는 meta.v2_relabel={from,to,rule_id,evidence}, 검수 태그는 meta.review_tags.

규칙 우선순위: 사람 검수 > R2(visibility override를 GET/HEAD로 한정) > R3(public 재판정) > R1(SELF→owner_match) > R4(인증 없음→public). R2로 유지된 visibility override(GET)는 R3의 "reqToken 없으면 public 유지"보다 우선한다(검수 기준 3번: 공개/비공개 분기는 manual(VIS)).

## 1. 규칙 검증 (검수 52건, 사람 라벨 가림)

정밀도 = 규칙이 라벨 변경을 제안한 건 중 사람 라벨과 일치한 비율. 90% 미만이면 미적용(후보 목록만).

| 규칙 | 발동 | 일치 | 정밀도 | 판정 |
|---|---:|---:|---:|---:|
| R1_self_owner | 13 | 13 | 1.0 | 적용 |
| R2_vis_readonly | 1 | 0 | 0.0 | 미적용(후보만) |
| R3_public_rejudge | 13 | 6 | 0.4615 | 미적용(후보만) |
| R4_noauth_public | 1 | 1 | 1.0 | 적용 |

R1_self_owner 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:post:/user/emails | owner_match | owner_match | ○ | routers/api/v1/user/email.go:43 match "AddEmailAddresses(ctx, ctx.Doer," |
| gitea:get:/user/blocks/{username} | owner_match | owner_match | ○ | routers/api/v1/user/block.go:33 match "CheckUserBlock(ctx, ctx.Doer)" |
| gitea:get:/user/actions/runners/{runner_id} | owner_match | owner_match | ○ | routers/api/v1/user/runners.go:52 match "shared.GetRunner(ctx, ctx.Doer.ID" |
| gitea:patch:/user/actions/runners/{runner_id} | owner_match | owner_match | ○ | routers/api/v1/user/runners.go:98 match "shared.UpdateRunner(ctx, ctx.Doer.ID" |
| gitea:get:/user/following | owner_match | owner_match | ○ | routers/api/v1/user/follower.go:106 match "listUserFollowing(ctx, ctx.Doer)" |
| gitea:post:/user/hooks | owner_match | owner_match | ○ | routers/api/v1/user/hook.go:79 match "AddOwnerHook(
		ctx,
		ctx.Doer," |
| gitea:patch:/user/hooks/{id} | owner_match | owner_match | ○ | routers/api/v1/user/hook.go:105 match "EditOwnerHook(
		ctx,
		ctx.Doer," |
| gitea:delete:/user/blocks/{username} | owner_match | owner_match | ○ | routers/api/v1/user/block.go:77 match "UnblockUser(ctx, ctx.Doer," |
| gitea:get:/user/orgs | owner_match | owner_match | ○ | routers/api/v1/org/org.go:63 match "listUserOrgs(ctx, ctx.Doer)" |
| gitea:post:/user/avatar | owner_match | owner_match | ○ | routers/api/v1/user/avatar.go:17 match "UploadAvatar(ctx, ctx.Doer," |
| gitea:get:/notifications/new | owner_match | owner_match | ○ | routers/api/v1/notify/notifications.go:18 match "UserID: ctx.Doer.ID" |
| gitea:put:/user/blocks/{username} | owner_match | owner_match | ○ | routers/api/v1/user/block.go:52 match "BlockUser(ctx, ctx.Doer)" |
| gitea:get:/user/gpg_keys | owner_match | owner_match | ○ | routers/api/v1/user/gpg_key.go:76 match "listGPGKeys(ctx, ctx.Doer.ID," |

R2_vis_readonly 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:delete:/repos/{owner}/{repo}/actions/artifacts/{artifact_id} | owner_or_admin | role_required | ✗ | write DELETE + ['reqRepoWriter'] ; restored label_before_override |

R3_public_rejudge 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:get:/repos/{owner}/{repo}/tags | public | manual_review_required | ✗ | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/labels | public | manual_review_required | ✗ | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/comments/{id}/assets | public | manual_review_required | ✗ | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/branches | public | manual_review_required | ✗ | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/file-contents | public | manual_review_required | ✗ | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/actions/workflows/{workflow_id} | manual_review_required | manual_review_required | ○ | reqToken + ['repoAssignment', 'reqRepoReader'] -> VIS |
| gitea:get:/repos/{owner}/{repo}/collaborators | manual_review_required | manual_review_required | ○ | reqToken + ['repoAssignment', 'reqAnyRepoReader'] -> VIS |
| gitea:get:/repos/{owner}/{repo}/keys | role_required | role_required | ○ | reqToken + ['reqAdmin'] |
| gitea:get:/repos/{owner}/{repo}/notifications | manual_review_required | owner_match | ✗ | reqToken + ['repoAssignment'] -> VIS |
| gitea:get:/repos/{owner}/{repo}/teams | manual_review_required | manual_review_required | ○ | reqToken + ['repoAssignment', 'reqAnyRepoReader'] -> VIS |
| gitea:get:/repos/{owner}/{repo}/times | manual_review_required | owner_or_admin | ✗ | reqToken + ['repoAssignment'] -> VIS |
| gitea:get:/user/keys | owner_match | owner_match | ○ | reqToken + SELF routers/api/v1/user/key.go:102 "listPublicKeys(ctx, ctx.Doer)" |
| gitea:post:/markdown | manual_review_required | manual_review_required | ○ | reqToken only, no object -> AUTH_ANY |

R4_noauth_public 발동 상세:

| id | 규칙 라벨 | 사람 라벨 | 일치 | 근거 |
|---|---:|---:|---:|---:|
| gitea:get:/settings/attachment | public | public | ○ | chain ['sudo']: no authn/authz middleware |

## 2. 적용 건수

| rule_id | 변경 건수 |
|---|---:|
| human_review_v2 | 34 |
| R2_vis_readonly | 0 |
| R3_public_rejudge | 0 |
| R1_self_owner | 30 |
| R4_noauth_public | 14 |

사람 검수 52건 중 라벨 변경 34건(나머지는 현재 라벨 확인). R1 제외(VIS 복합) 17건, R3 판정 보류 0건.

### R3_public_rejudge 미적용 후보 44건 (라벨 변경 없음)

| id | 현재 | 규칙 제안 | 근거 |
|---|---:|---:|---:|
| gitea:get:/repos/{owner}/{repo}/compare/{basehead} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/raw/{filepath} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/media/{filepath} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/forks | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/tags/{tag} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/actions/tasks | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/actions/artifacts | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/wiki/page/{pageName} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/wiki/revisions/{pageName} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/wiki/pages | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/stargazers | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/subscribers | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/releases | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/releases/latest | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/editorconfig/{filepath} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/commits | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/git/blobs/{sha} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/signing-key.gpg | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/signing-key.pub | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/topics | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issue_templates | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/languages | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/licenses | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/activities/feeds | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/pinned | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/comments | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/comments/{id} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/comments/{id}/reactions | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/comments/{id}/assets/{attachment_id} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/comments | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/timeline | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/subscriptions | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/reactions | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/assets | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/assets/{attachment_id} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/dependencies | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/blocks | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/labels | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/labels/{id} | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/milestones | manual_review_required | public | no reqToken in chain -> public kept |
| gitea:get:/repos/{owner}/{repo}/milestones/{id} | manual_review_required | public | no reqToken in chain -> public kept |

## 3. 변경 전후 label 분포

| label | 전체 전 | 전체 후 | 코드 있음 전 | 코드 있음 후 | Gitea 전 | Gitea 후 |
|---|---:|---:|---:|---:|---:|---:|
| public | 47 | 53 | 28 | 34 | 12 | 18 |
| role_required | 161 | 164 | 57 | 60 | 37 | 40 |
| membership_required | 55 | 58 | 30 | 33 | 8 | 11 |
| tenant_match | 52 | 52 | 20 | 20 | 0 | 0 |
| owner_match | 182 | 231 | 56 | 105 | 36 | 85 |
| owner_or_admin | 32 | 35 | 31 | 34 | 0 | 3 |
| manual_review_required | 442 | 378 | 338 | 274 | 278 | 214 |
| 합계 | 971 | 971 | 560 | 560 | 371 | 371 |

코드 있는 레코드의 manual 비율: 60.4% → 48.9%. Gitea manual: 278 → 214.

## 4. 남은 Gitea manual의 사유·태그 분포

| 사유 | 건수 |
|---|---:|
| VIS | 139 |
| 기타 | 18 |
| 복합(VIS+SELF) | 17 |
| VIS(검수) | 16 |
| AUTH_ANY(객체 경로 있음) | 12 |
| AUTH_ANY | 8 |
| AUTH_ANY(검수) | 3 |
| 복합(VIS·SELF, 검수) | 1 |

## 5. R3 판정 보류 목록 (라벨 변경 없음)

없음

## 6. R1 제외(VIS 복합, manual 유지)

| id | SELF 매칭 |
|---|---:|
| gitea:put:/user/starred/{owner}/{repo} | StarRepo(ctx, ctx.Doer, |
| gitea:delete:/user/starred/{owner}/{repo} | StarRepo(ctx, ctx.Doer, |
| gitea:post:/repos/{template_owner}/{template_repo}/generate | GenerateRepository(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/transfer | StartRepositoryTransfer(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches | DispatchActionWorkflow(ctx, ctx.Doer, |
| gitea:put:/repos/{owner}/{repo}/subscription | WatchRepoAuto(ctx, ctx.Doer, |
| gitea:delete:/repos/{owner}/{repo}/subscription | WatchRepoAuto(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/releases | UpdateRelease(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/merge | CheckPullMergeable(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/reviews | CreateCodeComment(ctx,
			ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/reviews/{id} | SubmitReview(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/pulls/{index}/comments/{id}/replies | CreateCodeComment(ctx,
		ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/comments | CreateIssueComment(ctx, ctx.Doer, |
| gitea:get:/repos/{owner}/{repo}/issues/{index}/timeline | isXRefCommentAccessible(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/stopwatch/start | CreateIssueStopwatch(ctx, ctx.Doer, |
| gitea:post:/repos/{owner}/{repo}/issues/{index}/stopwatch/stop | FinishIssueStopwatch(ctx, ctx.Doer, |
| gitea:delete:/repos/{owner}/{repo}/issues/{index}/stopwatch/delete | CancelStopwatch(ctx, ctx.Doer, |

## 7. 라벨 체계 일관성 점검

기존 Gitea 구체 label 93건 중 미들웨어 기준(쓰기·admin → role_required, org/팀 멤버십 → membership_required)과 다르게 붙은 건: 1건 (변경 없음, id만).

| id | 현재 label | 미들웨어 기준 | 근거 미들웨어 |
|---|---:|---:|---:|
| gitea:get:/repos/{owner}/{repo}/keys | public | role_required | ['reqAdmin'] |

test_v30에서 AUTH_ANY 유형(인증 검사만 있고 대상 객체·역할·소유 검사 없음, 경로 파라미터 없음; 휴리스틱 정규식) 후보: 35건.

| id | service | method | path | 정답 label |
|---|---:|---:|---:|---:|
| 887fef961a2a2394c816 | crAPI | GET | /identity/api/auth/jwks.json | public |
| 860383f68102b772bb99 | crAPI | GET | /workshop/api/mechanic | public |
| a0f5f54a6d4c22bb18e7 | crAPI | GET | /workshop/api/mechanic/service_requests | owner_match |
| af6e2ae1b29132ee1d77 | crAPI | GET | /workshop/api/shop/orders/all | owner_match |
| 7a19e5a3a9eb0d5947f3 | crAPI | GET | /workshop/api/shop/products | public |
| bc1dce3621c7da44ddfe | crAPI | POST | /identity/api/auth/login | public |
| 875c33706a68c4c9a61a | crAPI | POST | /identity/api/auth/unlock | public |
| 61f662463e13765b9478 | crAPI | POST | /identity/api/auth/v2.7/user/login-with-token | public |
| 769288e3cd1d5d4c117d | crAPI | POST | /identity/api/auth/verify | public |
| 6224f0ab777c554bb796 | crAPI | POST | /workshop/api/merchant/contact_mechanic | owner_match |
| 0f7dacc4c4c5dc50ad69 | crAPI | POST | /workshop/api/shop/orders | owner_match |
| e878000888f7f413f8b0 | crAPI | POST | /workshop/api/shop/orders/return_order | owner_match |
| 79d4449bddc16ef5992f | crAPI | POST | /workshop/api/shop/products | role_required |
| a786e652a128f7d49fcb | juice-shop | GET | /api/Complaints | owner_or_admin |
| 7cf042f2cfd8f56045a3 | juice-shop | GET | /api/PrivacyRequests | role_required |
| 6c0c7e81f4263be705bd | juice-shop | GET | /api/SecurityAnswers | role_required |
| 9c760e36b50d4ee7a2d9 | juice-shop | GET | /api/Users | role_required |
| 447fc0aa6c34613756ff | juice-shop | GET | /rest/2fa/status | owner_match |
| c64b7f4c9538c700b710 | juice-shop | GET | /rest/user/change-password | owner_match |
| bbaf2ce2f276bd2f4679 | juice-shop | POST | /api/Complaints | owner_match |
| af9828d3c503f11fb3fe | juice-shop | POST | /api/PrivacyRequests | owner_match |
| 39034afdb110cdb9defc | juice-shop | POST | /api/Products | role_required |
| 063fa7598db37c095700 | juice-shop | POST | /api/Quantitys | role_required |
| ed9b8680702e673060d4 | juice-shop | POST | /api/Recycles | owner_match |
| 1b6a93b2cd2fddfc5d01 | juice-shop | POST | /api/SecurityQuestions | role_required |
| 01df9f46f6e721fa4cb0 | Pixi | POST | /api/login | public |
| 680ac46b983584d4552d | Pixi | POST | /api/user/login | public |
| 963209fb55865d6f2acf | DVWS-node | GET | /api/upload | owner_match |
| 06ba24e97fdcb059ad92 | DVWS-node | GET | /api/v2/notes | owner_match |
| 0a8fb9b5c84b26b19826 | DVWS-node | POST | /api/download | owner_match |
| 0f7af84126bd72a56bd5 | DVWS-node | POST | /api/upload | owner_match |
| 3f37f7f30c7bc18f180a | DVWS-node | POST | /api/v2/export | owner_match |
| 60c95e757a6b732073ae | DVWS-node | POST | /api/v2/notes | owner_match |
| e48aca1abec6c374bfa1 | DVWS-node | POST | /api/v2/notes/import/xml | owner_match |
| 26c60d2fb9155d63f00c | DVWS-node | POST | /api/v2/passphrase | owner_match |

## 8. AGENTS.md에 옮긴 판정 기준

- test_v30 정답은 "의도된 정책" 기준: 본인 리소스(/user/..., Doer 기준 처리)는 owner_match (test의 /user/dashboard·change-email 등과 동일)
- 저장소 권한 레벨(쓰기·admin)은 role_required, org/팀 멤버십은 membership_required로 처리
- 공개/비공개 저장소 분기(repoAssignment·reqRepoReader·reqAnyRepoReader)는 manual(VIS)
- reqToken만 있고 객체가 없는 엔드포인트는 7종에 맞는 label이 없어 manual(AUTH_ANY)

원자료: train_v2_draft_r1.jsonl(meta.v2_relabel·review_tags), scripts/apply_review_v2_r1.py(SELF 패턴·미들웨어 집합 상수).
