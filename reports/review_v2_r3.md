# data-v2 r3 — 잔여 판정 반영·authonly 재라벨·VIS cap 1 (동결 직전) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): train_v30.jsonl a99d30da2d29907e…, val_v30.jsonl 62bdadb29cae7aaf…, test_v30.jsonl 9bd47216575afc60…, policy_label_v3.0.1.md d0913c27b5de185e…. 입력 train_v2_draft_r2.jsonl(971, 불변) → 출력 train_v2_draft_r3.jsonl(867) + train_v2_draft_r3_vis_excluded.jsonl(104). 쿼터 미적용(dry-run만).

## 1. 사용자 확정 라벨 (rule_id=human_review_v2_r3)

| id | 이전 | 확정 | 근거 |
|---|---:|---:|---:|
| gitea:post:/users/{username}/tokens | manual_review_required | owner_or_admin | reqSelfOrAdmin |
| gitea:patch:/notifications/threads/{id} | manual_review_required | owner_or_admin | getThread: 본인 또는 admin |
| gitea:post:/user/actions/variables/{variablename} | manual_review_required | owner_match | ownerID := ctx.Doer.ID |
| gitea:delete:/user/applications/oauth2/{id} | manual_review_required | owner_match | DeleteOAuth2Application(appID, ctx.Doer.ID) |

보고서 r2 6·7절의 나머지 18건은 manual 유지, meta.review_tags 기록: VIS 10 · AUTH_ANY 8.

| id | 태그 |
|---|---:|
| gitea:get:/users/search | VIS |
| gitea:get:/users/{username} | VIS |
| gitea:get:/users/{username}/repos | VIS |
| gitea:get:/users/{username}/projects | VIS |
| gitea:get:/users/{username}/gpg_keys | AUTH_ANY |
| gitea:get:/users/{username}/followers | AUTH_ANY |
| gitea:get:/users/{username}/following | AUTH_ANY |
| gitea:get:/users/{username}/following/{target} | AUTH_ANY |
| gitea:get:/users/{username}/subscriptions | AUTH_ANY |
| gitea:get:/user/keys/{id} | AUTH_ANY |
| gitea:get:/repositories/{id} | AUTH_ANY |
| gitea:get:/packages/{owner}/{type}/{name} | VIS |
| gitea:get:/packages/{owner}/{type}/{name}/{version} | VIS |
| gitea:get:/packages/{owner}/{type}/{name}/-/latest | VIS |
| gitea:post:/packages/{owner}/{type}/{name}/-/link/{repo_name} | VIS |
| gitea:post:/packages/{owner}/{type}/{name}/-/unlink | VIS |
| gitea:get:/users/{username}/orgs | AUTH_ANY |
| gitea:get:/users/{username}/orgs/{org}/permissions | VIS |

R3' 불일치 2건 사람 라벨 유지 확인: gitea:get:/repos/{owner}/{repo}/notifications = owner_match, gitea:get:/repos/{owner}/{repo}/times = owner_or_admin

## 2. 합성 변형 재라벨 (rule_id=variant_intended_policy)

변형 38건 유형별: {'authonly': 19, 'extauth': 19}. authonly → base label(intended_labels.yaml base_label), extauth → manual 유지.

| id | 이전 | 재라벨 |
|---|---:|---:|
| orbit_tickets_drafts_authonly | manual_review_required | owner_match |
| orbit_tickets_shared_authonly | manual_review_required | owner_or_admin |
| orbit_tickets_workspace_authonly | manual_review_required | tenant_match |
| orbit_tickets_audit_authonly | manual_review_required | role_required |
| copper_wallet_drafts_authonly | manual_review_required | owner_match |
| copper_wallet_shared_authonly | manual_review_required | owner_or_admin |
| copper_wallet_workspace_authonly | manual_review_required | tenant_match |
| copper_wallet_audit_authonly | manual_review_required | role_required |
| campus_records_drafts_authonly | manual_review_required | owner_match |
| campus_records_shared_authonly | manual_review_required | owner_or_admin |
| campus_records_workspace_authonly | manual_review_required | tenant_match |
| campus_records_audit_authonly | manual_review_required | role_required |
| relay_forum_drafts_authonly | manual_review_required | owner_match |
| relay_forum_shared_authonly | manual_review_required | owner_or_admin |
| relay_forum_moderation_authonly | manual_review_required | owner_or_admin |
| relay_forum_workspace_authonly | manual_review_required | tenant_match |
| relay_forum_audit_authonly | manual_review_required | role_required |
| relay_forum_roster_authonly | manual_review_required | membership_required |
| relay_forum_pins_authonly | manual_review_required | membership_required |

기준 추가(AGENTS.md): 인가 검사가 코드에서 빠졌어도 경로·스키마로 의도된 정책이 드러나면 그 정책을 label로 한다(test_v30 취약 API와 동일). 외부 인가처럼 의도를 코드로 확인할 수 없는 경우만 manual.

같은 기준 해당 여부 점검 — 기존 합성 manual(변경 없음, 목록만): 22건. disputed/council(복합 조건 설계)·subscription(구독 조건)·extauth(외부 인가)는 '의도 정책이 경로·스키마로 드러남'에 해당하지 않아 기준 적용 대상 아님.

| id | 출처 | 설계 사유 | variant_kind |
|---|---:|---:|---:|
| campus_records_disputed_0 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| campus_records_disputed_1 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| campus_records_subscription_0 | synthetic | A premium plan is required. | - |
| campus_records_subscription_1 | synthetic | A premium plan is required. | - |
| copper_wallet_disputed_0 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| copper_wallet_disputed_1 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| copper_wallet_subscription_0 | synthetic | A premium plan is required. | - |
| copper_wallet_subscription_1 | synthetic | A premium plan is required. | - |
| orbit_tickets_disputed_0 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| orbit_tickets_disputed_1 | synthetic | Conflicting owner and tenant requirements are deliberately unresolved; deny pending review. | - |
| orbit_tickets_subscription_0 | synthetic | A premium plan is required. | - |
| orbit_tickets_subscription_1 | synthetic | A premium plan is required. | - |
| relay_forum_council_0 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| relay_forum_council_1 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| harbor_manifests_council_0 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| harbor_manifests_council_1 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| pixel_gallery_council_0 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| pixel_gallery_council_1 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| meadow_plots_council_0 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| meadow_plots_council_1 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| atlas_leases_council_0 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |
| atlas_leases_council_1 | synthetic | Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one lab | - |

## 3. VIS cap 적용 (시그니처당 1건, seed 42, 경로 다양성 우선)

대상 156건(검수·human_* 레코드 제외), 시그니처 52개 → 유지 52건, 제외 104건(train_v2_draft_r3_vis_excluded.jsonl, meta.vis_cap_excluded에 시그니처·kept_id 기록).

## 4. r2 → r3 label 분포

| label | r2 전체 | r2 코드 | r2 Gitea | r2 합성 | r3 전체 | r3 코드 | r3 Gitea | r3 합성 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| public | 53 | 34 | 18 | 16 | 53 | 34 | 18 | 16 |
| role_required | 164 | 60 | 40 | 20 | 168 | 64 | 40 | 24 |
| membership_required | 58 | 33 | 11 | 22 | 60 | 35 | 11 | 24 |
| tenant_match | 52 | 20 | 0 | 20 | 56 | 24 | 0 | 24 |
| owner_match | 240 | 114 | 94 | 20 | 246 | 120 | 96 | 24 |
| owner_or_admin | 35 | 34 | 3 | 31 | 42 | 41 | 5 | 36 |
| manual_review_required | 369 | 265 | 205 | 60 | 242 | 138 | 97 | 41 |
| 합계 | 971 | 560 | 371 | 189 | 867 | 456 | 267 | 189 |

코드 있는 레코드 manual 비율: 47.3% → **30.3%**; 전체 manual 비율: 38.0% → **27.9%**.

## 5. 25% 쿼터 dry-run (apply_reviews_v2 공식, 적용 안 함)

| 항목 | 값 |
|---|---:|
| concrete | 625 |
| target | 208 |
| fixed | 145 |
| gitea_manual | 97 |
| slots_for_gitea | 63 |
| gitea_manual_excluded | 34 |
| human_reviewed_gitea_manual | 19 |
| note | fixed manual이 target을 넘으면 합성·data-v1은 줄이지 않고 보고 |
| fixed 출처 | {"data_v1_apisguru": 104, "synthetic": 41} |

해석: 구체 625건 → manual 목표 208건. data-v1 manual + 합성 manual = 145건이 고정이므로 Gitea manual 97건 중 63건만 들어가고 34건이 pool로 빠진다(검수 manual 19건 포함 여부는 쿼터 선택 규칙에 따름).

## 6. 남은 Gitea manual 사유·태그 분포 (r3)

| 사유 | 건수 |
|---|---:|
| VIS | 50 |
| VIS(검수) | 16 |
| VIS(사용자 확인, r3) | 10 |
| AUTH_ANY | 8 |
| AUTH_ANY(사용자 확인, r3) | 8 |
| AUTH_ANY(검수) | 3 |
| 복합(VIS+SELF actor) | 2 |

원자료: train_v2_draft_r3.jsonl, train_v2_draft_r3_vis_excluded.jsonl, scripts/apply_review_v2_r3.py.
