# taiga-back — data-v5 training candidate extraction

## Repository

- Repository: https://github.com/taigaio/taiga-back (Django REST backend of Taiga project management)
- Tag: `6.10.2` (latest tag; the repo has no GitHub "releases", `gh api .../releases/latest` → 404)
- Commit: `4b023d8414fc675780c6aae9d541b538c5c71369`
- Clone: `datasets/blade/raw/opensource/taigaio_taiga-back/` (`git clone --depth 1 --branch 6.10.2`), read-only, not git-tracked.
- License: SPDX `MPL-2.0` (GitHub API `license.spdx_id`). `LICENSE` file begins "Mozilla Public License Version 2.0 / 1. Definitions / 1.1. "Contributor" means each individual or legal entity that creates, contributes to the creation of, or owns Covered Software." — file-level weak copyleft, not AGPL. Every source file carries the header "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0." and "Copyright (c) 2021-present Kaleidos INC".
- Extraction date: 2026-10-31. Static analysis only (no build/run/modify). No LLM API calls.
- Output: `candidates.jsonl` (150 lines), produced by `extract_taiga.py` (run with `python -I`).

## Extraction scope

All routes are mounted under `path('api/v1/', include(router.urls))` (`taiga/urls.py:21`) with `DefaultRouter(trailing_slash=False)` (`taiga/routers.py:11`), so paths are `/api/v1/<prefix>[/{id}][/<action>]`. Nested router: `/api/v1/epics/{epic}/related_userstories[/{user_story}]`. Extra routers: `taiga/stats/routers.py` (`stats/discover`, `stats/system` if STATS_ENABLED) and `taiga/feedback/routers.py` (`feedback`).

Covered: history comment actions (all 5 object types), attachments, users, auth, projects, memberships/invitations/roles, project values (statuses, points, swimlanes), project templates, user stories / tasks / issues / epics (+ related user stories) / wiki pages / wiki links / milestones, custom attributes, user-storage, notify-policies, web-notifications, user-project-settings, webhooks/webhooklogs, applications/application-tokens, feedback, contact, importer/exporter, search, resolver, timeline, stats, locales.

`oas_status` is `generated` for every record (no OpenAPI file in the repository). `oas_operation.security` is `[{"bearerAuth": []}]` unless the action permission is `AllowAny` / token-only (then `[]`). Test-only fields (draft_label, evidence, advisory…) are intentionally absent.

## Authorization architecture

1. **Dispatch**: every ViewSet declares `permission_classes = (<App>Permission,)`. Handlers call `self.check_permissions(request, '<action>', obj)` (`taiga/base/api/views.py:318-324`), which instantiates each class and calls `ResourcePermission.check_permissions(action, obj)` (`taiga/base/api/permissions.py:39-64`). Generic CRUD mixins call it with action `create` (on `validator.object`), `retrieve`, `update` (also for `partial_update`), `destroy` (`taiga/base/api/mixins.py:85,142,162,230`). Custom `@detail_route`/`@list_route` methods (`taiga/base/decorators.py`) call it with their own action name, usually on the project.
2. **Permission sets**: `class <X>Permission(TaigaResourcePermission)` holds `<action>_perms = <PermissionComponent expression>` built with `|` (Or), `&` (And), `~` (Not). `ResourcePermission.check_permissions` composes `enough_perms | (global_perms & <action>_perms)`; `None` action perms become `And()` (always true). **`TaigaResourcePermission.enough_perms = IsSuperUser()` (`taiga/base/api/permissions.py:197-198`) is inherited by every permission class, so every action is effectively `IsSuperUser() | <action>_perms`**. Work-item classes override it with `enough_perms = IsProjectAdmin() | IsSuperUser()` (e.g. `taiga/projects/userstories/permissions.py:15`). Records carry the bypass in `enough_perms_bypass` / `effective_expression` and as `auth_checks` entries with `"bypass": true` and `"via"`.
3. **Primitives** (`taiga/base/api/permissions.py` and the duplicate definitions in `taiga/permissions/permissions.py`): `AllowAny`, `DenyAll`, `IsAuthenticated`, `IsSuperUser`, `HasProjectPerm(perm)`, `IsProjectAdmin`, `IsObjectOwner`, `CommentAndOrUpdatePerm(update_perm, comment_perm)`. App-local primitives: `IsTheSameUser`, `CanRetrieveUser` (users), `IsCommentOwner`, `IsCommentDeleter`, `IsCommentProjectAdmin` (history), `IsAttachmentOwnerPerm`, `CommentAttachmentPerm` (attachments), `CanLeaveProject` (projects), `IsWebhookProjectAdmin` (webhooks), `CanUseToken` (external_apps), `IsContactActivated` (contact).
4. **Services** (`taiga/permissions/services.py`): `is_project_admin(user, obj)` → superuser, or the user's `Membership` row for the object's project has `is_admin=True` (lines 48-60). `user_has_perm(user, perm, obj)` → `perm in get_user_project_permissions(user, project)` (63-72) → `calculate_permissions(...)` (81-110):
   - superuser → ADMINS + MEMBERS + ANON perms;
   - member → `role.permissions` (+ ADMINS+MEMBERS if `membership.is_admin`) + `project.public_permissions` + `project.anon_permissions`;
   - authenticated non-member → `project.public_permissions` + `project.anon_permissions`;
   - anonymous → `project.anon_permissions`.
   `set_base_permissions_for_project` (132-141) puts all `ANON_PERMISSIONS` (= the eight `view_*` perms, `taiga/permissions/choices.py:10-19`) into both lists when the project is not private. Hence `HasProjectPerm('view_*')` is a public/private visibility branch, while `add_*/modify_*/comment_*/delete_*` (`MEMBERS_PERMISSIONS`, 21-63) are never in the anon/public lists and depend on the member's role.
5. **Membership model**: `projects.Membership(project, user, role, is_admin, email, token, invited_by)`; `Role.permissions` is the list of perm codenames. Project admin = membership row with `is_admin` (not a global role). `Project.owner` is a separate owner FK (`IsObjectOwner`, `transfer_start`).
6. **Self-scoped viewsets**: user-storage, notify-policies, user-project-settings, application-tokens and web-notifications use `IsAuthenticated` plus `get_queryset()` filtered on `request.user` (recorded as `self_target` with the filter line).

## Permission primitive → auth_checks kind

| primitive / pattern | kind | evidence |
|---|---|---|
| `AllowAny()` | anonymous | `taiga/base/api/permissions.py:143-145` |
| `IsAuthenticated()` with no object | auth_only | `taiga/base/api/permissions.py:153-155` |
| `IsAuthenticated()` where the handler only touches `request.user` (`/users/me`, `change_password`, `change_avatar`, applications `token`, self-filtered querysets) | self_target | `taiga/users/api.py:296-303`, `taiga/userstorage/api.py:28-31`, `taiga/projects/notifications/api.py:37-45`, `taiga/external_apps/api.py:57-66` |
| `IsTheSameUser()` | self_target | `taiga/users/permissions.py:18-20` (`request.user.pk == obj.pk`) |
| `IsObjectOwner()` | owner_field | `taiga/base/api/permissions.py:177-182` (`obj.owner == request.user`) |
| `IsCommentOwner()` / `IsCommentDeleter()` | owner_field | `taiga/projects/history/permissions.py:16-23` |
| `IsAttachmentOwnerPerm()` | owner_field | `taiga/projects/attachments/permissions.py:12-16` |
| `CanUseToken()` | owner_field | `taiga/external_apps/permissions.py:19-24` (`request.user == obj.user`) |
| `<owner primitive> \| IsCommentProjectAdmin()` / `\| HasProjectPerm('modify_*')` | owner_or_privileged | `taiga/projects/history/permissions.py:36-39`, `taiga/projects/attachments/permissions.py:26-31` |
| `CanLeaveProject()` | membership_row | `taiga/projects/permissions.py:27-38` → `can_user_leave_project` (`taiga/projects/services/members.py:84-96`, `project.memberships.get(user=user)`) |
| `IsContactActivated()` (private project → `cached_memberships_for_user`) | setting_dependent (+ membership_row entry) | `taiga/projects/contact/permissions.py:12-20` |
| `IsProjectAdmin()` / `IsCommentProjectAdmin()` / `IsWebhookProjectAdmin()` | group_role | `taiga/base/api/permissions.py:172-174` → `is_project_admin` (`taiga/permissions/services.py:48-60`, `membership.is_admin`) |
| `HasProjectPerm('add_*'/'modify_*'/'comment_*'/'delete_*'/'add_us_to_project')` | group_role | `taiga/permissions/choices.py:21-63` (MEMBERS_PERMISSIONS, role-dependent), `services.py:89-96` |
| `CommentAndOrUpdatePerm('modify_x','comment_x')` | group_role | `taiga/permissions/permissions.py:49-71` |
| `HasProjectPerm('view_*')` | visibility_branch | `taiga/permissions/services.py:97-108` (public_permissions / anon_permissions) + `132-141` |
| `user_has_perm(request.user, "view_*", project)` inline (search) | visibility_branch | `taiga/searches/api.py:32-48` |
| `IsSuperUser()` as the action perm | global_role | `taiga/base/api/permissions.py:158-160` (`create_template`, project templates) |
| `IsSuperUser()` / `IsProjectAdmin()` via `enough_perms` | global_role / group_role with `"bypass": true` | `taiga/base/api/permissions.py:198`, per-class `enough_perms` lines |
| `CanRetrieveUser()` (PRIVATE_USER_PROFILES) | setting_dependent | `taiga/users/permissions.py:23-28` |
| `IsAuthenticated() & HasProjectPerm(...)` | compound_and (+ one entry per operand) | e.g. `taiga/projects/permissions.py:65-68` |
| no `check_permissions` call, token in body (`users/cancel`, `change_email`, `application-tokens/validate`, `invitations/{token}`) | anonymous | handler lines quoted in `auth_checks` |

Note for the rule script: `membership_row` in the strict sense (membership alone decides, no role) occurs only for `leave` and the private-project branch of `contact`; in Taiga, "member" access to work items is always mediated by `role.permissions`, which is why `HasProjectPerm('modify_*')` is recorded as `group_role` (the note on each entry says so) and `view_*` as `visibility_branch`.

## Excluded scopes

- `github-hook`, `gitlab-hook`, `bitbucket-hook`, `gogs-hook` (secret-signed webhooks from external services; not a user authorization policy).
- `importers/trello|jira|github|asana` (registered only when `settings.IMPORTERS[...]['active']`; external OAuth flows).
- `admin/` (Django admin), `front/sitemap*.xml`, DEBUG static/media routes, `auth/verify` (DEBUG only).
- `list` actions whose permission is `AllowAny()` + filter backend (userstories/tasks/issues/epics/wiki/milestones/memberships/roles/… lists, `filters_data`, `csv`) except the four kept as examples (`GET /api/v1/users`, `/user-storage`-style self lists, `/application-tokens`): the policy lives in filter backends, which this extraction does not quote.
- Near-duplicate siblings dropped by the `DROP` set in `extract_taiga.py` (83 of 233 generated records) to stay ≤150: e.g. `history/*/{id}` retrieve, per-type voters/watchers lists, tasks/epics `bulk_create`, 7 of 11 project-value variants, `PUT` duplicates of `PATCH`.
- `search`: no `permission_classes` on the viewset; kept because the inline `user_has_perm` calls are the policy.

## Counts

- Candidates: **150** (233 generated, 83 dropped as near-duplicates). `unlocated`: 0. All records have non-empty `auth_checks`; `controller_text` 411–2992 chars; (method, path) unique.
- Dominant kind (field `dominant_kind`, the kind of the action permission ignoring the `enough_perms` bypass):

| dominant_kind | count |
|---|---:|
| group_role | 49 |
| owner_or_privileged | 32 |
| self_target | 19 |
| visibility_branch | 15 |
| anonymous | 12 |
| compound_and | 7 |
| auth_only | 6 |
| owner_field | 4 |
| global_role | 3 |
| setting_dependent | 2 |
| membership_row | 1 |

- owner_or_privileged (32): history `edit_comment` / `delete_comment` / `undelete_comment` / `comment_versions` for epic, userstory, task, issue, wiki (20, `IsCommentProjectAdmin() | IsCommentOwner()` or `| IsCommentDeleter()`); attachments `PATCH`/`DELETE` for all 5 types (10, `HasProjectPerm('modify_*') | IsAttachmentOwnerPerm()`); attachments `GET` for userstories and issues (2, `HasProjectPerm('view_*') | IsAttachmentOwnerPerm()`).
- `owner_field` without OR-bypass in the action expression (4): `POST /projects/{id}/transfer_start` (`IsObjectOwner()`), `GET|DELETE /application-tokens/{id}` (`IsAuthenticated() & CanUseToken()`), `POST /memberships/remove_user_from_all_my_projects` (queryset `project__owner=request.user`). All still inherit the `IsSuperUser()` enough_perms bypass (recorded).
- `omitted_blocks` (56 records): when the 3000-char cap was reached the lowest-priority optional service function (`calculate_permissions` or `get_user_project_permissions` / `user_has_perm`) was left out; every `visibility_branch` record keeps `calculate_permissions`. Authorization lines inside quoted blocks are never cut (handler bodies are truncated with `...` only after the last `check_permissions` line).

## Observations useful for review (not labels)

- `PATCH /api/v1/web-notifications/{resource_id}/set-as-read`: the overridden `check_permissions(request, obj=None)` returns a boolean and is invoked without `obj`; the row is then fetched by pk with `get_object_or_error` without comparing `user_id` to `request.user` (`taiga/projects/notifications/api.py:52-87`). Recorded as `auth_only`.
- `POST /api/v1/tasks/{id}/promote_to_user_story`: only `IsAuthenticated() & HasProjectPerm('view_tasks')` (a view perm) yet it creates a user story and deletes the task.
- Users: `UserPermission.enough_perms = IsSuperUser()` turns `IsTheSameUser()` on `PATCH|PUT|DELETE /users/{id}` into "self or superuser".
