# NodeBB — data-v5 training candidate extraction (Write API v3)

## Repository

- Repository: https://github.com/NodeBB/NodeBB
- Tag: `v4.16.5` (latest release per `gh api repos/NodeBB/NodeBB/releases/latest`, 2026-10-31)
- Commit: `c3d8dc512292a376f19e06cb93512bdff2505102`
- Clone: `datasets/blade/raw/opensource/NodeBB_NodeBB` (`git clone --depth 1 --branch v4.16.5`), read-only; never built, run or modified.
- License: SPDX `GPL-3.0` (`install/package.json` → `"license": "GPL-3.0"`). `LICENSE` file header: "GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007 / Copyright (C) 2007 Free Software Foundation, Inc. / Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed." (GPL-3.0 is not AGPL; copyleft applies to redistribution of the code, excerpts here are quoted for static analysis.)
- OpenAPI spec shipped in-repo: `public/openapi/write.yaml` (+ `public/openapi/write/**/*.yaml`), `servers: /api/v3`, license GPL-3.0. All 146 candidates have a matching operation → `oas_status = repository_spec`; `oas_operation` (summary/description/parameters/requestBody/responses) is copied from the spec file named in `oas_spec_file`; `response_schema_fields` resolved from `components/schemas/*.yaml` `$ref`s; `permission_doc` = sentences of the description containing permission words (admin/privilege/owner/only/must/moderator/calling user/…), empty for 106 records. `security` is set to `[{"bearerAuth": []}]` per instruction (the spec itself declares no securitySchemes; `oas_security_schemes = {}`, `oas_global_security = []`).

## Extraction scope

- Routes: `src/routes/write/{chats,users,groups,posts,topics,categories,admin,flags,files,tags,notifications,search,utilities,index}.js`, mounted at `/api/v3/...` by `src/routes/write/index.js`.
- One record per `(method, OAS path)`; 146 records (cap 150). Collected all chat-room routes first (membership), then users (self/privileged), groups, posts/topics, categories, admin, flags, utilities.
- `controller_text` = route line (with its middleware array) + `src/controllers/write/*.js` controller + `src/api/*.js` function + bodies of the authorization helpers reached (middleware, `privileges/*`, `user.*`, `messaging.*`, `groups.*`, `topics/tools.js`, `posts/tools.js`, `flags.js`). Excerpts are read verbatim from the clone by anchor pattern (`extract_nodebb.py`); long non-authorization tails are cut and marked with a `...` line; no authorization line is cut. 181–2998 chars (median 1587).
- `auth_checks`: every check in evaluation order with `file`, `line` and the verbatim decisive line. `dominant_kind` is an extra convenience field (my reading of the decisive check); `unlocated` is `false` for every record (every check was located in code).

## Authorization architecture (v4.16.5)

1. **Route helper** `src/routes/helpers.js:57 setupApiRoute` prepends `autoLocale, applyBlacklist, authenticateRequest, maintenanceMode, registrationComplete, pluginHooks, logApiUsage` to every Write API route. `authenticateRequest` (`src/middleware/user.js:99`) resolves session cookie or Bearer token into `req.uid` / `req.loggedIn`; it skips only `POST /api/v3/utilities/login`. Guests get `req.uid = 0`.
2. **Route-level middlewares** (`src/routes/write/*.js`):
   - `middleware.ensureLoggedIn` (`src/middleware/index.js:48`) — 401/403 when `!req.loggedIn`. Not applied to several read routes (GET post/topic/category, HEAD user/group, post queue, ping).
   - `middleware.canChat` (`src/middleware/user.js:166`) — global privilege `chat`/`chat:privileged` (granted to `registered-users` by default, `src/install.js:437`).
   - `middleware.admin.checkPrivileges` (`src/middleware/admin.js:42`) — guests rejected; `privileges.admin.resolve(path)` maps the admin path to an `admin:*` privilege via `routeMap`/`routePrefixMap` (`src/privileges/admin.js:126`); paths not in the map (e.g. `chats/`, `tokens`, `analytics`, `groups`, `activitypub/`, `/api/v3/files`, `categories/{cid}/follow`) resolve to `undefined`, and `privileges.admin.can(undefined, uid)` passes only for members of `administrators`. Mapped prefixes: `settings/`, `plugins/` → `admin:settings`.
   - `middleware.assert.*` (`src/middleware/assert.js`): `user/group/category/topic/post` assert **existence only**. `assert.room` (line 133) asserts existence **and** `messaging.isUserInRoom(req.uid, roomId)` with an `user.isAdministrator` bypass (line 147) — so every `/api/v3/chats/{roomId}...` and `/api/v3/search/chats/{roomId}/...` route already enforces room membership (or admin) before the controller. `assert.message` (line 154) requires `messaging.canViewMessage` (admin, or room member whose join timestamp ≤ message timestamp; any member for public rooms). `assert.flag` (line 75) requires `flags.canView`.
   - `middleware.requireAPIReAuth` / `requirePasswordAuth` — re-authentication only (not authorization).
3. **API layer** `src/api/*.js` (shared by HTTP and socket.io) holds the object-level checks:
   - Users: `privileges.users.canEdit(caller, uid)` (`src/privileges/users.js:76`) = self, or admin, or (global mod / `admin:users` holder) when target is not an admin → used by update/picture/settings/addEmail. `processDeletion` (`src/api/users.js:550`): self needs `meta.config.allowAccountDelete`, non-self needs `admin:users`, and methods `delete`/`deleteContent` need `admin:users` even for self. `user.changePassword` (`src/user/profile.js:321`): `isSelf || (isAdmin && !isTargetAdmin)`. `privileges.users.canExportData` (`src/privileges/users.js:148`): self or admin or `admin:users`. `hasBanPrivilege/hasMutePrivilege/hasInvitePrivilege` → global privileges `ban`/`mute`/`invite` (`ban` and `view:users:info` default to Global Moderators; `invite` and `group:create` not granted by default; admins always pass `privileges.global.can`).
   - `user.isAdminOrGlobalModOrSelf / isAdminOrSelf / isPrivilegedOrSelf` (`src/user/index.js:253-273`) → `isSelfOrMethod`: self short-circuit, else the method. Only `isAdminOrGlobalModOrSelf` is reached from the Write API (category watch state).
   - Chats: `messaging.isUserInRoom` (`src/messaging/rooms.js:192`, sorted-set `chat:room:{roomId}:uids`), `messaging.isRoomOwner` (`:236`, set `chat:room:{roomId}:owners`), `messaging.canMessageRoom` (`src/messaging/index.js:475`, inRoom + chat privilege + not muted), `messaging.canMessageUser` (`:419`, target settings/allow-deny lists/reputation), `messaging.canViewMessage` (`:550`), `messaging.canEdit/canDelete` → `canEditDelete` (`src/messaging/edit.js:53`: admin/global mod always; otherwise sender within `chatEditDuration`/`chatDeleteDuration`), `messaging.canPin` (`:104`, admin/global mod or in-room owner), `renameRoom` (`rooms.js:475`, owner), `addUsersToRoom` (`rooms.js:275`, inviter must be in room), `removeUsersFromRoom` (`rooms.js:320`, owner), `loadRoom` (`rooms.js:518`, private: member; public: group member), `getRecentChats/getMessages → canGet` (`index.js:81`, `callerUid === uid`).
   - Groups: `api/groups.js isOwner()` (`:435`) = group owner (`group:{name}:owners`) OR `admin:groups` OR global moderator (non-system group); `adminGroupCheck` (`:14`, `admin:admins-mods` for the `administrators` group); `canSearchMembers` (`:128`, hidden groups need membership/admin:groups/global mod); join/leave branch on `isSelf`, `groupData.private`, `meta.config.allowPrivateGroups`.
   - Posts/topics: `privileges.posts.canEdit/canDelete/canPurge/canMove` (`src/privileges/posts.js:142-284`), `privileges.topics.canDelete/canPurge/canTag/canEdit/isAdminOrMod` (`src/privileges/topics.js:160-229`), `privileges.categories.isAdminOrMod` (`src/privileges/categories.js:147`, admin or category moderator), category privilege matrix via `privileges.categories.can/get` (guests may hold `read`/`topics:read`/`find`). Topic actions go through `apiHelpers.doTopicAction → topics.tools.*` (`src/topics/tools.js`), post delete/restore through `posts.tools.*` (`src/posts/tools.js`), votes/bookmarks through `apiHelpers.postCommand` (`canRead` only, action is the caller's own). Post queue: `posts.canEditQueue` (`src/posts/queue.js`, admin/global mod; author for reject/edit; category moderator).
   - Flags: `flags.canView` (`src/flags.js:698`) branches by flag type (message → administrator; user → `admin:users`; post → admin/global mod/category moderator); `flags.validate` (reputation threshold `min:rep:flag`); rescind/note deletion require the caller to be the reporter/note author (no bypass).
   - Admin/files: route-level `admin.checkPrivileges`, plus `privileges.admin.can('admin:settings'|'admin:users')` re-checks in `src/api/admin.js`; `src/api/files.js` has no checks of its own (comment: "path assertion ... in src/middleware/assert.js").

## helper → auth_checks kind (with evidence)

| helper | kind | decisive line |
|---|---|---|
| `middleware.ensureLoggedIn` | auth_only | `src/middleware/index.js:49` `if (!req.loggedIn) {` |
| `middleware.canChat` (global priv `chat`, default registered-users) | auth_only | `src/middleware/user.js:167` |
| `privileges.global.can('view:users' / 'view:groups' / 'search:users')` (default registered-users; guests have view:*) | auth_only (logged-in route) / anonymous (no login route) | `src/api/users.js:43`, `src/api/groups.js:24`, `:102` |
| `privileges.global.can('group:create' / 'ban' / 'mute' / 'invite' / 'view:users:info')` (not default for registered-users) | global_role | `src/api/groups.js:54`, `src/api/users.js:208`, `:272`, `:419`, `src/api/chats.js:424` |
| `middleware.admin.checkPrivileges` → `privileges.admin.can(resolve(path))` | global_role | `src/middleware/admin.js:52` |
| `privileges.admin.can('admin:users'/'admin:categories'/'admin:privileges'/'admin:admins-mods'/'admin:settings'/'admin:groups')` | global_role | `src/privileges/admin.js:188` `return isAdministrator \|\| isUserAllowedTo[0];` |
| `user.isAdministrator`, `user.isAdminOrGlobalMod` | global_role | `src/user/index.js:221`, `:245` |
| `middleware.assert.room` (member of `chat:room:{roomId}:uids` OR admin) | membership_row | `src/middleware/assert.js:147` |
| `messaging.isUserInRoom`, `messaging.canMessageRoom`, `addUsersToRoom` inRoom | membership_row | `src/messaging/rooms.js:198`, `src/messaging/index.js:492`, `rooms.js:287` |
| `middleware.assert.message` → `messaging.canViewMessage` | membership_row (join-timestamp qualified) | `src/messaging/index.js:571` |
| `messaging.isRoomOwner` (via renameRoom / removeUsersFromRoom / toggleOwner / canPin) | group_role | `src/messaging/rooms.js:485`, `:327`, `src/api/chats.js:337`, `src/messaging/edit.js:114` |
| `api/groups.js isOwner()` (group owner / admin:groups / global mod) | group_role | `src/api/groups.js:446` |
| `privileges.categories.isAdminOrMod`, `privileges.topics.isAdminOrMod`, `posts.isModerator` (category moderator or admin) | group_role | `src/privileges/categories.js:155` |
| `flags.canView` post branch | group_role | `src/flags.js:721` |
| `privileges.users.canEdit` | owner_or_privileged (self_target short-circuit at `:79`) | `src/privileges/users.js:95` |
| `processDeletion` (self w/ setting OR admin:users) | owner_or_privileged / global_role (delete, deleteContent) | `src/api/users.js:557`, `:564` |
| `user.changePassword` | owner_or_privileged | `src/user/profile.js:339` |
| `privileges.users.canExportData` | owner_or_privileged | `src/privileges/users.js:157` |
| `user.isAdminOrGlobalModOrSelf` → `isSelfOrMethod` | owner_or_privileged | `src/user/index.js:266` |
| `messaging.canEdit/canDelete` (admin/gmod OR sender, duration setting) | owner_or_privileged + setting_dependent | `src/messaging/edit.js:85`, `:90`, `:94` |
| `privileges.posts.canEdit / canDelete / canPurge` | owner_or_privileged (+ setting_dependent durations) | `src/privileges/posts.js:195`, `:239`, `:283` |
| `privileges.topics.canDelete / canPurge / canTag / canEdit(isOwnerOrAdminOrMod)` | owner_or_privileged | `src/privileges/topics.js:199`, `:174`, `:208`, `:220` |
| `posts.canEditQueue` (reject/edit: author OR admin/gmod/moderator) | owner_or_privileged | `src/posts/queue.js` `if (isAdminOrGlobalMod \|\| ((action === 'reject' \|\| action === 'edit') && selfPost)) {` |
| `messaging canGet` (`callerUid === uid`), `uid === caller.uid` guards (tokens, invites, acceptInvite), own-data writes (follow, watch/read state, notifications `ownsNids`) | self_target | `src/messaging/index.js:85`, `src/api/users.js:354`, `src/api/groups.js:404`, `src/notifications.js:437` |
| `flags.exists(type, targetId, callerUid)`, `note.uid !== caller.uid` | owner_field | `src/api/flags.js:52`, `:105` |
| category privilege matrix (`privileges.posts.get`, `privileges.topics.canRead`, `privileges.categories.get/can`) on routes without login | visibility_branch (+ anonymous) | `src/api/posts.js:31`, `src/privileges/topics.js:154`, `src/api/categories.js:44` |
| `messaging.loadRoom` public/private branch, `canSearchMembers` hidden-group branch, `showemail` user setting | visibility_branch | `src/messaging/rooms.js:529`, `src/api/groups.js:137`, `src/api/users.js:490` |
| `meta.config.*` gates (`allowAccountDelete`, `password:disableEdit`, `postEditDuration`, `postDeleteDuration`, `chatEditDuration`, `preventTopicDeleteAfterReplies`, `movingTopicsMaxPosts`, `allowPrivateGroups`, `registrationType`, `upvoteVisibility`, `min:rep:flag`) | setting_dependent | lines quoted per record |
| two independent required conditions (`admin:settings` AND self for tokens; `view:users:info` AND inRoom; self AND invite privilege) | compound_and | `src/api/users.js:353-354`, `src/api/chats.js:423-431` |

## Excluded scopes

- Plugin/hook-only routes (`/api/v3/plugins/*`, `static:api.routes`), `/api/v3/intents/*` (ActivityPub), `/api/v3/users/bySlug/*` and `/api/v3/posts/byIndex/*` redirects, `POST /api/v3/users/reauth/verify` (re-auth only).
- Routes whose authorization lives deep inside non-API modules and could not be excerpted within budget: `POST /api/v3/topics` (`topics.post` → category `topics:create`), `POST /api/v3/topics/{tid}` (`topics.reply`), `POST /api/v3/topics/{tid}/thumbs` (upload controller), `/api/v3/topics/{tid}/crossposts`, `GET /api/v3/users/{uid}/status*` (`canViewUsers`, guests allowed by privilege), `POST /api/v3/ping` (reads `req.user.uid`), `GET /api/v3/posts/{pid}/{index,summary,upvoters,announcers*}`, `GET /api/v3/notifications/{nid}`, `GET /api/v3/categories/{cid}/{posts,children}`.
- To stay ≤150, one verb was kept where PUT/DELETE pairs share identical checks (the dropped verb is listed in `extract_nodebb.py` `SKIP`): chats state/watch/owners/pin DELETE, chat message `POST .../messages/{mid}` (restore, same as `PUT .../state`), users ban/mute/follow DELETE, HEAD exports, topics follow/read/tags/lock/pin DELETE, tags DELETE, posts vote/bookmark DELETE, `POST /posts/owner`, category privileges copy/DELETE, moderator DELETE, watch DELETE, admin tokens GET/roll, analytics/{set}, plugins active, 4 of 5 activitypub admin routes, notifications/count.
- Read-side Read API (`/api/*` non-v3) and socket.io endpoints are out of scope.

## Counts

- Candidates: **146** (`candidates.jsonl`), all `repository_spec`, `(method, path)` unique, `auth_checks` non-empty, `controller_text` 181–2998 chars, `unlocated` = 0.
- Dominant kind: owner_or_privileged 33, global_role 28, group_role 25, self_target 16, membership_row 14, visibility_branch 11, anonymous 7, compound_and 5, auth_only 4, owner_field 2, setting_dependent 1.
- membership_row (14): HEAD/GET/POST `/chats/{roomId}`, PUT `/chats/{roomId}/state`, PUT `/chats/{roomId}/watch`, PUT `/chats/{roomId}/typing`, GET/POST `/chats/{roomId}/users`, GET `/chats/{roomId}/messages`, GET `/chats/{roomId}/messages/pinned`, GET `/chats/{roomId}/messages/{mid}`, GET `/chats/{roomId}/messages/{mid}/raw`, GET `/search/chats/{roomId}/users`, GET `/search/chats/{roomId}/messages` (all with administrator bypass in `assert.room`, except `GET .../users`, `.../typing`, `.../watch`, `.../messages/pinned`, `search/.../messages` whose api-layer `isUserInRoom` has no bypass).
- Notes for the rule script: `middleware.assert.room` is the membership check for all `{roomId}` routes (not existence-only). Room owner (`chat:room:{roomId}:owners`) and group owner (`group:{name}:owners`) are roles inside the named group (`group_role`). Category moderator checks are recorded as `group_role`; admin / global moderator / `admin:*` privileges as `global_role`. Default registered-user global privileges (`chat`, `view:users`, `view:groups`, `search:users`) are recorded as `auth_only`; `group:create`, `invite`, `ban`, `mute`, `view:users:info` as `global_role`.

Script: `extract_nodebb.py` (run with `python -I`; reads the clone only, writes `candidates.jsonl`).
