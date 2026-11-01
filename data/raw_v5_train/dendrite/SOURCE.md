# Dendrite (Matrix homeserver) — data-v5 training candidate extraction

- Repository: https://github.com/matrix-org/dendrite (archived upstream; successor element-hq/dendrite is not used)
- Tag: `v0.13.8` (newest tag of matrix-org/dendrite) — commit `763c79f1421200c3fd74401fd68298bc00ecefbc`
- Clone: `datasets/blade/raw/opensource/matrix-org_dendrite` (`git clone --depth 1 --branch v0.13.8`), read-only; not built, run or modified.
- License: root `LICENSE` is the Apache License, Version 2.0, January 2004 ("Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License." in every Go source header). GitHub SPDX: Apache-2.0.
- Output: `candidates.jsonl` (136 records, one per (method, path)), produced by `extract_dendrite.py` (run with `python -I`; assembles every excerpt from verbatim line ranges of the clone). SHA-256 of candidates.jsonl: `1f7cad1b2df73d86da2681aef14ae7ba0e7930a7913b14288ebc065d84449301`.
- Labels are NOT assigned here. Each record carries `auth_checks` (kind, name, file, line, verbatim text) in evaluation order for the deterministic rule script.

## Extraction scope

Client-Server API handlers registered in `clientapi/routing/routing.go` (mux prefixes `/_matrix/client/{r0|v3}`, `/_matrix/client/v1`, `/_dendrite/admin`, `/_synapse/admin`) and `syncapi/routing/routing.go` (`/sync`, `/rooms/{roomId}/messages|event|context|members`, `/relations`, `/search`, `/user/{userId}/filter`, `/keys/changes`). Paths are written OAS-style with the real server prefix; `/unstable` and `/r0` duplicates of the same handler are omitted (one record per handler/method).

Priority targets collected first: every room-scoped endpoint whose handler checks the caller's membership row, power level, or history visibility (send/state/typing/receipt/read_markers/leave/forget/members/joined_members/messages/event/context/state/aliases/relations/hierarchy/report/upgrade/tags/room account_data/redact/kick/ban/unban/invite/join, directory list/alias). Then a natural mix of account, device, profile, push, key, presence, login/register, admin endpoints.

## Authorization architecture (as implemented at v0.13.8)

1. **Access-token resolution** — `internal/httputil/httpapi.go`: `MakeAuthAPI` (line 70) calls `auth.VerifyUserFromRequest(req, userAPI)` (line 77) to resolve the bearer token to a `*userapi.Device` (UserID, ID, AccountType, AppserviceID); failure → 401. Unless the route passes `httputil.WithAllowGuests()`, guest accounts are rejected (line 112, `device.AccountType == userapi.AccountTypeGuest` → 403). `MakeExternalAPI` (line 149) performs no authentication. `MakeAdminAPI` (line 132) wraps MakeAuthAPI and rejects `device.AccountType != userapi.AccountTypeAdmin` (line 137) → 403; used by `/_dendrite/admin/*` and `/_synapse/admin/v1/event_reports*`.
2. **Room membership** — handlers call the roomserver: `checkMemberInRoom` (`clientapi/routing/membership.go:590-610`) → `rsAPI.QueryMembershipForUser{RoomID, UserID}` and requires `IsInRoom` (403 "user does not belong to room"); some handlers call `QueryMembershipForUser` directly and test `HasBeenInRoom` / `IsInRoom` / `Membership` / `RoomExists` / `IsRoomForgotten`. In `SendEvent`, membership is implied by `QuerySenderIDForUser` returning nil → 403 "not joined to room" (`sendevent.go:354-361`). Roomserver-side leave checks the caller's `m.room.member` state (`perform_leave.go:166`).
3. **Power levels (room roles)** — `getPowerlevels` (`membership.go:671-690`) reads `m.room.power_levels`; checks `pl.UserLevel(sender) >= pl.Ban / pl.Kick / pl.Redact / pl.EventLevel(type)` (ban/kick/redact/visibility/alias removal/upgrade). For generic events, `gomatrixserverlib.Allowed` runs in the handler (`sendevent.go:426`) and again in roomserver input (`roomserver/internal/input/input_events.go:304`), which is the only power-level enforcement for unban, join and invite (`perform_invite.go:225` → `gomatrixserverlib.PerformInvite`).
4. **History visibility** — read endpoints in syncapi use `internal.ApplyHistoryVisibilityFilter` (`syncapi/internal/history_visibility.go:107`) whose `allowed()` (lines 71-101) admits `world_readable` to anyone, `joined`/`shared`/`invited` based on the caller's membership at the event. clientapi GET state/aliases branch on `history_visibility == "world_readable"` before querying membership. Room hierarchy uses roomserver `authorisedUser` (join/invite membership, else world_readable, else public/knock join rule).
5. **Self-target** — per-user resources compare the path user to the token user (`userID != device.UserID → 403`: account_data, tags, filter, profile PUT, typing, presence PUT, openid) or are keyed by `device.UserID` only (devices, push rules, pushers, notifications, key backups, 3PIDs, logout). Sensitive changes add user-interactive auth (`userInteractiveAuth.Verify`, password re-auth).
6. **Server admin** — `AccountTypeAdmin` (MakeAdminAPI, `server_notices.go:68`, `admin_whois.go:50` OR self). Appservice-only: `AccountTypeAppService` (`directory.go:458`).
7. **Config-dependent** — registration (`cfg.RegistrationDisabled`, shared-secret HMAC), TURN config, presence outbound, fulltext search, registration tokens, appservice alias namespaces.

## check function → auth_checks kind (evidence)

| Check (file:line) | kind |
|---|---|
| `httputil.MakeExternalAPI(...)` route wrapper (`clientapi/routing/routing.go` e.g. 554, 583, 623, 727, 881) | anonymous |
| `httputil.MakeAuthAPI(...)` with no further check in handler (e.g. routing.go:1271 capabilities, keys.go:117 QueryKeys, sendtodevice.go:53, presence.go:95 GetPresence) | auth_only |
| `if userID != device.UserID { 403 }` (account_data.go:38,81; room_tagging.go:39,74,127; filter.go:37,79; profile.go:97,186; sendtyping.go:39; presence.go:53; openid.go:43) and handlers keyed by `device.UserID` (device.go:59,99,142; pushrules.go:37…; key_backup.go:71…; logout.go:30) ; UIA `login.Username() != device.UserID` (device.go:226,274) | self_target |
| `allowedToRedact := ev.SenderID() == *senderID` (redaction.go:112); `spec.SenderID(creatorID) != senderID` (roomserver/internal/alias.go:144) | owner_field |
| `checkMemberInRoom` → `QueryMembershipForUser` `!IsInRoom` (membership.go:590-610; call sites membership.go:81,179,247,321; sendtyping.go:55; account_data.go:157; report_event.go:48; redaction.go:73; directory.go:401); direct `QueryMembershipForUser` tests (state.go:123,323; aliases.go:77; memberships.go:85,92; syncapi memberships.go:64; messages.go:118; context.go:105; directory.go:287; membership.go:646 forget); `senderID == nil → "not joined to room"` (sendevent.go:354); roomserver `membership != join && != invite` (perform_leave.go:166); hierarchy `membership == spec.Join || spec.Invite` (query_room_hierarchy.go:327); search `RoomIDsWithMembership(device.UserID, "join")` (search.go:81) | membership_row |
| `pl.UserLevel(sender) >= pl.Ban` (membership.go:90), `>= pl.Kick || self` (membership.go:196), `>= pl.Redact` (redaction.go:133), `< EventLevel(m.room.canonical_alias)` (directory.go:425; alias.go:158), tombstone level (perform_upgrade.go:309), `gomatrixserverlib.Allowed` event auth (sendevent.go:426; input_events.go:304), `gomatrixserverlib.PerformInvite` (perform_invite.go:225) | group_role |
| `device.AccountType != AccountTypeAdmin` (httpapi.go:137 MakeAdminAPI; server_notices.go:68; admin_whois.go:50 OR self); `AccountType != AccountTypeAppService` (directory.go:458) | global_role |
| `history_visibility == "world_readable"` (state.go:85,285; aliases.go:57; query_room_hierarchy.go:334); `ApplyHistoryVisibilityFilter` (messages.go:383; getevent.go:103; context.go:154; relations.go:124); join rules via event auth (perform_join.go:376) | visibility_branch |
| `cfg.RegistrationDisabled` (register.go:691), shared-secret MAC (register.go:1084), `cfg.RegistrationRequiresToken` (admin.go:35), TURN config (voip.go:40), `Presence.EnableOutbound` (presence.go:47), `cfg.Fulltext.Enabled` (syncapi routing.go:162), appservice alias namespace (directory.go:166), guest_access room state (perform_join.go:271) | setting_dependent |

`compound_and` was not needed: AND-combinations are expressed as consecutive entries in `auth_checks` (e.g. membership_row then group_role). OR-combinations are noted in `name` (kick: power level OR self; admin whois: admin OR self; redact: owner_field then group_role fallback).

## Endpoints where a check could not be located (`"unlocated": true`)

- `POST /rooms/{roomId}/receipt/{receiptType}/{eventId}` — receipt is written for `device.UserID` but no room membership check exists in `SetReceipt` (receipt.go:31-76).
- `PUT /directory/room/{roomAlias}` — alias creation only requires a local alias domain, config namespace rules and a sender ID in the room; no membership/power-level check in `SetLocalAlias` or roomserver `SetRoomAlias` (alias.go:36-58).
- `POST /account/3pid/delete` — `Forget3PID` deletes by address/medium without binding to `device.UserID` (threepid.go:214-235).

## Excluded scopes and reasons

- Federation API (`federationapi/`), media API (`mediaapi/`), key server `/_matrix/key`, `/.well-known` — out of scope per instructions.
- `/rooms/{roomId}/initialSync`, `/events`, `/initialSync` — stub handlers that always return 403 / empty (no authorization logic).
- `/pushrules`, `/pushrules/{scope}`, `/pushrules/{scope}/{kind}` without trailing slash and PUT on partial push-rule paths — error-only stubs (400).
- `/peek/{roomIdOrAlias}` — gated behind MSC2753 feature flag.
- `/unstable/...` and `/r0/...` duplicates of the same handlers, `/keys/upload/{deviceId}` (deprecated duplicate of `/keys/upload`), `/room_keys/keys/{roomId}` PUT (same handler shape as the single-session PUT) — deduplicated.
- `/_synapse/admin/v1/register` GET (nonce issuance) — only POST kept.
- `/thirdparty/user/{protocol}`, `/thirdparty/location/{protocol}` — same handler as the un-parameterised variants.

## Counts

- Total candidates: **136** (unique (method, path)); controller_text 582–2986 chars; 15 anonymous (no `security`), 121 with `accessToken` bearer security.
- Dominant kind (first entry of `auth_checks`): membership_row 20, visibility_branch 8, self_target 54, group_role 1, global_role 20, anonymous 15, auth_only 12, setting_dependent 6.
- Records containing at least one `membership_row` check: 27; containing `group_role`: 15 (ban, kick, unban, invite, send ×4, redact ×2, upgrade, directory visibility PUT, alias DELETE, join ×2); `owner_field`: 3 (redact ×2, alias DELETE); `visibility_branch`: 13.
