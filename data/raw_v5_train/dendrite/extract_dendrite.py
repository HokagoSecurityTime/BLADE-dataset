"""Extract data-v5 training candidates from matrix-org/dendrite v0.13.8 (static, read-only).

Usage: python -I extract_dendrite.py <clone_dir> <out_dir>

Every candidate is assembled from verbatim line ranges of the clone. No label is
assigned here; `auth_checks` records the authorization checks in evaluation order.
"""
import json
import sys
from pathlib import Path

CLONE = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

REPO = "https://github.com/matrix-org/dendrite"
COMMIT = "763c79f1421200c3fd74401fd68298bc00ecefbc"
TAG = "v0.13.8"
LICENSE = "Apache-2.0"

RT = "clientapi/routing/routing.go"
SRT = "syncapi/routing/routing.go"
HTTPAPI = "internal/httputil/httpapi.go"
MEM = "clientapi/routing/membership.go"
SE = "clientapi/routing/sendevent.go"
ST = "clientapi/routing/state.go"
RED = "clientapi/routing/redaction.go"
HV = "syncapi/internal/history_visibility.go"
INPUT = "roomserver/internal/input/input_events.go"

_cache = {}


def lines(rel):
    if rel not in _cache:
        _cache[rel] = (CLONE / rel).read_text(encoding="utf-8").splitlines()
    return _cache[rel]


def seg(rel, a, b):
    ls = lines(rel)
    assert 1 <= a <= b <= len(ls), (rel, a, b, len(ls))
    return "\n".join(ls[a - 1:b])


def line(rel, n):
    return lines(rel)[n - 1].strip()


# Middleware excerpts (global authentication wrapper)
MW_AUTH = [(HTTPAPI, 69, 81), (HTTPAPI, 103, 117)]
MW_ADMIN = [(HTTPAPI, 130, 148)]
HELPER_MEMBER = [(MEM, 590, 610)]
HELPER_PL = [(MEM, 671, 690)]
HV_ALLOWED = [(HV, 69, 101), (HV, 103, 114)]
HV_SHORT = [(HV, 71, 101)]
HELPER_PL_SHORT = [(MEM, 671, 675), (MEM, 682, 690)]
EVENT_AUTH = [(INPUT, 302, 310)]

SEC_TOKEN = [{"accessToken": []}]


def chk(kind, name, rel, n, **extra):
    d = {"kind": kind, "name": name, "file": rel, "line": n, "text": line(rel, n)}
    d.update(extra)
    return d


def build_text(blocks):
    """blocks: list of (rel, a, b). Consecutive blocks from the same file with a gap
    are separated by a '...' line; different files by a blank line."""
    out = []
    prev = None
    for rel, a, b in blocks:
        s = seg(rel, a, b)
        if prev is None:
            out.append(s)
        elif prev[0] == rel and a > prev[2] + 1:
            out.append("\t...\n" + s)
        else:
            out.append("\n" + s)
        prev = (rel, a, b)
    return "\n".join(out)


def locs(blocks):
    return [{"file": rel, "start_line": a, "end_line": b} for rel, a, b in blocks]


def param(name, typ="string"):
    return {"name": name, "in": "path", "required": True, "schema": {"type": typ}}


def params_from_path(path):
    import re
    return [param(p) for p in re.findall(r"{([^}]+)}", path)]


CANDS = []


def add(method, path, summary, blocks, checks, auth_summary, security=SEC_TOKEN, mw=MW_AUTH, resp_fields=None, op_id=None, note=None):
    blocks = list(mw) + list(blocks)
    text = build_text(blocks)
    rec = {
        "project": "dendrite",
        "service": "Dendrite",
        "repository": REPO,
        "commit": COMMIT,
        "tag": TAG,
        "license": LICENSE,
        "method": method,
        "path": path,
        "oas_status": "generated",
        "oas_operation": {
            "operationId": op_id or (method.lower() + "".join(w.capitalize() for w in path.replace("{", "").replace("}", "").replace("_", "/").replace("-", "/").replace(".", "/").split("/") if w)),
            "summary": summary,
            "parameters": params_from_path(path),
            "responses": {"200": {"description": "OK"}},
            "security": security,
        },
        "oas_global_security": [],
        "oas_security_schemes": {"accessToken": {"type": "http", "scheme": "bearer"}} if security else {},
        "response_schema_fields": resp_fields or [],
        "controller_text": text,
        "source_locations": locs(blocks),
        "auth_summary": auth_summary,
        "permission_doc": "",
        "auth_checks": checks,
    }
    if note:
        rec["note"] = note
    CANDS.append(rec)


V3 = "/_matrix/client/v3"
V1 = "/_matrix/client/v1"
DADM = "/_dendrite/admin"
SADM = "/_synapse/admin/v1"

# ---------------------------------------------------------------------------
# 1. Room-scoped endpoints (membership / power level / visibility)
# ---------------------------------------------------------------------------
SENDEVENT_BLOCKS = [(SE, 73, 80), (SE, 169, 172), (SE, 220, 240), (SE, 325, 333), (SE, 348, 361), (SE, 420, 433)]
SENDEVENT_CHECKS = lambda: [
    chk("membership_row", "QuerySenderIDForUser → nil sender ID means not joined (403 'not joined to room')", SE, 354),
    chk("group_role", "event auth (gomatrixserverlib.Allowed, power levels / state auth rules)", SE, 426),
]
SENDEVENT_SUMMARY = "MakeAuthAPI access token → generateSendEvent: caller must have a sender ID in the room (joined), then gomatrixserverlib.Allowed enforces room power levels for the event type; event is submitted to the roomserver (SendEvents)."

add("PUT", f"{V3}/rooms/{{roomId}}/send/{{eventType}}/{{txnId}}", "Send a message event to a room (idempotent by txnId)",
    [(RT, 455, 465)] + SENDEVENT_BLOCKS, SENDEVENT_CHECKS(), SENDEVENT_SUMMARY, resp_fields=["event_id"], mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/send/{{eventType}}", "Send a message event to a room",
    [(RT, 446, 454)] + SENDEVENT_BLOCKS, SENDEVENT_CHECKS(), SENDEVENT_SUMMARY, resp_fields=["event_id"], mw=[])
add("PUT", f"{V3}/rooms/{{roomId}}/state/{{eventType}}", "Send a state event with empty state key to a room",
    [(RT, 503, 513)] + SENDEVENT_BLOCKS, SENDEVENT_CHECKS(), SENDEVENT_SUMMARY, resp_fields=["event_id"], mw=[])
add("PUT", f"{V3}/rooms/{{roomId}}/state/{{eventType}}/{{stateKey}}", "Send a state event to a room",
    [(RT, 515, 524)] + SENDEVENT_BLOCKS, SENDEVENT_CHECKS(), SENDEVENT_SUMMARY, resp_fields=["event_id"], mw=[])

# GET state
add("GET", f"{V3}/rooms/{{roomId}}/state", "Get the current state events of a room",
    [(RT, 467, 473), (ST, 46, 48), (ST, 71, 75), (ST, 84, 89), (ST, 97, 137)],
    [chk("visibility_branch", "history_visibility world_readable → latest state without membership", ST, 85),
     chk("membership_row", "QueryMembershipForUser (HasBeenInRoom required; IsInRoom → latest state, else state at leave)", ST, 123)],
    "World-readable rooms return latest state to any authenticated user; otherwise QueryMembershipForUser: never-joined → 403, joined → latest state, left → state at leave event.", mw=[])
STATE_TYPE_BLOCKS = [(ST, 201, 206), (ST, 271, 275), (ST, 284, 289), (ST, 297, 337)]
STATE_TYPE_CHECKS = lambda: [
    chk("visibility_branch", "history_visibility world_readable → latest state without membership", ST, 285),
    chk("membership_row", "QueryMembershipForUser (HasBeenInRoom and not banned required)", ST, 323)]
STATE_TYPE_SUMMARY = "World-readable rooms are readable by any authenticated user; otherwise QueryMembershipForUser must show the user has been in the room and is not banned (joined → latest state, left → state at leave)."
add("GET", f"{V3}/rooms/{{roomId}}/state/{{eventType}}", "Get a state event with empty state key",
    [(RT, 483, 492)] + STATE_TYPE_BLOCKS, STATE_TYPE_CHECKS(), STATE_TYPE_SUMMARY, mw=[])
add("GET", f"{V3}/rooms/{{roomId}}/state/{{eventType}}/{{stateKey}}", "Get a specific state event of a room",
    [(RT, 494, 501)] + STATE_TYPE_BLOCKS, STATE_TYPE_CHECKS(), STATE_TYPE_SUMMARY, mw=[])

add("GET", f"{V3}/rooms/{{roomId}}/aliases", "List local aliases of a room",
    [(RT, 475, 481), ("clientapi/routing/aliases.go", 30, 32), ("clientapi/routing/aliases.go", 47, 92)],
    [chk("visibility_branch", "history_visibility world_readable → skip membership check", "clientapi/routing/aliases.go", 57),
     chk("membership_row", "QueryMembershipForUser IsInRoom", "clientapi/routing/aliases.go", 77)],
    "If room history visibility is world_readable anyone authenticated may list aliases; otherwise QueryMembershipForUser must return IsInRoom.", resp_fields=["aliases"], mw=[])

add("POST", f"{V3}/rooms/{{roomId}}/ban", "Ban a user from a room",
    [(RT, 407, 415), (MEM, 42, 47), (MEM, 73, 99)] + HELPER_MEMBER + HELPER_PL_SHORT,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", MEM, 81),
     chk("group_role", "power level 'ban': pl.UserLevel(sender) >= pl.Ban", MEM, 90)],
    "Caller must be joined (checkMemberInRoom) and have power level >= ban level in the room's m.room.power_levels.", mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/kick", "Kick a user from a room",
    [(RT, 428, 436), (MEM, 141, 145), (MEM, 179, 182), (MEM, 192, 202), (MEM, 204, 208), (MEM, 212, 221)] + HELPER_MEMBER,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", MEM, 179),
     chk("group_role", "power level 'kick' OR target user is the caller (self-kick)", MEM, 196),
     chk("membership_row", "target's QueryMembershipForUser must be join/invite", MEM, 213)],
    "Caller must be joined; then power level >= kick level, or the kicked user_id equals the caller. Target must be joined/invited.", mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/unban", "Unban a user from a room",
    [(RT, 437, 445), (MEM, 223, 227), (MEM, 247, 250), (MEM, 259, 277), (MEM, 117, 118)] + HELPER_MEMBER + EVENT_AUTH,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", MEM, 247),
     chk("membership_row", "target's QueryMembershipForUser must be ban", MEM, 269),
     chk("group_role", "event auth (gomatrixserverlib.Allowed, power levels) in roomserver input on the m.room.member leave event", INPUT, 304)],
    "Caller must be joined; target must currently be banned. No power-level check in the handler: the unban membership event is submitted via SendEvents and the roomserver's event auth (gomatrixserverlib.Allowed) enforces the ban power level.", mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/invite", "Invite a user to a room",
    [(RT, 416, 427), (MEM, 279, 283), (MEM, 313, 329), (MEM, 369, 383), (MEM, 390, 394), ("roomserver/internal/perform/perform_invite.go", 225, 234)] + HELPER_MEMBER,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", MEM, 321),
     chk("group_role", "event auth (gomatrixserverlib.PerformInvite → invite power level / join rules)", "roomserver/internal/perform/perform_invite.go", 225)],
    "Caller must be joined (checkMemberInRoom); rsAPI.PerformInvite builds the invite event and gomatrixserverlib.PerformInvite enforces invite power level (ErrNotAllowed → 403).", mw=[])

add("POST", f"{V3}/rooms/{{roomId}}/leave", "Leave a room",
    [(RT, 382, 395), ("clientapi/routing/leaveroom.go", 26, 65), ("roomserver/internal/perform/perform_leave.go", 139, 168)],
    [chk("self_target", "leaver is the token user (Leaver: *userID from device.UserID)", "clientapi/routing/leaveroom.go", 43),
     chk("membership_row", "roomserver: caller's m.room.member state must be join or invite", "roomserver/internal/perform/perform_leave.go", 166)],
    "Only the caller's own membership is changed; roomserver performLeaveRoomByID requires the caller's membership to be join or invite in the room.", mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/forget", "Forget a room the caller has left",
    [(RT, 1135, 1146), (MEM, 612, 669)],
    [chk("membership_row", "QueryMembershipForUser: RoomExists required and caller must NOT currently be in room", MEM, 646),
     chk("self_target", "forget applies to caller's own membership (UserID: device.UserID)", MEM, 655)],
    "Operates on the caller's own membership row: room must exist and caller must have already left (IsInRoom → 400).", mw=[])
add("PUT", f"{V3}/rooms/{{roomId}}/typing/{{userId}}", "Set typing state of a user in a room",
    [(RT, 640, 651), ("clientapi/routing/sendtyping.go", 34, 58)] + HELPER_MEMBER,
    [chk("self_target", "device.UserID != userID → 403", "clientapi/routing/sendtyping.go", 39),
     chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", "clientapi/routing/sendtyping.go", 55)],
    "Path userId must equal token user, and the user must be joined to the room (checkMemberInRoom).")
add("POST", f"{V3}/rooms/{{roomId}}/receipt/{{receiptType}}/{{eventId}}", "Send a read receipt for an event",
    [(RT, 1486, 1498), ("clientapi/routing/receipt.go", 31, 76)],
    [chk("self_target", "receipt stored for device.UserID only; no room membership check in handler", "clientapi/routing/receipt.go", 43, unlocated=True)],
    "Receipt is written for the caller's own user ID. No membership check for the room is performed in the handler.",
    note="unlocated: no membership check found for roomID in SetReceipt")
add("POST", f"{V3}/rooms/{{roomId}}/read_markers", "Set read markers / fully read for the caller in a room",
    [(RT, 1122, 1133), ("clientapi/routing/account_data.go", 143, 160), ("clientapi/routing/account_data.go", 176, 202)] + HELPER_MEMBER,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", "clientapi/routing/account_data.go", 157),
     chk("self_target", "account data written for device.UserID", "clientapi/routing/account_data.go", 178)],
    "Caller must be joined to the room (checkMemberInRoom); markers are stored for the caller's own user.", mw=[])
add("GET", f"{V3}/rooms/{{roomId}}/joined_members", "Get joined members of a room",
    [(RT, 1518, 1526), ("clientapi/routing/memberships.go", 47, 58), ("clientapi/routing/memberships.go", 69, 97)],
    [chk("membership_row", "QueryMembershipForUser HasBeenInRoom", "clientapi/routing/memberships.go", 85),
     chk("membership_row", "QueryMembershipForUser IsInRoom", "clientapi/routing/memberships.go", 92)],
    "Caller must currently be a member of the room (QueryMembershipForUser HasBeenInRoom and IsInRoom).", resp_fields=["joined"])
add("GET", f"{V3}/rooms/{{roomId}}/members", "Get membership events of a room",
    [(SRT, 183, 202), ("syncapi/routing/memberships.go", 38, 69), ("syncapi/routing/memberships.go", 80, 94)],
    [chk("membership_row", "QueryMembershipForUser HasBeenInRoom (left users see members at leave)", "syncapi/routing/memberships.go", 64)],
    "Caller must be or have been a member of the room; users who left get the member list as of their leave event.", resp_fields=["chunk"], mw=[])
add("GET", f"{V3}/rooms/{{roomId}}/messages", "Paginate events of a room",
    [(SRT, 56, 66), ("syncapi/routing/messages.go", 72, 78), ("syncapi/routing/messages.go", 103, 123), ("syncapi/routing/messages.go", 236, 238), ("syncapi/routing/messages.go", 381, 386)] + HV_SHORT,
    [chk("membership_row", "getMembershipForUser → QueryMembershipForUser (RoomExists, not forgotten; leave → events before leave)", "syncapi/routing/messages.go", 118),
     chk("visibility_branch", "ApplyHistoryVisibilityFilter: world_readable / joined / shared / invited per event", "syncapi/routing/messages.go", 383)],
    "Room must exist and not be forgotten by the caller; each event is filtered by history visibility against the caller's membership at the event (world_readable allows non-members).", resp_fields=["start", "end", "chunk", "state"], mw=[])
add("GET", f"{V3}/rooms/{{roomId}}/event/{{eventId}}", "Get a single event from a room",
    [(SRT, 68, 76), ("syncapi/routing/getevent.go", 37, 45), ("syncapi/routing/getevent.go", 87, 93), ("syncapi/routing/getevent.go", 101, 120)] + HV_SHORT,
    [chk("visibility_branch", "ApplyHistoryVisibilityFilter against caller membership at event (world_readable allows anyone)", "syncapi/routing/getevent.go", 103)],
    "Event is returned only if the room history visibility rules allow the caller (joined/invited at the event, shared+joined later, or world_readable).", mw=[])
add("GET", f"{V3}/rooms/{{roomId}}/context/{{eventId}}", "Get events around an event",
    [(SRT, 102, 116), ("syncapi/routing/context.go", 50, 56), ("syncapi/routing/context.go", 95, 110), ("syncapi/routing/context.go", 140, 142), ("syncapi/routing/context.go", 154, 159)] + HV_SHORT,
    [chk("membership_row", "QueryMembershipForUser (RoomExists only)", "syncapi/routing/context.go", 105),
     chk("visibility_branch", "ApplyHistoryVisibilityFilter on the requested event; empty → 403", "syncapi/routing/context.go", 154)],
    "Room must exist; the requested event must pass history-visibility filtering for the caller (membership-at-event or world_readable).", resp_fields=["start", "end", "event", "events_before", "events_after", "state"], mw=[])
REL_BLOCKS = [("syncapi/routing/relations.go", 42, 48), ("syncapi/routing/relations.go", 122, 127)] + HV_SHORT
REL_CHECKS = lambda: [chk("visibility_branch", "ApplyHistoryVisibilityFilter on result events", "syncapi/routing/relations.go", 124)]
REL_SUMMARY = "Related events are fetched from the DB and filtered by history visibility against the caller's membership (world_readable visible to any authenticated user)."
add("GET", f"{V1}/rooms/{{roomId}}/relations/{{eventId}}", "Get events related to an event", [(SRT, 118, 130)] + REL_BLOCKS, REL_CHECKS(), REL_SUMMARY, resp_fields=["chunk", "next_batch", "prev_batch"], mw=[])
add("GET", f"{V1}/rooms/{{roomId}}/relations/{{eventId}}/{{relType}}", "Get events related to an event by relation type", [(SRT, 132, 144)] + REL_BLOCKS, REL_CHECKS(), REL_SUMMARY, resp_fields=["chunk", "next_batch", "prev_batch"], mw=[])
add("GET", f"{V1}/rooms/{{roomId}}/relations/{{eventId}}/{{relType}}/{{eventType}}", "Get related events by relation and event type", [(SRT, 146, 158)] + REL_BLOCKS, REL_CHECKS(), REL_SUMMARY, resp_fields=["chunk", "next_batch", "prev_batch"], mw=[])
add("GET", f"{V1}/rooms/{{roomId}}/hierarchy", "Get the space hierarchy of a room",
    [(RT, 529, 537), ("clientapi/routing/room_hierarchy.go", 69, 78), ("clientapi/routing/room_hierarchy.go", 125, 128), ("clientapi/routing/room_hierarchy.go", 141, 158), ("roomserver/internal/query/query_room_hierarchy.go", 297, 300), ("roomserver/internal/query/query_room_hierarchy.go", 323, 337)],
    [chk("membership_row", "roomserver authorisedUser: caller m.room.member join or invite", "roomserver/internal/query/query_room_hierarchy.go", 327),
     chk("visibility_branch", "history_visibility world_readable (or public/knock join rule for children)", "roomserver/internal/query/query_room_hierarchy.go", 334)],
    "Roomserver authorisedUser: caller joined/invited to the room, or room world_readable (children also allowed via public/knock join rule); otherwise ErrRoomUnknownOrNotAllowed → 403.", resp_fields=["rooms", "next_batch"], mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/report/{{eventId}}", "Report an event in a room",
    [(RT, 1528, 1536), ("clientapi/routing/report_event.go", 32, 54), ("clientapi/routing/report_event.go", 81, 93)] + HELPER_MEMBER,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom (404 on failure)", "clientapi/routing/report_event.go", 48)],
    "Caller must be joined to the room (checkMemberInRoom); otherwise 404 per spec.", mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/upgrade", "Upgrade a room to a new version",
    [(RT, 1148, 1156), ("clientapi/routing/upgrade_room.go", 42, 48), ("clientapi/routing/upgrade_room.go", 62, 78), ("roomserver/internal/perform/perform_upgrade.go", 57, 73), ("roomserver/internal/perform/perform_upgrade.go", 294, 310)],
    [chk("group_role", "power level to send m.room.tombstone: pl.UserLevel(sender) >= pl.EventLevel('m.room.tombstone')", "roomserver/internal/perform/perform_upgrade.go", 309)],
    "Roomserver userIsAuthorized: caller's power level must reach the level required to send m.room.tombstone in the old room; otherwise ErrNotAllowed → 403.", resp_fields=["replacement_room"], mw=[])

RED_BLOCKS = [(RED, 45, 50), (RED, 73, 76), (RED, 109, 140), (RED, 186, 186)] + HELPER_MEMBER
RED_CHECKS = lambda: [
    chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", RED, 73),
    chk("owner_field", "event sender == caller (ev.SenderID() == *senderID)", RED, 112),
    chk("group_role", "power level 'redact': pl.UserLevel(sender) >= pl.Redact", RED, 133)]
RED_SUMMARY = "Caller must be joined; then may redact if they are the sender of the target event, otherwise their power level must be >= the room's redact level."
add("POST", f"{V3}/rooms/{{roomId}}/redact/{{eventId}}", "Redact an event", [(RT, 652, 660)] + RED_BLOCKS, RED_CHECKS(), RED_SUMMARY, resp_fields=["event_id"], mw=[])
add("PUT", f"{V3}/rooms/{{roomId}}/redact/{{eventId}}/{{txnId}}", "Redact an event (idempotent by txnId)", [(RT, 661, 670)] + RED_BLOCKS, RED_CHECKS(), RED_SUMMARY, resp_fields=["event_id"], mw=[])

JOIN_BLOCKS = [("clientapi/routing/joinroom.go", 32, 38), ("clientapi/routing/joinroom.go", 81, 89), ("clientapi/routing/joinroom.go", 102, 110), ("roomserver/internal/perform/perform_join.go", 269, 274), ("roomserver/internal/perform/perform_join.go", 363, 377)] + EVENT_AUTH
JOIN_CHECKS = lambda: [
    chk("setting_dependent", "guest join requires m.room.guest_access == can_join (room state)", "roomserver/internal/perform/perform_join.go", 271),
    chk("visibility_branch", "join rule public / invite pending / restricted: event auth (gomatrixserverlib.Allowed) on the m.room.member join event", "roomserver/internal/perform/perform_join.go", 376),
    chk("group_role", "event auth (gomatrixserverlib.Allowed, join rules & power levels)", INPUT, 304)]
JOIN_SUMMARY = "Caller joins as themselves; roomserver performJoinRoomByID builds the join event and roomserver event auth (join_rules public / pending invite / restricted, guest_access for guests) decides; ErrNotAllowed → 403."
add("POST", f"{V3}/join/{{roomIdOrAlias}}", "Join a room by ID or alias", [(RT, 316, 337)] + JOIN_BLOCKS, JOIN_CHECKS(), JOIN_SUMMARY, resp_fields=["room_id"], mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/join", "Join a room by ID", [(RT, 360, 381)] + JOIN_BLOCKS, JOIN_CHECKS(), JOIN_SUMMARY, resp_fields=["room_id"], mw=[])
add("POST", f"{V3}/rooms/{{roomId}}/unpeek", "Stop peeking into a room",
    [(RT, 396, 406), ("clientapi/routing/peekroom.go", 101, 127)],
    [chk("self_target", "PerformUnpeek with device.UserID and device.ID (own peek only)", "clientapi/routing/peekroom.go", 107)],
    "Removes the caller's own peek (user ID and device ID from the token); no other authorization.")

add("GET", f"{V3}/directory/list/room/{{roomId}}", "Get the public-directory visibility of a room",
    [(RT, 582, 590), ("clientapi/routing/directory.go", 343, 370)],
    [chk("anonymous", "MakeExternalAPI: no access token required", RT, 583)],
    "Unauthenticated endpoint; returns whether the room is published in the directory.", security=[], mw=[], resp_fields=["visibility"])
add("PUT", f"{V3}/directory/list/room/{{roomId}}", "Set the public-directory visibility of a room",
    [(RT, 592, 600), ("clientapi/routing/directory.go", 374, 377), ("clientapi/routing/directory.go", 400, 430), ("clientapi/routing/directory.go", 437, 440)] + HELPER_MEMBER,
    [chk("membership_row", "checkMemberInRoom → QueryMembershipForUser IsInRoom", "clientapi/routing/directory.go", 401),
     chk("group_role", "power level to send m.room.canonical_alias (NOTSPEC)", "clientapi/routing/directory.go", 425)],
    "Caller must be joined and have power level >= the level required for m.room.canonical_alias state events.", mw=[])
ASVIS_BLOCKS = [("clientapi/routing/directory.go", 454, 464), ("clientapi/routing/directory.go", 474, 479)]
ASVIS_CHECKS = lambda: [chk("global_role", "device.AccountType == AccountTypeAppService (appservice accounts only)", "clientapi/routing/directory.go", 458)]
ASVIS_SUMMARY = "Only application-service accounts (device.AccountType == AccountTypeAppService) may publish/unpublish rooms on an appservice network."
add("PUT", f"{V3}/directory/list/appservice/{{networkId}}/{{roomId}}", "Publish a room on an appservice network directory", [(RT, 601, 609)] + ASVIS_BLOCKS, ASVIS_CHECKS(), ASVIS_SUMMARY)
add("DELETE", f"{V3}/directory/list/appservice/{{networkId}}/{{roomId}}", "Remove a room from an appservice network directory", [(RT, 612, 620)] + ASVIS_BLOCKS, ASVIS_CHECKS(), ASVIS_SUMMARY)
add("GET", f"{V3}/directory/room/{{roomAlias}}", "Resolve a room alias to a room ID",
    [(RT, 553, 561), ("clientapi/routing/directory.go", 46, 53), ("clientapi/routing/directory.go", 64, 70), ("clientapi/routing/directory.go", 78, 83), ("clientapi/routing/directory.go", 119, 123)],
    [chk("anonymous", "MakeExternalAPI: no access token required", RT, 554)],
    "Unauthenticated alias lookup (local DB, then federation).", security=[], mw=[], resp_fields=["room_id", "servers"])
add("PUT", f"{V3}/directory/room/{{roomAlias}}", "Create a local room alias",
    [(RT, 563, 571), ("clientapi/routing/directory.go", 126, 147), ("clientapi/routing/directory.go", 160, 176), ("clientapi/routing/directory.go", 200, 216), ("roomserver/internal/alias.go", 36, 58)],
    [chk("setting_dependent", "alias domain must be local; exclusive appservice alias namespaces from config reject non-AS users", "clientapi/routing/directory.go", 166),
     chk("auth_only", "QuerySenderIDForUser must find a sender ID (no explicit membership/power check before SetRoomAlias)", "clientapi/routing/directory.go", 207, unlocated=True)],
    "Any authenticated local user may create an alias for a room in which they have a sender ID; config-driven appservice namespaces are enforced. No room power-level check found.",
    note="unlocated: no membership/power-level check for alias creation beyond sender-ID lookup", mw=[])
add("DELETE", f"{V3}/directory/room/{{roomAlias}}", "Delete a local room alias",
    [(RT, 573, 581), ("clientapi/routing/directory.go", 238, 243), ("clientapi/routing/directory.go", 270, 292), ("clientapi/routing/directory.go", 309, 310), ("clientapi/routing/directory.go", 325, 330), ("roomserver/internal/alias.go", 119, 120), ("roomserver/internal/alias.go", 139, 160)],
    [chk("membership_row", "QueryMembershipForUser IsInRoom", "clientapi/routing/directory.go", 287),
     chk("owner_field", "alias creator == caller (GetCreatorIDForAlias)", "roomserver/internal/alias.go", 144),
     chk("group_role", "else power level for m.room.canonical_alias", "roomserver/internal/alias.go", 158)],
    "Caller must be joined to the aliased room; then they must be the alias creator, or have power level >= m.room.canonical_alias level.", mw=[])
add("GET", f"{V3}/publicRooms", "List public rooms in the directory",
    [(RT, 622, 626), ("clientapi/routing/directory_public.go", 56, 66)],
    [chk("anonymous", "MakeExternalAPI: no access token required", RT, 623)],
    "Unauthenticated public room directory listing.", security=[], mw=[], resp_fields=["chunk", "next_batch", "prev_batch", "total_room_count_estimate"])
add("POST", f"{V3}/publicRooms", "Search public rooms in the directory",
    [(RT, 622, 626), ("clientapi/routing/directory_public.go", 56, 66)],
    [chk("anonymous", "MakeExternalAPI: no access token required", RT, 623)],
    "Unauthenticated public room directory search.", security=[], mw=[], resp_fields=["chunk", "next_batch", "prev_batch", "total_room_count_estimate"])
add("POST", f"{V3}/search", "Full-text search over room events",
    [(SRT, 160, 181), ("syncapi/routing/search.go", 42, 48), ("syncapi/routing/search.go", 80, 114)],
    [chk("setting_dependent", "cfg.Fulltext.Enabled must be true", SRT, 162),
     chk("membership_row", "RoomIDsWithMembership(device.UserID, join): requested rooms restricted to rooms the caller is joined to", "syncapi/routing/search.go", 81)],
    "Search is limited to rooms the caller is currently joined to; requested room filter is intersected with joined rooms (none left → 403).", resp_fields=["search_categories"])

# ---------------------------------------------------------------------------
# 2. Per-user data (self-target) and account endpoints
# ---------------------------------------------------------------------------
TAG = "clientapi/routing/room_tagging.go"
add("GET", f"{V3}/user/{{userId}}/rooms/{{roomId}}/tags", "Get the caller's tags for a room",
    [(RT, 1240, 1248), (TAG, 30, 59)], [chk("self_target", "device.UserID != userId → 403", TAG, 39)], "Path userId must equal the token user; tags are per-user account data.", resp_fields=["tags"])
add("PUT", f"{V3}/user/{{userId}}/rooms/{{roomId}}/tags/{{tag}}", "Add a tag to a room for the caller",
    [(RT, 1250, 1258), (TAG, 64, 79), (TAG, 98, 112)], [chk("self_target", "device.UserID != userId → 403", TAG, 74)], "Path userId must equal the token user.")
add("DELETE", f"{V3}/user/{{userId}}/rooms/{{roomId}}/tags/{{tag}}", "Remove a tag from a room for the caller",
    [(RT, 1260, 1268), (TAG, 117, 132), (TAG, 143, 166)], [chk("self_target", "device.UserID != userId → 403", TAG, 127)], "Path userId must equal the token user.")
AD = "clientapi/routing/account_data.go"
add("PUT", f"{V3}/user/{{userId}}/account_data/{{type}}", "Set global account data for the caller",
    [(RT, 1033, 1041), (AD, 77, 102), (AD, 120, 136)], [chk("self_target", "userId != device.UserID → 403", AD, 81)], "Path userId must equal the token user; m.fully_read and m.push_rules cannot be set here.")
add("GET", f"{V3}/user/{{userId}}/account_data/{{type}}", "Get global account data for the caller",
    [(RT, 1053, 1061), (AD, 34, 74)], [chk("self_target", "userId != device.UserID → 403", AD, 38)], "Path userId must equal the token user.")
add("PUT", f"{V3}/user/{{userId}}/rooms/{{roomId}}/account_data/{{type}}", "Set room account data for the caller",
    [(RT, 1043, 1051), (AD, 77, 102), (AD, 120, 136)], [chk("self_target", "userId != device.UserID → 403", AD, 81)], "Path userId must equal the token user; no room membership check (per-user data).")
add("GET", f"{V3}/user/{{userId}}/rooms/{{roomId}}/account_data/{{type}}", "Get room account data for the caller",
    [(RT, 1063, 1071), (AD, 34, 74)], [chk("self_target", "userId != device.UserID → 403", AD, 38)], "Path userId must equal the token user.")
FL = "syncapi/routing/filter.go"
add("POST", f"{V3}/user/{{userId}}/filter", "Create a sync filter for the caller",
    [(SRT, 78, 86), (FL, 76, 94), (FL, 128, 141)], [chk("self_target", "userId != device.UserID → 403", FL, 79)], "Path userId must equal the token user.", resp_fields=["filter_id"])
add("GET", f"{V3}/user/{{userId}}/filter/{{filterId}}", "Get a sync filter of the caller",
    [(SRT, 88, 96), (FL, 34, 67)], [chk("self_target", "userId != device.UserID → 403", FL, 37)], "Path userId must equal the token user.")
PR = "clientapi/routing/profile.go"
add("GET", f"{V3}/profile/{{userId}}", "Get a user's profile",
    [(RT, 880, 888), (PR, 40, 69)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 881)], "Unauthenticated profile lookup (local DB or federation).", security=[], mw=[], resp_fields=["avatar_url", "displayname"])
add("GET", f"{V3}/profile/{{userId}}/avatar_url", "Get a user's avatar URL",
    [(RT, 890, 898), (PR, 72, 90)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 891)], "Unauthenticated.", security=[], mw=[], resp_fields=["avatar_url"])
add("GET", f"{V3}/profile/{{userId}}/displayname", "Get a user's display name",
    [(RT, 915, 923), (PR, 161, 179)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 916)], "Unauthenticated.", security=[], mw=[], resp_fields=["displayname"])
add("PUT", f"{V3}/profile/{{userId}}/avatar_url", "Set the caller's avatar URL",
    [(RT, 900, 911), (PR, 93, 123), (PR, 133, 140)], [chk("self_target", "userId != device.UserID → 403", PR, 97)], "Path userId must equal the token user and belong to a local domain.")
add("PUT", f"{V3}/profile/{{userId}}/displayname", "Set the caller's display name",
    [(RT, 925, 936), (PR, 182, 212), (PR, 222, 229)], [chk("self_target", "userId != device.UserID → 403", PR, 186)], "Path userId must equal the token user and belong to a local domain.")
DV = "clientapi/routing/device.go"
add("GET", f"{V3}/devices", "List the caller's devices",
    [(RT, 1158, 1162), (DV, 94, 124)], [chk("self_target", "QueryDevices for device.UserID (own devices only)", DV, 99)], "Lists devices of the token user only.", resp_fields=["devices"])
add("GET", f"{V3}/devices/{{deviceId}}", "Get one of the caller's devices",
    [(RT, 1164, 1172), (DV, 53, 91)], [chk("self_target", "QueryDevices for device.UserID, then match deviceId among own devices", DV, 59)], "Device is looked up only among the token user's devices (404 otherwise).", resp_fields=["device_id", "display_name", "last_seen_ip", "last_seen_ts"])
add("PUT", f"{V3}/devices/{{deviceId}}", "Update one of the caller's devices",
    [(RT, 1174, 1182), (DV, 127, 164)], [chk("self_target", "PerformDeviceUpdate with RequestingUserID: device.UserID", DV, 142)], "Update is scoped to the token user's devices.")
add("DELETE", f"{V3}/devices/{{deviceId}}", "Delete one of the caller's devices (UIA)",
    [(RT, 1184, 1192), (DV, 167, 170), (DV, 190, 251)],
    [chk("self_target", "UIA login username must match token user", DV, 226),
     chk("self_target", "PerformDeviceDeletion for device.UserID", DV, 235)],
    "User-interactive auth re-verifies the caller's own credentials; the device is deleted from the token user's account only.", mw=[])
add("POST", f"{V3}/delete_devices", "Delete several of the caller's devices (UIA)",
    [(RT, 1194, 1198), (DV, 254, 306)],
    [chk("self_target", "UIA login username must equal device.UserID", DV, 274),
     chk("self_target", "PerformDeviceDeletion for device.UserID", DV, 292)],
    "User-interactive auth must be for the token user; devices are deleted from the caller's own account.")
add("GET", f"{V3}/account/whoami", "Get the user ID bound to the access token",
    [(RT, 697, 704), ("clientapi/routing/whoami.go", 31, 40)], [chk("self_target", "returns device.UserID / device.ID of the token", "clientapi/routing/whoami.go", 35)], "Returns the token's own identity.", resp_fields=["user_id", "device_id", "is_guest"])
add("POST", f"{V3}/account/password", "Change the caller's password (password re-auth)",
    [(RT, 706, 713), ("clientapi/routing/password.go", 30, 38), ("clientapi/routing/password.go", 58, 82), ("clientapi/routing/password.go", 89, 106)],
    [chk("self_target", "requires password re-auth; password updated for device.UserID localpart", "clientapi/routing/password.go", 90)],
    "Password is changed for the token user only, after re-authenticating with the current password.")
add("POST", f"{V3}/account/deactivate", "Deactivate the caller's account (UIA)",
    [(RT, 715, 722), ("clientapi/routing/deactivate.go", 15, 62)],
    [chk("self_target", "UIA Verify with the caller's device; account from login.Username()", "clientapi/routing/deactivate.go", 31)],
    "User-interactive auth against the caller; the account identified by the verified login is deactivated.")
TP = "clientapi/routing/threepid.go"
add("GET", f"{V3}/account/3pid", "List third-party identifiers of the caller",
    [(RT, 942, 946), (TP, 182, 211)], [chk("self_target", "QueryThreePIDsForLocalpart for device.UserID", TP, 185)], "Returns 3PIDs of the token user only.", resp_fields=["threepids"])
add("POST", f"{V3}/account/3pid", "Add a validated third-party identifier to the caller",
    [(RT, 948, 952), (TP, 103, 113), (TP, 140, 173)], [chk("self_target", "association saved for device.UserID", TP, 153)], "3PID association is saved for the token user.")
add("POST", f"{V3}/account/3pid/delete", "Remove a third-party identifier",
    [(RT, 954, 958), (TP, 214, 235)],
    [chk("auth_only", "PerformForgetThreePID by address/medium only; not scoped to device.UserID", TP, 220, unlocated=True)],
    "Only a valid access token is required; the handler removes the 3PID by address and medium without checking it belongs to the caller.",
    note="unlocated: no ownership check of the 3PID")
add("POST", f"{V3}/account/3pid/email/requestToken", "Request an email validation token for adding a 3PID",
    [(RT, 960, 964), (TP, 45, 50), (TP, 54, 77), (TP, 96, 100)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 961)], "Unauthenticated; rejects emails already in use.", security=[], mw=[], resp_fields=["sid"])
add("POST", f"{V3}/register/email/requestToken", "Request an email validation token for registration",
    [(RT, 960, 964), (TP, 45, 50), (TP, 54, 77), (TP, 96, 100)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 961)], "Unauthenticated; rejects emails already in use.", security=[], mw=[], resp_fields=["sid"])
add("POST", f"{V3}/user/{{userId}}/openid/request_token", "Request an OpenID token for the caller",
    [(RT, 1083, 1094), ("clientapi/routing/openid.go", 35, 73)], [chk("self_target", "userId != device.UserID → 403", "clientapi/routing/openid.go", 43)], "Path userId must equal the token user.", resp_fields=["access_token", "token_type", "matrix_server_name", "expires_in"])
add("GET", f"{V3}/admin/whois/{{userId}}", "Get device/session information about a user",
    [(RT, 1073, 1081), ("clientapi/routing/admin_whois.go", 46, 68), ("clientapi/routing/admin_whois.go", 84, 91)],
    [chk("global_role", "device.AccountType == AccountTypeAdmin OR userId == device.UserID (OR)", "clientapi/routing/admin_whois.go", 50),
     chk("self_target", "userId == device.UserID (same OR condition)", "clientapi/routing/admin_whois.go", 50)],
    "Allowed if the caller is a server admin account, or the requested userId is the caller.", resp_fields=["user_id", "devices"])

# Push rules / pushers / notifications (all keyed by device.UserID)
PRU = "clientapi/routing/pushrules.go"
add("GET", f"{V3}/pushrules/", "Get all push rules of the caller", [(RT, 753, 757), (PRU, 36, 45)], [chk("self_target", "QueryPushRules(device.UserID)", PRU, 37)], "Push rules of the token user only.")
add("GET", f"{V3}/pushrules/{{scope}}/", "Get push rules by scope", [(RT, 768, 776), (PRU, 47, 60)], [chk("self_target", "QueryPushRules(device.UserID)", PRU, 48)], "Push rules of the token user only.")
add("GET", f"{V3}/pushrules/{{scope}}/{{kind}}/", "Get push rules by kind", [(RT, 796, 804), (PRU, 62, 80)], [chk("self_target", "QueryPushRules(device.UserID)", PRU, 63)], "Push rules of the token user only.")
add("GET", f"{V3}/pushrules/{{scope}}/{{kind}}/{{ruleId}}", "Get a push rule", [(RT, 824, 832), (PRU, 82, 103)], [chk("self_target", "QueryPushRules(device.UserID)", PRU, 83)], "Push rules of the token user only.")
add("PUT", f"{V3}/pushrules/{{scope}}/{{kind}}/{{ruleId}}", "Create or update a push rule", [(RT, 834, 846), (PRU, 105, 133), (PRU, 164, 169)], [chk("self_target", "QueryPushRules / PerformPushRulesPut for device.UserID", PRU, 164)], "Push rules of the token user only.")
add("DELETE", f"{V3}/pushrules/{{scope}}/{{kind}}/{{ruleId}}", "Delete a push rule", [(RT, 848, 856), (PRU, 171, 196)], [chk("self_target", "QueryPushRules / PerformPushRulesPut for device.UserID", PRU, 191)], "Push rules of the token user only.")
add("GET", f"{V3}/pushrules/{{scope}}/{{kind}}/{{ruleId}}/{{attr}}", "Get a push rule attribute", [(RT, 858, 866), (PRU, 198, 225)], [chk("self_target", "QueryPushRules(device.UserID)", PRU, 203)], "Push rules of the token user only.")
add("PUT", f"{V3}/pushrules/{{scope}}/{{kind}}/{{ruleId}}/{{attr}}", "Set a push rule attribute", [(RT, 868, 876), (PRU, 227, 238), (PRU, 249, 275)], [chk("self_target", "QueryPushRules / PerformPushRulesPut for device.UserID", PRU, 269)], "Push rules of the token user only.")
PU = "clientapi/routing/pusher.go"
add("GET", f"{V3}/pushers", "List the caller's pushers", [(RT, 1206, 1210), (PU, 29, 60)], [chk("self_target", "QueryPushers for localpart of device.UserID", PU, 42)], "Pushers of the token user only.", resp_fields=["pushers"])
add("POST", f"{V3}/pushers/set", "Create, modify or delete a pusher for the caller", [(RT, 1212, 1219), (PU, 65, 80), (PU, 105, 121)], [chk("self_target", "body.Localpart/ServerName forced to device.UserID", PU, 105)], "Pusher is bound to the token user.")
add("GET", f"{V3}/notifications", "List the caller's notifications", [(RT, 1200, 1204), ("clientapi/routing/notification.go", 28, 32), ("clientapi/routing/notification.go", 45, 73)], [chk("self_target", "QueryNotifications for localpart of device.UserID", "clientapi/routing/notification.go", 54)], "Notifications of the token user only.", resp_fields=["notifications", "next_token"])
PS = "clientapi/routing/presence.go"
add("PUT", f"{V3}/presence/{{userId}}/status", "Set the caller's presence",
    [(RT, 1499, 1507), (PS, 40, 85)],
    [chk("setting_dependent", "cfg.Matrix.Presence.EnableOutbound false → no-op 200", PS, 47),
     chk("self_target", "device.UserID != userId → 403", PS, 53)],
    "Outbound presence must be enabled in config; path userId must equal the token user.")
add("GET", f"{V3}/presence/{{userId}}/status", "Get a user's presence",
    [(RT, 1508, 1516), (PS, 87, 104), (PS, 125, 136)],
    [chk("auth_only", "any authenticated user may query any userId; no relationship check", PS, 95)],
    "Only a valid access token is required; presence of any user ID is returned.", resp_fields=["presence", "status_msg", "currently_active", "last_active_ago"])

# Auth / session
LG = "clientapi/routing/login.go"
add("GET", f"{V3}/login", "Get supported login flows", [(RT, 726, 733), (LG, 45, 60)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 727)], "Unauthenticated.", security=[], mw=[], resp_fields=["flows"])
add("POST", f"{V3}/login", "Authenticate and obtain an access token", [(RT, 726, 733), (LG, 45, 48), (LG, 61, 75)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 727)], "Unauthenticated login.", security=[], mw=[], resp_fields=["user_id", "access_token", "device_id"])
RG = "clientapi/routing/register.go"
add("POST", f"{V3}/register", "Register a new account",
    [(RT, 539, 544), (RG, 466, 480), (RG, 691, 701)],
    [chk("anonymous", "MakeExternalAPI: no access token required", RT, 539),
     chk("setting_dependent", "cfg.RegistrationDisabled / virtual host RegistrationAllowed", RG, 691)],
    "Unauthenticated; refused when registration is disabled in config (shared-secret flow excepted).", security=[], mw=[], resp_fields=["user_id", "access_token", "device_id"])
add("GET", f"{V3}/register/available", "Check whether a username is available",
    [(RT, 546, 551), (RG, 1002, 1012)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 546)], "Unauthenticated.", security=[], mw=[], resp_fields=["available"])
LO = "clientapi/routing/logout.go"
add("POST", f"{V3}/logout", "Invalidate the current access token", [(RT, 628, 632), (LO, 26, 46)], [chk("self_target", "PerformDeviceDeletion of device.UserID / device.ID", LO, 30)], "Deletes the token's own device.")
add("POST", f"{V3}/logout/all", "Invalidate all access tokens of the caller", [(RT, 634, 638), (LO, 49, 69)], [chk("self_target", "PerformDeviceDeletion of all devices of device.UserID", LO, 53)], "Deletes all devices of the token user.")
add("GET", f"{V3}/capabilities", "Get server capabilities", [(RT, 1270, 1277), ("clientapi/routing/capabilities.go", 28, 54)], [chk("auth_only", "valid access token (guests allowed); no object or role check", RT, 1271)], "Any authenticated user.", resp_fields=["capabilities"])
add("GET", "/_matrix/client/versions", "Get supported spec versions", [(RT, 133, 154)], [chk("anonymous", "MakeExternalAPI: no access token required", RT, 134)], "Unauthenticated.", security=[], mw=[], resp_fields=["versions", "unstable_features"])
add("GET", f"{V3}/sync", "Synchronise the caller's state",
    [(SRT, 52, 54), ("syncapi/sync/requestpool.go", 286, 300), ("syncapi/sync/requestpool.go", 305, 315)],
    [chk("self_target", "sync request built from the token's device (newSyncRequest(req, *device))", "syncapi/sync/requestpool.go", 288)],
    "Returns data for the token user's own rooms and devices.", resp_fields=["next_batch", "rooms", "presence", "account_data", "to_device", "device_lists"])
add("GET", f"{V3}/keys/changes", "Get device key changes since a sync token",
    [(SRT, 98, 100)], [chk("self_target", "OnIncomingKeyChangeRequest for the token device", SRT, 99)], "Key changes relevant to the token user's rooms.", resp_fields=["changed", "left"])
add("POST", f"{V3}/createRoom", "Create a new room",
    [(RT, 311, 315), ("clientapi/routing/createroom.go", 111, 133), ("clientapi/routing/createroom.go", 144, 157)],
    [chk("auth_only", "any authenticated user whose domain is local; creator becomes the room creator", "clientapi/routing/createroom.go", 152)],
    "Any authenticated (non-guest) local user may create a room; no further authorization.", resp_fields=["room_id", "room_alias"])
add("GET", f"{V3}/joined_rooms", "List rooms the caller is joined to",
    [(RT, 355, 359), ("clientapi/routing/joined_rooms.go", 31, 68)], [chk("self_target", "QueryRoomsForUser(deviceUserID, join)", "clientapi/routing/joined_rooms.go", 45)], "Rooms of the token user only.", resp_fields=["joined_rooms"])
add("POST", f"{V3}/user_directory/search", "Search the user directory",
    [(RT, 1096, 1120), ("clientapi/routing/userdirectory.go", 39, 67)],
    [chk("auth_only", "results limited to users sharing a room with device.UserID (QueryKnownUsers); no other check", "clientapi/routing/userdirectory.go", 60)],
    "Any authenticated user; the result set is restricted to users known to the caller (shared rooms).", resp_fields=["results", "limited"])
TPY = "clientapi/routing/thirdparty.go"
add("GET", f"{V3}/thirdparty/protocols", "List third-party protocols", [(RT, 975, 979), (TPY, 32, 63)], [chk("auth_only", "valid access token (guests allowed); no further check", RT, 976)], "Any authenticated user.")
add("GET", f"{V3}/thirdparty/protocol/{{protocol}}", "Get a third-party protocol", [(RT, 981, 989), (TPY, 32, 63)], [chk("auth_only", "valid access token (guests allowed); no further check", RT, 982)], "Any authenticated user.")
add("GET", f"{V3}/thirdparty/user", "Look up third-party users", [(RT, 1001, 1005), (TPY, 69, 92)], [chk("auth_only", "valid access token (guests allowed); no further check", RT, 1002)], "Any authenticated user.")
add("GET", f"{V3}/thirdparty/location", "Look up third-party locations", [(RT, 1017, 1021), (TPY, 98, 121)], [chk("auth_only", "valid access token (guests allowed); no further check", RT, 1018)], "Any authenticated user.")
add("GET", f"{V3}/voip/turnServer", "Get TURN server credentials",
    [(RT, 966, 973), ("clientapi/routing/voip.go", 36, 84)],
    [chk("setting_dependent", "TURN URIs / lifetime configured, else empty 200", "clientapi/routing/voip.go", 40),
     chk("auth_only", "credentials derived from device.UserID; no further check", "clientapi/routing/voip.go", 57)],
    "Any authenticated user; response depends on TURN configuration.", resp_fields=["uris", "ttl", "username", "password"])
add("PUT", f"{V3}/sendToDevice/{{eventType}}/{{txnId}}", "Send to-device messages",
    [(RT, 672, 681), ("clientapi/routing/sendtodevice.go", 30, 62)],
    [chk("auth_only", "sender is device.UserID; messages may target any user/device; no relationship check", "clientapi/routing/sendtodevice.go", 53)],
    "Any authenticated user (guests allowed) may send to-device events to arbitrary users.")
KY = "clientapi/routing/keys.go"
add("POST", f"{V3}/keys/upload", "Upload device and one-time keys", [(RT, 1471, 1475), (KY, 34, 63)], [chk("self_target", "keys uploaded for device.UserID / device.ID", KY, 42)], "Keys are stored for the token's own device.", resp_fields=["one_time_key_counts"])
add("POST", f"{V3}/keys/query", "Query device keys of users", [(RT, 1476, 1480), (KY, 110, 132)], [chk("auth_only", "any authenticated user may query any users' device keys", KY, 117)], "Any authenticated user.", resp_fields=["device_keys", "master_keys", "self_signing_keys", "user_signing_keys", "failures"])
add("POST", f"{V3}/keys/claim", "Claim one-time keys", [(RT, 1481, 1485), (KY, 147, 172)], [chk("auth_only", "any authenticated user may claim any users' one-time keys", KY, 154)], "Any authenticated user.", resp_fields=["one_time_keys", "failures"])
KC = "clientapi/routing/key_crosssigning.go"
add("POST", f"{V3}/keys/device_signing/upload", "Upload cross-signing keys (password re-auth)", [(RT, 1451, 1453), (RT, 1459, 1459), (KC, 34, 50), (KC, 64, 74)], [chk("self_target", "password re-auth; uploadReq.UserID = device.UserID", KC, 73)], "Cross-signing keys stored for the token user after password re-auth.")
add("POST", f"{V3}/keys/signatures/upload", "Upload cross-signing signatures", [(RT, 1455, 1457), (RT, 1460, 1460), (KC, 107, 116)], [chk("self_target", "uploadReq.UserID = device.UserID", KC, 115)], "Signatures stored for the token user.")
KB = "clientapi/routing/key_backup.go"
add("POST", f"{V3}/room_keys/version", "Create a key backup version", [(RT, 1309, 1311), (RT, 1317, 1317), (KB, 58, 86)], [chk("self_target", "PerformKeyBackup for device.UserID", KB, 71)], "Backup is created for the token user.", resp_fields=["version"])
add("GET", f"{V3}/room_keys/version", "Get the latest key backup version", [(RT, 1289, 1291), (RT, 1314, 1314), (KB, 90, 114)], [chk("self_target", "QueryKeyBackup for device.UserID", KB, 92)], "Backup of the token user only.", resp_fields=["algorithm", "auth_data", "count", "etag", "version"])
add("GET", f"{V3}/room_keys/version/{{version}}", "Get a key backup version", [(RT, 1281, 1287), (RT, 1313, 1313), (KB, 90, 114)], [chk("self_target", "QueryKeyBackup for device.UserID", KB, 92)], "Backup of the token user only.", resp_fields=["algorithm", "auth_data", "count", "etag", "version"])
add("PUT", f"{V3}/room_keys/version/{{version}}", "Update auth data of a key backup version", [(RT, 1293, 1299), (RT, 1315, 1315), (KB, 118, 153)], [chk("self_target", "UpdateBackupKeyAuthData for device.UserID", KB, 125)], "Backup of the token user only.", resp_fields=["version"])
add("DELETE", f"{V3}/room_keys/version/{{version}}", "Delete a key backup version", [(RT, 1301, 1307), (RT, 1316, 1316), (KB, 157, 172)], [chk("self_target", "DeleteKeyBackup(device.UserID, version)", KB, 158)], "Backup of the token user only.")
add("PUT", f"{V3}/room_keys/keys", "Upload backup keys for all rooms", [(RT, 1328, 1342), (RT, 1409, 1409), (KB, 175, 183)], [chk("self_target", "UpdateBackupKeyAuthData keys for device.UserID", KB, 179)], "Backup of the token user only.", resp_fields=["count", "etag"])
add("PUT", f"{V3}/room_keys/keys/{{roomId}}/{{sessionId}}", "Upload a backup key for one session", [(RT, 1377, 1395), (RT, 1406, 1407), (RT, 1411, 1411), (KB, 175, 183)], [chk("self_target", "UpdateBackupKeyAuthData keys for device.UserID", KB, 179)], "Backup of the token user only; no room membership check (roomId is only a key in the user's backup).", resp_fields=["count", "etag"])
add("GET", f"{V3}/room_keys/keys", "Get all backup keys", [(RT, 1419, 1421), (RT, 1439, 1439), (KB, 210, 228)], [chk("self_target", "QueryKeyBackup for device.UserID", KB, 214)], "Backup of the token user only.", resp_fields=["rooms"])
add("GET", f"{V3}/room_keys/keys/{{roomId}}", "Get backup keys of a room", [(RT, 1423, 1429), (RT, 1440, 1440), (KB, 210, 228), (KB, 241, 256)], [chk("self_target", "QueryKeyBackup for device.UserID", KB, 214)], "Backup of the token user only; no room membership check.", resp_fields=["sessions"])

# ---------------------------------------------------------------------------
# 3. Server admin endpoints
# ---------------------------------------------------------------------------
ADM = "clientapi/routing/admin.go"
ADMIN_CHECK = lambda: [chk("global_role", "MakeAdminAPI: device.AccountType != AccountTypeAdmin → 403", HTTPAPI, 137)]
ADMIN_SUMMARY = "MakeAdminAPI wraps MakeAuthAPI and requires the account type to be server admin."
add("POST", f"{DADM}/registrationTokens/new", "Create a registration token", [(RT, 181, 185), (ADM, 34, 40)], ADMIN_CHECK() + [chk("setting_dependent", "cfg.RegistrationRequiresToken must be enabled", ADM, 35)], ADMIN_SUMMARY + " Also requires token registration enabled.", mw=MW_ADMIN, resp_fields=["token", "uses_allowed", "pending", "completed", "expiry_time"])
add("GET", f"{DADM}/registrationTokens", "List registration tokens", [(RT, 187, 191), (ADM, 147, 176)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN, resp_fields=["registration_tokens"])
add("GET", f"{DADM}/registrationTokens/{{token}}", "Get a registration token", [(RT, 193, 210), (ADM, 178, 195)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("PUT", f"{DADM}/registrationTokens/{{token}}", "Update a registration token", [(RT, 193, 210), (ADM, 216, 230), (ADM, 256, 267)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("DELETE", f"{DADM}/registrationTokens/{{token}}", "Delete a registration token", [(RT, 193, 210), (ADM, 197, 214)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("POST", f"{DADM}/evacuateRoom/{{roomId}}", "Make all local users leave a room", [(RT, 212, 216), (ADM, 269, 293)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN, resp_fields=["affected"])
add("POST", f"{DADM}/evacuateUser/{{userId}}", "Make a user leave all rooms", [(RT, 218, 222), (ADM, 295, 313)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN, resp_fields=["affected"])
add("POST", f"{DADM}/purgeRoom/{{roomId}}", "Purge a room from the database", [(RT, 224, 228), (ADM, 315, 329)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("POST", f"{DADM}/resetPassword/{{userId}}", "Reset a user's password", [(RT, 230, 234), (ADM, 331, 344), (ADM, 384, 409)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN, resp_fields=["password_updated"])
add("GET", f"{DADM}/downloadState/{{serverName}}/{{roomId}}", "Download room state from a remote server", [(RT, 236, 240), (ADM, 460, 497)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("GET", f"{DADM}/fulltext/reindex", "Trigger a full-text reindex", [(RT, 242, 246), (ADM, 411, 424)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("POST", f"{DADM}/refreshDevices/{{userId}}", "Mark a remote user's device list as stale", [(RT, 248, 252), (ADM, 426, 458)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
SN = "clientapi/routing/server_notices.go"
add("POST", f"{SADM}/send_server_notice", "Send a server notice to a user",
    [(RT, 283, 296), (SN, 56, 73)], [chk("global_role", "device.AccountType != AccountTypeAdmin → 403", SN, 68)], "Handler itself requires a server admin account (MakeAuthAPI + explicit AccountTypeAdmin check).", resp_fields=["event_id"])
add("PUT", f"{SADM}/send_server_notice/{{txnId}}", "Send a server notice to a user (idempotent)",
    [(RT, 262, 281), (SN, 56, 73)], [chk("global_role", "device.AccountType != AccountTypeAdmin → 403", SN, 68)], "Handler itself requires a server admin account (MakeAuthAPI + explicit AccountTypeAdmin check).", resp_fields=["event_id"])
add("GET", f"{SADM}/event_reports", "List reported events", [(RT, 1538, 1550), (ADM, 500, 520)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN, resp_fields=["event_reports", "total"])
add("GET", f"{SADM}/event_reports/{{reportId}}", "Get a reported event", [(RT, 1552, 1560)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("DELETE", f"{SADM}/event_reports/{{reportId}}", "Delete a reported event", [(RT, 1562, 1570)], ADMIN_CHECK(), ADMIN_SUMMARY, mw=MW_ADMIN)
add("POST", f"{SADM}/register", "Shared-secret registration",
    [(RT, 156, 179), (RG, 1072, 1088)],
    [chk("anonymous", "MakeExternalAPI: no access token", RT, 160),
     chk("setting_dependent", "enabled only when cfg.RegistrationSharedSecret set; request must carry a valid HMAC over the shared secret", RG, 1084)],
    "No access token; the request is accepted only if its MAC was computed with the server's configured registration shared secret.", security=[], mw=[], resp_fields=["user_id", "access_token", "device_id"])

# ---------------------------------------------------------------------------
# Validation and output
# ---------------------------------------------------------------------------
KINDS = {"anonymous", "auth_only", "self_target", "owner_field", "membership_row", "group_role", "global_role", "visibility_branch", "setting_dependent", "compound_and"}
seen = set()
errors = []
for c in CANDS:
    key = (c["method"], c["path"])
    if key in seen:
        errors.append(f"duplicate {key}")
    seen.add(key)
    n = len(c["controller_text"])
    if not (1 <= n <= 3000):
        errors.append(f"{key}: controller_text length {n}")
    if not c["auth_checks"]:
        errors.append(f"{key}: empty auth_checks")
    for a in c["auth_checks"]:
        if a["kind"] not in KINDS:
            errors.append(f"{key}: bad kind {a['kind']}")
        if not a["text"]:
            errors.append(f"{key}: empty text at {a['file']}:{a['line']}")
if errors:
    for e in errors:
        print("ERROR", e)
    sys.exit(1)

with (OUT / "candidates.jsonl").open("w", encoding="utf-8") as f:
    for c in CANDS:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")

from collections import Counter
dom = Counter(c["auth_checks"][0]["kind"] for c in CANDS)
print("candidates:", len(CANDS))
print("dominant kind (first check):", dict(dom))
print("length min/max:", min(len(c["controller_text"]) for c in CANDS), max(len(c["controller_text"]) for c in CANDS))
