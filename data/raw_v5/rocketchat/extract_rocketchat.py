"""Rocket.Chat 8.9.0 REST v1 static extraction helper (read-only on the clone).

Usage:
  python -I extract_rocketchat.py survey <v1 file>...   # list routes
  python -I extract_rocketchat.py show <v1 file> <name> # print a route block
  python -I extract_rocketchat.py build                 # write candidates.jsonl
  python -I extract_rocketchat.py validate              # check candidates.jsonl
"""
import re, sys, json, os, collections
sys.stdout.reconfigure(encoding="utf-8")

ROOT = "C:/BLADE/datasets/blade/raw/opensource/RocketChat_Rocket.Chat"
OUT = "C:/BLADE/data/raw_v5/rocketchat"
V1 = "apps/meteor/server/api/v1/"
MM = "apps/meteor/server/meteor-methods/"
SL = "apps/meteor/server/lib/"
API_DIR = ROOT + "/" + V1

COMMIT = "057a927d903c83b5d61cf236d650c4500ebb4b66"
TAG = "8.9.0"
REPO = "https://github.com/RocketChat/Rocket.Chat"

TOP_RE = re.compile(r"^(?:(?:export )?const \w+ = )?API\.(?:v1|default)\.(get|post|put|delete|addRoute)\(\s*$")
TOP_RE_INLINE = re.compile(r"^(?:(?:export )?const \w+ = )?API\.(?:v1|default)\.(get|post|put|delete|addRoute)\(\s*'([^']+)'")
NAME_NEXT = re.compile(r"^\s*(?:\[)?'([^']+)'")
CHAIN_RE = re.compile(r"^\t\.(get|post|put|delete)\(\s*$")
CHAIN_RE_INLINE = re.compile(r"^\t\.(get|post|put|delete)\('([^']+)'")

FEATS = ["permissionsRequired", "authRequired: false", "authOrAnonRequired", "findPrivateGroupByIdOrName", "findDirectMessageRoom",
         "canAccessRoomAsync", "canAccessRoomIdAsync", "hasPermissionAsync", "hasAllPermissionAsync", "hasAtLeastOnePermissionAsync",
         "isUserFromParams", "Subscriptions.", "TeamMember", "Team.", "twoFactorRequired", "this.userId ===", "this.userId !==", "_createdBy",
         "getUserFromParams", "forbidden()", "this.user._id", "userWithoutUsername"]

_cache = {}


def lines(rel):
    if rel not in _cache:
        with open(ROOT + "/" + rel, encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def seg(rel, start, end):
    ls = lines(rel)
    return "\n".join(ls[start - 1:end])


def func(rel, start_pat, end_pat=r"^\};?$", max_lines=None):
    """Return (start, end, text) for the block starting at the first line matching start_pat
    and ending at the first following line matching end_pat."""
    ls = lines(rel)
    sp, ep = re.compile(start_pat), re.compile(end_pat)
    s = next(i for i, l in enumerate(ls) if sp.match(l))
    e = next(i for i in range(s + 1, len(ls)) if ep.match(ls[i]))
    if max_lines and e - s + 1 > max_lines:
        return (s + 1, s + max_lines, "\n".join(ls[s:s + max_lines]) + "\n\t...")
    return (s + 1, e + 1, "\n".join(ls[s:e + 1]))


def routes(rel):
    ls = lines(rel)
    out, i, n = [], 0, len(ls)
    while i < n:
        m = TOP_RE.match(ls[i]) or TOP_RE_INLINE.match(ls[i])
        cm = CHAIN_RE.match(ls[i]) or CHAIN_RE_INLINE.match(ls[i])
        if m:
            kind = m.group(1)
            name = m.group(2) if m.lastindex == 2 else (NAME_NEXT.match(ls[i + 1]).group(1) if NAME_NEXT.match(ls[i + 1]) else "?")
            j = i + 1
            while j < n and ls[j] != ");":
                j += 1
            block = "\n".join(ls[i:j + 1])
            methods = re.findall(r"^\t\t(get|post|put|delete)\s*[:(]", block, re.M) if kind == "addRoute" else [kind]
            out.append(dict(name=name, methods=[x.upper() for x in methods], start=i + 1, end=j + 1, text=block, kind=kind))
            i = j + 1
        elif cm:
            kind = cm.group(1)
            name = cm.group(2) if cm.lastindex == 2 else (NAME_NEXT.match(ls[i + 1]).group(1) if NAME_NEXT.match(ls[i + 1]) else "?")
            j = i + 1
            while j < n and ls[j] not in ("\t)", "\t);"):
                j += 1
            block = "\n".join(ls[i:j + 1])
            out.append(dict(name=name, methods=[kind.upper()], start=i + 1, end=j + 1, text=block, kind="chain"))
            i = j + 1
        else:
            i += 1
    return out


def route(rel, name):
    for r in routes(rel):
        if r["name"] == name:
            return r
    raise KeyError(f"{rel}:{name}")


def survey(rel):
    for r in routes(rel):
        feats = [k for k in FEATS if k in r["text"]]
        perms = re.findall(r"permissionsRequired:\s*(\[[^\]]*\]|\{.*?operation: '\w+'\s*\})", r["text"], re.S)
        p = " ".join(perms[0].split()) if perms else ""
        print("\t".join([os.path.basename(rel), r["name"], ",".join(r["methods"]), f"{r['start']}-{r['end']}", str(len(r["text"])), p, " ".join(feats)]))


# ---------------------------------------------------------------- compaction

def _collapse(text, head_pat):
    """Collapse brace-balanced blocks whose first line matches head_pat into 'head ... },'."""
    ls = text.split("\n")
    out, i = [], 0
    hp = re.compile(head_pat)
    while i < len(ls):
        l = ls[i]
        if hp.match(l):
            depth = l.count("{") + l.count("(") - l.count("}") - l.count(")")
            j = i
            while depth > 0 and j + 1 < len(ls):
                j += 1
                depth += ls[j].count("{") + ls[j].count("(") - ls[j].count("}") - ls[j].count(")")
            if j > i:
                indent = re.match(r"^\s*", l).group(0)
                out.append(l.rstrip() + " ... " + ls[j].strip())
                i = j + 1
                continue
        out.append(l)
        i += 1
    return "\n".join(out)


AUTH_WORDS = ("hasPermission", "canAccessRoom", "Subscriptions.", "TeamMember", "permissionsRequired", "authRequired", "forbidden",
              "unauthorized", "not-allowed", "not-authorized", "_createdBy", "isUserFromParams", "this.userId", "findPrivateGroup",
              "findDirectMessageRoom", "error-invalid-subscription", "isMember", "canSeeAll", "allowPrivateTeam", "canAccess", "canRead")


def compact(text, limit=3000):
    text = "\n".join(l for l in text.split("\n") if l.strip() != "")
    if len(text) <= limit:
        return text
    text = _collapse(text, r"^\s*response: \{\s*$")
    if len(text) <= limit:
        return text
    text = _collapse(text, r"^\s*(body|query): (ajv|ajvQuery)\.compile.*\(\{\s*$")
    if len(text) <= limit:
        return text
    text = _collapse(text, r"^\s*(check|const \{ cursor, totalCount \} = |return API\.v1\.success\()")
    if len(text) <= limit:
        return text
    # last resort: drop non-authorization lines from the end until it fits
    ls = text.split("\n")
    keep = list(ls)
    idx = len(keep) - 1
    while len("\n".join(x for x in keep if x is not None)) > limit and idx > 0:
        if not any(w in keep[idx] for w in AUTH_WORDS):
            keep[idx] = None
        idx -= 1
    res = []
    prev_gap = False
    for l in keep:
        if l is None:
            if not prev_gap:
                res.append("\t...")
            prev_gap = True
        else:
            res.append(l)
            prev_gap = False
    return "\n".join(res)


def ev(rel, substr, start=None, end=None):
    ls = lines(rel)
    rng = range((start or 1) - 1, min(end or len(ls), len(ls)))
    for i in rng:
        if substr in ls[i]:
            return {"type": "code", "text": ls[i].strip(), "location": f"{rel}:{i + 1}"}
    raise KeyError(f"evidence not found: {rel} :: {substr}")


# ---------------------------------------------------------------- helper snippets (relpath, start, end)
def H():
    h = {}
    g = V1 + "groups.ts"
    s, e, _ = func(g, r"^async function findPrivateGroupByIdOrName", r"^}$")
    h["FPG"] = [(g, 99, 104), (g, 107, e)]
    car = "packages/authorization/src/canAccessRoom.ts"
    s, e, _ = func(car, r"^\tasync function _validateIfAlreadyJoined", r"^\t},$")
    h["CAR_JOINED"] = (car, s, e)
    s, e, _ = func(car, r"^\tasync function _validateAccessToPublicRooms\(", r"^\t},$")
    h["CAR_PUBLIC"] = (car, 9, 16)
    h["CAR_PUBLIC2"] = (car, s, e)
    s, e, _ = func(car, r"^\tasync function _validateAccessToDiscussionsParentRoom", r"^\t},$")
    h["CAR_DISC"] = (car, s, e)
    im = V1 + "im.ts"
    s, e, _ = func(im, r"^const findDirectMessageRoom", r"^};$")
    h["FDM"] = (im, s, e)
    ah = "apps/meteor/server/api/api.helpers.ts"
    s, e, _ = func(ah, r"^export async function checkPermissionsForInvocation", r"^}$")
    h["CHECKPERM"] = (ah, s, e)
    h["ISUFP"] = ("apps/meteor/server/api/lib/isUserFromParams.ts", 3, 14)
    h["GUFP"] = ("apps/meteor/server/api/lib/getUserFromParams.ts", 7, 38)
    f = MM + "rooms/leaveRoom.ts"; s, e, _ = func(f, r"^export const leaveRoomMethod", r"^};$"); h["LEAVE"] = (f, s, e)
    f = MM + "rooms/hideRoom.ts"; s, e, _ = func(f, r"^export const hideRoomMethod", r"^};$"); h["HIDE"] = (f, s, e)
    h["OPEN"] = (SL + "openRoom.ts", 5, 13)
    f = MM + "rooms/getRoomRoles.ts"; s, e, _ = func(f, r"^export const executeGetRoomRoles", r"^};$"); h["ROLES"] = (f, s, e)
    h["FAV"] = (MM + "rooms/toggleFavorite.ts", 17, 25)
    h["NOTIF"] = (MM + "users/saveNotificationSettings.ts", 119, 124)
    h["READ"] = (SL + "readMessages.ts", 7, 14)
    h["UNREAD"] = (SL + "messaging/unread/unreadMessages.ts", 48, 66)
    h["IGNORE"] = (MM + "users/ignoreUser.ts", 16, 34)
    f = MM + "messages/getSingleMessage.ts"; s, e, _ = func(f, r"^export const getSingleMessage", r"^};$"); h["GETMSG"] = (f, s, e)
    h["PIN"] = (SL + "messaging/pins/pinMessage.ts", 47, 75)
    h["STAR"] = (SL + "messaging/stars/starMessage.ts", 20, 47)
    f = SL + "authorization/canDeleteMessage.ts"; s, e, _ = func(f, r"^export const canDeleteMessageAsync", r"^};$"); h["CANDEL"] = (f, s, e)
    h["DELVAL"] = (SL + "messages/deleteMessage.ts", 13, 26)
    h["REACT"] = (SL + "messaging/reactions/setReaction.ts", 133, 141)
    h["MENTIONED"] = ("apps/meteor/server/api/lib/messages.ts", 7, 24)
    h["STARRED"] = ("apps/meteor/server/api/lib/messages.ts", 46, 63)
    h["ADDROLE"] = (MM + "auth/addUserToRole.ts", 10, 35)
    h["MUTE"] = (MM + "rooms/muteUserInRoom.ts", 19, 25)
    h["BAN"] = (SL + "banUserFromRoom.ts", 11, 30)
    h["CLEAN"] = (MM + "rooms/cleanRoomHistory.ts", 44, 52)
    h["DISC"] = (MM + "messages/createDiscussion.ts", 225, 236)
    f = MM + "rooms/saveRoomSettings.ts"
    n = next(i for i, l in enumerate(lines(f)) if "'edit-room'" in l) + 1
    h["SAVEROOM"] = (f, n - 6, n + 8)
    h["ERASE"] = (SL + "eraseRoom.ts", 11, 42)
    h["CANBEDEL"] = (SL + "rooms/roomCoordinator.ts", 24, 29)
    f = MM + "rooms/archiveRoom.ts"; s, e, _ = func(f, r"^export const executeArchiveRoom", r"^};$", max_lines=22); h["ARCHIVE"] = (f, s, e)
    f = MM + "rooms/unarchiveRoom.ts"; s, e, _ = func(f, r"^export const executeUnarchiveRoom", r"^};$", max_lines=20); h["UNARCHIVE"] = (f, s, e)
    f = MM + "rooms/addRoomModerator.ts"; s, e, _ = func(f, r"^export const addRoomModerator", r"^};$", max_lines=20); h["ADDMOD"] = (f, s, e)
    f = MM + "rooms/addRoomOwner.ts"; s, e, _ = func(f, r"^export const addRoomOwner", r"^};$", max_lines=20); h["ADDOWNER"] = (f, s, e)
    f = MM + "rooms/addRoomLeader.ts"; s, e, _ = func(f, r"^export const addRoomLeader", r"^};$", max_lines=12); h["ADDLEADER"] = (f, s, e)
    f = MM + "rooms/removeRoomModerator.ts"; s, e, _ = func(f, r"^export const removeRoomModerator", r"^};$", max_lines=18); h["RMMOD"] = (f, s, e)
    f = MM + "rooms/removeRoomOwner.ts"; s, e, _ = func(f, r"^export const removeRoomOwner", r"^};$", max_lines=18); h["RMOWNER"] = (f, s, e)
    f = MM + "rooms/removeUserFromRoom.ts"; s, e, _ = func(f, r"^export const removeUserFromRoomMethod", r"^};$", max_lines=32); h["KICK"] = (f, s, e)
    f = MM + "rooms/addUsersToRoom.ts"; s, e, _ = func(f, r"^export const addUsersToRoomMethod", r"^};$", max_lines=48); h["ADDUSERS"] = (f, s, e)
    f = MM + "rooms/createPrivateGroup.ts"; s, e, _ = func(f, r"^export const createPrivateGroupMethod", r"^};$", max_lines=30); h["CREATEP"] = (f, s, e)
    f = MM + "rooms/addAllUserToRoom.ts"; s, e, _ = func(f, r"^export const addAllUserToRoomFn", r"^};$", max_lines=10); h["ADDALL"] = (f, s, e)
    h["HISTORY"] = (MM + "messages/getChannelHistory.ts", 29, 62)
    h["CANREAD"] = ("packages/authorization/src/canReadRoom.ts", 7, 26)
    ts = "apps/meteor/server/services/team/service.ts"
    h["T_LISTROOMS"] = (ts, 507, 528)
    h["T_LISTROOMSUSER"] = (ts, 557, 575)
    h["T_MEMBERS"] = (ts, 651, 663)
    h["T_REMOVE"] = (ts, 776, 799)
    h["T_CHILDREN"] = (ts, 1080, 1100)
    h["T_LIST"] = (ts, 223, 240)
    h["VALEDIT"] = (SL + "users/saveUser/validateUserEditing.ts", 33, 66)
    h["VALDATA"] = (SL + "users/saveUser/validateUserData.ts", 25, 37)
    h["GENTOKEN"] = (MM + "auth/createToken.ts", 14, 22)
    h["FINDINT"] = ("apps/meteor/server/api/lib/integrations.ts", 6, 40)
    h["MOUNTQ"] = (SL + "integrations/lib/mountQueriesBasedOnPermission.ts", 7, 39)
    h["MOUNTH"] = (SL + "integrations/lib/mountQueriesBasedOnPermission.ts", 41, 55)
    h["UPDOUT"] = (MM + "integrations/outgoing/updateOutgoingIntegration.ts", 36, 52)
    h["UPDIN"] = (MM + "integrations/incoming/updateIncomingIntegration.ts", 52, 70)
    h["DELOUT"] = (MM + "integrations/outgoing/deleteOutgoingIntegration.ts", 16, 40)
    h["DELIN"] = (MM + "integrations/incoming/deleteIncomingIntegration.ts", 16, 36)
    f = MM + "integrations/incoming/addIncomingIntegration.ts"
    n = next(i for i, l in enumerate(lines(f)) if "'manage-incoming-integrations'" in l) + 1
    h["ADDIN"] = (f, n - 3, n + 6)
    f = MM + "integrations/outgoing/addOutgoingIntegration.ts"
    n = next(i for i, l in enumerate(lines(f)) if "'manage-outgoing-integrations'" in l) + 1
    h["ADDOUT"] = (f, n - 3, n + 6)
    h["CREATEC"] = (V1 + "channels.ts", 1000, 1016)
    h["FCH"] = (V1 + "channels.ts", 82, 116)
    h["AUTHMW"] = ("apps/meteor/server/api/v1/middlewares/authenticationHono.ts", 15, 48)
    f = V1 + "rooms.ts"; s, e, _ = func(f, r"^export async function findRoomByIdOrName", r"^}$"); h["FRM"] = (f, s, e)
    return h


HELP = None

# ---------------------------------------------------------------- endpoint table
# E(name, method, label, conf, reason, helpers, evidence[(rel|None, substr)], q=[], b=[], summary, auth_summary, file=None, extra_ev=[])
E = collections.namedtuple("E", "name method label conf reason helpers evidence q b summary auth file")

FILE_BY_PREFIX = {"groups": "groups.ts", "im": "im.ts", "teams": "teams.ts", "users": "users.ts", "rooms": "rooms.ts",
                  "subscriptions": "subscriptions.ts", "chat": "chat.ts", "integrations": "integrations.ts",
                  "oauth-apps": "oauthapps.ts", "e2e": "e2e.ts", "permissions": "permissions.ts", "roles": "roles.ts",
                  "settings": "settings.ts", "channels": "channels.ts", "me": "misc.ts", "pw": "misc.ts"}


def e(name, method, label, conf, reason, helpers=(), evidence=(), q=(), b=(), summary="", auth="", file=None):
    return E(name, method, label, conf, reason, list(helpers), list(evidence), list(q), list(b), summary, auth, file)


MEM_P = "findPrivateGroupByIdOrName이 t='p' 방만 조회하고 canAccessRoomAsync→_validateIfAlreadyJoined에서 Subscriptions.countByRoomIdAndUserId(요청자, 방) 구독 행을 요구한다."
MEM_P_ALT = " 구독 외 추가 역할·권한 검사가 없어 membership_required. 대안: discussion(prid) 방은 상위 방 접근으로도 통과하므로 보류 가능."
DM_MEM = "findDirectMessageRoom이 t='d' 방만 조회하고 canAccessRoomIdAsync→_validateIfAlreadyJoined가 요청자의 Subscriptions 행(DM 참여자)을 요구한다."
ROOMPERM = "방 범위 권한 {p}(hasPermissionAsync(userId, '{p}', rid): 방 안 owner·moderator 역할 또는 전역 역할)이 거부를 결정하므로 role_required."
CAR_ANY = "canAccessRoomAsync가 방 유형별로 다른 조건(공개 채널: view-c-room 권한, 비공개·DM: 구독 행, 팀 채널: 팀 구성원, discussion: 상위 방)을 OR로 적용하므로 단일 라벨로 표현되지 않아 보류."
OOA = "본인 대상이면 허용, 타인 대상이면 전역 권한 {p}가 필요하다. 소유자 OR 관리자 우회 구조이므로 owner_or_admin."

ENDPOINTS = [
    # ---------------- groups (private rooms) ----------------
    e("groups.info", "GET", "membership_required", 0.75, MEM_P + MEM_P_ALT, ["FPG", "CAR_JOINED"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (V1 + "groups.ts", "if (!room || !user || !(await canAccessRoomAsync(room, user)))"),
       ("packages/authorization/src/canAccessRoom.ts", "if (!(await Subscriptions.countByRoomIdAndUserId(room._id, user._id, includeInvitations)))")],
      q=["roomId", "roomName"], summary="Get private group info", auth="findPrivateGroupByIdOrName → canAccessRoomAsync(p room) → 요청자 구독 행 필요"),
    e("groups.messages", "GET", "membership_required", 0.75, MEM_P + MEM_P_ALT, ["FPG", "CAR_JOINED"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (V1 + "groups.ts", "if (!room || !user || !(await canAccessRoomAsync(room, user)))"),
       ("packages/authorization/src/canAccessRoom.ts", "if (!(await Subscriptions.countByRoomIdAndUserId(room._id, user._id, includeInvitations)))")],
      q=["roomId", "roomName", "offset", "count", "sort", "query"], summary="List messages of a private group", auth="findPrivateGroupByIdOrName → 구독 행 필요"),
    e("groups.history", "GET", "membership_required", 0.75, MEM_P + " 이후 getChannelHistory가 canReadRoom으로 같은 조건을 다시 검사한다." + MEM_P_ALT, ["FPG", "CAR_JOINED", "HISTORY"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (V1 + "groups.ts", "if (!room || !user || !(await canAccessRoomAsync(room, user)))"),
       (MM + "messages/getChannelHistory.ts", "if (!(await Authorization.canReadRoom(room, { _id: fromUserId })))")],
      q=["roomId", "roomName", "latest", "oldest", "inclusive", "offset", "count", "unreads"], summary="Private group message history", auth="findPrivateGroupByIdOrName + getChannelHistory(canReadRoom)"),
    e("groups.files", "GET", "membership_required", 0.75, MEM_P + MEM_P_ALT, ["FPG", "CAR_JOINED"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (V1 + "groups.ts", "if (!room || !user || !(await canAccessRoomAsync(room, user)))")],
      q=["roomId", "roomName", "typeGroup", "name", "offset", "count"], summary="List files of a private group", auth="findPrivateGroupByIdOrName → 구독 행 필요"),
    e("groups.roles", "GET", "membership_required", 0.75, MEM_P + " executeGetRoomRoles도 canAccessRoomAsync를 다시 검사한다." + MEM_P_ALT, ["FPG", "CAR_JOINED", "ROLES"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (MM + "rooms/getRoomRoles.ts", "if (fromUser && !(await canAccessRoomAsync(room, fromUser)))")],
      q=["roomId", "roomName"], summary="List room roles of a private group", auth="findPrivateGroupByIdOrName + executeGetRoomRoles(canAccessRoom)"),
    e("groups.moderators", "GET", "membership_required", 0.75, MEM_P + MEM_P_ALT, ["FPG", "CAR_JOINED"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (V1 + "groups.ts", "if (!room || !user || !(await canAccessRoomAsync(room, user)))")],
      q=["roomId", "roomName"], summary="List moderators of a private group", auth="findPrivateGroupByIdOrName → 구독 행 필요"),
    e("groups.members", "GET", "membership_required", 0.6,
      MEM_P + " 단, broadcast 방이면 방 범위 권한 view-broadcast-member-list가 추가로 필요하다(AND 분기). 일반 방 기준으로 membership_required를 초안으로 두지만 broadcast 분기 때문에 보류(manual) 가능.",
      ["FPG", "CAR_JOINED"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (None, "if (findResult.broadcast && !(await hasPermissionAsync(this.user, 'view-broadcast-member-list', findResult.rid)))")],
      q=["roomId", "roomName", "offset", "count", "status", "filter"], summary="List members of a private group", auth="findPrivateGroupByIdOrName(구독) + broadcast면 view-broadcast-member-list"),
    e("groups.online", "GET", "membership_required", 0.7,
      "query로 t='p' 방을 찾고 canAccessRoomAsync(room, this.user)를 요구한다. 비공개 방이므로 _validateIfAlreadyJoined의 구독 행이 실질 조건. discussion 상위 방 경로가 있어 보류 대안.",
      ["CAR_JOINED", "CAR_DISC"],
      [(None, "if (!(await canAccessRoomAsync(room, this.user)))"), (None, "t: 'p',")],
      q=["_id", "query"], summary="Online users of a private group", auth="canAccessRoomAsync on p room → 구독 행"),
    e("groups.close", "POST", "membership_required", 0.75, MEM_P + " hideRoomMethod는 요청자 본인 구독만 숨긴다." + MEM_P_ALT, ["FPG", "CAR_JOINED", "HIDE"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (MM + "rooms/hideRoom.ts", "const { modifiedCount } = await Subscriptions.hideByRoomIdAndUserId(rid, userId);")],
      b=["roomId", "roomName"], summary="Close (hide) a private group for the caller", auth="findPrivateGroupByIdOrName(구독) → 본인 구독 hide"),
    e("groups.open", "POST", "membership_required", 0.75, MEM_P + " openRoom은 요청자 본인 구독만 연다." + MEM_P_ALT, ["FPG", "CAR_JOINED", "OPEN"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (SL + "openRoom.ts", "const openByRoomResponse = await Subscriptions.openByRoomIdAndUserId(roomId, userId);")],
      b=["roomId", "roomName"], summary="Open a private group for the caller", auth="findPrivateGroupByIdOrName(구독) → 본인 구독 open"),
    e("groups.leave", "POST", "membership_required", 0.7,
      MEM_P + " leaveRoomMethod가 Subscriptions.findOneByRoomIdAndUserId로 본인 구독을 다시 요구하고 leave-p 권한(기본 user 역할 보유)도 검사한다. 구성원 여부가 핵심이므로 membership_required; leave-p를 역할 조건으로 보면 role_required 대안.",
      ["FPG", "LEAVE"],
      [(None, "const findResult = await findPrivateGroupByIdOrName"), (MM + "rooms/leaveRoom.ts", "const subscription = await Subscriptions.findOneByRoomIdAndUserId(rid, user._id, {"),
       (MM + "rooms/leaveRoom.ts", "(room.t === 'p' && !(await hasPermissionAsync(user, 'leave-p')))")],
      b=["roomId", "roomName"], summary="Leave a private group", auth="findPrivateGroupByIdOrName + leaveRoomMethod(본인 구독, leave-p)"),
    e("groups.counters", "GET", "manual_review_required", 0.7,
      "userId 파라미터가 있으면 view-room-administration 권한이 필요하고, 없으면 본인 구독으로 joined 여부만 계산해 비구성원도 일부 필드를 받는다. 파라미터에 따라 정책이 달라지고 비구성원 허용 범위가 섞여 보류. 구성원 기준으로 보면 membership_required 대안.",
      [],
      [(None, "const access = await hasPermissionAsync(this.user, 'view-room-administration');"), (None, "if (params.userId) {"), (None, "const subscription = await Subscriptions.findOneByRoomIdAndUserId(room._id, user);")],
      q=["roomId", "roomName", "userId"], summary="Counters of a private group", auth="userId 지정 시 view-room-administration, 아니면 본인 구독 기준"),
    e("groups.list", "GET", "owner_match", 0.8, "요청자 본인 구독(Subscriptions.findByUserIdAndTypes(this.userId, ['p']))만 조회해 반환한다. 대상이 인증 사용자 본인으로 고정.", [],
      [(None, "const subs = await Subscriptions.findByUserIdAndTypes(this.userId, ['p'], { projection: { rid: 1 } }).toArray();")],
      q=["offset", "count", "sort"], summary="List private groups the caller belongs to", auth="본인 구독 목록"),
    e("groups.listAll", "GET", "role_required", 0.9, "permissionsRequired: ['view-room-administration'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['view-room-administration'],")],
      q=["offset", "count", "sort", "query"], summary="List all private groups (admin)", auth="permissionsRequired view-room-administration"),
    e("groups.getIntegrations", "GET", "manual_review_required", 0.7,
      "permissionsRequired(hasAny manage-*-integrations) AND findPrivateGroupByIdOrName(구독)이 모두 필요하고, 결과는 다시 권한별 _createdBy 필터로 제한된다. 서로 다른 독립 조건의 AND 결합이라 보류.",
      ["FPG", "MOUNTQ"],
      [(None, "permissionsRequired: {"), (None, "const findResult = await findPrivateGroupByIdOrName"), (SL + "integrations/lib/mountQueriesBasedOnPermission.ts", "return { '_createdBy._id': userId };")],
      q=["roomId", "roomName", "includeAllPrivateGroups", "offset", "count"], summary="Integrations of a private group", auth="manage-*-integrations(hasAny) AND 그룹 구독 AND 권한별 own 필터"),
    e("groups.create", "POST", "role_required", 0.8, "createPrivateGroupMethod가 팀 소속이면 create-team-group(팀 방 범위), 아니면 전역 create-p 권한을 요구한다. 역할·권한 보유가 유일한 조건.", ["CREATEP"],
      [(MM + "rooms/createPrivateGroup.ts", "} else if (!(await hasPermissionAsync(user, 'create-p'))) {"), (MM + "rooms/createPrivateGroup.ts", "if (!(await hasPermissionAsync(user, 'create-team-group', team.roomId)))")],
      b=["name", "members", "readOnly", "customFields", "extraData"], summary="Create a private group", auth="create-p 또는 create-team-group(팀 범위)"),
    e("groups.delete", "POST", "role_required", 0.8, "findPrivateGroupByIdOrName(구독) 후 eraseRoom이 canBeDeleted→" + ROOMPERM.format(p="delete-p") + " 구독은 방 식별 전제이고 삭제 허용은 권한이 결정한다.", ["FPG", "ERASE", "CANBEDEL"],
      [(None, "await eraseRoom(findResult.rid, this.user);"), (SL + "rooms/roomCoordinator.ts", "return hasPermission(`delete-${room.t}`, room._id);")],
      b=["roomId", "roomName"], summary="Delete a private group", auth="findPrivateGroupByIdOrName + eraseRoom(delete-p 방 범위)"),
    e("groups.archive", "POST", "role_required", 0.85, ROOMPERM.format(p="archive-room"), ["FPG", "ARCHIVE"],
      [(None, "await executeArchiveRoom(this.userId, findResult.rid);"), (MM + "rooms/archiveRoom.ts", "if (!(await hasPermissionAsync(userId, 'archive-room', room._id)))")],
      b=["roomId", "roomName"], summary="Archive a private group", auth="executeArchiveRoom → archive-room(방 범위)"),
    e("groups.unarchive", "POST", "role_required", 0.85, ROOMPERM.format(p="unarchive-room"), ["FPG", "UNARCHIVE"],
      [(None, "await executeUnarchiveRoom(this.userId, findResult.rid);"), (MM + "rooms/unarchiveRoom.ts", "if (!(await hasPermissionAsync(userId, 'unarchive-room', room._id)))")],
      b=["roomId", "roomName"], summary="Unarchive a private group", auth="executeUnarchiveRoom → unarchive-room(방 범위)"),
    e("groups.rename", "POST", "role_required", 0.8, "saveRoomSettings가 " + ROOMPERM.format(p="edit-room"), ["FPG", "SAVEROOM"],
      [(None, "await saveRoomSettings(this.userId, findResult.rid, 'roomName', this.bodyParams.name);"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {")],
      b=["roomId", "roomName", "name"], summary="Rename a private group", auth="saveRoomSettings → edit-room(방 범위)"),
    e("groups.setTopic", "POST", "role_required", 0.8, "saveRoomSettings가 " + ROOMPERM.format(p="edit-room"), ["FPG", "SAVEROOM"],
      [(None, "await saveRoomSettings(this.userId, findResult.rid, 'roomTopic', this.bodyParams.topic || '');"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {")],
      b=["roomId", "roomName", "topic"], summary="Set topic of a private group", auth="saveRoomSettings → edit-room(방 범위)"),
    e("groups.setReadOnly", "POST", "role_required", 0.8, "saveRoomSettings가 " + ROOMPERM.format(p="edit-room"), ["FPG", "SAVEROOM"],
      [(None, "await saveRoomSettings(this.userId, findResult.rid, 'readOnly', this.bodyParams.readOnly);"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {")],
      b=["roomId", "roomName", "readOnly"], summary="Set read-only flag of a private group", auth="saveRoomSettings → edit-room(방 범위)"),
    e("groups.setType", "POST", "role_required", 0.75, "saveRoomSettings가 edit-room(방 범위)을 요구하고 roomType 검증기가 공개 전환 시 create-c 권한도 요구한다. 둘 다 역할·권한 조건이라 role_required; 권한 AND 결합을 독립 조건으로 보면 보류 대안.", ["FPG", "SAVEROOM"],
      [(None, "await saveRoomSettings(this.userId, findResult.rid, 'roomType', this.bodyParams.type as RoomType);"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {"),
       (MM + "rooms/saveRoomSettings.ts", "if (value === 'c' && (!room.teamId || room.teamMain) && !(await hasPermissionAsync(userId, 'create-c')))")],
      b=["roomId", "roomName", "type"], summary="Change private group type", auth="saveRoomSettings → edit-room + create-c"),
    e("groups.addModerator", "POST", "role_required", 0.85, ROOMPERM.format(p="set-moderator"), ["FPG", "ADDMOD"],
      [(None, "await addRoomModerator(this.userId, findResult.rid, user._id);"), (MM + "rooms/addRoomModerator.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-moderator', rid)) && !isFederated)")],
      b=["roomId", "roomName", "userId", "username"], summary="Add a moderator to a private group", auth="addRoomModerator → set-moderator(방 범위)"),
    e("groups.addOwner", "POST", "role_required", 0.85, ROOMPERM.format(p="set-owner"), ["FPG", "ADDOWNER"],
      [(None, "await addRoomOwner(this.userId, findResult.rid, user._id);"), (MM + "rooms/addRoomOwner.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-owner', rid)) && !isFederated)")],
      b=["roomId", "roomName", "userId", "username"], summary="Add an owner to a private group", auth="addRoomOwner → set-owner(방 범위)"),
    e("groups.addLeader", "POST", "role_required", 0.85, ROOMPERM.format(p="set-leader"), ["FPG", "ADDLEADER"],
      [(None, "await addRoomLeader(this.userId, findResult.rid, user._id);"), (MM + "rooms/addRoomLeader.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-leader', rid)))")],
      b=["roomId", "roomName", "userId", "username"], summary="Add a leader to a private group", auth="addRoomLeader → set-leader(방 범위)"),
    e("groups.removeModerator", "POST", "role_required", 0.85, ROOMPERM.format(p="set-moderator"), ["FPG", "RMMOD"],
      [(None, "await removeRoomModerator(this.userId, findResult.rid, user._id);"), (MM + "rooms/removeRoomModerator.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-moderator', rid)) && !isRoomFederated(room))")],
      b=["roomId", "roomName", "userId", "username"], summary="Remove a moderator from a private group", auth="removeRoomModerator → set-moderator(방 범위)"),
    e("groups.removeOwner", "POST", "role_required", 0.85, ROOMPERM.format(p="set-owner"), ["FPG", "RMOWNER"],
      [(None, "await removeRoomOwner(this.userId, findResult.rid, user._id);"), (MM + "rooms/removeRoomOwner.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-owner', rid)) && !isRoomFederated(room))")],
      b=["roomId", "roomName", "userId", "username"], summary="Remove an owner from a private group", auth="removeRoomOwner → set-owner(방 범위)"),
    e("groups.kick", "POST", "role_required", 0.85, "removeUserFromRoomMethod가 " + ROOMPERM.format(p="remove-user"), ["KICK"],
      [(None, "await removeUserFromRoomMethod(this.userId, { rid: room._id, username: user.username });"), (MM + "rooms/removeUserFromRoom.ts", "if (!(await hasPermissionAsync(fromId, 'remove-user', data.rid)))")],
      b=["roomId", "roomName", "userId", "username"], summary="Kick a user from a private group", auth="removeUserFromRoomMethod → remove-user(방 범위)"),
    e("groups.invite", "POST", "role_required", 0.65,
      "addUsersToRoomMethod가 (요청자 구독 존재 AND 방 범위 add-user-to-joined-room) OR 전역 add-user-to-any-p-room 으로 허용한다. 결정 조건이 방 범위·전역 권한이므로 role_required 초안; 구독 AND 권한 결합을 독립 조건으로 보면 보류 대안.",
      ["ADDUSERS"],
      [(None, "await addUsersToRoomMethod(this.userId, { rid, users: users.map((u) => u.username).filter(isTruthy) }, this.user);"),
       (MM + "rooms/addUsersToRoom.ts", "if (userInRoom && (await hasPermissionAsync(userId, 'add-user-to-joined-room', room._id))) {"),
       (MM + "rooms/addUsersToRoom.ts", "} else if (room.t === 'p' && (await hasPermissionAsync(userId, 'add-user-to-any-p-room'))) {")],
      b=["roomId", "roomName", "userId", "username", "userIds", "usernames"], summary="Invite users to a private group", auth="addUsersToRoomMethod → add-user-to-joined-room(구독자) 또는 add-user-to-any-p-room"),
    e("groups.addAll", "POST", "role_required", 0.85, "addAllUserToRoomFn이 전역 권한 add-all-to-room을 요구한다. findPrivateGroupByIdOrName의 구독은 방 식별 전제.", ["FPG", "ADDALL"],
      [(None, "await addAllUserToRoomFn(this.userId, findResult.rid, activeUsersOnly === true || activeUsersOnly === 'true' || activeUsersOnly === 1);"),
       (MM + "rooms/addAllUserToRoom.ts", "if (!(await hasPermissionAsync(userId, 'add-all-to-room'))) {")],
      b=["roomId", "roomName", "activeUsersOnly"], summary="Add all users to a private group", auth="add-all-to-room 전역 권한"),
    e("groups.convertToTeam", "POST", "role_required", 0.7, "findPrivateGroupByIdOrName(구독) 후 hasAllPermissionAsync(['create-team','edit-room'], rid)로 두 권한을 모두 요구한다. 둘 다 역할·권한 조건이라 role_required; 독립 조건 AND로 보면 보류 대안.", ["FPG"],
      [(None, "if (!(await hasAllPermissionAsync(this.user, ['create-team', 'edit-room'], room.rid))) {")],
      b=["roomId", "roomName"], summary="Convert a private group to a team", auth="create-team AND edit-room(방 범위)"),
    # ---------------- im / dm ----------------
    e("im.delete", "POST", "role_required", 0.65, "(DM 참여자 구독 OR view-room-administration) 통과 후 eraseRoom→canBeDeleted가 방 범위 권한 delete-d(기본 admin 역할만 보유)를 추가로 요구한다. 최종 허용을 결정하는 것은 delete-d 권한이므로 role_required 초안; 구성원 조건과 권한의 AND 결합으로 보면 보류, 앞단만 보면 membership_required 대안.", ["FDM", "ERASE", "CANBEDEL"],
      [(None, "(await canAccessRoomIdAsync(room._id, this.userId)) || (await hasPermissionAsync(this.user, 'view-room-administration'));"), (None, "await eraseRoom(room._id, this.user);"), (SL + "rooms/roomCoordinator.ts", "return hasPermission(`delete-${room.t}`, room._id);")],
      b=["roomId", "username"], summary="Delete a direct message room", auth="(DM 구독 OR view-room-administration) AND delete-d(방 범위)"),
    e("im.close", "POST", "membership_required", 0.75, DM_MEM + " 이어서 본인 구독이 있어야 hide한다. 본인 구독 중심이므로 owner_match 대안.", ["FDM", "CAR_JOINED", "HIDE"],
      [(None, "const canAccess = await canAccessRoomIdAsync(roomId, this.userId);"), (None, "return API.v1.failure(`The user is not subscribed to the room`);")],
      b=["roomId"], summary="Close a direct message room for the caller", auth="canAccessRoomId(DM 구독) + 본인 구독 hide"),
    e("im.open", "POST", "membership_required", 0.75, DM_MEM + " 이어서 본인 구독을 open한다. owner_match 대안.", ["FDM", "CAR_JOINED", "OPEN"],
      [(None, "const canAccess = await canAccessRoomIdAsync(roomId, this.userId);")],
      b=["roomId"], summary="Open a direct message room for the caller", auth="canAccessRoomId(DM 구독) + 본인 구독 open"),
    e("im.files", "GET", "membership_required", 0.8, DM_MEM, ["FDM", "CAR_JOINED"],
      [(None, "const canAccess = await canAccessRoomIdAsync(room._id, this.userId);"), ("packages/authorization/src/canAccessRoom.ts", "if (!(await Subscriptions.countByRoomIdAndUserId(room._id, user._id, includeInvitations)))")],
      q=["roomId", "username", "typeGroup", "name", "offset", "count"], summary="List files of a direct message room", auth="canAccessRoomId(DM 구독)"),
    e("im.members", "GET", "membership_required", 0.8, DM_MEM, ["FDM", "CAR_JOINED"],
      [(None, "const canAccess = await canAccessRoomIdAsync(room._id, this.userId);")],
      q=["roomId", "username", "offset", "count", "status", "filter"], summary="List members of a direct message room", auth="canAccessRoomId(DM 구독)"),
    e("im.messages", "GET", "membership_required", 0.8, DM_MEM, ["FDM", "CAR_JOINED"],
      [(None, "const canAccess = await canAccessRoomIdAsync(room._id, this.userId);")],
      q=["roomId", "username", "mentionIds", "starredIds", "pinned", "offset", "count"], summary="List messages of a direct message room", auth="canAccessRoomId(DM 구독)"),
    e("im.history", "GET", "membership_required", 0.75, "findDirectMessageRoom이 t='d' 방을 찾고 getChannelHistory가 canReadRoom→canAccessRoom→구독 행을 요구한다(실패 시 false→forbidden).", ["FDM", "HISTORY", "CAR_JOINED"],
      [(None, "const result = await getChannelHistory(objectParams);"), (MM + "messages/getChannelHistory.ts", "if (!(await Authorization.canReadRoom(room, { _id: fromUserId })))")],
      q=["roomId", "latest", "oldest", "inclusive", "offset", "count", "unreads"], summary="Direct message history", auth="getChannelHistory(canReadRoom → DM 구독)"),
    e("im.setTopic", "POST", "role_required", 0.7, "canAccessRoomId(DM 구독) 후 saveRoomSettings가 edit-room(방 범위) 권한을 요구한다. 허용을 결정하는 것은 권한이므로 role_required; DM에서 edit-room이 참여자에게 기본 부여되는지에 따라 membership_required 대안.", ["FDM", "SAVEROOM"],
      [(None, "const canAccess = await canAccessRoomIdAsync(roomId, this.userId);"), (None, "await saveRoomSettings(this.userId, room._id, 'roomTopic', topic ?? '');"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {")],
      b=["roomId", "topic"], summary="Set topic of a direct message room", auth="DM 구독 + edit-room(방 범위)"),
    e("im.counters", "GET", "manual_review_required", 0.7, "userId 파라미터가 있으면 view-room-administration 권한, 없으면 본인 구독(canAccessRoomId)으로 정책이 갈린다. 파라미터 의존 분기라 보류; 본인 기준만 보면 membership_required 대안.", ["FDM"],
      [(None, "const access = await hasPermissionAsync(this.userId, 'view-room-administration');"), (None, "const canAccess = await canAccessRoomIdAsync(roomId, user);")],
      q=["roomId", "userId"], summary="Counters of a direct message room", auth="userId 지정 시 view-room-administration, 아니면 DM 구독"),
    e("im.leave", "POST", "membership_required", 0.75, "findDirectMessageRoom 후 leaveRoomMethod가 Subscriptions.findOneByRoomIdAndUserId로 요청자 본인 구독을 요구한다(없으면 error-user-not-in-room).", ["FDM", "LEAVE"],
      [(None, "await leaveRoomMethod(this.user, room._id);"), (MM + "rooms/leaveRoom.ts", "throw new Meteor.Error('error-user-not-in-room', 'You are not in this room', {")],
      b=["roomId", "roomName"], summary="Leave a direct message room", auth="leaveRoomMethod → 본인 구독 필요"),
    e("im.list", "GET", "owner_match", 0.85, "Subscriptions.find({'u._id': this.userId, t: 'd'})로 요청자 본인 구독 DM만 반환한다. 대상이 본인으로 고정.", [],
      [(None, "const subscriptions = await Subscriptions.find({ 'u._id': this.userId, 't': 'd' }, { projection: { rid: 1 } })")],
      q=["offset", "count", "sort"], summary="List direct message rooms of the caller", auth="본인 구독 목록"),
    e("im.list.everyone", "GET", "role_required", 0.9, "permissionsRequired: ['view-room-administration'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['view-room-administration'],")],
      q=["offset", "count", "sort", "query"], summary="List all direct message rooms (admin)", auth="view-room-administration"),
    # ---------------- teams ----------------
    e("teams.list", "GET", "owner_match", 0.8, "Team.list가 TeamMember.findByUserId(uid)로 요청자 본인의 팀만 조회한다. 대상이 본인으로 고정.", ["T_LIST"],
      [(None, "const { records, total } = await Team.list(this.userId, { offset, count }, { sort, query });"), ("apps/meteor/server/services/team/service.ts", "const userTeams = await TeamMember.findByUserId<Pick<ITeamMember, 'teamId'>>(uid, {")],
      q=["offset", "count", "sort", "query"], summary="List teams of the caller", auth="본인 TeamMember 목록"),
    e("teams.listAll", "GET", "role_required", 0.9, "permissionsRequired: ['view-all-teams'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['view-all-teams'],")],
      q=["offset", "count"], summary="List all teams (admin)", auth="view-all-teams"),
    e("teams.create", "POST", "role_required", 0.9, "permissionsRequired: ['create-team'] 전역 권한. 기존 방을 팀으로 전환하면 create-team AND edit-room(방 범위)까지 요구한다.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['create-team'],"), (None, "if (room?.id && !(await hasAllPermissionAsync(this.user, ['create-team', 'edit-room'], room.id))) {")],
      b=["name", "type", "members", "room", "owner"], summary="Create a team", auth="create-team (+ edit-room when converting a room)"),
    e("teams.info", "GET", "manual_review_required", 0.65, "canAccessRoomAsync(팀 메인 방) OR view-all-teams. 메인 방이 공개 채널(c)인 공개 팀은 view-c-room 권한만으로 통과하고, 비공개 팀은 구독 행이 필요해 팀 유형에 따라 조건이 달라진다(가시성 분기). 비공개 팀 기준이면 membership_required 대안.", ["CAR_JOINED", "CAR_PUBLIC", "CAR_PUBLIC2"],
      [(None, "const canViewInfo = (await canAccessRoomAsync(room, { _id: this.userId })) || (await hasPermissionAsync(this.user, 'view-all-teams'));")],
      q=["teamId", "teamName"], summary="Get team info", auth="canAccessRoom(팀 메인 방; 공개/비공개 분기) OR view-all-teams"),
    e("teams.members", "GET", "membership_required", 0.8, "Team.members가 TeamMember.findOneByUserIdAndTeamId(요청자, 팀)로 구성원 행을 요구하고, view-all-teams(팀 방 범위) 보유 시 우회한다. 구성원 OR 관리자 우회이므로 membership_required.", ["T_MEMBERS"],
      [(None, "const canSeeAllMembers = await hasPermissionAsync(this.user, 'view-all-teams', team.roomId);"), ("apps/meteor/server/services/team/service.ts", "const isMember = await TeamMember.findOneByUserIdAndTeamId(uid, teamId);"), ("apps/meteor/server/services/team/service.ts", "if (!isMember && !canSeeAll) {")],
      q=["teamId", "teamName", "offset", "count", "status", "username", "name"], summary="List team members", auth="TeamMember 행 OR view-all-teams"),
    e("teams.listRooms", "GET", "manual_review_required", 0.65, "Team.listRooms는 비공개 팀일 때만 TeamMember 행 OR view-all-teams를 요구하고 공개 팀은 누구나 조회한다. 팀 유형(공개/비공개)에 따른 가시성 분기라 보류; 비공개 팀 기준이면 membership_required 대안.", ["T_LISTROOMS"],
      [(None, "const allowPrivateTeam: boolean = await hasPermissionAsync(this.user, 'view-all-teams', team.roomId);"), ("apps/meteor/server/services/team/service.ts", "if (team.type === TeamType.PRIVATE && !allowPrivateTeam && !isMember) {")],
      q=["teamId", "teamName", "filter", "type", "offset", "count"], summary="List rooms of a team", auth="비공개 팀: TeamMember OR view-all-teams; 공개 팀: 제한 없음"),
    e("teams.listRoomsOfUser", "GET", "manual_review_required", 0.65, "본인(userId === this.userId) OR view-all-team-channels(팀 방 범위)에 더해, 비공개 팀이면 TeamMember OR view-all-teams가 추가로 필요하다. 소유자/관리자 분기와 팀 가시성 분기가 결합돼 보류; 공개 팀 기준이면 owner_or_admin 대안.", ["T_LISTROOMSUSER"],
      [(None, "if (!(this.userId === userId || (await hasPermissionAsync(this.user, 'view-all-team-channels', team.roomId)))) {"), ("apps/meteor/server/services/team/service.ts", "if (team.type === TeamType.PRIVATE && !allowPrivateTeam && !isMember) {")],
      q=["teamId", "teamName", "userId", "canUserDelete", "offset", "count"], summary="List team rooms of a user", auth="본인 OR view-all-team-channels, 비공개 팀이면 구성원 OR view-all-teams"),
    e("teams.listChildren", "GET", "membership_required", 0.85, "Team.listChildren이 TeamMember.findOneByUserIdAndTeamId(요청자, 팀) 행이 없으면 error-invalid-team-not-a-member로 거부한다. 우회 권한 없음.", ["T_CHILDREN"],
      [(None, "const result = await Team.listChildren(this.userId, team, filter, type, sort, offset, count);"), ("apps/meteor/server/services/team/service.ts", "throw new Error('error-invalid-team-not-a-member');")],
      q=["teamId", "teamName", "roomId", "filter", "type", "offset", "count"], summary="List child rooms of a team", auth="TeamMember 행 필수"),
    e("teams.leave", "POST", "membership_required", 0.6, "Team.removeMembers가 본인 userId에 대해 TeamMember 행 또는 메인 방 구독이 없으면 member-does-not-exist로 거부한다. 요청 대상 팀의 구성원 관계가 조건이므로 membership_required; 처리 대상이 본인으로 고정되므로 owner_match 대안.", ["T_REMOVE"],
      [(None, "await Team.removeMembers(this.userId, team._id, ["), ("apps/meteor/server/services/team/service.ts", "if (!existingMember && !subscription) {")],
      b=["teamId", "teamName", "rooms"], summary="Leave a team", auth="본인 TeamMember 행 필요"),
    e("teams.addMembers", "POST", "role_required", 0.9, "hasAtLeastOnePermissionAsync(['add-team-member','edit-team-member'], team.roomId) 팀 방 범위 권한이 유일한 조건.", [],
      [(None, "if (!(await hasAtLeastOnePermissionAsync(this.user, ['add-team-member', 'edit-team-member'], team.roomId))) {")],
      b=["teamId", "teamName", "members"], summary="Add members to a team", auth="add-team-member/edit-team-member(팀 방 범위)"),
    e("teams.removeMember", "POST", "role_required", 0.9, "hasAtLeastOnePermissionAsync(['edit-team-member'], team.roomId) 팀 방 범위 권한이 유일한 조건.", [],
      [(None, "if (!(await hasAtLeastOnePermissionAsync(this.user, ['edit-team-member'], team.roomId))) {")],
      b=["teamId", "teamName", "userId", "rooms"], summary="Remove a member from a team", auth="edit-team-member(팀 방 범위)"),
    e("teams.update", "POST", "role_required", 0.9, "hasPermissionAsync('edit-team', team.roomId) 팀 방 범위 권한이 유일한 조건.", [],
      [(None, "if (!(await hasPermissionAsync(this.user, 'edit-team', team.roomId))) {")],
      b=["teamId", "teamName", "data"], summary="Update a team", auth="edit-team(팀 방 범위)"),
    e("teams.delete", "POST", "role_required", 0.9, "hasPermissionAsync('delete-team', team.roomId) 팀 방 범위 권한이 유일한 조건.", [],
      [(None, "if (!(await hasPermissionAsync(this.user, 'delete-team', team.roomId))) {")],
      b=["teamId", "teamName", "roomsToRemove"], summary="Delete a team", auth="delete-team(팀 방 범위)"),
    # ---------------- users ----------------
    e("users.setAvatar", "POST", "owner_or_admin", 0.75, "isUserFromParams면 본인, 아니면 edit-other-user-avatar 권한 보유 시 타인 대상 허용(폼 데이터 경로도 같은 권한 검사). " + OOA.format(p="edit-other-user-avatar") + " 단, 설정 Accounts_AllowUserAvatarChange가 꺼지면 본인도 권한이 필요해 설정 의존이 섞인다.", ["ISUFP"],
      [(None, "const canEditOtherUserAvatar = await hasPermissionAsync(this.user, 'edit-other-user-avatar');"), (None, "if (isUserFromParams(this.bodyParams, this.userId, this.user)) {"), (None, "if (isAnotherUser && !(await hasPermissionAsync(this.user, 'edit-other-user-avatar'))) {")],
      b=["avatarUrl", "userId", "username", "user", "image"], summary="Set avatar of self or another user", auth="본인 OR edit-other-user-avatar"),
    e("users.resetAvatar", "POST", "owner_or_admin", 0.75, "본인(user._id === this.userId, 설정 허용 시) OR edit-other-user-avatar/manage-moderation-actions 권한. " + OOA.format(p="edit-other-user-avatar"), ["GUFP"],
      [(None, "if (settings.get('Accounts_AllowUserAvatarChange') && user._id === this.userId) {"), (None, "(await hasPermissionAsync(this.user, 'edit-other-user-avatar')) ||")],
      b=["userId", "username", "user"], summary="Reset avatar of self or another user", auth="본인 OR edit-other-user-avatar/manage-moderation-actions"),
    e("users.setPreferences", "POST", "owner_or_admin", 0.85, OOA.format(p="edit-other-user-info"), [],
      [(None, "this.bodyParams.userId !== this.userId &&"), (None, "!(await hasPermissionAsync(this.user, 'edit-other-user-info'))")],
      b=["userId", "data"], summary="Set preferences of self or another user", auth="본인 OR edit-other-user-info"),
    e("users.setStatus", "POST", "owner_or_admin", 0.8, "isUserFromParams면 본인, 아니면 edit-other-user-info 권한 보유 시 타인 대상. " + OOA.format(p="edit-other-user-info") + " message 변경은 설정에 추가로 의존.", ["ISUFP"],
      [(None, "if (isUserFromParams(this.bodyParams, this.userId, this.user)) {"), (None, "if (await hasPermissionAsync(this.user, 'edit-other-user-info')) {")],
      b=["status", "message", "expiresAt", "userId", "username", "user"], summary="Set status of self or another user", auth="본인 OR edit-other-user-info"),
    e("users.logout", "POST", "owner_or_admin", 0.9, OOA.format(p="logout-other-user"), [],
      [(None, "if (userId !== this.userId && !(await hasPermissionAsync(this.user, 'logout-other-user'))) {")],
      b=["userId"], summary="Log out self or another user", auth="본인 OR logout-other-user"),
    e("users.resetE2EKey", "POST", "owner_or_admin", 0.85, "대상 사용자 파라미터가 있으면 edit-other-user-e2ee 권한 필요, 없으면 본인 키 리셋. " + OOA.format(p="edit-other-user-e2ee"), ["GUFP"],
      [(None, "if (!(await hasPermissionAsync(this.user, 'edit-other-user-e2ee'))) {"), (None, "await resetUserE2EEncriptionKey(this.userId, false);")],
      b=["userId", "username", "user"], summary="Reset E2E key of self or another user", auth="본인 OR edit-other-user-e2ee"),
    e("users.resetTOTP", "POST", "owner_or_admin", 0.85, "대상 사용자 파라미터가 있으면 edit-other-user-totp 권한 필요, 없으면 본인 TOTP 리셋. " + OOA.format(p="edit-other-user-totp"), ["GUFP"],
      [(None, "if (!(await hasPermissionAsync(this.user, 'edit-other-user-totp'))) {"), (None, "await resetTOTP(this.userId, false);")],
      b=["userId", "username", "user"], summary="Reset TOTP of self or another user", auth="본인 OR edit-other-user-totp"),
    e("users.createToken", "POST", "manual_review_required", 0.6, "generateAccessToken이 환경변수 비밀값 일치 AND (본인 OR user-generate-access-token 권한)을 요구한다. 서버 비밀값이라는 독립 조건이 AND로 결합돼 보류; 비밀값을 배포 설정으로 보면 owner_or_admin 대안.", ["GUFP", "GENTOKEN"],
      [(None, "const data = await generateAccessToken(user._id, this.bodyParams.secret, this.user);"), (MM + "auth/createToken.ts", "if (secret !== CREATE_TOKENS_FOR_USERS_SECRET) {"), (MM + "auth/createToken.ts", "if (caller._id !== userId && !(await Authorization.hasPermission(caller, 'user-generate-access-token'))) {")],
      b=["userId", "secret"], summary="Create a login token for a user", auth="서버 비밀값 AND (본인 OR user-generate-access-token)"),
    e("users.listTeams", "GET", "manual_review_required", 0.6, "view-all-teams 보유자는 대상 사용자의 모든 팀, 아니면 요청자 본인도 가입한 팀으로만 필터(Team.findBySubscribedUserIds(userId, adminId))한다. 관리자 우회 OR 공통 구성원 필터라는 혼합 조건이라 보류.", [],
      [(None, "const adminId = (await hasPermissionAsync(this.user, 'view-all-teams')) ? undefined : this.userId;"), (None, "const teams = await Team.findBySubscribedUserIds(userId, adminId);")],
      q=["userId"], summary="List teams of a user", auth="view-all-teams면 전체, 아니면 요청자와 공통 팀만"),
    e("users.info", "GET", "manual_review_required", 0.7, "기본 사용자 정보는 인증 사용자 누구나 조회(getFullUserDataByUniqueSearchTerm 내부 필드 제한). includeUserRooms는 본인 OR view-other-user-channels. 필드별로 정책이 달라 보류; 방 목록 부분만 보면 owner_or_admin.", [],
      [(None, "const myself = user._id === this.userId;"), (None, "if (this.queryParams.includeUserRooms === 'true' && (myself || (await hasPermissionAsync(this.user, 'view-other-user-channels')))) {")],
      q=["userId", "username", "importId", "email", "includeUserRooms", "fields"], summary="Get user info", auth="인증 사용자 조회; rooms 필드는 본인 OR view-other-user-channels"),
    e("users.update", "POST", "manual_review_required", 0.7, "validateUserData가 타인 편집에 edit-other-user-info를 요구하고(본인 OR 권한), validateUserEditing은 필드별(username·name·email·password·roles·status)로 설정 Accounts_AllowUserProfileChange와 edit-other-user-info/edit-other-user-password/assign-roles를 달리 요구한다. 필드·설정 의존 복합 조건이라 보류; 기본 구조만 보면 owner_or_admin 대안.", ["VALDATA", "VALEDIT"],
      [(None, "await saveUser(this.userId, userData, { auditStore });"), (SL + "users/saveUser/validateUserData.ts", "if (isUpdateUserData(userData) && userId !== userData._id && !(await hasPermissionAsync(userId, 'edit-other-user-info'))) {"),
       (SL + "users/saveUser/validateUserEditing.ts", "const editingMyself = userData._id && userId === userData._id;")],
      b=["userId", "data", "confirmRelinquish"], summary="Update a user", auth="본인 OR edit-other-user-info, 필드별 추가 권한·설정"),
    e("users.create", "POST", "role_required", 0.85, "saveUser→validateUserData가 신규 사용자 생성에 전역 권한 create-user를 요구한다.", ["VALDATA"],
      [(None, "const newUserId = await saveUser(this.userId, this.bodyParams);"), (SL + "users/saveUser/validateUserData.ts", "if (!isUpdateUserData(userData) && !(await hasPermissionAsync(userId, 'create-user'))) {")],
      b=["email", "name", "password", "username", "roles", "active", "joinDefaultChannels", "customFields"], summary="Create a user", auth="create-user"),
    e("users.delete", "POST", "role_required", 0.9, "permissionsRequired: ['delete-user'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['delete-user'],")],
      b=["userId", "username", "user", "confirmRelinquish"], summary="Delete a user", auth="delete-user"),
    e("users.setActiveStatus", "POST", "role_required", 0.9, "permissionsRequired hasAny ['edit-other-user-active-status','manage-moderation-actions'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "POST: { permissions: ['edit-other-user-active-status', 'manage-moderation-actions'], operation: 'hasAny' },")],
      b=["userId", "activeStatus", "confirmRelinquish"], summary="Activate or deactivate a user", auth="edit-other-user-active-status 또는 manage-moderation-actions"),
    e("users.deactivateIdle", "POST", "role_required", 0.9, "permissionsRequired: ['edit-other-user-active-status'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['edit-other-user-active-status'],")],
      b=["daysIdle", "role"], summary="Deactivate idle users", auth="edit-other-user-active-status"),
    e("users.list", "GET", "role_required", 0.75, "permissionsRequired: ['view-d-room'] 전역 권한. 설정 API_Apply_permission_view-outside-room_on_users-list가 켜지면 view-outside-room도 요구하고, email 검색은 view-full-other-user-info가 필요하다. 모두 역할 권한이므로 role_required; 설정 의존을 중시하면 보류 대안.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['view-d-room'],"), (None, "!(await hasPermissionAsync(this.user, 'view-outside-room'))")],
      q=["offset", "count", "sort", "fields", "query", "email"], summary="List users", auth="view-d-room (+ view-outside-room 설정, view-full-other-user-info)"),
    e("users.register", "POST", "public", 0.65, "authRequired: false로 익명 요청을 받으며 로그인 사용자는 거부한다. 익명 가입이 명시된 공개 엔드포인트. 단, registerUser 내부의 가입 허용 설정(Accounts_RegistrationForm)에 의존하므로 설정 의존을 중시하면 보류 대안.", [],
      [(None, "authRequired: false,"), (None, "return API.v1.failure('Logged in users can not register again.');")],
      b=["username", "email", "pass", "name", "secret", "customFields"], summary="Register a new user", auth="익명 허용(authRequired: false), 설정 의존"),
    e("users.forgotPassword", "POST", "public", 0.7, "authRequired: false로 익명 허용. 설정 Accounts_PasswordReset이 꺼지면 실패하지만 접근 조건은 익명 허용이 명시적이다.", [],
      [(None, "authRequired: false,"), (None, "const isPasswordResetEnabled = settings.get('Accounts_PasswordReset');")],
      b=["email"], summary="Request password reset email", auth="익명 허용(authRequired: false)"),
    e("users.updateOwnBasicInfo", "POST", "owner_match", 0.9, "executeSaveUserProfile(this.user, ...)로 처리 대상이 인증 사용자 본인으로 고정된다.", [],
      [(None, "await executeSaveUserProfile.call(this, this.user, userData, this.bodyParams.customFields, twoFactorOptions);")],
      b=["data", "customFields"], summary="Update own profile", auth="본인 고정"),
    e("users.deleteOwnAccount", "POST", "owner_match", 0.85, "deleteUserOwnAccount(this.userId, password)로 본인 계정만 삭제한다. 설정 Accounts_AllowDeleteOwnAccount에 의존.", [],
      [(None, "await deleteUserOwnAccount(this.userId, this.bodyParams.password, confirmRelinquish);"), (None, "if (!settings.get('Accounts_AllowDeleteOwnAccount')) {")],
      b=["password", "confirmRelinquish"], summary="Delete own account", auth="본인 고정(설정 의존)"),
    e("users.getPreferences", "GET", "owner_match", 0.9, "Users.findOneById(this.userId)로 본인 설정만 반환한다.", [],
      [(None, "const user = await Users.findOneById(this.userId);")],
      summary="Get own preferences", auth="본인 고정"),
    e("users.generatePersonalAccessToken", "POST", "owner_match", 0.8, "generatePersonalAccessTokenOfUser({userId: this.userId})로 본인 토큰만 생성한다(2FA 필요). 내부에서 create-personal-access-tokens 기능 권한을 검사하더라도 기능 권한으로 본다.", [],
      [(None, "const token = await generatePersonalAccessTokenOfUser({ tokenName, userId: this.userId, bypassTwoFactor });")],
      b=["tokenName", "bypassTwoFactor"], summary="Generate own personal access token", auth="본인 고정"),
    e("users.getPersonalAccessTokens", "GET", "owner_match", 0.6, "Users.getLoginTokensByUserId(this.userId)로 본인 토큰만 반환하지만 permissionsRequired: ['create-personal-access-tokens']가 추가로 걸린다. 본인 고정 + 기능 권한이므로 owner_match 초안; 권한을 독립 조건으로 보면 role_required 또는 보류 대안.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['create-personal-access-tokens'],"), (None, "const user = (await Users.getLoginTokensByUserId(this.userId).toArray())[0] as unknown as IUser | undefined;")],
      summary="List own personal access tokens", auth="본인 고정 + create-personal-access-tokens"),
    e("users.removePersonalAccessToken", "POST", "owner_match", 0.85, "removePersonalAccessTokenOfUser(tokenName, this.userId)로 본인 토큰만 제거한다.", [],
      [(None, "await removePersonalAccessTokenOfUser(this.bodyParams.tokenName, this.userId);")],
      b=["tokenName"], summary="Remove own personal access token", auth="본인 고정"),
    e("users.2fa.enableEmail", "POST", "owner_match", 0.9, "Users.enableEmail2FAByUserId(this.userId)로 본인 2FA만 켠다.", [],
      [(None, "await Users.enableEmail2FAByUserId(this.userId);")],
      summary="Enable email 2FA for self", auth="본인 고정"),
    e("users.requestDataDownload", "GET", "owner_match", 0.85, "requestDataDownload({userData: this.user})로 본인 데이터 내보내기만 요청한다.", [],
      [(None, "const result = await requestDataDownload({ userData: this.user, fullExport: fullExport === 'true' });")],
      q=["fullExport"], summary="Request own data export", auth="본인 고정"),
    e("users.logoutOtherClients", "POST", "owner_match", 0.9, "Users.removeNonPATLoginTokensExcept(this.userId, hashedToken)로 본인 토큰만 정리한다.", [],
      [(None, "if (!(await Users.removeNonPATLoginTokensExcept(this.userId, hashedToken))) {")],
      summary="Log out own other clients", auth="본인 고정"),
    e("users.removeOtherTokens", "POST", "owner_match", 0.9, "Users.removeNonLoginTokensExcept(this.userId, this.token)로 본인 토큰만 제거한다.", ["AUTHMW"],
      [(None, "await Users.removeNonLoginTokensExcept(this.userId, this.token);")],
      summary="Remove own other tokens", auth="본인 고정"),
    e("users.enableTotp", "POST", "owner_match", 0.9, "enableTotp(this.userId)로 본인 TOTP만 설정한다.", [],
      [(None, "return API.v1.success(await enableTotp(this.userId));")],
      summary="Enable TOTP for self", auth="본인 고정"),
    e("users.getPresence", "GET", "manual_review_required", 0.65, "본인이면 상세, 타인이면 숨김 설정만 적용한 presence를 인증 사용자 누구에게나 반환한다. 요청자-대상 관계나 역할 검사가 없어 인증만 확인하는 경우로 보류.", ["ISUFP", "GUFP"],
      [(None, "if (isUserFromParams(this.queryParams, this.userId, this.user)) {"), (None, "const user = await getUserFromParams(this.queryParams);")],
      q=["userId", "username", "user"], summary="Get presence of a user", auth="인증만(타인 presence 열람 제한 없음)"),
    e("users.getStatus", "GET", "manual_review_required", 0.65, "본인이면 상세, 타인이면 숨김 설정만 적용한 status를 인증 사용자 누구에게나 반환한다. 요청자-대상 관계나 역할 검사가 없어 보류.", ["ISUFP", "GUFP"],
      [(None, "if (isUserFromParams(this.queryParams, this.userId, this.user)) {"), (None, "const user = await getUserFromParams(this.queryParams);")],
      q=["userId", "username", "user"], summary="Get status of a user", auth="인증만(타인 status 열람 제한 없음)"),
    e("users.checkUsernameAvailability", "GET", "manual_review_required", 0.7, "authRequired만 있고 대상 객체·역할 검사가 없다(인증만 확인).", [],
      [(None, "authRequired: true,"), (None, "const result = await checkUsernameAvailabilityWithValidation(this.userId, username);")],
      q=["username"], summary="Check username availability", auth="인증만"),
    # ---------------- rooms ----------------
    e("rooms.leave", "POST", "membership_required", 0.7, "leaveRoomMethod가 Subscriptions.findOneByRoomIdAndUserId로 요청자 본인 구독을 요구하고(없으면 error-user-not-in-room) 방 유형별 leave-c/leave-p 권한도 검사한다. 구성원 관계가 핵심.", ["FRM", "LEAVE"],
      [(None, "await leaveRoomMethod(user, room._id);"), (MM + "rooms/leaveRoom.ts", "throw new Meteor.Error('error-user-not-in-room', 'You are not in this room', {")],
      b=["roomId", "roomName"], summary="Leave a room", auth="leaveRoomMethod → 본인 구독 + leave-c/leave-p"),
    e("rooms.favorite", "POST", "owner_match", 0.8, "toggleFavoriteMethod가 요청자 본인 구독(Subscriptions.findOneByRoomIdAndUserId(rid, userId))의 favorite 플래그만 바꾼다. 본인 구독 플래그이므로 owner_match; 방 구성원 조건으로 보면 membership_required 대안.", ["FRM", "FAV"],
      [(None, "await toggleFavoriteMethod(this.userId, room._id, favorite);"), (MM + "rooms/toggleFavorite.ts", "throw new Meteor.Error('error-invalid-subscription', 'You must be part of a room to favorite it', { method: 'toggleFavorite' });")],
      b=["roomId", "roomName", "favorite"], summary="Favorite or unfavorite a room", auth="본인 구독 플래그"),
    e("rooms.saveNotification", "POST", "owner_match", 0.8, "saveNotificationSettingsMethod가 요청자 본인 구독이 없으면 error-invalid-subscription으로 거부하고 본인 알림 설정만 갱신한다.", ["NOTIF"],
      [(None, "saveNotificationSettingsMethod(this.userId, roomId, notificationKey as NotificationFieldType, notificationValue),"), (MM + "users/saveNotificationSettings.ts", "const subscription = await Subscriptions.findOneByRoomIdAndUserId(roomId, userId);")],
      b=["roomId", "notifications"], summary="Save own notification settings for a room", auth="본인 구독 설정"),
    e("rooms.saveDraft", "POST", "owner_match", 0.8, "Subscriptions.updateDraftByRoomIdAndUserId(rid, this.userId)로 본인 구독의 초안만 저장한다(없으면 error-invalid-subscription).", [],
      [(None, "const subscription = await Subscriptions.updateDraftByRoomIdAndUserId(rid, this.userId, draft || undefined, tmid);")],
      b=["rid", "draft", "tmid"], summary="Save own draft for a room", auth="본인 구독 초안"),
    e("rooms.open", "POST", "owner_match", 0.8, "openRoom이 Subscriptions.openByRoomIdAndUserId(roomId, userId)로 본인 구독만 연다. 다른 검사 없음.", ["OPEN"],
      [(None, "await openRoom(this.userId, roomId);"), (SL + "openRoom.ts", "const openByRoomResponse = await Subscriptions.openByRoomIdAndUserId(roomId, userId);")],
      b=["roomId"], summary="Open a room for the caller", auth="본인 구독 open"),
    e("rooms.info", "GET", "manual_review_required", 0.75, CAR_ANY, ["FRM", "CAR_JOINED", "CAR_PUBLIC", "CAR_PUBLIC2"],
      [(None, "if (!room || !(await canAccessRoomAsync(room, { _id: this.userId }))) {")],
      q=["roomId", "roomName", "fields"], summary="Get room info (any type)", auth="canAccessRoom(방 유형별 분기)"),
    e("rooms.isMember", "GET", "manual_review_required", 0.7, CAR_ANY, ["FRM", "CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "if (await canAccessRoomAsync(room, { _id: this.user._id })) {")],
      q=["roomId", "userId", "username"], summary="Check whether a user is member of a room", auth="canAccessRoom(방 유형별 분기)"),
    e("rooms.hide", "POST", "manual_review_required", 0.6, "canAccessRoomIdAsync(방 유형별 분기) 통과 후 본인 구독을 숨긴다. 공개 채널은 구독 없이도 통과하므로 접근 조건이 방 유형에 따라 달라 보류; 본인 구독 처리로 보면 owner_match 대안.", ["CAR_JOINED", "CAR_PUBLIC2", "HIDE"],
      [(None, "if (!(await canAccessRoomIdAsync(roomId, this.userId))) {"), (None, "const modCount = await hideRoomMethod(this.userId, roomId);")],
      b=["roomId"], summary="Hide a room for the caller", auth="canAccessRoomId + 본인 구독 hide"),
    e("rooms.delete", "POST", "role_required", 0.85, "eraseRoom이 canBeDeleted→hasPermission(`delete-${room.t}`, rid) 방 범위 권한을 요구하고 팀 방이면 delete-team-channel/group도 요구한다.", ["ERASE", "CANBEDEL"],
      [(None, "await eraseRoom(room, this.user);"), (SL + "rooms/roomCoordinator.ts", "return hasPermission(`delete-${room.t}`, room._id);")],
      b=["roomId"], summary="Delete a room", auth="delete-c/delete-p(방 범위)"),
    e("rooms.bannedUsers", "GET", "manual_review_required", 0.7, CAR_ANY, ["CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "if (!(await canAccessRoomIdAsync(roomId, this.userId))) {")],
      q=["roomId", "offset", "count"], summary="List banned users of a room", auth="canAccessRoomId(방 유형별 분기)"),
    e("rooms.history", "GET", "manual_review_required", 0.8, "authOrAnonRequired로 익명(설정 Accounts_AllowAnonymousRead) 허용, canAccessRoomAsync 방 유형별 분기, 공개 채널은 preview-c-room 권한 OR 구독까지 요구한다. 익명·설정·유형 분기가 결합돼 보류.", ["CAR_JOINED", "CAR_PUBLIC", "CAR_PUBLIC2"],
      [(None, "authOrAnonRequired: true,"), (None, "if (!(await canAccessRoomAsync(room, this.user))) {"), (None, "!(await hasPermissionAsync(this.userId, 'preview-c-room')) &&")],
      q=["roomId", "next", "previous", "aroundId", "lastSeen", "count", "showThreadMessages"], summary="Room history (any type, anonymous allowed by setting)", auth="authOrAnon + canAccessRoom + preview-c-room/구독"),
    e("rooms.roles", "GET", "manual_review_required", 0.7, "executeGetRoomRoles가 canAccessRoomAsync로 검사한다. " + CAR_ANY, ["ROLES", "CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "const roles = await executeGetRoomRoles(rid, this.user);"), (MM + "rooms/getRoomRoles.ts", "if (fromUser && !(await canAccessRoomAsync(room, fromUser)))")],
      q=["rid"], summary="Room roles (any type)", auth="canAccessRoom(방 유형별 분기)"),
    e("rooms.muteUser", "POST", "role_required", 0.9, "muteUserInRoom이 " + ROOMPERM.format(p="mute-user"), ["GUFP", "MUTE"],
      [(None, "await muteUserInRoom(this.userId, { rid: this.bodyParams.roomId, username: user.username });"), (MM + "rooms/muteUserInRoom.ts", "if (!fromId || !(await hasPermissionAsync(fromId, 'mute-user', data.rid))) {")],
      b=["roomId", "userId", "username"], summary="Mute a user in a room", auth="mute-user(방 범위)"),
    e("rooms.banUser", "POST", "role_required", 0.8, "banUserFromRoomMethod가 ban-user(방 범위) 권한을 먼저 요구하고 canAccessRoomAsync도 검사한다. 권한이 결정 조건이라 role_required.", ["GUFP", "BAN"],
      [(None, "await banUserFromRoomMethod(this.userId, { rid: this.bodyParams.roomId, username: user.username });"), (SL + "banUserFromRoom.ts", "if (!(await hasPermissionAsync(fromId, 'ban-user', data.rid))) {")],
      b=["roomId", "userId", "username"], summary="Ban a user from a room", auth="ban-user(방 범위) + canAccessRoom"),
    e("rooms.cleanHistory", "POST", "role_required", 0.75, "canAccessRoomAsync 통과 후 cleanRoomHistoryMethod가 clean-channel-history(방 범위) 권한을 요구한다. 권한이 결정 조건이라 role_required; 접근 AND 권한 결합으로 보면 보류 대안.", ["FRM", "CLEAN"],
      [(None, "if (!room || !(await canAccessRoomAsync(room, { _id: this.userId }))) {"), (MM + "rooms/cleanRoomHistory.ts", "if (!(await hasPermissionAsync(userId, 'clean-channel-history', roomId))) {")],
      b=["roomId", "roomName", "latest", "oldest", "inclusive", "limit", "excludePinned", "filesOnly", "users"], summary="Clean room history", auth="canAccessRoom + clean-channel-history(방 범위)"),
    e("rooms.adminRooms", "GET", "role_required", 0.9, "findAdminRooms가 view-room-administration 전역 권한을 요구한다.", [],
      [("apps/meteor/server/api/lib/rooms.ts", "if (!(await hasPermissionAsync(uid, 'view-room-administration'))) {")],
      q=["filter", "types", "offset", "count", "sort"], summary="List rooms for administration", auth="view-room-administration"),
    e("rooms.adminRooms.getRoom", "GET", "role_required", 0.9, "findAdminRoom이 view-room-administration 전역 권한을 요구한다.", [],
      [("apps/meteor/server/api/lib/rooms.ts", "if (!(await hasPermissionAsync(uid, 'view-room-administration'))) {")],
      q=["rid"], summary="Get a room for administration", auth="view-room-administration"),
    e("rooms.createDiscussion", "POST", "role_required", 0.55, "createDiscussion이 상위 방(prid) 범위 권한 start-discussion 또는 start-discussion-other-user를 요구한다(설정 Discussion_enabled 의존). start-discussion은 기본적으로 user 역할에 부여된 기능 권한이라 실질 조건이 약하다. 발췌 범위 밖의 상위 방 접근 검사를 확인하지 못해 보류 대안.", ["DISC"],
      [(MM + "messages/createDiscussion.ts", "if (!(await hasAtLeastOnePermissionAsync(userId, ['start-discussion', 'start-discussion-other-user'], prid))) {")],
      b=["prid", "pmid", "t_name", "reply", "users", "encrypted", "topic"], summary="Create a discussion", auth="start-discussion(상위 방 범위)"),
    e("rooms.membersOrderedByRole", "GET", "manual_review_required", 0.7, CAR_ANY + " broadcast 방은 view-broadcast-member-list도 필요.", ["FRM", "CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "if (!(await canAccessRoomAsync(findResult, this.user))) {"), (None, "if (findResult.broadcast && !(await hasPermissionAsync(this.user, 'view-broadcast-member-list', findResult._id))) {")],
      q=["roomId", "roomName", "offset", "count", "status", "filter", "sort"], summary="List room members ordered by role", auth="canAccessRoom(방 유형별 분기) + broadcast 권한"),
    e("rooms.nameExists", "GET", "manual_review_required", 0.75, "authRequired만 있고 대상 방에 대한 접근·역할 검사 없이 존재 여부를 반환한다(인증만 확인).", [],
      [(None, "authRequired: true,"), (None, "const room = await Rooms.findOneByName(roomName, { projection: { _id: 1 } });")],
      q=["roomName"], summary="Check whether a room name exists", auth="인증만"),
    # ---------------- subscriptions ----------------
    e("subscriptions.get", "GET", "owner_match", 0.85, "getSubscriptions(this.userId, ...)로 요청자 본인 구독만 반환한다.", [],
      [(None, "const result = await getSubscriptions(this.userId, updatedSinceDate);")],
      q=["updatedSince"], summary="List own subscriptions", auth="본인 구독"),
    e("subscriptions.getOne", "GET", "owner_match", 0.9, "Subscriptions.findOneByRoomIdAndUserId(roomId, this.userId)로 본인 구독만 반환한다.", [],
      [(None, "subscription: await Subscriptions.findOneByRoomIdAndUserId(roomId, this.userId),")],
      q=["roomId"], summary="Get own subscription of a room", auth="본인 구독"),
    e("subscriptions.read", "POST", "owner_match", 0.85, "readMessages가 본인 구독(Subscriptions.findOneByRoomIdAndUserId(room._id, uid))이 없으면 error-invalid-subscription으로 거부하고 본인 읽음 상태만 갱신한다.", ["READ"],
      [(None, "await readMessages(room, this.userId, readThreads);"), (SL + "readMessages.ts", "const sub = await Subscriptions.findOneByRoomIdAndUserId(room._id, uid, { projection });")],
      b=["rid", "roomId", "readThreads"], summary="Mark own subscription as read", auth="본인 구독"),
    e("subscriptions.unread", "POST", "owner_match", 0.8, "unreadMessages가 본인 구독(Subscriptions.findOneByRoomIdAndUserId / setAsUnreadByRoomIdAndUserId)만 갱신한다.", ["UNREAD"],
      [(None, "await unreadMessages("), (SL + "messaging/unread/unreadMessages.ts", "const lastSeen = (await Subscriptions.findOneByRoomIdAndUserId(originalMessage.rid, userId))?.ls;")],
      b=["firstUnreadMessage", "roomId"], summary="Mark own subscription as unread", auth="본인 구독"),
    # ---------------- chat ----------------
    e("chat.getMessage", "GET", "manual_review_required", 0.75, "getSingleMessage이 메시지 방에 대해 canAccessRoomIdAsync를 검사한다. " + CAR_ANY, ["GETMSG", "CAR_JOINED", "CAR_PUBLIC2"],
      [(MM + "messages/getSingleMessage.ts", "if (!(await canAccessRoomIdAsync(msg.rid, userId))) {")],
      q=["msgId"], summary="Get a single message", auth="canAccessRoomId(방 유형별 분기)"),
    e("chat.delete", "POST", "manual_review_required", 0.85, "canDeleteMessageAsync: canAccessRoom AND (force-delete-message OR delete-message OR (작성자 본인 AND delete-own-message)) AND 설정 Message_AllowDeleting AND 시간 제한(bypass-time-limit-edit-and-delete) AND 읽기전용 방 post-readonly. asUser는 force-delete-message 추가. 독립 조건이 다층으로 결합돼 보류.", ["DELVAL", "CANDEL"],
      [(None, "if (this.bodyParams.asUser && msg.u._id !== this.userId && !(await hasPermissionAsync(this.user, 'force-delete-message', msg.rid))) {"),
       (SL + "authorization/canDeleteMessage.ts", "allowedToDeleteAny || (deletingUser._id === u._id && (await hasPermissionAsync(deletingUser._id, 'delete-own-message', rid)));")],
      b=["msgId", "fileId", "roomId", "asUser"], summary="Delete a message", auth="canAccessRoom + 권한/소유자/설정/시간 복합"),
    e("chat.ignoreUser", "GET", "owner_match", 0.7, "ignoreUser가 요청자 본인 구독과 대상 사용자 구독이 같은 방에 있어야 하며 본인 구독의 ignored 목록만 바꾼다. 본인 구독 플래그이므로 owner_match; 방 구성원 관계로 보면 membership_required 대안.", ["IGNORE"],
      [(None, "await ignoreUser(this.userId, { rid, userId, ignore });"), (MM + "users/ignoreUser.ts", "Subscriptions.findOneByRoomIdAndUserId(rid, fromUserId),")],
      q=["rid", "userId", "ignore"], summary="Ignore or unignore a user in a room", auth="본인 구독 플래그"),
    e("chat.starMessage", "POST", "membership_required", 0.65, "starMessage가 요청자 본인 구독(Subscriptions.findOneByRoomIdAndUserId(message.rid, user._id))이 없으면 false, canAccessRoomAsync도 검사한다. 메시지가 속한 방의 구성원 관계가 조건이라 membership_required; 본인 별표 플래그로 보면 owner_match 대안. 설정 Message_AllowStarring 의존.", ["STAR"],
      [(None, "await starMessage(this.user, {"), (SL + "messaging/stars/starMessage.ts", "const subscription = await Subscriptions.findOneByRoomIdAndUserId(message.rid, user._id, {")],
      b=["messageId"], summary="Star a message", auth="본인 구독(방 구성원) + canAccessRoom"),
    e("chat.getPinnedMessages", "GET", "manual_review_required", 0.75, CAR_ANY, ["CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "if (!(await canAccessRoomIdAsync(roomId, this.userId))) {")],
      q=["roomId", "offset", "count"], summary="List pinned messages of a room", auth="canAccessRoomId(방 유형별 분기)"),
    e("chat.pinMessage", "POST", "role_required", 0.8, "pinMessage가 pin-message(방 범위) 권한을 요구하고 canAccessRoomAsync도 검사한다(설정 Message_AllowPinning 의존). 권한이 결정 조건.", ["PIN"],
      [(None, "const pinnedMessage = await pinMessage(msg, this.userId);"), (SL + "messaging/pins/pinMessage.ts", "if (!(await hasPermissionAsync(userId, 'pin-message', originalMessage.rid))) {")],
      b=["messageId", "pinnedAt"], summary="Pin a message", auth="pin-message(방 범위) + canAccessRoom"),
    e("chat.getMentionedMessages", "GET", "manual_review_required", 0.7, "findMentionedMessages가 canAccessRoomAsync로 검사한다. " + CAR_ANY, ["MENTIONED", "CAR_JOINED", "CAR_PUBLIC2"],
      [("apps/meteor/server/api/lib/messages.ts", "if (!room || !(await canAccessRoomAsync(room, { _id: uid }))) {")],
      q=["roomId", "offset", "count", "sort"], summary="List messages mentioning the caller in a room", auth="canAccessRoom(방 유형별 분기)"),
    e("chat.getStarredMessages", "GET", "manual_review_required", 0.7, "findStarredMessages가 canAccessRoomAsync로 검사한다. " + CAR_ANY, ["STARRED", "CAR_JOINED", "CAR_PUBLIC2"],
      [("apps/meteor/server/api/lib/messages.ts", "if (!room || !(await canAccessRoomAsync(room, { _id: uid }))) {")],
      q=["roomId", "offset", "count", "sort"], summary="List starred messages of the caller in a room", auth="canAccessRoom(방 유형별 분기)"),
    e("chat.react", "POST", "manual_review_required", 0.7, "executeSetReaction이 canAccessRoomAsync(방 유형별 분기)에 더해 뮤트·읽기전용(post-readonly) 조건을 결합한다.", ["REACT", "CAR_JOINED", "CAR_PUBLIC2"],
      [(None, "await executeSetReaction(this.userId, emoji, msg, this.bodyParams.shouldReact);"), (SL + "messaging/reactions/setReaction.ts", "if (!(await canAccessRoomAsync(room, user))) {")],
      b=["messageId", "emoji", "reaction", "shouldReact"], summary="React to a message", auth="canAccessRoom + 뮤트/읽기전용"),
    e("chat.getDeletedMessages", "GET", "manual_review_required", 0.8, "authRequired만 있고 roomId에 대한 접근·구독·역할 검사가 전혀 없다(인증만 확인). 보류.", [],
      [(None, "authRequired: true,"), (None, "const { cursor, totalCount } = Messages.trashFindPaginatedDeletedAfter(")],
      q=["roomId", "since", "offset", "count"], summary="List deleted message ids of a room", auth="인증만(방 접근 검사 없음)"),
    # ---------------- integrations ----------------
    e("integrations.get", "GET", "owner_or_admin", 0.6, "findOneIntegration→hasIntegrationsPermission: manage-{type}-integrations 권한이면 허용, 아니면 _createdBy._id === userId(소유자)이면서 manage-own-{type}-integrations 권한 필요. 소유자 OR 관리자 구조라 owner_or_admin 초안; 소유자 분기에도 기능 권한이 AND로 붙어 보류 대안.", ["FINDINT"],
      [("apps/meteor/server/api/lib/integrations.ts", "if (await hasPermissionAsync(userId, `manage-${type}-integrations`)) {"), ("apps/meteor/server/api/lib/integrations.ts", "if (userId === integration._createdBy?._id) {")],
      q=["integrationId", "createdBy"], summary="Get an integration", auth="manage-*-integrations OR (소유자 AND manage-own-*-integrations)"),
    e("integrations.update", "PUT", "owner_or_admin", 0.6, "updateOutgoing/IncomingIntegration: manage-*-integrations면 아무 통합, 아니면 manage-own-*-integrations 보유 시 '_createdBy._id': userId 조건으로만 조회한다. 소유자 OR 관리자 구조라 owner_or_admin 초안; 소유자 분기의 기능 권한 AND를 중시하면 보류 대안.", ["UPDOUT", "UPDIN"],
      [(MM + "integrations/outgoing/updateOutgoingIntegration.ts", "if (await hasPermissionAsync(userId, 'manage-outgoing-integrations')) {"), (MM + "integrations/outgoing/updateOutgoingIntegration.ts", "'_createdBy._id': userId,")],
      b=["type", "integrationId", "target_url", "name", "enabled", "channel", "username", "urls", "event"], summary="Update an integration", auth="manage-*-integrations OR (소유자 AND manage-own-*-integrations)"),
    e("integrations.remove", "POST", "owner_or_admin", 0.6, "permissionsRequired hasAny(manage-*/manage-own-*) 후 deleteOutgoing/IncomingIntegration이 manage-*면 아무 통합, manage-own-*면 createdBy: userId 조건으로만 삭제한다. 소유자 OR 관리자 구조라 owner_or_admin 초안; 소유자 분기의 기능 권한 AND를 중시하면 보류 대안.", ["DELOUT", "DELIN"],
      [(None, "operation: 'hasAny',"), (MM + "integrations/outgoing/deleteOutgoingIntegration.ts", "...(canManageOwnIntegrations && { createdBy: userId }),")],
      b=["type", "integrationId", "target_url"], summary="Remove an integration", auth="manage-*-integrations OR (소유자 AND manage-own-*-integrations)"),
    e("integrations.history", "GET", "owner_or_admin", 0.6, "permissionsRequired hasAny(manage-outgoing-integrations, manage-own-outgoing-integrations) 후 manage-own만 있으면 'integration._createdBy._id': userId로 본인 통합 이력만 조회한다. 소유자 OR 관리자 구조라 owner_or_admin 초안; 기능 권한 AND를 중시하면 보류 대안.", ["MOUNTH"],
      [(None, "GET: { permissions: ['manage-outgoing-integrations', 'manage-own-outgoing-integrations'], operation: 'hasAny' },"), (SL + "integrations/lib/mountQueriesBasedOnPermission.ts", "return { 'integration._id': integrationId, 'integration._createdBy._id': userId };")],
      q=["id", "offset", "count", "sort", "query"], summary="Integration history", auth="manage-outgoing-integrations OR (소유자 AND manage-own-outgoing-integrations)"),
    e("integrations.create", "POST", "role_required", 0.85, "addIncoming/OutgoingIntegration이 manage-*-integrations 또는 manage-own-*-integrations 권한이 없으면 거부한다. 생성은 소유자 개념이 없고 권한만 조건.", ["ADDIN", "ADDOUT"],
      [(MM + "integrations/outgoing/addOutgoingIntegration.ts", "(!(await hasPermissionAsync(userId, 'manage-outgoing-integrations')) &&"), (MM + "integrations/incoming/addIncomingIntegration.ts", "(!(await hasPermissionAsync(userId, 'manage-incoming-integrations')) &&")],
      b=["type", "name", "enabled", "username", "channel", "urls", "event", "scriptEnabled"], summary="Create an integration", auth="manage-*-integrations 또는 manage-own-*-integrations"),
    # ---------------- oauth apps ----------------
    e("oauth-apps.get", "GET", "manual_review_required", 0.7, "인증 사용자 누구나 앱을 조회할 수 있고 manage-oauth-apps 보유자만 clientSecret 필드를 추가로 받는다. 요청자-객체 관계 검사가 없고 권한은 필드 범위만 바꾸므로 보류.", [],
      [(None, "const isOAuthAppsManager = await hasPermissionAsync(this.user, 'manage-oauth-apps');"), (None, "!isOAuthAppsManager ? { projection: { clientSecret: 0 } } : {},")],
      q=["appId", "clientId"], summary="Get an OAuth app", auth="인증만; manage-oauth-apps면 clientSecret 포함"),
    e("oauth-apps.list", "GET", "role_required", 0.9, "permissionsRequired: ['manage-oauth-apps'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['manage-oauth-apps'],")],
      q=["uid"], summary="List OAuth apps", auth="manage-oauth-apps"),
    e("oauth-apps.delete", "POST", "role_required", 0.9, "permissionsRequired: ['manage-oauth-apps'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['manage-oauth-apps'],")],
      b=["appId"], summary="Delete an OAuth app", auth="manage-oauth-apps"),
    # ---------------- e2e ----------------
    e("e2e.fetchMyKeys", "GET", "owner_match", 0.9, "Users.fetchKeysByUserId(this.userId)로 본인 키만 반환한다.", [],
      [(None, "const result = await Users.fetchKeysByUserId(this.userId);")],
      summary="Fetch own E2E keys", auth="본인 고정"),
    e("e2e.setUserPublicAndPrivateKeys", "POST", "owner_match", 0.85, "setUserPublicAndPrivateKeysMethod(this.userId, ...)로 본인 키만 저장한다.", [],
      [(None, "await setUserPublicAndPrivateKeysMethod(this.userId, {")],
      b=["public_key", "private_key", "force"], summary="Set own E2E keys", auth="본인 고정"),
    e("e2e.resetRoomKey", "POST", "role_required", 0.75, "toggle-room-e2e-encryption(방 범위) 권한을 먼저 요구하고 canAccessRoomIdAsync도 검사한다. 권한이 결정 조건; 접근 AND 권한 결합으로 보면 보류 대안.", ["CAR_JOINED"],
      [(None, "if (!(await hasPermissionAsync(this.user, 'toggle-room-e2e-encryption', rid))) {"), (None, "if (!(await canAccessRoomIdAsync(rid, this.userId))) {")],
      b=["rid", "e2eKey", "e2eKeyId"], summary="Reset E2E room key", auth="toggle-room-e2e-encryption(방 범위) + canAccessRoomId"),
    # ---------------- permissions / roles / settings ----------------
    e("permissions.listAll", "GET", "manual_review_required", 0.75, "authRequired만 있고 역할·객체 검사 없이 전체 권한 목록을 반환한다(인증만 확인).", [],
      [(None, "authRequired: true,"), (None, "const result = (await permissionsGetMethod(updatedSinceDate)) as {")],
      q=["updatedSince"], summary="List all permissions", auth="인증만"),
    e("permissions.update", "POST", "role_required", 0.9, "permissionsRequired: ['access-permissions'] 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['access-permissions'],")],
      b=["permissions"], summary="Update permission-role mapping", auth="access-permissions"),
    e("roles.list", "GET", "manual_review_required", 0.75, "authRequired만 있고 역할·객체 검사 없이 전체 역할 목록을 반환한다(인증만 확인).", [],
      [(None, "authRequired: true,"), (None, "const roles = await Roles.find({}, { projection: { _updatedAt: 0 } }).toArray();")],
      summary="List roles", auth="인증만"),
    e("roles.addUserToRole", "POST", "role_required", 0.85, "addUserToRole이 전역 권한 access-permissions를 요구하고 admin 역할 부여에는 assign-admin-role도 요구한다.", ["GUFP", "ADDROLE"],
      [(None, "await addUserToRole(this.userId, role._id, user.username, roomId);"), (MM + "auth/addUserToRole.ts", "if (!(await hasPermissionAsync(userId, 'access-permissions'))) {")],
      b=["roleId", "roleName", "username", "roomId"], summary="Add a user to a role", auth="access-permissions (+assign-admin-role)"),
    e("roles.getUsersInRole", "GET", "role_required", 0.85, "permissionsRequired: ['access-permissions'] 전역 권한. roomId 지정 시 view-other-user-channels도 요구한다.", ["CHECKPERM"],
      [(None, "permissionsRequired: ['access-permissions'],"), (None, "if (roomId && !(await hasPermissionAsync(this.user, 'view-other-user-channels'))) {")],
      q=["role", "roomId", "offset", "count"], summary="List users in a role", auth="access-permissions (+view-other-user-channels)"),
    e("settings.public", "GET", "public", 0.9, "authRequired: false이고 public: true 설정만 조회한다. 익명 허용이 명시적.", [],
      [(None, "authRequired: false,"), (None, "public: true,")],
      q=["_id", "offset", "count", "query"], summary="List public settings", auth="익명 허용"),
    e("settings", "GET", "manual_review_required", 0.65, "인증 사용자 누구나 조회하되 view-privileged-setting이 없으면 public 설정으로 범위를 제한한다. 권한이 거부가 아니라 반환 범위를 바꾸므로 단일 라벨로 표현되지 않아 보류.", [],
      [(None, "if (!(await hasPermissionAsync(this.user, 'view-privileged-setting'))) {"), (None, "ourQuery.public = true;")],
      q=["includeDefaults", "offset", "count", "query"], summary="List settings (scope by permission)", auth="인증; view-privileged-setting 없으면 public만"),
    e("settings/:_id", "GET", "role_required", 0.9, "permissionsRequired GET: view-privileged-setting 전역 권한이 유일한 조건.", ["CHECKPERM"],
      [(None, "GET: { permissions: ['view-privileged-setting'], operation: 'hasAll' },")],
      summary="Get a setting by id", auth="view-privileged-setting"),
    e("settings/:_id", "POST", "role_required", 0.9, "permissionsRequired POST: edit-privileged-setting 전역 권한이 유일한 조건(2FA 필요).", ["CHECKPERM"],
      [(None, "POST: { permissions: ['edit-privileged-setting'], operation: 'hasAll' },")],
      b=["value", "editor", "execute"], summary="Update a setting by id", auth="edit-privileged-setting"),
    # ---------------- misc / default ----------------
    e("me", "GET", "owner_match", 0.9, "Users.findOneById(this.userId)로 본인 정보만 반환한다.", ["AUTHMW"],
      [(None, "const user = (await Users.findOneById(this.userId, { projection: userFields })) as IUser;")],
      summary="Get own user info", auth="본인 고정"),
    e("pw.getPolicy", "GET", "public", 0.9, "authRequired: false로 익명 허용, 조건 없음.", ["AUTHMW"],
      [(None, "authRequired: false,")],
      summary="Get password policy", auth="익명 허용"),
    e("info", "GET", "public", 0.9, "authRequired: false로 익명 허용. 상세 필드는 getServerInfo(this.userId)가 권한에 따라 추가하지만 접근 자체는 조건 없음.", ["AUTHMW"],
      [(None, "authRequired: false,")],
      summary="Server info", auth="익명 허용", file="apps/meteor/server/api/default/info.ts"),
    e("login", "POST", "public", 0.9, "authRequired: false인 로그인 엔드포인트. 익명 요청으로 자격 증명을 제출한다.", [],
      [(None, "{ authRequired: false, userWithoutUsername: true },")],
      b=["user", "username", "password", "resume", "code"], summary="Login", auth="익명 허용(로그인)", file="apps/meteor/server/api/ApiClass.ts"),
    # ---------------- channels (public rooms) ----------------
    e("channels.info", "GET", "manual_review_required", 0.7, "findChannelByIdOrName이 t='c' 방만 찾고 canAccessRoomAsync를 검사한다. 공개 채널은 view-c-room 권한(기본 user 역할) OR 구독 OR 비공개 팀이면 팀 구성원으로 통과해 조건이 OR 분기라 보류.", ["FCH", "CAR_PUBLIC", "CAR_PUBLIC2", "CAR_JOINED"],
      [(None, "if (!(await canAccessRoomAsync(findResult, { _id: this.userId }))) {"), ("packages/authorization/src/canAccessRoom.ts", "return Authorization.hasPermission(user, 'view-c-room');")],
      q=["roomId", "roomName"], summary="Get public channel info", auth="canAccessRoom(공개 채널: view-c-room OR 구독 OR 팀 구성원)"),
    e("channels.members", "GET", "manual_review_required", 0.7, "공개 채널 canAccessRoomAsync(view-c-room OR 구독 OR 팀 구성원) + broadcast면 view-broadcast-member-list. OR 분기라 보류.", ["FCH", "CAR_PUBLIC", "CAR_PUBLIC2", "CAR_JOINED"],
      [(None, "if (!(await canAccessRoomAsync(findResult, { _id: this.userId }))) {"), (None, "if (findResult.broadcast && !(await hasPermissionAsync(this.user, 'view-broadcast-member-list', findResult._id))) {")],
      q=["roomId", "roomName", "offset", "count", "status", "filter"], summary="List members of a public channel", auth="canAccessRoom(공개 채널 분기) + broadcast 권한"),
    e("channels.history", "GET", "manual_review_required", 0.7, "getChannelHistory→canReadRoom: canAccessRoom(공개 채널 분기) AND (preview-c-room 권한 OR 구독). 권한과 구독이 OR·AND로 섞여 보류.", ["FCH", "HISTORY", "CANREAD"],
      [(None, "const result = await getChannelHistory({"), ("packages/authorization/src/canReadRoom.ts", "!(await Authorization.hasPermission(userArgument, 'preview-c-room')) &&")],
      q=["roomId", "roomName", "latest", "oldest", "inclusive", "offset", "count", "unreads"], summary="Public channel history", auth="canReadRoom(canAccessRoom AND (preview-c-room OR 구독))"),
    e("channels.setTopic", "POST", "role_required", 0.85, "saveRoomSettings가 " + ROOMPERM.format(p="edit-room"), ["FCH", "SAVEROOM"],
      [(None, "await saveRoomSettings(this.userId, findResult._id, 'roomTopic', this.bodyParams.topic || '');"), (MM + "rooms/saveRoomSettings.ts", "if (!(await hasPermissionAsync(userId, 'edit-room', rid))) {")],
      b=["roomId", "roomName", "topic"], summary="Set topic of a public channel", auth="edit-room(방 범위)"),
    e("channels.kick", "POST", "role_required", 0.85, "removeUserFromRoomMethod가 " + ROOMPERM.format(p="remove-user"), ["FCH", "KICK"],
      [(None, "await removeUserFromRoomMethod(this.userId, { rid: findResult._id, username: user.username });"), (MM + "rooms/removeUserFromRoom.ts", "if (!(await hasPermissionAsync(fromId, 'remove-user', data.rid)))")],
      b=["roomId", "roomName", "userId", "username"], summary="Kick a user from a public channel", auth="remove-user(방 범위)"),
    e("channels.archive", "POST", "role_required", 0.85, ROOMPERM.format(p="archive-room"), ["FCH", "ARCHIVE"],
      [(None, "await executeArchiveRoom(this.userId, findResult._id);"), (MM + "rooms/archiveRoom.ts", "if (!(await hasPermissionAsync(userId, 'archive-room', room._id)))")],
      b=["roomId", "roomName"], summary="Archive a public channel", auth="archive-room(방 범위)"),
    e("channels.delete", "POST", "role_required", 0.85, "eraseRoom이 canBeDeleted→" + ROOMPERM.format(p="delete-c"), ["FCH", "ERASE", "CANBEDEL"],
      [(None, "await eraseRoom(room._id, this.user);"), (SL + "rooms/roomCoordinator.ts", "return hasPermission(`delete-${room.t}`, room._id);")],
      b=["roomId", "roomName"], summary="Delete a public channel", auth="delete-c(방 범위)"),
    e("channels.create", "POST", "role_required", 0.85, "createChannelValidator가 전역 create-c 또는 팀 소속이면 create-team-channel(팀 방 범위) 권한이 없으면 unauthorized를 던진다.", ["CREATEC"],
      [(V1 + "channels.ts", "(!teamId && !(await hasPermissionAsync(params.user.value, 'create-c'))) ||"), (V1 + "channels.ts", "(teamId && team && !(await hasPermissionAsync(params.user.value, 'create-team-channel', team.roomId)))")],
      b=["name", "members", "readOnly", "customFields", "teams", "extraData"], summary="Create a public channel", auth="create-c 또는 create-team-channel(팀 방 범위)"),
    e("channels.list", "GET", "manual_review_required", 0.65, "permissionsRequired hasAny(view-c-room, view-joined-room) 후 view-c-room이 없으면 본인 구독 채널로 범위를 제한하고 팀 채널은 구독 여부로 필터한다. 권한에 따라 반환 범위가 달라지는 혼합 조건이라 보류.", ["CHECKPERM"],
      [(None, "GET: { permissions: ['view-c-room', 'view-joined-room'], operation: 'hasAny' },"), (None, "if (!hasPermissionToSeeAllPublicChannels) {")],
      q=["offset", "count", "sort", "fields", "query", "_id"], summary="List public channels", auth="view-c-room 전체 / view-joined-room 본인 구독만"),
    e("channels.leave", "POST", "membership_required", 0.7, "leaveRoomMethod가 Subscriptions.findOneByRoomIdAndUserId로 요청자 본인 구독을 요구하고(없으면 error-user-not-in-room) leave-c 권한도 검사한다. 구성원 관계가 핵심.", ["FCH", "LEAVE"],
      [(None, "await leaveRoomMethod(user, findResult._id);"), (MM + "rooms/leaveRoom.ts", "throw new Meteor.Error('error-user-not-in-room', 'You are not in this room', {")],
      b=["roomId", "roomName"], summary="Leave a public channel", auth="leaveRoomMethod → 본인 구독 + leave-c"),
    e("channels.invite", "POST", "role_required", 0.65, "addUsersToRoomMethod가 (요청자 구독 AND add-user-to-joined-room 방 범위) OR 전역 add-user-to-any-c-room으로 허용한다. 결정 조건이 권한이라 role_required 초안; 구독 AND 권한 결합을 중시하면 보류 대안.", ["FCH", "ADDUSERS"],
      [(None, "await addUsersToRoomMethod(this.userId, { rid: findResult._id, users: users.map((u) => u.username).filter(isTruthy) }, this.user);"),
       (MM + "rooms/addUsersToRoom.ts", "if (userInRoom && (await hasPermissionAsync(userId, 'add-user-to-joined-room', room._id))) {"), (MM + "rooms/addUsersToRoom.ts", "} else if (room.t === 'c' && (await hasPermissionAsync(userId, 'add-user-to-any-c-room'))) {")],
      b=["roomId", "roomName", "userId", "username", "userIds", "usernames"], summary="Invite users to a public channel", auth="add-user-to-joined-room(구독자) 또는 add-user-to-any-c-room"),
    e("channels.addModerator", "POST", "role_required", 0.85, ROOMPERM.format(p="set-moderator"), ["FCH", "GUFP", "ADDMOD"],
      [(None, "await addRoomModerator(this.userId, findResult._id, user._id);"), (MM + "rooms/addRoomModerator.ts", "if (!(await hasPermissionAsync(fromUserId, 'set-moderator', rid)) && !isFederated)")],
      b=["roomId", "roomName", "userId", "username"], summary="Add a moderator to a public channel", auth="set-moderator(방 범위)"),
    e("channels.close", "POST", "membership_required", 0.7, "Subscriptions.findOneByRoomIdAndUserId(채널, 요청자) 구독 행이 없으면 거부하고 본인 구독만 숨긴다. 요청 대상 채널의 구성원 관계가 조건이라 membership_required; 본인 구독 처리로 보면 owner_match 대안.", ["FCH", "HIDE"],
      [(None, "const sub = await Subscriptions.findOneByRoomIdAndUserId(findResult._id, this.userId);"), (None, "return API.v1.failure(`The user/callee is not in the channel \"${findResult.name}.`);")],
      b=["roomId", "roomName"], summary="Close (hide) a public channel for the caller", auth="본인 구독 행 필요"),
    e("channels.open", "POST", "membership_required", 0.7, "Subscriptions.findOneByRoomIdAndUserId(채널, 요청자) 구독 행이 없으면 거부하고 본인 구독만 연다. membership_required; owner_match 대안.", ["FCH", "OPEN"],
      [(None, "const sub = await Subscriptions.findOneByRoomIdAndUserId(findResult._id, this.userId);"), (None, "return API.v1.failure(`The user/callee is not in the channel \"${findResult.name}\".`);")],
      b=["roomId", "roomName"], summary="Open a public channel for the caller", auth="본인 구독 행 필요"),
    e("channels.counters", "GET", "manual_review_required", 0.7, "userId 파라미터가 있으면 view-room-administration 권한, 없으면 본인 구독으로 joined 여부만 계산해 비구독자도 일부 필드를 받는다. 파라미터 의존 분기라 보류.", ["FCH"],
      [(None, "const access = await hasPermissionAsync(this.user, 'view-room-administration');"), (None, "const subscription = await Subscriptions.findOneByRoomIdAndUserId(room._id, user);")],
      q=["roomId", "roomName", "userId"], summary="Counters of a public channel", auth="userId 지정 시 view-room-administration, 아니면 본인 구독 기준"),
    e("channels.list.joined", "GET", "owner_match", 0.8, "Subscriptions.findByUserIdAndTypes(this.userId, ['c'])로 본인 구독 채널만 반환한다.", [],
      [(None, "const subs = await Subscriptions.findByUserIdAndTypes(this.userId, ['c'], { projection: { rid: 1 } }).toArray();")],
      q=["offset", "count", "sort"], summary="List public channels the caller joined", auth="본인 구독 목록"),
]


# ---------------------------------------------------------------- build
def oas_path(name):
    return "/api/v1/" + re.sub(r":(\w+)", r"{\1}", name)


def build():
    global HELP
    HELP = H()
    out = []
    seen = set()
    for ep in ENDPOINTS:
        rel = ep.file or (V1 + FILE_BY_PREFIX[ep.name.split(".")[0].split("/")[0]])
        if ep.name == "login":
            s, en, text = func(rel, r"^\t\t\(this as APIClass<'/v1'>\)\.addRoute\($", r"^\t\t\);$", max_lines=40)
            r = dict(start=s, end=en, text=text, methods=["POST"])
        elif ep.name.startswith("im."):
            ls = lines(rel)
            ci = next(i for i, l in enumerate(ls) if f"'{ep.name}'" in l and re.match(r"^	\.(get|post)\(", l))
            m = re.match(r"^	\.(get|post)\('[^']+', (\w+), (\w+)\(", ls[ci])
            props, action = m.group(2), m.group(3)
            ps, pe, ptext = func(rel, rf"^const {props} = ", r"^\}( as const)?;$")
            as_, ae, atext = func(rel, rf"^const {action} = ", r"^	\};$")
            r = dict(start=as_, end=ae, text=ls[ci].rstrip(",;") + chr(10) + chr(10) + ptext + chr(10) + chr(10) + atext, methods=[m.group(1).upper()])
            extra_locs = [{"file": rel, "start_line": ci + 1, "end_line": ci + 1}, {"file": rel, "start_line": ps, "end_line": pe}]
            r["ev_start"] = ps
        else:
            cands = [x for x in routes(rel) if x["name"] == ep.name and (ep.method in x["methods"] or not x["methods"])]
            if not cands:
                raise KeyError(f"{rel}:{ep.name}:{ep.method}")
            r = cands[0]
        parts = [r["text"]]
        locs = ([] if not ep.name.startswith("im.") else extra_locs) + [{"file": rel, "start_line": r["start"], "end_line": r["end"]}]
        for hk in ep.helpers:
            segs = HELP[hk]
            if isinstance(segs, tuple):
                segs = [segs]
            parts.append("\n\t...\n".join(seg(hrel, hs, he) for hrel, hs, he in segs))
            for hrel, hs, he in segs:
                locs.append({"file": hrel, "start_line": hs, "end_line": he})
        raw = "\n\n".join(parts)
        text = compact(raw)
        budget = 1200
        while len(text) > 3000 and budget >= 400:
            # compact each helper part separately then the route part
            cparts = [compact(parts[0], 1800)] + [compact(p, budget) for p in parts[1:]]
            text = compact("\n\n".join(cparts))
            budget -= 200
        assert len(text) <= 3000, (ep.name, len(text))
        evidence = []
        try:
            for erel, sub in ep.evidence:
                if erel is None:
                    evidence.append(ev(rel, sub, r.get("ev_start", r["start"]), r["end"]))
                else:
                    evidence.append(ev(erel, sub))
        except Exception as ex:
            raise RuntimeError(f"{ep.name} {ep.method}: {ex}")
        anon = any("authRequired: false" in p for p in parts[:1]) or ep.name in ("login",)
        params = [{"name": n, "in": "query", "required": False, "schema": {"type": "string"}} for n in ep.q]
        for pm in re.findall(r"\{(\w+)\}", oas_path(ep.name)):
            params.insert(0, {"name": pm, "in": "path", "required": True, "schema": {"type": "string"}})
        op = {
            "operationId": re.sub(r"[^A-Za-z0-9]", "_", ep.name) + "_" + ep.method.lower(),
            "summary": ep.summary,
            "description": "",
            "parameters": params,
            "responses": {"200": {"description": "success"}},
            "security": [] if anon else [{"userApiKey": []}],
        }
        if ep.b:
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": {n: {"type": "string"} for n in ep.b}}}}}
        key = (ep.method, oas_path(ep.name))
        assert key not in seen, key
        seen.add(key)
        rec = {
            "project": "rocketchat", "service": "Rocket.Chat", "repository": REPO, "commit": COMMIT, "tag": TAG, "license": "MIT",
            "method": ep.method, "path": oas_path(ep.name), "oas_status": "generated", "oas_operation": op,
            "oas_global_security": [{"userApiKey": []}],
            "oas_security_schemes": {"userApiKey": {"type": "apiKey", "in": "header", "name": "X-Auth-Token", "description": "with X-User-Id header"}},
            "response_schema_fields": [],
            "controller_text": text, "source_locations": locs, "auth_summary": ep.auth, "permission_doc": "",
            "draft_label": ep.label, "draft_confidence": ep.conf, "evidence": evidence, "draft_reason": ep.reason,
            "known_vulnerable": False, "advisory": None, "fix_commit": None,
        }
        out.append(rec)
    with open(OUT + "/candidates.jsonl", "w", encoding="utf-8") as f:
        for rec in out:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print("written", len(out))
    print(collections.Counter(r["draft_label"] for r in out))
    return out


REQ = ["project", "service", "repository", "commit", "tag", "license", "method", "path", "oas_status", "oas_operation",
       "oas_global_security", "oas_security_schemes", "response_schema_fields", "controller_text", "source_locations",
       "auth_summary", "permission_doc", "draft_label", "draft_confidence", "evidence", "draft_reason", "known_vulnerable",
       "advisory", "fix_commit"]
LABELS = {"public", "role_required", "membership_required", "tenant_match", "owner_match", "owner_or_admin", "manual_review_required"}


def validate():
    seen = set()
    n = 0
    lens = []
    for line in open(OUT + "/candidates.jsonl", encoding="utf-8"):
        rec = json.loads(line)
        n += 1
        for k in REQ:
            assert k in rec, (k, rec["path"])
        assert rec["draft_label"] in LABELS
        assert 0 <= rec["draft_confidence"] <= 1
        assert 1 <= len(rec["controller_text"]) <= 3000, (rec["path"], len(rec["controller_text"]))
        assert rec["evidence"] and all(e["type"] in ("code", "doc_permissions") and e["text"] and e["location"] for e in rec["evidence"])
        for loc in rec["source_locations"]:
            assert "/ee/" not in loc["file"] and not loc["file"].startswith("ee/"), loc
        assert "/ee/" not in rec["controller_text"]
        key = (rec["method"], rec["path"])
        assert key not in seen, key
        seen.add(key)
        lens.append(len(rec["controller_text"]))
    print("ok", n, "min/max controller_text", min(lens), max(lens), "under500", sum(1 for x in lens if x < 500))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "survey":
        for f in sys.argv[2:]:
            survey(V1 + f)
    elif cmd == "show":
        r = route(V1 + sys.argv[2], sys.argv[3])
        print(f"### {sys.argv[2]}:{r['start']}-{r['end']} {r['methods']}")
        print(r["text"])
    elif cmd == "build":
        build()
    elif cmd == "validate":
        validate()
