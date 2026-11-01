"""Static extraction of Umami API route authorization policy candidates (test_v5).

Read-only over the clone at datasets/blade/raw/opensource/umami-software_umami.
Writes candidates.jsonl next to this script. Run with: python -I extract_umami.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", "..", "datasets", "blade", "raw", "opensource", "umami-software_umami"))
OUT = os.path.join(HERE, "candidates.jsonl")

PROJECT = "umami"
SERVICE = "Umami"
REPO_URL = "https://github.com/umami-software/umami"
COMMIT = "559e3c607c23d2c72d9bd4f6481bda428255323c"
TAG = "v3.4.1"
LICENSE = "MIT"

_cache = {}


def lines_of(rel):
    if rel not in _cache:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def func_end(rel, start):
    """Return end line (1-based, inclusive) of a brace-delimited block starting at line `start`."""
    ls = lines_of(rel)
    depth = 0
    seen = False
    for i in range(start - 1, len(ls)):
        for ch in ls[i]:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
        if depth > 0:
            seen = True
        if seen and depth == 0:
            return i + 1
    raise RuntimeError(f"no block end {rel}:{start}")


def block(rel, start, end=None, elide=()):
    """Verbatim lines start..end (inclusive). `elide` = list of (a, b) line ranges replaced by '...'."""
    if end is None:
        end = func_end(rel, start)
    ls = lines_of(rel)
    out = []
    i = start
    elide = sorted(elide)
    while i <= end:
        hit = [e for e in elide if e[0] == i]
        if hit:
            a, b = hit[0]
            ref = next((ls[j - 1] for j in range(a, b + 1) if ls[j - 1].strip()), ls[a - 1])
            indent = len(ref) - len(ref.lstrip())
            out.append(" " * indent + "...")
            i = b + 1
            continue
        out.append(ls[i - 1])
        i += 1
    return {"file": rel, "start_line": start, "end_line": end, "text": "\n".join(out)}


def line(rel, n):
    return lines_of(rel)[n - 1].strip()


def ev(rel, a, b=None):
    if b is None:
        return {"type": "code", "text": line(rel, a), "location": f"{rel}:{a}"}
    text = "\n".join(l.strip() for l in lines_of(rel)[a - 1:b])
    return {"type": "code", "text": text, "location": f"{rel}:{a}-{b}"}


# ---- shared blocks -------------------------------------------------------
REQ = "src/lib/request.ts"
AUTH = "src/lib/auth.ts"
CONST = "src/lib/constants.ts"
TU = "src/queries/prisma/teamUser.ts"
P_USER = "src/permissions/user.ts"
P_TEAM = "src/permissions/team.ts"
P_WEB = "src/permissions/website.ts"
P_SHARE = "src/permissions/share.ts"
P_ENT = "src/permissions/entity.ts"
P_REP = "src/permissions/report.ts"
P_BOARD = "src/permissions/board.ts"
P_LINK = "src/permissions/link.ts"

PARSE_REQUEST = block(REQ, 16, elide=[(21, 49)])
CHECK_AUTH = block(AUTH, 71, elide=[(80, 87), (96, 100), (102, 111), (114, 120)])
CHECK_AUTH_SHORT = block(AUTH, 71, elide=[(79, 87), (89, 121), (127, 134)])
HAS_PERMISSION = block(AUTH, 163)
GET_TEAM_USER = block(TU, 19)
ROLE_PERMS = block(CONST, 203, 234, elide=[(205, 211)])
SHARE_INCLUDES = block(P_SHARE, 40)


def perm(rel, start):
    return block(rel, start)


BEARER = [{"bearerAuth": []}]
SEC_SCHEMES = {
    "bearerAuth": {"type": "http", "scheme": "bearer", "description": "Session JWT issued by POST /api/auth/login (or umami_* API key when API keys are enabled). Share-token header x-umami-share-token is accepted by checkAuth for share contexts."}
}


def p(name, where="path", typ="string", required=True, fmt=None):
    s = {"type": typ}
    if fmt:
        s["format"] = fmt
    return {"name": name, "in": where, "required": required, "schema": s}


def uuidp(name, where="path", required=True):
    return p(name, where, "string", required, "uuid")


PAGING = [p("page", "query", "integer", False), p("pageSize", "query", "integer", False)]
SORTING = [p("orderBy", "query", "string", False), p("sortDescending", "query", "string", False)]
SEARCH = [p("search", "query", "string", False)]
DATE_RANGE = [p("startAt", "query", "integer", True), p("endAt", "query", "integer", True), p("timezone", "query", "string", False)]


def body(keys, required=None):
    props = {}
    for k in keys:
        if isinstance(k, tuple):
            props[k[0]] = {"type": k[1]}
        else:
            props[k] = {"type": "string"}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"required": True, "content": {"application/json": {"schema": schema}}}


records = []


def add(method, path, summary, blocks, label, conf, evidence, reason, auth_summary,
        params=None, req_body=None, security=BEARER, response_fields=None, extra_sources=None, description=""):
    texts = [b["text"] for b in blocks]
    controller_text = "\n\n".join(texts)
    locs = [{"file": b["file"], "start_line": b["start_line"], "end_line": b["end_line"]} for b in blocks]
    op = {
        "operationId": method.lower() + "".join(seg.strip("{}").title() for seg in path.split("/") if seg and seg != "api"),
        "summary": summary,
        "description": description,
        "parameters": params or [],
        "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}},
    }
    if req_body:
        op["requestBody"] = req_body
    if security is not None:
        op["security"] = security
    rec = {
        "project": PROJECT, "service": SERVICE, "repository": REPO_URL,
        "commit": COMMIT, "tag": TAG, "license": LICENSE,
        "method": method, "path": path, "oas_status": "generated",
        "oas_operation": op,
        "oas_global_security": [],
        "oas_security_schemes": SEC_SCHEMES if security else {},
        "response_schema_fields": response_fields or [],
        "controller_text": controller_text,
        "source_locations": locs,
        "auth_summary": auth_summary,
        "permission_doc": "",
        "draft_label": label, "draft_confidence": conf,
        "evidence": evidence, "draft_reason": reason,
        "known_vulnerable": False, "advisory": None, "fix_commit": None,
    }
    records.append(rec)


# ============================================================================
# USERS
# ============================================================================
F = "src/app/api/users/route.ts"
add("POST", "/api/users", "Create user",
    [block(F, 11), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 3)],
    "role_required", 0.9,
    [ev(F, 25, 27), ev(P_USER, 3, 5), ev(AUTH, 137)],
    "canCreateUser는 user.isAdmin(전역 role === 'admin')만 허용한다. 전역 역할이 결정 조건이므로 role_required.",
    "parseRequest→checkAuth(세션/API키) → canCreateUser: user.isAdmin만 허용",
    req_body=body(["username", "password", "role", "id"], ["username", "password", "role"]),
    response_fields=["id", "username", "role", "createdAt"])

F = "src/app/api/users/[userId]/route.ts"
add("GET", "/api/users/{userId}", "Get user",
    [block(F, 9), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 7)],
    "owner_or_admin", 0.9,
    [ev(F, 18, 20), ev(P_USER, 12, 16)],
    "canViewUser는 user.isAdmin이면 허용, 아니면 user.id === viewedUserId(본인)만 허용한다. 본인 OR 관리자 우회이므로 owner_or_admin.",
    "canViewUser: isAdmin || user.id === viewedUserId",
    params=[uuidp("userId")], response_fields=["id", "username", "role", "createdAt"])
add("POST", "/api/users/{userId}", "Update user",
    [block(F, 27, elide=[(69, 80)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 23)],
    "owner_or_admin", 0.9,
    [ev(F, 42, 44), ev(P_USER, 28, 32), ev(F, 60, 66)],
    "canUpdateUser는 isAdmin OR user.id === viewedUserId. role·username 변경은 추가로 isAdmin만 가능하지만 접근 자체의 조건은 본인 OR 관리자이므로 owner_or_admin.",
    "canUpdateUser: isAdmin || self; role/username 필드는 isAdmin만 변경",
    params=[uuidp("userId")], req_body=body(["username", "password", "role"]),
    response_fields=["id", "username", "role"])
add("DELETE", "/api/users/{userId}", "Delete user",
    [block(F, 83), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 35)],
    "role_required", 0.9,
    [ev(F, 95, 97), ev(P_USER, 35, 37), ev(F, 99, 101)],
    "canDeleteUser는 user.isAdmin만 허용(본인 삭제는 400으로 거부). 전역 관리자 역할이 조건이므로 role_required.",
    "canDeleteUser: isAdmin only; self-delete rejected",
    params=[uuidp("userId")])

F = "src/app/api/users/[userId]/teams/route.ts"
add("GET", "/api/users/{userId}/teams", "List a user's teams",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_or_admin", 0.9,
    [ev(F, 21, 23)],
    "핸들러 인라인 검사 auth.user.id !== userId && !auth.user.isAdmin → 401. 본인 OR 관리자이므로 owner_or_admin.",
    "inline: auth.user.id === userId || auth.user.isAdmin",
    params=[uuidp("userId")] + PAGING + SORTING, response_fields=["data", "count", "page", "pageSize"])

F = "src/app/api/users/[userId]/websites/route.ts"
add("GET", "/api/users/{userId}/websites", "List a user's websites",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_or_admin", 0.9,
    [ev(F, 23, 25)],
    "핸들러 인라인 검사 !auth.user.isAdmin && auth.user.id !== userId → 401. 본인 OR 관리자이므로 owner_or_admin.",
    "inline: auth.user.isAdmin || auth.user.id === userId",
    params=[uuidp("userId")] + PAGING + SEARCH + SORTING + [p("includeTeams", "query", "string", False)],
    response_fields=["data", "count", "page", "pageSize"])

# ============================================================================
# TEAMS
# ============================================================================
F = "src/app/api/teams/route.ts"
add("GET", "/api/teams", "List my teams",
    [block(F, 13), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/team.ts", 54, elide=[(63, 85)])],
    "owner_match", 0.8,
    [ev(F, 27), ev("src/queries/prisma/team.ts", 57, 62)],
    "인가 함수는 없고 getUserTeams(auth.user.id)로 요청자 본인이 구성원인 팀만 조회한다. 처리 대상이 인증 사용자 본인으로 고정되므로 owner_match.",
    "no can*; query scoped to auth.user.id (members.some.userId)",
    params=PAGING + SORTING, response_fields=["data", "count", "page", "pageSize"])
add("POST", "/api/teams", "Create team",
    [block(F, 32, elide=[(53, 67), (78, 91)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 18), HAS_PERMISSION, ROLE_PERMS],
    "role_required", 0.75,
    [ev(F, 44, 46), ev(P_TEAM, 23, 27), ev(CONST, 205, 210), ev(CONST, 211)],
    "canCreateTeam은 isAdmin 또는 hasPermission(user.role, 'team:create')이며 전역 role 'user'는 허용, 'view-only'는 불허. 객체 없는 기능에 전역 역할 권한만 있는 경우이므로 role_required. ownerId 지정은 isAdmin만 반영.",
    "canCreateTeam: isAdmin || ROLE_PERMISSIONS[user.role] includes team:create (user: yes, view-only: no)",
    req_body=body(["name", "ownerId"], ["name"]), response_fields=["id", "name", "accessCode"])

F = "src/app/api/teams/join/route.ts"
add("POST", "/api/teams/join", "Join team by access code",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 20, 25), ev(F, 31, 37)],
    "인증만 확인하고 요청자-팀 관계·역할 검사가 없다. 팀 accessCode(비밀 초대 코드) 소지가 유일한 조건이며 6종 라벨로 표현되지 않아 보류.",
    "auth only; team looked up by secret accessCode; already-member rejected",
    req_body=body(["accessCode"], ["accessCode"]), response_fields=["id", "teamId", "userId", "role"])

F = "src/app/api/teams/[teamId]/route.ts"
add("GET", "/api/teams/{teamId}", "Get team",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 6), GET_TEAM_USER],
    "membership_required", 0.9,
    [ev(F, 16, 18), ev(P_TEAM, 11, 15), ev(TU, 19, 27)],
    "canViewTeam은 isAdmin 우회 또는 getTeamUser(teamId, user.id) 구성원 행 존재를 요구한다. 요청이 대상 팀을 지정하고 (요청자, 팀) 구성원 조회가 결정 조건이므로 membership_required.",
    "canViewTeam: isAdmin || teamUser row (teamId, user.id) exists",
    params=[uuidp("teamId")], response_fields=["id", "name", "accessCode", "members"])
add("POST", "/api/teams/{teamId}", "Update team",
    [block(F, 29), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 30), HAS_PERMISSION, GET_TEAM_USER, ROLE_PERMS],
    "role_required", 0.85,
    [ev(F, 43, 45), ev(P_TEAM, 39, 41), ev(CONST, 212, 214), ev(CONST, 221, 223)],
    "canUpdateTeam은 isAdmin 또는 팀 구성원 행의 role에 'team:update' 권한(team-owner·team-manager)이 있어야 한다. 구성원 확인 뒤 팀 안 역할이 결정 조건이므로 role_required(G3). 대안: membership_required.",
    "canUpdateTeam: isAdmin || teamUser.role has team:update (team-owner, team-manager)",
    params=[uuidp("teamId")], req_body=body(["name", "accessCode"]), response_fields=["id", "name", "accessCode"])
add("DELETE", "/api/teams/{teamId}", "Delete team",
    [block(F, 52), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 44), HAS_PERMISSION, GET_TEAM_USER, ROLE_PERMS],
    "role_required", 0.85,
    [ev(F, 64, 66), ev(P_TEAM, 53, 55), ev(CONST, 212, 214)],
    "canDeleteTeam은 isAdmin 또는 팀 구성원 role에 'team:delete' 권한(team-owner만)이 있어야 한다. 팀 안 역할이 결정 조건이므로 role_required.",
    "canDeleteTeam: isAdmin || teamUser.role has team:delete (team-owner only)",
    params=[uuidp("teamId")])

F = "src/app/api/teams/[teamId]/users/route.ts"
add("GET", "/api/teams/{teamId}/users", "List team members",
    [block(F, 8, elide=[(28, 49)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 6), GET_TEAM_USER],
    "membership_required", 0.9,
    [ev(F, 22, 24), ev(P_TEAM, 11, 15)],
    "canViewTeam(isAdmin OR 팀 구성원 행 존재)이 조건이며 오류 메시지도 'You must be a member of this team.'이다. membership_required.",
    "canViewTeam: isAdmin || teamUser row exists",
    params=[uuidp("teamId")] + PAGING + SEARCH, response_fields=["data", "count", "page", "pageSize"])
add("POST", "/api/teams/{teamId}/users", "Add team member",
    [block(F, 54, elide=[(74, 78)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 30), HAS_PERMISSION, GET_TEAM_USER, ROLE_PERMS],
    "role_required", 0.85,
    [ev(F, 68, 70), ev(P_TEAM, 39, 41), ev(CONST, 212, 214), ev(CONST, 221, 223)],
    "canUpdateTeam: isAdmin 또는 팀 구성원 role에 team:update(team-owner·team-manager). 팀 안 역할이 결정 조건이므로 role_required.",
    "canUpdateTeam: isAdmin || teamUser.role has team:update",
    params=[uuidp("teamId")], req_body=body(["userId", "role"], ["userId", "role"]),
    response_fields=["id", "teamId", "userId", "role"])

F = "src/app/api/teams/[teamId]/users/[userId]/route.ts"
add("GET", "/api/teams/{teamId}/users/{userId}", "Get team member",
    [block(F, 9), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 30), HAS_PERMISSION, GET_TEAM_USER, ROLE_PERMS],
    "role_required", 0.85,
    [ev(F, 21, 23), ev(P_TEAM, 39, 41), ev(CONST, 212, 214), ev(CONST, 221, 223)],
    "구성원 1명 조회인데도 canUpdateTeam(isAdmin OR team-owner/team-manager 역할)을 쓴다. 팀 안 역할이 결정 조건이므로 role_required.",
    "canUpdateTeam: isAdmin || teamUser.role has team:update",
    params=[uuidp("teamId"), uuidp("userId")], response_fields=["id", "teamId", "userId", "role"])
add("POST", "/api/teams/{teamId}/users/{userId}", "Update team member role",
    [block(F, 30), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 30), HAS_PERMISSION, GET_TEAM_USER],
    "role_required", 0.85,
    [ev(F, 46, 48), ev(F, 56, 65), ev(P_TEAM, 39, 41)],
    "canUpdateTeam(isAdmin OR team-owner/team-manager) 뒤 비관리자는 TEAM_ROLE_RANK로 대상보다 높은 팀 역할이어야 한다. 모두 팀 안 역할 조건이므로 role_required.",
    "canUpdateTeam + actor team-role rank must exceed target rank (non-admin)",
    params=[uuidp("teamId"), uuidp("userId")], req_body=body(["role"], ["role"]),
    response_fields=["id", "teamId", "userId", "role"])
add("DELETE", "/api/teams/{teamId}/users/{userId}", "Remove team member",
    [block(F, 72), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 58), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.6,
    [ev(F, 84, 86), ev(P_TEAM, 63, 73), ev(F, 94, 107)],
    "canDeleteTeamUser는 isAdmin OR removeUserId === user.id(본인 탈퇴) OR 팀 역할 team:update(owner/manager)이며, 비관리자는 소유자 제거 불가·역할 순위 검사가 추가된다. 본인(owner) 조건과 팀 역할 조건이 OR로 결합돼 단일 라벨로 표현되지 않아 보류. 대안: role_required(타인 제거 기준).",
    "canDeleteTeamUser: isAdmin || self-removal || teamUser.role has team:update; non-admin cannot remove team-owner; rank check",
    params=[uuidp("teamId"), uuidp("userId")])

for sub, qf in (("websites", "getTeamWebsites"), ("links", "getTeamLinks"), ("pixels", "getTeamPixels"), ("boards", "getTeamBoards")):
    F = f"src/app/api/teams/[teamId]/{sub}/route.ts"
    add("GET", f"/api/teams/{{teamId}}/{sub}", f"List team {sub}",
        [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 6), GET_TEAM_USER],
        "membership_required", 0.9,
        [ev(F, 21, 23), ev(P_TEAM, 11, 15), ev(TU, 20, 26)],
        f"canViewTeam(isAdmin OR getTeamUser(teamId, user.id) 구성원 행 존재)이 조건이고 {qf}(teamId)로 팀 자원을 조회한다. 대상 팀 구성원 관계가 결정 조건이므로 membership_required.",
        "canViewTeam: isAdmin || teamUser row exists",
        params=[uuidp("teamId")] + PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])

# ============================================================================
# ME / AUTH
# ============================================================================
F = "src/app/api/me/route.ts"
add("GET", "/api/me", "Get current auth/user",
    [block(F, 5), PARSE_REQUEST, CHECK_AUTH],
    "owner_match", 0.85,
    [ev(F, 12), ev(AUTH, 122, 125)],
    "인증 결과(auth.user 본인)만 반환한다. 처리 대상이 인증 사용자 본인으로 고정되므로 owner_match. 별도 인가 함수는 없다.",
    "returns auth (self); no object parameter",
    response_fields=["user", "authType", "shareToken"])
F = "src/app/api/me/password/route.ts"
add("POST", "/api/me/password", "Change my password",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.9,
    [ev(F, 19), ev(F, 22, 26), ev(F, 30)],
    "userId = auth.user.id로 고정되고 currentPassword 검증 후 본인 비밀번호만 갱신한다. owner_match.",
    "self only: userId = auth.user.id; current password verified",
    req_body=body(["currentPassword", "newPassword"], ["currentPassword", "newPassword"]),
    response_fields=["id", "username", "role"])
F = "src/app/api/me/teams/route.ts"
add("GET", "/api/me/teams", "List my teams",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/team.ts", 54, elide=[(63, 85)])],
    "owner_match", 0.9,
    [ev(F, 21), ev("src/queries/prisma/team.ts", 57, 62)],
    "getUserTeams(auth.user.id)로 본인이 구성원인 팀만 조회한다. 대상이 본인으로 고정되므로 owner_match.",
    "self only: getUserTeams(auth.user.id)",
    params=PAGING + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/me/websites/route.ts"
add("GET", "/api/me/websites", "List my websites",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/website.ts", 149, elide=[(155, 164)])],
    "owner_match", 0.9,
    [ev(F, 22, 26), ev("src/queries/prisma/website.ts", 152, 154)],
    "getUserWebsites(auth.user.id) 또는 팀 접근 포함 조회를 본인 id로만 수행한다. owner_match.",
    "self only: queries keyed by auth.user.id",
    params=PAGING + SORTING + [p("includeTeams", "query", "string", False)], response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/me/api-keys/route.ts"
add("GET", "/api/me/api-keys", "List my API keys",
    [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/apiKey.ts", 27)],
    "owner_match", 0.9,
    [ev(F, 19), ev("src/queries/prisma/apiKey.ts", 28, 29)],
    "getUserApiKeys(auth.user.id)로 본인 키만 조회한다. owner_match. (API 키 기능 비활성 시 404)",
    "self only: getUserApiKeys(auth.user.id)")
add("POST", "/api/me/api-keys", "Create my API key",
    [block(F, 22), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.9,
    [ev(F, 39, 45)],
    "createApiKey의 userId를 auth.user.id로 강제한다(본인 명의 생성). owner_match.",
    "self only: userId forced to auth.user.id",
    req_body=body(["name"], ["name"]), response_fields=["id", "name", "keyPrefix", "key"])
F = "src/app/api/me/api-keys/[keyId]/route.ts"
add("DELETE", "/api/me/api-keys/{keyId}", "Delete my API key",
    [block(F, 6), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/apiKey.ts", 41)],
    "owner_match", 0.85,
    [ev(F, 19), ev("src/queries/prisma/apiKey.ts", 41, 44)],
    "deleteApiKey(keyId, auth.user.id)가 where { id, userId }로 본인 소유 키만 삭제한다(타인 키는 count 0 → 404). 소유자 == 요청자, 관리자 우회 없음이므로 owner_match.",
    "deleteMany where { id: keyId, userId: auth.user.id }",
    params=[uuidp("keyId")])

F = "src/app/api/auth/login/route.ts"
add("POST", "/api/auth/login", "Login",
    [block(F, 14, elide=[(29, 61)]), PARSE_REQUEST],
    "public", 0.95,
    [ev(F, 15), ev(REQ, 51, 57)],
    "parseRequest에 skipAuth: true로 인증을 건너뛰고 username/password로 토큰을 발급한다. 익명 허용 로그인 엔드포인트이므로 public.",
    "skipAuth: true; credential check only",
    req_body=body(["username", "password"], ["username", "password"]), security=[], response_fields=["token", "user"])
F = "src/app/api/auth/logout/route.ts"
add("POST", "/api/auth/logout", "Logout",
    [block(F, 5), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.6,
    [ev(F, 12, 14)],
    "인증만 확인하고 요청자 자신의 세션 키(auth.authKey)만 삭제한다. 대상이 본인 세션으로 고정돼 owner_match로 두되, 객체 없는 인증 전용으로 보면 manual_review_required가 대안이다.",
    "auth only; deletes caller's own authKey",
    security=BEARER)
F = "src/app/api/auth/verify/route.ts"
add("POST", "/api/auth/verify", "Verify session",
    [block(F, 5), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.75,
    [ev(F, 12, 14)],
    "인증 후 auth.user 본인과 getAllUserTeams(auth.user.id) 결과만 반환한다. 대상이 본인으로 고정되므로 owner_match. 대안: 인증 전용 manual_review_required.",
    "auth only; returns self + own teams",
    response_fields=["id", "username", "role", "isAdmin", "teams"])
F = "src/app/api/auth/sso/route.ts"
add("POST", "/api/auth/sso", "Issue SSO token for self",
    [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.7,
    [ev(F, 19, 20)],
    "인증된 본인(auth.user.id)에 대한 24h 토큰을 발급한다. 대상이 본인으로 고정되므로 owner_match. 대안: 인증 전용 manual_review_required.",
    "auth only; token minted for auth.user.id",
    response_fields=["user", "token"])
F = "src/app/api/auth/subscription/route.ts"
add("GET", "/api/auth/subscription", "Get subscription (own account or team)",
    [block(F, 13), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 6), GET_TEAM_USER],
    "manual_review_required", 0.6,
    [ev(F, 26), ev(F, 39, 41), ev(P_TEAM, 11, 15)],
    "teamId 쿼리가 있으면 canViewTeam(구성원 OR 관리자), 없으면 본인 계정(auth.user.id) 구독을 반환한다. 요청 형태에 따라 조건 유형이 바뀌므로 보류. 대안: membership_required(teamId 있을 때) / owner_match(없을 때).",
    "teamId? canViewTeam : self account",
    params=[uuidp("teamId", "query", False)], response_fields=["hasSubscription", "isPro", "isBusiness"])

# ============================================================================
# ADMIN
# ============================================================================
F = "src/app/api/admin/users/route.ts"
add("GET", "/api/admin/users", "List all users (admin)",
    [block(F, 8, elide=[(25, 44)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 19)],
    "role_required", 0.95,
    [ev(F, 21, 23), ev(P_USER, 19, 21)],
    "canViewUsers는 user.isAdmin만 허용한다. 전역 역할이 조건이므로 role_required.",
    "canViewUsers: isAdmin only",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/admin/teams/route.ts"
add("GET", "/api/admin/teams", "List all teams (admin)",
    [block(F, 8, elide=[(25, 56)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 90)],
    "role_required", 0.95,
    [ev(F, 21, 23), ev(P_TEAM, 90, 92)],
    "canViewAllTeams는 user.isAdmin만 허용한다. role_required.",
    "canViewAllTeams: isAdmin only",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/admin/websites/route.ts"
add("GET", "/api/admin/websites", "List all websites (admin)",
    [block(F, 9, elide=[(26, 56)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 116)],
    "role_required", 0.95,
    [ev(F, 22, 24), ev(P_WEB, 116, 118)],
    "canViewAllWebsites는 user.isAdmin만 허용한다. role_required.",
    "canViewAllWebsites: isAdmin only",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/admin/2fa/global/route.ts"
add("POST", "/api/admin/2fa/global", "Set global 2FA requirement (admin)",
    [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 39)],
    "role_required", 0.9,
    [ev(F, 21, 23), ev(P_USER, 39, 41)],
    "canEnforceTwoFactorAuthForEveryone은 user.isAdmin만 허용한다. role_required. (CLOUD_MODE면 404)",
    "canEnforceTwoFactorAuthForEveryone: isAdmin only",
    req_body=body([("required", "boolean")], ["required"]), response_fields=["ok", "required"])
F = "src/app/api/admin/users/[userId]/2fa/route.ts"
add("GET", "/api/admin/users/{userId}/2fa", "Get a user's 2FA status (admin)",
    [block(F, 9), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 43)],
    "role_required", 0.9,
    [ev(F, 20, 22), ev(P_USER, 43, 45)],
    "canEnforceTwoFactorAuthForUser는 user.isAdmin만 허용하며 대상 userId와 무관하다. role_required.",
    "canEnforceTwoFactorAuthForUser: isAdmin only",
    params=[uuidp("userId")], response_fields=["isEnabled"])
add("POST", "/api/admin/users/{userId}/2fa", "Set a user's 2FA requirement (admin)",
    [block(F, 31), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 43)],
    "role_required", 0.9,
    [ev(F, 44, 46), ev(P_USER, 43, 45)],
    "canEnforceTwoFactorAuthForUser는 user.isAdmin만 허용한다. role_required.",
    "canEnforceTwoFactorAuthForUser: isAdmin only",
    params=[uuidp("userId")], req_body=body([("required", "boolean")], ["required"]), response_fields=["ok", "userId", "twoFactorRequired"])
add("DELETE", "/api/admin/users/{userId}/2fa", "Reset a user's 2FA (admin)",
    [block(F, 60, elide=[(77, 93)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_USER, 43)],
    "role_required", 0.9,
    [ev(F, 71, 73), ev(P_USER, 43, 45)],
    "canEnforceTwoFactorAuthForUser는 user.isAdmin만 허용한다. role_required.",
    "canEnforceTwoFactorAuthForUser: isAdmin only",
    params=[uuidp("userId")], response_fields=["ok", "userId", "reset"])
F = "src/app/api/admin/teams/[teamId]/2fa/route.ts"
add("POST", "/api/admin/teams/{teamId}/2fa", "Set a team's 2FA requirement (admin)",
    [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_TEAM, 94)],
    "role_required", 0.9,
    [ev(F, 23, 25), ev(P_TEAM, 94, 100)],
    "canEnforceTwoFactorAuthForTeam은 teamId를 받지만 실제로는 user.isAdmin만 반환한다. 전역 관리자 역할이 조건이므로 role_required.",
    "canEnforceTwoFactorAuthForTeam: returns user.isAdmin (teamId unused)",
    params=[uuidp("teamId")], req_body=body([("required", "boolean")], ["required"]), response_fields=["ok", "teamId", "twoFactorRequired"])

# ============================================================================
# WEBSITES
# ============================================================================
F = "src/app/api/websites/route.ts"
add("GET", "/api/websites", "List my websites",
    [block(F, 12), PARSE_REQUEST, CHECK_AUTH_SHORT, block("src/queries/prisma/website.ts", 149, elide=[(155, 164)])],
    "owner_match", 0.85,
    [ev(F, 19), ev(F, 23, 27), ev("src/queries/prisma/website.ts", 152, 154)],
    "인가 함수 없이 getUserWebsites(auth.user.id)로 본인 소유(또는 includeTeams 시 본인 팀 접근) 웹사이트만 조회한다. 대상이 본인으로 고정되므로 owner_match.",
    "self only: queries keyed by auth.user.id",
    params=PAGING + SEARCH + SORTING + [p("includeTeams", "query", "string", False)], response_fields=["data", "count", "page", "pageSize"])
add("POST", "/api/websites", "Create website",
    [block(F, 30, elide=[(39, 52), (72, 82)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 120), perm(P_TEAM, 76), HAS_PERMISSION, GET_TEAM_USER],
    "role_required", 0.6,
    [ev(F, 54, 56), ev(P_WEB, 125, 129), ev(P_TEAM, 85, 87)],
    "canCreateWebsite(isAdmin OR 전역 role에 website:create; view-only 불허) AND teamId가 있으면 canCreateTeamWebsite(팀 구성원 role에 website:create). 두 조건 모두 역할 권한이지만 전역 역할과 팀 안 역할의 AND 결합이라 보류(manual_review_required)도 가능하다.",
    "canCreateWebsite (global role perm) && (teamId ? canCreateTeamWebsite (team role perm))",
    req_body=body(["name", "domain", "shareId", "teamId", "id"], ["name", "domain"]), response_fields=["id", "name", "domain", "userId", "teamId", "shareId"])

F = "src/app/api/websites/[websiteId]/route.ts"
add("GET", "/api/websites/{websiteId}", "Get website",
    [block(F, 18), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 80), SHARE_INCLUDES, perm(P_WEB, 8)],
    "manual_review_required", 0.85,
    [ev(F, 30, 32), ev(P_SHARE, 80, 86), ev(P_WEB, 9, 11), ev(P_WEB, 30, 38)],
    "canViewSharedWebsite는 로그인 사용자면 canViewWebsite(isAdmin OR 공유 토큰 OR 소유자 OR 소유 팀 구성원), 비로그인이면 공유 토큰만 허용한다. 서로 다른 유형의 조건이 OR로 결합돼 6종 하나로 표현되지 않아 보류.",
    "canViewSharedWebsite → canViewWebsite: isAdmin || shareToken covers id || owner || team member; share-token-only when no user",
    params=[uuidp("websiteId")], response_fields=["id", "name", "domain", "userId", "teamId"])
add("POST", "/api/websites/{websiteId}", "Update website",
    [block(F, 39, elide=[(56, 106)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 132), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 52, 54), ev(P_WEB, 137, 157)],
    "canUpdateWebsite는 isAdmin OR (개인 소유 웹사이트면 소유자 본인) OR (팀 소유면 팀 구성원 role에 website:update). 소유자 조건과 팀 역할 조건이 자원 소유 형태에 따라 분기돼 단일 라벨로 표현되지 않아 보류. 대안: owner_or_admin(개인 소유 기준).",
    "canUpdateWebsite: isAdmin || (website.userId ? owner : teamUser.role has website:update)",
    params=[uuidp("websiteId")], req_body=body(["name", "domain", "shareId", ("replayConfig", "object")]), response_fields=["id", "name", "domain", "shareId"])
add("DELETE", "/api/websites/{websiteId}", "Delete website",
    [block(F, 109), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 160), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 121, 123), ev(P_WEB, 165, 185)],
    "canDeleteWebsite는 isAdmin OR 개인 소유자 본인 OR 팀 구성원 role에 website:delete. 소유자·팀 역할 조건이 분기 결합돼 보류. 대안: owner_or_admin.",
    "canDeleteWebsite: isAdmin || (website.userId ? owner : teamUser.role has website:delete)",
    params=[uuidp("websiteId")])

WEB = "src/app/api/websites/[websiteId]/"
SECTION_REASON = ("canViewWebsiteSection은 로그인 사용자면 canViewWebsite(isAdmin OR 공유 토큰 OR 소유자 OR 소유 팀 구성원), 비로그인이면 해당 섹션이 허용된 공유 토큰만 허용한다. "
                  "서로 다른 유형의 조건이 OR로 결합되고 공유 토큰 파라미터에 따라 허용 범위가 바뀌므로 보류.")
SECTION_SUMMARY = "canViewWebsiteSection: user ? canViewWebsite (admin||share||owner||team member) : share token with section enabled"
for sub, start, elide, summary, sections, extra_params in (
    ("stats", 8, [(28, 44)], "Website stats", "overview, compare", DATE_RANGE),
    ("pageviews", 8, [(28, 69)], "Website pageviews", "overview, compare", DATE_RANGE),
    ("sessions", 7, [], "Website sessions", "sessions", DATE_RANGE + PAGING + SEARCH),
    ("events", 7, [], "Website events", "events", DATE_RANGE + PAGING + SEARCH),
    ("active", 6, [], "Active visitors", "overview, realtime", []),
):
    F = WEB + sub + "/route.ts"
    first = {"stats": 24, "pageviews": 24, "sessions": 25, "events": 25, "active": 18}[sub]
    add("GET", f"/api/websites/{{websiteId}}/{sub}", summary,
        [block(F, start, elide=elide), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 53), perm(P_WEB, 8)],
        "manual_review_required", 0.85,
        [ev(F, first, first + 2), ev(P_SHARE, 58, 60), ev(P_SHARE, 64, 66), ev(P_WEB, 9, 11), ev(P_WEB, 30, 38)],
        f"섹션 [{sections}]에 대해 " + SECTION_REASON,
        SECTION_SUMMARY,
        params=[uuidp("websiteId")] + extra_params)

F = WEB + "export/route.ts"
add("GET", "/api/websites/{websiteId}/export", "Export website data (zip)",
    [block(F, 9, elide=[(29, 81)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 101), perm(P_WEB, 8), GET_TEAM_USER],
    "manual_review_required", 0.8,
    [ev(F, 25, 27), ev(P_SHARE, 105, 109), ev(P_WEB, 9, 11), ev(P_WEB, 30, 38)],
    "canViewAuthenticatedWebsite는 로그인 필수 후 canViewWebsite(isAdmin OR 소유자 OR 소유 팀 구성원; 로그인 상태라 공유 토큰도 통과)를 적용한다. 소유자 조건과 팀 구성원 조건이 OR로 결합돼 보류. 대안: owner_or_admin.",
    "canViewAuthenticatedWebsite: user required; then canViewWebsite (admin||owner||team member)",
    params=[uuidp("websiteId")] + DATE_RANGE + PAGING, response_fields=["zip"])
F = WEB + "reset/route.ts"
add("POST", "/api/websites/{websiteId}/reset", "Reset website data",
    [block(F, 6), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 132), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 18, 20), ev(P_WEB, 137, 157)],
    "canUpdateWebsite: isAdmin OR 개인 소유자 OR 팀 구성원 role에 website:update. 소유자·팀 역할 조건 분기 결합이라 보류. 대안: owner_or_admin.",
    "canUpdateWebsite: isAdmin || owner || team role website:update",
    params=[uuidp("websiteId")])
F = WEB + "transfer/route.ts"
add("POST", "/api/websites/{websiteId}/transfer", "Transfer website to user or team",
    [block(F, 7, elide=[(30, 35), (41, 46)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 188), perm(P_WEB, 212), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.75,
    [ev(F, 25, 28), ev(F, 36, 39), ev(P_WEB, 203, 207), ev(P_WEB, 227, 231)],
    "userId 전송: isAdmin OR (팀 소유 웹사이트이고 본인에게 전송하며 팀 role에 website:transfer-to-user). teamId 전송: isAdmin OR (개인 소유자 본인이면서 대상 팀 role에 website:transfer-to-team). 본인·팀 역할 조건의 AND/OR 결합이라 보류.",
    "canTransferWebsiteToUser / canTransferWebsiteToTeam: admin || (owner-side && team role permission)",
    params=[uuidp("websiteId")], req_body=body(["userId", "teamId"]), response_fields=["id", "userId", "teamId"])
F = WEB + "shares/route.ts"
add("GET", "/api/websites/{websiteId}/shares", "List website shares",
    [block(F, 11), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 101), perm(P_WEB, 8), GET_TEAM_USER],
    "manual_review_required", 0.8,
    [ev(F, 29, 31), ev(P_SHARE, 105, 109), ev(P_WEB, 30, 38)],
    "canViewAuthenticatedWebsite: 로그인 필수 후 canViewWebsite(isAdmin OR 소유자 OR 소유 팀 구성원). 소유자·팀 구성원 조건 OR 결합이라 보류. 대안: owner_or_admin.",
    "canViewAuthenticatedWebsite: user required; canViewWebsite (admin||owner||team member)",
    params=[uuidp("websiteId")] + PAGING + SEARCH, response_fields=["data", "count", "page", "pageSize"])
add("POST", "/api/websites/{websiteId}/shares", "Create website share",
    [block(F, 42, elide=[(65, 76)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 132), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 61, 63), ev(P_WEB, 137, 157)],
    "canUpdateWebsite: isAdmin OR 개인 소유자 OR 팀 구성원 role에 website:update. 분기 결합이라 보류. 대안: owner_or_admin.",
    "canUpdateWebsite: isAdmin || owner || team role website:update",
    params=[uuidp("websiteId")], req_body=body(["name", ("parameters", "object")], ["name"]), response_fields=["id", "entityId", "slug", "parameters"])
F = WEB + "goals/[goalId]/route.ts"
add("GET", "/api/websites/{websiteId}/goals/{goalId}", "Get goal report",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_REP, 27), perm(P_SHARE, 53, )],
    "manual_review_required", 0.8,
    [ev(F, 14, 16), ev(P_REP, 32, 46)],
    "canViewReport: isAdmin OR report.userId === 본인(작성자) OR 웹사이트 'goals' 섹션 열람 권한(canViewWebsiteSection: 소유자/팀 구성원/공유 토큰). 작성자 조건과 웹사이트 접근 조건이 OR로 결합돼 보류.",
    "canViewReport: admin || report author || canViewWebsiteSection(goals)",
    params=[uuidp("websiteId"), uuidp("goalId")], response_fields=["id", "websiteId", "userId", "type", "name", "parameters"])
add("POST", "/api/websites/{websiteId}/goals/{goalId}", "Update goal report",
    [block(F, 20), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_REP, 49), perm(P_WEB, 132), GET_TEAM_USER],
    "manual_review_required", 0.75,
    [ev(F, 27, 29), ev(P_REP, 54, 62), ev(P_WEB, 147, 155)],
    "canUpdateReport: isAdmin OR report.userId === 본인(작성자) OR canUpdateWebsite(소유자 또는 팀 role website:update). 작성자·소유자·팀 역할 조건이 OR로 결합돼 보류. 대안: owner_or_admin.",
    "canUpdateReport: admin || report author || canUpdateWebsite",
    params=[uuidp("websiteId"), uuidp("goalId")], req_body=body(["name", "description", ("parameters", "object")], ["name", "parameters"]), response_fields=["id", "name", "parameters"])
add("DELETE", "/api/websites/{websiteId}/goals/{goalId}", "Delete goal report",
    [block(F, 39), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_REP, 65), perm(P_WEB, 160), GET_TEAM_USER],
    "manual_review_required", 0.75,
    [ev(F, 46, 48), ev(P_REP, 70, 78), ev(P_WEB, 175, 183)],
    "canDeleteReport: isAdmin OR 작성자 본인 OR canDeleteWebsite(소유자 또는 팀 role website:delete). 작성자·소유자·팀 역할 OR 결합이라 보류. 대안: owner_or_admin.",
    "canDeleteReport: admin || report author || canDeleteWebsite",
    params=[uuidp("websiteId"), uuidp("goalId")])
F = WEB + "sessions/[sessionId]/route.ts"
add("DELETE", "/api/websites/{websiteId}/sessions/{sessionId}", "Delete a session",
    [block(F, 62), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_WEB, 160), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 78, 80), ev(P_WEB, 165, 185)],
    "canDeleteWebsite(websiteId): isAdmin OR 개인 소유자 OR 팀 구성원 role에 website:delete. 소유자·팀 역할 분기 결합이라 보류. 대안: owner_or_admin.",
    "canDeleteWebsite: isAdmin || owner || team role website:delete",
    params=[uuidp("websiteId"), p("sessionId")])
F = WEB + "annotations/route.ts"
add("GET", "/api/websites/{websiteId}/annotations", "List website annotations",
    [block(F, 9, elide=[(33, 41)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 88), SHARE_INCLUDES, perm(P_WEB, 8)],
    "manual_review_required", 0.8,
    [ev(F, 29, 31), ev(P_SHARE, 92, 98), ev(P_WEB, 30, 38)],
    "canViewSharedWebsiteFilters: 로그인 사용자면 canViewWebsite(isAdmin OR 공유 토큰 OR 소유자 OR 팀 구성원), 비로그인이면 allowFilter !== false인 공유 토큰. 조건 유형 OR 결합이라 보류.",
    "canViewSharedWebsiteFilters: user ? canViewWebsite : share token && allowFilter !== false",
    params=[uuidp("websiteId"), p("startAt", "query", "integer", False), p("endAt", "query", "integer", False)] + SEARCH + PAGING)
F = WEB + "recorder/route.ts"
add("GET", "/api/websites/{websiteId}/recorder", "Public recorder config for tracker",
    [block(F, 10, elide=[(32, 46)]), PARSE_REQUEST],
    "public", 0.9,
    [ev(F, 14), ev(REQ, 51, 57)],
    "parseRequest에 skipAuth: true로 인증 없이 웹사이트 레코더 설정(enabled 등)을 반환하고 CORS 공개 헤더를 붙인다. 익명 허용이 코드로 드러나므로 public.",
    "skipAuth: true; public CORS; returns recorder config by websiteId",
    params=[uuidp("websiteId")], security=[], response_fields=["enabled", "replayEnabled", "heatmapEnabled", "sampleRate"])
F = "src/app/api/realtime/[websiteId]/route.ts"
add("GET", "/api/realtime/{websiteId}", "Realtime data",
    [block(F, 10, elide=[(32, 43)]), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_SHARE, 53), perm(P_WEB, 8)],
    "manual_review_required", 0.85,
    [ev(F, 28, 30), ev(P_SHARE, 58, 60), ev(P_SHARE, 64, 66), ev(P_WEB, 30, 38)],
    "섹션 'realtime'에 대해 " + SECTION_REASON,
    SECTION_SUMMARY,
    params=[uuidp("websiteId"), p("timezone", "query", "string", False), p("unit", "query", "string", False)])

# ============================================================================
# SHARE / COLLECT / MISC
# ============================================================================
F = "src/app/api/share/[slug]/route.ts"
add("GET", "/api/share/{slug}", "Resolve public share link (issues share token)",
    [block(F, 130, elide=[(145, 159), (164, 177), (180, 187)])],
    "public", 0.9,
    [ev(F, 130, 133), ev(F, 178)],
    "parseRequest/checkAuth를 호출하지 않고 slug로 share 레코드를 찾아 공유 토큰을 발급한다. 익명 접근이 코드로 드러나므로 public.",
    "no auth; lookup by share slug; mints share token",
    params=[p("slug")], security=[], response_fields=["shareId", "shareType", "websiteId", "token", "parameters"])
F = "src/app/api/share/id/[shareId]/route.ts"
add("GET", "/api/share/id/{shareId}", "Get share by id",
    [block(F, 8), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_ENT, 7), block("src/lib/entity.ts", 4), GET_TEAM_USER],
    "manual_review_required", 0.75,
    [ev(F, 19, 21), ev(P_ENT, 12, 32)],
    "canViewEntity(share.entityId): isAdmin OR 엔티티 개인 소유자 본인 OR 엔티티 소유 팀의 구성원. 소유자 조건과 팀 구성원 조건이 분기 OR로 결합돼 보류. 대안: owner_or_admin.",
    "canViewEntity: isAdmin || entity owner || team member of entity.teamId",
    params=[uuidp("shareId")], response_fields=["id", "entityId", "shareType", "slug", "parameters"])
add("DELETE", "/api/share/id/{shareId}", "Delete share",
    [block(F, 61), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_ENT, 63), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 75, 77), ev(P_ENT, 68, 88)],
    "canDeleteEntity: isAdmin OR 엔티티 개인 소유자 OR 팀 구성원 role에 website:delete. 소유자·팀 역할 분기 결합이라 보류. 대안: owner_or_admin.",
    "canDeleteEntity: isAdmin || owner || team role website:delete",
    params=[uuidp("shareId")])
F = "src/app/api/share/route.ts"
add("POST", "/api/share", "Create share for an entity",
    [block(F, 10), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_ENT, 35), HAS_PERMISSION, GET_TEAM_USER],
    "manual_review_required", 0.7,
    [ev(F, 28, 30), ev(P_ENT, 40, 60)],
    "canUpdateEntity(body.entityId): isAdmin OR 엔티티 개인 소유자 OR 팀 구성원 role에 website:update. 분기 결합이라 보류. 대안: owner_or_admin.",
    "canUpdateEntity: isAdmin || owner || team role website:update",
    req_body=body(["entityId", ("shareType", "integer"), "name", "slug", ("parameters", "object")], ["entityId", "shareType", "name", "parameters"]),
    response_fields=["id", "entityId", "shareType", "slug"])

F = "src/app/api/send/route.ts"
add("POST", "/api/send", "Tracker collect endpoint",
    [block(F, 75, 81), {"file": F, "start_line": 82, "end_line": 387, "text": "    ...\n  } catch (e) {\n    return serverError(e);\n  }\n}"}, PARSE_REQUEST],
    "public", 0.95,
    [ev(F, 77), ev(REQ, 51, 57)],
    "parseRequest에 skipAuth: true로 인증 없이 추적 이벤트를 수집한다(봇·IP 차단만). 익명 허용 수집 엔드포인트이므로 public.",
    "skipAuth: true; anonymous tracker payload (bot check, IP block)",
    req_body=body(["type", ("payload", "object")], ["type", "payload"]), security=[], response_fields=["cache", "sessionId", "visitId"])
F = "src/app/api/batch/route.ts"
add("POST", "/api/batch", "Batch collect endpoint",
    [block(F, 9, elide=[(17, 47)]), PARSE_REQUEST],
    "public", 0.9,
    [ev(F, 11), ev(F, 36)],
    "skipAuth: true로 인증 없이 배열 payload를 /api/send 핸들러에 위임한다. 익명 허용이므로 public.",
    "skipAuth: true; delegates each item to send.POST",
    req_body={"required": True, "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object"}}}}},
    security=[], response_fields=["size", "processed", "errors", "details", "cache"])
F = "src/app/api/heartbeat/route.ts"
add("GET", "/api/heartbeat", "Heartbeat",
    [block(F, 1, 3)],
    "public", 0.95,
    [ev(F, 1, 3)],
    "parseRequest/checkAuth 없이 { ok: true }를 반환한다. 익명 허용이 코드로 드러나므로 public.",
    "no auth", security=[], response_fields=["ok"])
F = "src/app/api/config/route.ts"
add("GET", "/api/config", "App config flags",
    [block(F, 7), PARSE_REQUEST],
    "public", 0.9,
    [ev(F, 8), ev(REQ, 51, 57)],
    "parseRequest에 skipAuth: true로 인증 없이 공개 설정 플래그를 반환한다. public.",
    "skipAuth: true", security=[], response_fields=["cloudMode", "privateMode", "telemetryDisabled", "updatesDisabled"])
F = "src/app/api/scripts/telemetry/route.ts"
add("GET", "/api/scripts/telemetry", "Telemetry script",
    [block(F, 3, elide=[(16, 22)])],
    "public", 0.9,
    [ev(F, 3, 8)],
    "인증 코드 없이 환경변수에 따라 JS 스니펫을 반환한다. 익명 허용이므로 public.",
    "no auth", security=[], response_fields=[])

F = "src/app/api/dashboard/route.ts"
add("GET", "/api/dashboard", "Get my dashboard board",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.9,
    [ev(F, 14, 18)],
    "getBoard(auth.user.id)로 본인 id를 키로 조회하고 board.userId !== auth.user.id면 401. 소유자 == 요청자이며 관리자 우회가 없으므로 owner_match.",
    "self only: board id = auth.user.id; userId must equal auth.user.id",
    response_fields=["id", "type", "userId", "name", "parameters"])
add("POST", "/api/dashboard", "Create/update my dashboard board",
    [block(F, 23, elide=[(43, 66)]), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 36, 41), ev(F, 59, 64)],
    "userId = auth.user.id로 고정하고 기존 보드의 userId가 본인이 아니면 401, 생성 시 userId를 본인으로 강제한다. owner_match.",
    "self only: existing.userId must equal auth.user.id; create with userId = auth.user.id",
    req_body=body(["name", "description", ("parameters", "object")]), response_fields=["id", "type", "userId", "name", "parameters"])
F = "src/app/api/boards/route.ts"
add("GET", "/api/boards", "List my boards",
    [block(F, 15), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 30)],
    "getUserBoards(auth.user.id)로 본인 보드만 조회한다. 대상이 본인으로 고정되므로 owner_match.",
    "self only: getUserBoards(auth.user.id)",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/boards/[boardId]/route.ts"
add("GET", "/api/boards/{boardId}", "Get board",
    [block(F, 15), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_BOARD, 154), GET_TEAM_USER],
    "manual_review_required", 0.8,
    [ev(F, 24, 26), ev(P_BOARD, 155, 183)],
    "canViewBoard: isAdmin OR 공유 토큰 boardId 일치 OR 개인 소유자 본인 OR 소유 팀 구성원. 조건 유형 OR 결합이라 보류.",
    "canViewBoard: isAdmin || shareToken.boardId || owner || team member",
    params=[uuidp("boardId")], response_fields=["id", "type", "userId", "teamId", "name", "parameters"])
F = "src/app/api/links/route.ts"
add("GET", "/api/links", "List my links",
    [block(F, 9), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 24)],
    "getUserLinks(auth.user.id)로 본인 링크만 조회한다. owner_match.",
    "self only: getUserLinks(auth.user.id)",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/links/[linkId]/route.ts"
add("GET", "/api/links/{linkId}", "Get link",
    [block(F, 7), PARSE_REQUEST, CHECK_AUTH_SHORT, perm(P_LINK, 6), GET_TEAM_USER],
    "manual_review_required", 0.8,
    [ev(F, 16, 18), ev(P_LINK, 7, 40)],
    "canViewLink: isAdmin OR 공유 토큰 linkId 일치 OR 개인 소유자 본인 OR 소유 팀 구성원. 조건 유형 OR 결합이라 보류.",
    "canViewLink: isAdmin || shareToken covers linkId || owner || team member",
    params=[uuidp("linkId")], response_fields=["id", "name", "url", "slug", "userId", "teamId"])
F = "src/app/api/pixels/route.ts"
add("GET", "/api/pixels", "List my pixels",
    [block(F, 9), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 24)],
    "getUserPixels(auth.user.id)로 본인 픽셀만 조회한다. owner_match.",
    "self only: getUserPixels(auth.user.id)",
    params=PAGING + SEARCH + SORTING, response_fields=["data", "count", "page", "pageSize"])
F = "src/app/api/2fa/status/route.ts"
add("GET", "/api/2fa/status", "My 2FA status",
    [block(F, 6, elide=[(25, 94)]), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 23), ev(F, 25)],
    "userId = auth.user.id로 고정해 본인 2FA 상태만 조회한다. owner_match.",
    "self only: userId = auth.user.id",
    response_fields=["isEnabled", "isRequired", "requiredReason", "isConfigured", "globalRequired"])
F = "src/app/api/2fa/disable/route.ts"
add("POST", "/api/2fa/disable", "Disable my 2FA",
    [block(F, 12, elide=[(35, 65), (75, 111)]), PARSE_REQUEST, CHECK_AUTH_SHORT],
    "owner_match", 0.85,
    [ev(F, 32), ev(F, 66, 73), ev(F, 112, 116)],
    "userId = auth.user.id로 고정하고 본인 비밀번호·TOTP를 검증한 뒤 본인 2FA만 삭제한다. owner_match.",
    "self only: userId = auth.user.id; password + TOTP verified",
    req_body=body(["password", "token"], ["password", "token"]), response_fields=["ok"])
F = "src/app/api/2fa/verify/route.ts"
add("POST", "/api/2fa/verify", "Complete 2FA login with partial token",
    [block(F, 21, elide=[(58, 149)])],
    "public", 0.6,
    [ev(F, 31, 39), ev(F, 45)],
    "세션 인증을 건너뛰고(skipAuth: true) 로그인 1단계가 발급한 partial token(type 검사)과 TOTP/백업 코드로 세션 토큰을 발급하는 로그인 절차다. 인가가 아닌 인증 단계라 G7(로그인·토큰 갱신)에 따라 public으로 두되, 익명이 아닌 partial token 필수이므로 manual_review_required가 대안이다.",
    "skipAuth: true; requires PARTIAL_AUTH_TOKEN_TYPE bearer + TOTP/backup code; login step 2",
    req_body=body(["token", "backupCode"]), security=[], response_fields=["token", "user"])


# ============================================================================
# write + validate
# ============================================================================
REQUIRED = ["project", "service", "repository", "commit", "tag", "license", "method", "path", "oas_status",
            "oas_operation", "oas_global_security", "oas_security_schemes", "response_schema_fields",
            "controller_text", "source_locations", "auth_summary", "permission_doc", "draft_label",
            "draft_confidence", "evidence", "draft_reason", "known_vulnerable", "advisory", "fix_commit"]
LABELS = {"public", "role_required", "membership_required", "tenant_match", "owner_match", "owner_or_admin", "manual_review_required"}

SKIP = {
    ("GET", "/api/websites/{websiteId}/pageviews"), ("GET", "/api/websites/{websiteId}/events"),
    ("GET", "/api/websites/{websiteId}/annotations"), ("GET", "/api/links/{linkId}"),
    ("GET", "/api/pixels"), ("GET", "/api/links"), ("GET", "/api/boards"),
    ("GET", "/api/2fa/status"), ("POST", "/api/2fa/disable"), ("POST", "/api/2fa/verify"),
    ("GET", "/api/scripts/telemetry"), ("GET", "/api/config"), ("POST", "/api/me/api-keys"),
    ("POST", "/api/auth/sso"), ("GET", "/api/admin/users/{userId}/2fa"),
    ("POST", "/api/admin/users/{userId}/2fa"), ("DELETE", "/api/admin/users/{userId}/2fa"),
    ("POST", "/api/admin/teams/{teamId}/2fa"), ("DELETE", "/api/websites/{websiteId}/goals/{goalId}"),
    ("POST", "/api/share"), ("DELETE", "/api/websites/{websiteId}/sessions/{sessionId}"),
    ("GET", "/api/teams/{teamId}/boards"),
}
records = [r for r in records if (r["method"], r["path"]) not in SKIP]

seen = set()
problems = []
for r in records:
    key = (r["method"], r["path"])
    if key in seen:
        problems.append(f"duplicate {key}")
    seen.add(key)
    for k in REQUIRED:
        if k not in r:
            problems.append(f"missing {k} in {key}")
    n = len(r["controller_text"])
    if not (1 <= n <= 3000):
        problems.append(f"controller_text length {n} for {key}")
    if n < 500:
        print(f"note: short controller_text {n} for {key}", file=sys.stderr)
    if r["draft_label"] not in LABELS:
        problems.append(f"bad label {key}")
    if not (0 <= r["draft_confidence"] <= 1):
        problems.append(f"bad confidence {key}")
    if not r["evidence"]:
        problems.append(f"no evidence {key}")

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    for r in records:
        f.write(json.dumps(r, ensure_ascii=False) + "\n")

from collections import Counter
cnt = Counter(r["draft_label"] for r in records)
print(f"wrote {len(records)} records to {OUT}")
for k, v in sorted(cnt.items()):
    print(f"  {k}: {v}")
lens = sorted(len(r["controller_text"]) for r in records)
print(f"controller_text len min={lens[0]} max={lens[-1]} median={lens[len(lens)//2]}")
if problems:
    print("PROBLEMS:")
    for pr in problems:
        print("  " + pr)
    sys.exit(1)
