"""Static extraction of Penpot backend RPC command authorization policy candidates (test_v6).

Read-only over the clone at datasets/blade/raw/opensource/test_v6_candidates/penpot
(tag 2.18.5, commit f44566963daf61fce4d8608e7c5e8c27c5853a88, MPL-2.0).
Writes candidates.jsonl next to this script. Run from C:\\BLADE with:
    python -I data/raw_v6/penpot/extract_penpot.py

Every RPC command is exposed as POST /api/rpc/command/<command-name>
(backend/src/app/rpc.clj route "/rpc/command/:method-name" under "/api").
Commands are `(sv/defmethod ::name {metadata} [cfg params] ...)` forms in
backend/src/app/rpc/commands/*.clj. No LLM API, no model runs.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", "..", "datasets", "blade", "raw", "opensource",
                                     "test_v6_candidates", "penpot"))
OUT = os.path.join(HERE, "candidates.jsonl")

PROJECT = "penpot"
SERVICE = "Penpot"
REPO_URL = "https://github.com/penpot/penpot"
COMMIT = "f44566963daf61fce4d8608e7c5e8c27c5853a88"
TAG = "2.18.5"
LICENSE = "MPL-2.0"

_cache = {}


def lines_of(rel):
    if rel not in _cache:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def form_end(rel, start):
    """Return end line (1-based, inclusive) of the Clojure top-level form that starts
    at line `start`. Counts '(' / ')' outside string literals, `;` comments and
    character literals (\\x). Regex literals #"..." are handled as strings."""
    ls = lines_of(rel)
    depth = 0
    seen = False
    in_str = False
    for i in range(start - 1, len(ls)):
        line = ls[i]
        j = 0
        while j < len(line):
            ch = line[j]
            if in_str:
                if ch == "\\":
                    j += 2
                    continue
                if ch == '"':
                    in_str = False
                j += 1
                continue
            if ch == '"':
                in_str = True
            elif ch == ";":
                break
            elif ch == "\\":
                j += 2
                continue
            elif ch == "(":
                depth += 1
                seen = True
            elif ch == ")":
                depth -= 1
            j += 1
        if seen and depth == 0 and not in_str:
            return i + 1
    raise RuntimeError(f"no form end {rel}:{start}")


def block(rel, start, end=None, elide=()):
    """Verbatim lines start..end (inclusive). `elide` = list of (a, b) line ranges
    replaced by '...'; b=None means 'up to end-1' (keep the closing line)."""
    if end is None:
        end = form_end(rel, start)
    ls = lines_of(rel)
    elide = sorted((a, (end - 1) if b is None else b) for a, b in elide)
    out = []
    i = start
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


def docstring(rel, start):
    """Docstring of the sv/defmethod form at `start` (the string literal right after the name), or ''."""
    ls = lines_of(rel)
    first = ls[start - 1]
    nxt = ls[start].strip() if start < len(ls) else ""
    if not nxt.startswith('"'):
        return ""
    # collect until closing quote
    buf = []
    i = start  # 0-based index of the line after the defmethod line
    while i < len(ls):
        buf.append(ls[i])
        txt = "\n".join(buf)
        body = txt.strip()
        if len(body) >= 2 and body.endswith('"') and not body.endswith('\\"') and body.count('"') >= 2:
            inner = body[1:-1]
            return " ".join(s.strip() for s in inner.split("\n")).strip()
        i += 1
    return ""


# ---- file aliases -----------------------------------------------------------
RPC = "backend/src/app/rpc.clj"
PERM = "backend/src/app/rpc/permissions.clj"
TEAMS = "backend/src/app/rpc/commands/teams.clj"
PROJ = "backend/src/app/rpc/commands/projects.clj"
FILES = "backend/src/app/rpc/commands/files.clj"
FC = "backend/src/app/rpc/commands/files_create.clj"
FU = "backend/src/app/rpc/commands/files_update.clj"
FSH = "backend/src/app/rpc/commands/files_share.clj"
FSN = "backend/src/app/rpc/commands/files_snapshot.clj"
BFC = "backend/src/app/binfile/common.clj"
WEBH = "backend/src/app/rpc/commands/webhooks.clj"
FONTS = "backend/src/app/rpc/commands/fonts.clj"
TINV = "backend/src/app/rpc/commands/teams_invitations.clj"
MGMT = "backend/src/app/rpc/commands/management.clj"
BIN = "backend/src/app/rpc/commands/binfile.clj"
MEDIA = "backend/src/app/rpc/commands/media.clj"
PROF = "backend/src/app/rpc/commands/profile.clj"
AUTH = "backend/src/app/rpc/commands/auth.clj"
AT = "backend/src/app/rpc/commands/access_token.clj"
COMM = "backend/src/app/rpc/commands/comments.clj"
VT = "backend/src/app/rpc/commands/verify_token.clj"
ER = "backend/src/app/rpc/commands/error_reports.clj"
AUD = "backend/src/app/rpc/commands/audit.clj"
FB = "backend/src/app/rpc/commands/feedback.clj"
TTEAM = "common/src/app/common/types/team.cljc"

# ---- shared blocks ------------------------------------------------------------
# wrap-authentication: ::auth true (default) requires a session/token profile-id; ::auth false = anonymous allowed
WRAP_AUTH = block(RPC, 163, 198, elide=[(178, 196)])
WRAP_AUTH_FULL = block(RPC, 163, 198)
ADMIN_PRED = block(PERM, 52, 58)
EDIT_PRED = block(PERM, 60, 66)
CHECK_FN = block(PERM, 86, 94)
TEAM_SQL_PERMS = block(TEAMS, 41, 61)          # sql:team-permissions + get-permissions (team_profile_rel row)
TEAM_PREDS = block(TEAMS, 68, 81)              # has-admin/edit/read-permissions? + check-*-permissions!
TEAM_PROCESS_PERMS = block(TEAMS, 163, 174)    # process-permissions (perms attached to team row by get-team)
PROJ_PERMS = block(PROJ, 31, 64)               # sql:project-permissions + get-permissions
PROJ_PREDS = block(PROJ, 71, 78)               # has-edit/read-permissions? + check-edition-permissions!
FILE_PREDS = block(FILES, 83, 93, elide=[(86, 91)])  # has-edit-permissions? (bfc/get-file-permissions) + check-edition-permissions!
FILE_SQL_PERMS = block(BFC, 343, 399)          # sql:file-permissions + get-file-permissions 1-arity (membership only)
ROLE_FLAGS = block(TTEAM, 14, 18)              # permissions-for-role

SEC = [{"sessionCookie": []}]
SEC_SCHEMES = {
    "sessionCookie": {
        "type": "apiKey", "in": "cookie", "name": "auth-token",
        "description": "Penpot session cookie (app.http.session) or Authorization: Token <access-token>",
    }
}

TYPES = {"uuid": {"type": "string", "format": "uuid"}, "string": {"type": "string"},
         "boolean": {"type": "boolean"}, "integer": {"type": "integer"}, "object": {"type": "object"},
         "uri": {"type": "string", "format": "uri"}, "email": {"type": "string", "format": "email"},
         "datetime": {"type": "string", "format": "date-time"}}


def body(fields):
    """fields: list of (key, type, required[, items_type]) built from the command's ::sm/params [:map ...]."""
    props = {}
    req = []
    for f in fields:
        key, typ, required = f[0], f[1], f[2]
        if typ == "array":
            schema = {"type": "array", "items": dict(TYPES[f[3]]) if len(f) > 3 else {}}
        else:
            schema = dict(TYPES[typ])
        props[key] = schema
        if required:
            req.append(key)
    schema = {"type": "object", "properties": props}
    if req:
        schema["required"] = req
    return {"required": True, "content": {"application/json": {"schema": schema}}}


records = []


def add(name, summary, blocks, label, conf, evidence, reason, auth_summary,
        fields=(), anonymous=False, permission_doc="", response_fields=None, _out=None):
    path = f"/api/rpc/command/{name}"
    texts = [b["text"] for b in blocks]
    controller_text = "\n\n".join(texts)
    locs = [{"file": b["file"], "start_line": b["start_line"], "end_line": b["end_line"]} for b in blocks]
    op = {
        "operationId": "rpc_" + name.replace("-", "_"),
        "summary": summary,
        "description": f"Penpot RPC command `{name}` (sv/defmethod ::{name}); body keys from ::sm/params. "
                       + ("Metadata ::rpc/auth false: anonymous allowed." if anonymous
                          else "profile-id is injected from the session/access token, not a body key."),
        "parameters": [],
        "requestBody": body(fields),
        "responses": {"200": {"description": "OK"}, "400": {"description": "Validation error"},
                      "401": {"description": "authentication-required"},
                      "404": {"description": "object-not-found (permission check failed)"}},
        "security": [] if anonymous else SEC,
    }
    rec = {
        "project": PROJECT, "service": SERVICE, "repository": REPO_URL,
        "commit": COMMIT, "tag": TAG, "license": LICENSE,
        "method": "POST", "path": path, "oas_status": "generated",
        "oas_operation": op,
        "oas_global_security": [],
        "oas_security_schemes": {} if anonymous else SEC_SCHEMES,
        "response_schema_fields": response_fields or [],
        "controller_text": controller_text,
        "source_locations": locs,
        "auth_summary": auth_summary,
        "permission_doc": permission_doc,
        "draft_label": label, "draft_confidence": conf,
        "evidence": evidence, "draft_reason": reason,
        "known_vulnerable": False, "advisory": None, "fix_commit": None,
    }
    (records if _out is None else _out).append(rec)


# shorthand evidence for the three membership-only permission providers
EV_TEAM_EDIT = [ev(TEAMS, 80, 81), ev(TEAMS, 57, 61)]
EV_TEAM_ROWS = ev(TEAMS, 41, 49)
EV_PROJ_EDIT = [ev(PROJ, 77, 78), ev(PROJ, 60, 64)]
EV_FILE_EDIT = [ev(FILES, 92, 93), ev(BFC, 393, 399)]
EV_EDIT_PRED = ev(PERM, 64, 66)

R_TEAM_EDIT = ("teams/check-edition-permissions!는 get-permissions(team_profile_rel에서 (profile_id, team_id) 행 조회)의 "
               ":can-edit = is_owner OR is_admin OR can_edit 플래그를 요구한다. 구성원 확인 뒤 팀 안 역할(editor 이상)이 "
               "결정 조건이므로 role_required(G3). 조직 소유자 viewer 경로는 read 전용이며 edition 검사에는 없다.")
R_PROJ_EDIT = ("projects/check-edition-permissions!는 sql:project-permissions(프로젝트 소속 팀의 team_profile_rel 또는 "
               "project_profile_rel 행)의 :can-edit = is_owner OR is_admin OR can_edit를 요구한다. 구성원 확인 뒤 "
               "팀/프로젝트 안 역할이 결정 조건이므로 role_required(G3).")
R_FILE_EDIT = ("files/check-edition-permissions!는 bfc/get-file-permissions(file_profile_rel·team_profile_rel·"
               "project_profile_rel 행, 모두 팀 구성원 존재 조건)의 :can-edit = is_owner OR is_admin OR can_edit를 "
               "요구한다. 구성원 확인 뒤 역할 플래그가 결정 조건이므로 role_required(G3). 조직 소유자 OR 경로는 "
               "read 전용 get-file-read-permissions에만 있고 edition에는 없다.")

A_TEAM_EDIT = "::auth 기본(세션/토큰 필수) → teams/check-edition-permissions!: team_profile_rel.can_edit|is_admin|is_owner"
A_PROJ_EDIT = "::auth 기본 → projects/check-edition-permissions!: 팀/프로젝트 profile_rel.can_edit|is_admin|is_owner"
A_FILE_EDIT = "::auth 기본 → files/check-edition-permissions!: bfc/get-file-permissions can_edit|is_admin|is_owner (membership only)"

# ============================================================================
# role_required — team-level edition (teams/check-edition-permissions!)
# ============================================================================
add("update-team", "Rename a team",
    [block(TEAMS, 719), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(TEAMS, 725)] + EV_TEAM_EDIT + [EV_EDIT_PRED],
    "update-team은 check-edition-permissions!(conn profile-id id)로 팀 구성원 행의 can-edit(is_owner OR is_admin OR can_edit)를 요구한다. " + R_TEAM_EDIT,
    A_TEAM_EDIT, fields=[("name", "string", True), ("id", "uuid", True)])

add("create-project", "Create a project in a team",
    [block(PROJ, 214), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(PROJ, 220)] + EV_TEAM_EDIT + [EV_EDIT_PRED],
    "create-project는 teams/check-edition-permissions!(team-id)를 먼저 통과해야 한다(그 뒤 quota 검사). " + R_TEAM_EDIT,
    A_TEAM_EDIT, fields=[("team-id", "uuid", True), ("name", "string", True), ("id", "uuid", False)],
    response_fields=["id", "name", "team-id", "is-default", "is-pinned"])

add("create-webhook", "Create a team webhook",
    [block(WEBH, 117), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(WEBH, 121)] + EV_TEAM_EDIT + [EV_EDIT_PRED],
    "create-webhook은 t/check-edition-permissions!(pool profile-id team-id)로 팀 can-edit를 요구한다. " + R_TEAM_EDIT,
    A_TEAM_EDIT, fields=[("team-id", "uuid", True), ("uri", "uri", True), ("mtype", "string", True)],
    response_fields=["id", "team-id", "uri", "mtype", "is-active", "profile-id"])

add("create-font-variant", "Upload a team font variant",
    [block(FONTS, 136), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(FONTS, 148)] + EV_TEAM_EDIT + [EV_EDIT_PRED],
    "create-font-variant는 teams/check-edition-permissions!(pool profile-id team-id)를 먼저 요구하고, 그 뒤 font-id의 팀 일치·quota를 검사한다. " + R_TEAM_EDIT,
    A_TEAM_EDIT,
    fields=[("team-id", "uuid", True), ("font-id", "uuid", True), ("font-family", "string", True),
            ("font-weight", "integer", True), ("font-style", "string", True), ("uploads", "object", True)],
    permission_doc="", response_fields=["id", "team-id", "font-id", "font-family", "font-weight", "font-style"])

add("permanently-delete-team-files", "Permanently delete files of a team",
    [block(FILES, 1276), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(FILES, 1285), ev(FILES, 1277, 1279)] + EV_TEAM_EDIT,
    "permanently-delete-team-files는 teams/check-edition-permissions!(pool profile-id team-id)를 요구하고 docstring도 team-id로 writable 권한을 검사한다고 명시한다. " + R_TEAM_EDIT,
    A_TEAM_EDIT, fields=[("team-id", "uuid", True), ("ids", "array", True, "uuid")],
    permission_doc=docstring(FILES, 1276))

add("move-project", "Move a project to another team",
    [block(MGMT, 403), block(MGMT, 344, elide=[(374, 394)]), TEAM_SQL_PERMS, TEAM_PREDS, EDIT_PRED],
    "role_required", 0.85,
    [ev(MGMT, 371, 372)] + EV_TEAM_EDIT,
    "move-project는 원 팀과 대상 팀 둘 다에 teams/check-edition-permissions!를 요구한다(동일 유형 조건 2회, 모두 팀 안 can-edit 역할). "
    "그 뒤 teams/get-team으로 팀 호환성만 검사한다. " + R_TEAM_EDIT,
    A_TEAM_EDIT + " (원 팀·대상 팀 모두)", fields=[("team-id", "uuid", True), ("project-id", "uuid", True)],
    permission_doc=docstring(MGMT, 344) and "Permission checks on both source and destination teams")

# ============================================================================
# role_required — team admin/owner flags read directly from get-permissions
# ============================================================================
add("update-team-member-role", "Change a team member's role",
    [block(TEAMS, 958), block(TEAMS, 899, elide=[(931, 949)]), TEAM_SQL_PERMS, ROLE_FLAGS],
    "role_required", 0.9,
    [ev(TEAMS, 905, 909), ev(TEAMS, 917, 919), ev(TEAMS, 927, 929), EV_TEAM_ROWS],
    "update-team-member-role은 get-permissions(team_profile_rel 행)의 is-owner OR is-admin이 없으면 insufficient-permissions로 거부하고, "
    "owner 승격은 is-owner만 가능하다. 구성원 확인 뒤 팀 안 역할(admin 이상)이 결정 조건이므로 role_required(G3).",
    "::auth 기본 → get-permissions: team_profile_rel.is_owner OR is_admin; owner 승격은 is_owner만",
    fields=[("team-id", "uuid", True), ("member-id", "uuid", True), ("role", "string", True)])

add("delete-team-member", "Remove a member from a team",
    [block(TEAMS, 971, elide=[(998, 1016)]), TEAM_SQL_PERMS],
    "role_required", 0.85,
    [ev(TEAMS, 977), ev(TEAMS, 980, 983), ev(TEAMS, 985, 987), ev(TEAMS, 993, 996)],
    "delete-team-member는 get-permissions(team_profile_rel 행)의 is-owner OR is-admin을 요구하고, 자기 자신 제거는 거부, owner 제거는 is-owner만 가능하다. "
    "팀 안 역할(admin 이상)이 결정 조건이므로 role_required(G3). 976행 get-team은 팀 이름 조회용이며(조직 소유자 viewer 폴백 포함) 허용 결정은 977행 perms가 한다.",
    "::auth 기본 → get-permissions: is_owner OR is_admin; self 제거 거부; owner 제거는 is_owner만",
    fields=[("team-id", "uuid", True), ("member-id", "uuid", True)])

add("create-team-invitations", "Invite emails to a team",
    [block(TINV, 450, elide=[(462, 475), (499, 532)]), TEAM_SQL_PERMS],
    "role_required", 0.85,
    [ev(TINV, 460), ev(TINV, 477, 479), ev(TINV, 493, 497), EV_TEAM_ROWS],
    "create-team-invitations는 teams/get-permissions(team_profile_rel 행)의 :is-admin이 아니면 insufficient-permissions로 거부하고, owner 역할 초대는 is-owner만 가능하다. "
    "팀 안 역할(admin 이상)이 결정 조건이므로 role_required(G3). admin-console 플래그가 켜진 조직 팀에서는 추가로 조직 정책(cto/allowed? :send-invitations)이 AND로 붙지만 기본 경로는 is-admin 단일 조건이다.",
    "::auth 기본 → teams/get-permissions :is-admin 필수; owner 초대는 :is-owner; (플래그) 조직 정책 추가",
    fields=[("team-id", "uuid", True), ("emails", "array", False, "email"), ("role", "string", False),
            ("invitations", "array", False, "object")],
    response_fields=["total", "invitations"])

add("delete-team-invitation", "Delete a pending team invitation",
    [block(TINV, 660), TEAM_SQL_PERMS],
    "role_required", 0.9,
    [ev(TINV, 665), ev(TINV, 667, 669), EV_TEAM_ROWS],
    "delete-team-invitation은 teams/get-permissions(team_profile_rel 행)의 :is-admin(= is_owner OR is_admin)이 아니면 거부한다. 팀 안 역할이 결정 조건이므로 role_required(G3).",
    "::auth 기본 → teams/get-permissions :is-admin 필수",
    fields=[("team-id", "uuid", True), ("email", "email", True)])

add("update-team-photo", "Upload a team photo",
    [block(TEAMS, 1029), block(TEAMS, 1039, elide=[(1046, 1055)]), TEAM_SQL_PERMS, TEAM_PREDS, ADMIN_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(TEAMS, 1044), ev(TEAMS, 77, 78), ev(TEAMS, 58, 59), ev(PERM, 56, 58)],
    "update-team-photo는 check-admin-permissions!(pool profile-id team-id)로 team_profile_rel 행의 :is-admin(= is_owner OR is_admin)을 요구한다. "
    "팀 안 역할(admin 이상)이 결정 조건이므로 role_required(G3). 1041행 get-team은 사진 id 조회용이다.",
    "::auth 기본 → teams/check-admin-permissions!: team_profile_rel.is_admin|is_owner",
    fields=[("team-id", "uuid", True), ("file", "object", True)])

add("delete-font", "Delete a team font family",
    [block(FONTS, 272, elide=[(293, 307)]), TEAM_SQL_PERMS, TEAM_PROCESS_PERMS, TEAM_PREDS, EDIT_PRED],
    "role_required", 0.8,
    [ev(FONTS, 278, 280), ev(FONTS, 291), ev(TEAMS, 168, 171), ev(PERM, 64, 66)],
    "delete-font는 teams/get-team으로 얻은 팀 행의 :permissions(team_profile_rel의 is_owner/is_admin/can_edit → process-permissions)에 "
    "check-edition-permissions!의 1-인자 형태(:can-edit)를 적용한다. 구성원 확인 뒤 팀 안 역할이 결정 조건이므로 role_required(G3). "
    "get-team의 조직 소유자 viewer 폴백은 can-edit false로 만들어져 이 검사를 통과하지 못하므로 결정 조건은 구성원 can-edit 그대로다.",
    "::auth 기본 → get-team 팀 행 permissions → check-edition-permissions! (:can-edit)",
    fields=[("team-id", "uuid", True), ("id", "uuid", True)])

add("delete-webhook", "Delete a team webhook",
    [block(WEBH, 146), block(WEBH, 25, 35), TEAM_SQL_PERMS],
    "role_required", 0.9,
    [ev(WEBH, 152), ev(WEBH, 27, 29), ev(WEBH, 31, 35), EV_TEAM_ROWS],
    "delete-webhook은 webhook 행의 team-id로 check-webhook-edition-permissions!를 적용하며, 이는 t/get-permissions(team_profile_rel 행)의 :can-edit를 "
    "make-edition-predicate-fn으로 검사한다. 구성원 확인 뒤 팀 안 역할(editor 이상)이 결정 조건이므로 role_required(G3).",
    "::auth 기본 → check-webhook-edition-permissions!: team_profile_rel.can_edit|is_admin|is_owner (webhook.team_id)",
    fields=[("id", "uuid", True)])

add("delete-team", "Mark a team for deletion",
    [block(TEAMS, 888), block(TEAMS, 836, elide=[(867, 881)]), TEAM_PROCESS_PERMS, TEAM_SQL_PERMS],
    "role_required", 0.5,
    [ev(TEAMS, 847, 854), ev(TEAMS, 856, 858), ev(TEAMS, 168, 171)],
    "EXCLUDE 후보: 허용 주체가 설정 플래그에 따라 바뀐다. admin-console 플래그가 꺼진 기본 경로는 (boolean (:is-owner perms))로 팀 owner만 삭제할 수 있어 "
    "role_required(G3)이지만, 플래그가 켜져 팀이 조직에 속하면 cto/allowed? :delete-team(조직 소유자/조직 권한 + 팀 perms)이 결정한다. "
    "G6 '조직 설정에 따라 허용 주체가 바뀜'에 해당할 수 있어 검수자가 EXCLUDE(G8) 또는 manual 판단. 기본 경로 기준 초안은 role_required.",
    "::auth 기본 → 기본: team perms :is-owner만; (admin-console 플래그·조직 팀) cto/allowed? :delete-team",
    fields=[("id", "uuid", True)])

# ============================================================================
# role_required — project-level edition (projects/check-edition-permissions!)
# ============================================================================
add("rename-project", "Rename a project",
    [block(PROJ, 265), PROJ_PERMS, PROJ_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(PROJ, 272)] + EV_PROJ_EDIT + [EV_EDIT_PRED],
    "rename-project는 check-edition-permissions!(conn profile-id id)로 프로젝트 권한 행의 can-edit를 요구한다. " + R_PROJ_EDIT,
    A_PROJ_EDIT, fields=[("name", "string", True), ("id", "uuid", True)])

add("delete-project", "Mark a project for deletion",
    [block(PROJ, 309), PROJ_PERMS, PROJ_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(PROJ, 316)] + EV_PROJ_EDIT + [EV_EDIT_PRED],
    "delete-project는 check-edition-permissions!(conn profile-id id)를 먼저 요구하고, 그 뒤 teams/get-team은 삭제 지연 계산용 팀 조회다. " + R_PROJ_EDIT,
    A_PROJ_EDIT, fields=[("id", "uuid", True)])

add("create-file", "Create a file in a project",
    [block(FC, 82, elide=[(95, 139)]), PROJ_PERMS, PROJ_PREDS, EDIT_PRED, CHECK_FN],
    "role_required", 0.9,
    [ev(FC, 89)] + EV_PROJ_EDIT + [EV_EDIT_PRED],
    "create-file은 projects/check-edition-permissions!(conn profile-id project-id)를 먼저 요구한다(이후 get-team은 feature 계산용). " + R_PROJ_EDIT,
    A_PROJ_EDIT,
    fields=[("name", "string", True), ("project-id", "uuid", True), ("id", "uuid", False),
            ("is-shared", "boolean", False), ("features", "array", False, "string")],
    response_fields=["id", "name", "project-id", "revn", "vern", "is-shared", "features"])

add("move-files", "Move files to another project",
    [block(MGMT, 334), block(MGMT, 277, elide=[(299, 325)]), PROJ_PERMS, PROJ_PREDS],
    "role_required", 0.85,
    [ev(MGMT, 293), ev(MGMT, 296, 297)] + EV_PROJ_EDIT,
    "move-files는 대상 프로젝트와 모든 원 프로젝트에 proj/check-edition-permissions!를 요구한다(같은 유형 조건의 반복). " + R_PROJ_EDIT,
    A_PROJ_EDIT + " (대상·원 프로젝트 모두)", fields=[("ids", "array", True, "uuid"), ("project-id", "uuid", True)])

add("import-binfile", "Import a penpot binary file into a project",
    [block(BIN, 139, elide=[(157, 183)]), PROJ_PERMS, PROJ_PREDS, EDIT_PRED],
    "role_required", 0.9,
    [ev(BIN, 156)] + EV_PROJ_EDIT,
    "import-binfile은 projects/check-edition-permissions!(pool profile-id project-id)를 먼저 요구한다. " + R_PROJ_EDIT,
    A_PROJ_EDIT,
    fields=[("name", "string", True), ("project-id", "uuid", True), ("version", "integer", False),
            ("file", "object", False), ("upload-id", "uuid", False)])

# ============================================================================
# role_required — file-level edition (files/check-edition-permissions! / bfc/get-file-permissions)
# ============================================================================
add("rename-file", "Rename a file",
    [block(FILES, 874, elide=[(879, 898)]), FILE_PREDS, FILE_SQL_PERMS, EDIT_PRED],
    "role_required", 0.9,
    [ev(FILES, 901), ev(FILES, 83, 84)] + EV_FILE_EDIT,
    "rename-file은 check-edition-permissions!(conn profile-id id)로 파일 권한 행의 can-edit를 요구한다. " + R_FILE_EDIT,
    A_FILE_EDIT, fields=[("name", "string", True), ("id", "uuid", True)],
    response_fields=["id", "name", "created-at", "modified-at"])

add("update-file", "Apply changes to a file",
    [block(FU, 132, elide=[(134, 140), (152, None)]), FILE_PREDS, FILE_SQL_PERMS, EDIT_PRED],
    "role_required", 0.9,
    [ev(FU, 149), ev(FILES, 83, 84)] + EV_FILE_EDIT,
    "update-file은 files/check-edition-permissions!(conn profile-id id)를 먼저 요구한 뒤 파일을 잠그고 변경을 적용한다. " + R_FILE_EDIT,
    A_FILE_EDIT,
    fields=[("id", "uuid", True), ("session-id", "uuid", True), ("revn", "integer", True), ("vern", "integer", True),
            ("features", "array", False, "string"), ("changes", "array", False, "object"),
            ("changes-with-metadata", "array", False, "object"), ("skip-validate", "boolean", False)],
    response_fields=["changes", "file-id", "id", "revn", "session-id"])

add("delete-file", "Mark a file for deletion",
    [block(FILES, 1090), block(FILES, 1069, elide=[(1076, 1087)]), FILE_PREDS, FILE_SQL_PERMS],
    "role_required", 0.9,
    [ev(FILES, 1071)] + EV_FILE_EDIT,
    "delete-file은 check-edition-permissions!(conn profile-id id)를 먼저 요구하고 그 뒤 teams/get-team은 삭제 지연 계산용이다. " + R_FILE_EDIT,
    A_FILE_EDIT, fields=[("id", "uuid", True)])

add("set-file-shared", "Toggle the shared-library flag of a file",
    [block(FILES, 1034), block(FILES, 980, elide=[(983, 1025)]), FILE_PREDS, FILE_SQL_PERMS],
    "role_required", 0.9,
    [ev(FILES, 982)] + EV_FILE_EDIT,
    "set-file-shared는 check-edition-permissions!(conn profile-id id)를 먼저 요구한다. " + R_FILE_EDIT,
    A_FILE_EDIT, fields=[("id", "uuid", True), ("is-shared", "boolean", True)],
    response_fields=["id", "name", "is-shared"])

add("link-file-to-library", "Link a file to a shared library",
    [block(FILES, 1137, elide=[(1145, 1148), (1154, 1158)]), FILE_PREDS, FILE_SQL_PERMS],
    "role_required", 0.85,
    [ev(FILES, 1150, 1152)] + EV_FILE_EDIT,
    "link-file-to-library는 파일과 라이브러리 둘 다에 check-edition-permissions!를 요구하고(같은 유형 조건 2회) 두 파일이 같은 팀인지 확인한다. " + R_FILE_EDIT,
    A_FILE_EDIT + " (file·library 모두)", fields=[("file-id", "uuid", True), ("library-id", "uuid", True)])

add("create-share-link", "Create a share link for a file",
    [block(FSH, 31), FILE_PREDS, FILE_SQL_PERMS, EDIT_PRED],
    "role_required", 0.9,
    [ev(FSH, 41)] + EV_FILE_EDIT,
    "create-share-link는 files/check-edition-permissions!(conn profile-id file-id)를 요구한다. " + R_FILE_EDIT,
    A_FILE_EDIT,
    fields=[("file-id", "uuid", True), ("who-comment", "string", True), ("who-inspect", "string", True),
            ("pages", "array", True, "uuid")],
    response_fields=["id", "file-id", "who-comment", "who-inspect", "pages", "owner-id"])

add("upload-file-media-object", "Upload a media object into a file",
    [block(MEDIA, 59, elide=[(66, 97)]), FILE_PREDS, FILE_SQL_PERMS, EDIT_PRED],
    "role_required", 0.9,
    [ev(MEDIA, 65)] + EV_FILE_EDIT,
    "upload-file-media-object는 files/check-edition-permissions!(pool profile-id file-id)를 먼저 요구한다. " + R_FILE_EDIT,
    A_FILE_EDIT,
    fields=[("id", "uuid", False), ("file-id", "uuid", True), ("is-local", "boolean", True),
            ("name", "string", True), ("content", "object", True)],
    response_fields=["id", "file-id", "is-local", "name", "media-id", "thumbnail-id", "width", "height", "mtype"])

add("create-file-snapshot", "Create a named snapshot (version) of a file",
    [block(FSN, 83, elide=[(90, 103)]), FILE_PREDS, FILE_SQL_PERMS],
    "role_required", 0.9,
    [ev(FSN, 89)] + EV_FILE_EDIT,
    "create-file-snapshot은 files/check-edition-permissions!(cfg profile-id file-id)를 먼저 요구하고 그 뒤 quota를 검사한다. " + R_FILE_EDIT,
    A_FILE_EDIT, fields=[("file-id", "uuid", True), ("label", "string", False)])

# ============================================================================
# owner_or_admin
# ============================================================================
add("delete-share-link", "Delete a share link",
    [block(FSH, 63, elide=[(72, 74)]), FILE_PREDS, FILE_SQL_PERMS],
    "owner_or_admin", 0.6,
    [ev(FSH, 70), ev(FSH, 72, 77), ev(BFC, 393, 397)],
    "delete-share-link는 먼저 files/check-edition-permissions!(can-edit)를 통과한 뒤, share-link의 owner-id == profile-id(작성자 본인) OR "
    "bfc/get-file-permissions의 :is-admin(= is_owner OR is_admin)을 요구한다. 작성자 본인 OR 관리자 우회가 실제 조건이므로 owner_or_admin(G5). "
    "단, can-edit가 AND로 선행하므로(관리자는 항상 can-edit) 엄밀히는 '관리자 OR (작성자 AND 편집 권한)'이며, AND 결합을 중시하면 manual_review_required가 대안이다.",
    "::auth 기본 → check-edition-permissions!(can_edit) AND (share_link.owner_id == profile-id OR perms.is-admin)",
    fields=[("id", "uuid", True)])

# ============================================================================
# manual_review_required
# ============================================================================
add("lock-file-snapshot", "Lock a user-created file version",
    [block(FSN, 205, elide=[(213, 218), (229, 237)]), FILE_PREDS, FILE_SQL_PERMS],
    "manual_review_required", 0.7,
    [ev(FSN, 211), ev(FSN, 213, 214), ev(FSN, 220, 227)],
    "lock-file-snapshot은 files/check-edition-permissions!(파일 can-edit 역할) AND snapshot의 :profile-id == profile-id(버전 작성자 본인)를 "
    "모두 요구한다. 역할 조건과 소유자 조건이 독립 필수 조건으로 AND 결합돼 하나를 버려야 단일 라벨이 되므로 보류(프롬프트 '보류가 필수인 경우' 3). "
    "대안: owner_match(작성자 조건 중심) 또는 role_required.",
    "::auth 기본 → check-edition-permissions!(can_edit) AND snapshot.profile_id == profile-id AND created_by = user",
    fields=[("id", "uuid", True)])

add("delete-file-snapshot", "Delete a user-created file version",
    [block(FSN, 170, elide=[(178, 183), (193, 196)]), FILE_PREDS, FILE_SQL_PERMS],
    "manual_review_required", 0.6,
    [ev(FSN, 176), ev(FSN, 178, 180), ev(FSN, 185, 187)],
    "delete-file-snapshot은 files/check-edition-permissions!(can-edit 역할)를 요구하고, 추가로 system 스냅샷은 거부하며 다른 사용자가 잠근 버전은 "
    "(:locked-by snapshot) != profile-id이면 거부한다. 역할 조건 AND '잠금 소유자 본인' 조건이 결합돼 단일 라벨로 표현되지 않아 보류. 대안: role_required(잠기지 않은 버전 기준).",
    "::auth 기본 → check-edition-permissions!(can_edit) AND (locked_by IS NULL OR locked_by == profile-id)",
    fields=[("id", "uuid", True)])

add("create-team-access-request", "Request access to a team (non-member)",
    [block(TINV, 746, elide=[(768, 804)]), WRAP_AUTH],
    "manual_review_required", 0.75,
    [ev(TINV, 752, 753), ev(TINV, 755, 759), ev(TINV, 778), ev(RPC, 173, 176)],
    "create-team-access-request는 인증(profile-id)만 요구하고 요청자와 대상 팀의 구성원 관계·역할 검사가 없다(비구성원이 접근을 요청하는 기능). "
    "팀 소유자에게 메일을 보내고 team_access_request 행을 만든다. 인증만 확인하고 요청자-객체 관계 검사가 없으므로 manual_review_required(G6).",
    "::auth 기본(인증만) → 팀/파일 조회 후 team_access_request upsert, 구성원·역할 검사 없음",
    fields=[("file-id", "uuid", False), ("team-id", "uuid", False), ("is-viewer", "boolean", False)],
    permission_doc="")

add("send-user-feedback", "Send user feedback email",
    [block(FB, 32), WRAP_AUTH],
    "manual_review_required", 0.75,
    [ev(FB, 37, 41), ev(FB, 43), ev(RPC, 173, 176)],
    "send-user-feedback은 인증(profile-id)과 user-feedback 플래그만 확인하고 대상 객체가 없다(본인 프로필 이메일로 피드백 메일 발송). "
    "인증만 확인·객체 없음이므로 manual_review_required(G6).",
    "::auth 기본(인증만) + cf/flags :user-feedback; 객체 없음",
    fields=[("subject", "string", True), ("content", "string", True), ("type", "string", False),
            ("error-href", "string", False), ("error-report", "string", False)])

add("push-audit-events", "Push frontend audit events",
    [block(AUD, 159), WRAP_AUTH],
    "manual_review_required", 0.7,
    [ev(AUD, 159, 165), ev(RPC, 173, 176)],
    "push-audit-events는 ::auth 기본(인증 필수) 외에 어떤 인가 검사도 없고 대상 객체도 없다(audit-log/telemetry 플래그가 켜져 있으면 이벤트 저장). "
    "인증만 확인·객체 없음이므로 manual_review_required(G6).",
    "::auth 기본(인증만); 객체 없음; 플래그에 따라 저장",
    fields=[("events", "array", True, "object")])

add("logout", "Logout the current session",
    [block(AUTH, 142), WRAP_AUTH],
    "manual_review_required", 0.5,
    [ev(AUTH, 144), ev(AUTH, 149, 150), ev(AUTH, 168)],
    "EXCLUDE 후보: public/owner_match 경계. ::rpc/auth false로 익명 호출이 허용되지만 익명이면 {}만 반환하고, 본문 profile-id가 세션의 "
    "::rpc/profile-id와 같을 때만 자기 세션을 삭제한다. 익명 허용은 조건부(no-op)라 G7 public이 아니고, 실제 효과는 본인 세션에 고정돼 owner_match로 볼 수도 있다. "
    "객체 없는 인증 절차로 보면 manual. 검수자 판단 필요.",
    "::rpc/auth false; params.profile-id == 세션 profile-id일 때만 세션 삭제, 아니면 {}",
    fields=[("profile-id", "uuid", False)], anonymous=True)

add("get-error-reports", "List server error reports (access-token perm)",
    [block(ER, 144, elide=[(151, 164)]), WRAP_AUTH_FULL],
    "manual_review_required", 0.5,
    [ev(ER, 146, 147), ev(RPC, 184, 195)],
    "EXCLUDE 후보: 역할과 토큰 스코프의 경계. ::rpc/auth-type :token과 ::rpc/perms #{\"error-reports:read\"}로 access-token 인증이면서 토큰에 "
    "운영자가 SQL/REPL로만 부여하는 권한 문자열이 있어야 한다(access_token.clj: 공개 API로는 부여 불가). 객체 없는 기능에 권한 문자열만 있는 경우라 "
    "G3 role_required로 볼 수도 있으나, 사용자 역할이 아닌 토큰 스코프이고(GlitchTip has_permission 선례는 근거 제외) 6종 의미와 정확히 맞지 않아 보류.",
    "::rpc/auth-type :token AND token perms ⊇ #{error-reports:read} (운영자 부여)",
    fields=[("since", "datetime", False), ("since-id", "uuid", False), ("limit", "integer", False),
            ("source", "string", False), ("kind", "string", False), ("until", "datetime", False)],
    response_fields=["items", "next-since", "next-id"])

# ============================================================================
# public — ::rpc/auth false, unconditional anonymous
# ============================================================================
R_PUBLIC = ("메타데이터 ::rpc/auth false로 wrap-authentication의 required-auth?가 false가 되어 profile-id 없이(익명) 호출할 수 있고, "
            "핸들러 안에 요청자 관계·역할 검사가 없다. 조건 없는 익명 허용이 코드로 드러나므로 public(G7).")

add("login-with-password", "Login with email and password",
    [block(AUTH, 127), block(AUTH, 55, elide=[(64, 118)]), WRAP_AUTH],
    "public", 0.95,
    [ev(AUTH, 129), ev(RPC, 165), ev(RPC, 173, 176)],
    "login-with-password는 " + R_PUBLIC + " 자격 증명 검증은 인증 절차이지 인가 조건이 아니다(login 플래그 비활성 시 전체 거부).",
    "::rpc/auth false(익명); email/password 검증 후 세션 쿠키 발급",
    fields=[("email", "email", True), ("password", "string", True), ("invitation-token", "string", False)],
    anonymous=True, response_fields=["id", "email", "fullname", "is-admin"])

add("prepare-register-profile", "Prepare registration (issue register token)",
    [block(AUTH, 312), block(AUTH, 258, elide=[(263, 301)]), block(AUTH, 206, 213), WRAP_AUTH],
    "public", 0.9,
    [ev(AUTH, 313), ev(AUTH, 261), ev(RPC, 165)],
    "prepare-register-profile은 " + R_PUBLIC + " registration 플래그가 꺼져 있으면 전부 거부하지만 이는 기능 활성화 조건이지 요청자 인가가 아니다.",
    "::rpc/auth false(익명); registration 플래그·이메일 검증 후 prepared-register 토큰 발급",
    fields=[("fullname", "string", True), ("email", "email", True), ("password", "string", True),
            ("accept-newsletter-updates", "boolean", False), ("invitation-token", "string", False)],
    anonymous=True, response_fields=["token"])

add("register-profile", "Register a profile from a prepared token",
    [block(AUTH, 582), block(AUTH, 445, elide=[(448, 574)]), WRAP_AUTH],
    "public", 0.9,
    [ev(AUTH, 583), ev(AUTH, 447), ev(RPC, 165)],
    "register-profile은 " + R_PUBLIC + " prepared-register 토큰 검증은 익명 등록 절차의 일부다.",
    "::rpc/auth false(익명); prepared-register 토큰 검증 후 프로필 생성/세션 발급",
    fields=[("token", "string", True), ("accept-newsletter-updates", "boolean", False)],
    anonymous=True, response_fields=["id", "email"])

add("request-profile-recovery", "Request a password recovery email",
    [block(AUTH, 656), block(AUTH, 592, elide=[(594, 614), (618, 642)]), WRAP_AUTH],
    "public", 0.9,
    [ev(AUTH, 657), ev(RPC, 165)],
    "request-profile-recovery는 " + R_PUBLIC + " 이메일로 프로필을 찾아 복구 메일을 보내며 실패 사유는 로그만 남긴다.",
    "::rpc/auth false(익명); email로 프로필 조회 후 복구 토큰 메일 발송",
    fields=[("email", "email", True)], anonymous=True)

add("recover-profile", "Reset password with a recovery token",
    [block(AUTH, 195), block(AUTH, 173), WRAP_AUTH],
    "public", 0.9,
    [ev(AUTH, 196), ev(AUTH, 175, 177), ev(RPC, 165)],
    "recover-profile은 " + R_PUBLIC + " password-recovery 토큰이 가리키는 profile-id의 비밀번호를 바꾸며 토큰 소지가 유일한 조건(인증 절차)이다.",
    "::rpc/auth false(익명); password-recovery 토큰 검증 후 비밀번호 갱신",
    fields=[("token", "string", True), ("password", "string", True)], anonymous=True)

add("verify-token", "Verify an emailed token (email change, verify email, invitation...)",
    [block(VT, 37), block(VT, 31, 31), WRAP_AUTH],
    "public", 0.85,
    [ev(VT, 38), ev(VT, 43, 44), ev(RPC, 165)],
    "verify-token은 " + R_PUBLIC + " 토큰의 :iss에 따라 process-token 멀티메서드로 분기하며 토큰 소지가 유일한 조건이다.",
    "::rpc/auth false(익명); tokens/verify 후 :iss별 process-token",
    fields=[("token", "string", True)], anonymous=True)

add("get-team-info", "Retrieve minimal team info by id (anonymous)",
    [block(TEAMS, 504), block(TEAMS, 497), block(TEAMS, 231, 239), WRAP_AUTH],
    "public", 0.8,
    [ev(TEAMS, 506), ev(TEAMS, 499, 501), ev(RPC, 165)],
    "get-team-info는 " + R_PUBLIC + " 임의 team id의 id·is-default·features를 구성원 여부와 무관하게 반환한다.",
    "::rpc/auth false(익명); team 행 최소 컬럼 조회, 검사 없음",
    fields=[("id", "uuid", False), ("file-id", "uuid", False)], anonymous=True,
    response_fields=["id", "is-default", "features"])

add("get-file-info", "Retrieve minimal file info by id (anonymous)",
    [block(FILES, 852), block(FILES, 846), block(FILES, 146, 150), WRAP_AUTH],
    "public", 0.8,
    [ev(FILES, 854), ev(FILES, 848, 850), ev(RPC, 165)],
    "get-file-info는 " + R_PUBLIC + " 임의 file id의 id·deleted-at를 권한 검사 없이 반환한다.",
    "::rpc/auth false(익명); file 행 최소 컬럼 조회, 검사 없음",
    fields=[("id", "uuid", True), ("features", "array", False, "string")], anonymous=True,
    response_fields=["id", "deleted-at"])

# ============================================================================
# owner_match — self-fixed profile/session resources
# ============================================================================
R_SELF = "처리 대상이 세션의 ::rpc/profile-id(인증 사용자 본인)로 고정되고 관리자 우회가 없으므로 owner_match(G4)."

add("get-profile", "Get own profile (anonymous stub when not logged in)",
    [block(PROF, 120), WRAP_AUTH],
    "owner_match", 0.5,
    [ev(PROF, 121), ev(PROF, 125), ev(PROF, 130), ev(PROF, 136, 137)],
    "EXCLUDE 후보: public/owner_match 경계. ::rpc/auth false로 익명 호출이 허용되며 익명이면 'Anonymous User' 스텁을 반환하고, 로그인 상태면 "
    "세션 profile-id 본인 프로필만 반환한다. 반환 대상은 본인으로 고정돼 owner_match 초안이지만, 조건 없는 익명 허용(스텁)도 코드로 드러나 G7 public 판단도 가능하다.",
    "::rpc/auth false; 세션 profile-id 본인 프로필 반환, 없으면 익명 스텁",
    fields=[], anonymous=True, response_fields=["id", "fullname", "email", "props", "default-team-id", "default-project-id"])

add("update-profile", "Update own profile name/lang/theme",
    [block(PROF, 155, elide=[(165, 176)]), WRAP_AUTH],
    "owner_match", 0.9,
    [ev(PROF, 160), ev(PROF, 164), ev(PROF, 178, 182)],
    "update-profile은 세션 ::rpc/profile-id로 자기 프로필 행을 잠가 갱신한다(db/update! :profile {:id profile-id}). 대상 id는 본문에서 받지 않는다. " + R_SELF,
    "::auth 기본 → 세션 profile-id 행만 갱신",
    fields=[("fullname", "string", True), ("lang", "string", False), ("theme", "string", False)],
    response_fields=["id", "fullname", "email", "lang", "theme"])

add("update-profile-password", "Change own password",
    [block(PROF, 204), block(PROF, 228), block(PROF, 237)],
    "owner_match", 0.9,
    [ev(PROF, 209, 210), ev(PROF, 230, 234), ev(PROF, 240, 242)],
    "update-profile-password는 세션 profile-id의 프로필을 조회해 old-password를 검증하고 같은 행의 비밀번호만 바꾼다. " + R_SELF,
    "::auth 기본 → validate-password!(세션 profile-id, old-password) → 본인 행 갱신",
    fields=[("password", "string", True), ("old-password", "string", False)])

add("update-profile-notifications", "Update own notification settings",
    [block(PROF, 257), block(PROF, 264), WRAP_AUTH],
    "owner_match", 0.9,
    [ev(PROF, 261, 262), ev(PROF, 267), ev(PROF, 278, 281)],
    "update-profile-notifications는 세션 profile-id로 자기 프로필 props의 notifications만 갱신한다. " + R_SELF,
    "::auth 기본 → 세션 profile-id 행의 props.notifications 갱신",
    fields=[("dashboard-comments", "string", True), ("email-comments", "string", True), ("email-invites", "string", True)])

add("update-profile-photo", "Upload own profile photo",
    [block(PROF, 294), block(PROF, 304)],
    "owner_match", 0.9,
    [ev(PROF, 298), ev(PROF, 302), ev(PROF, 308), ev(PROF, 315, 317)],
    "update-profile-photo는 세션 profile-id로 자기 프로필 행을 잠가 photo-id를 갱신한다. " + R_SELF,
    "::auth 기본 → 세션 profile-id 행 photo-id 갱신",
    fields=[("file", "object", True)])

add("delete-profile", "Delete own profile",
    [block(PROF, 498, elide=[(519, 541)]), WRAP_AUTH],
    "owner_match", 0.85,
    [ev(PROF, 501, 502), ev(PROF, 508, 512), ev(PROF, 515, 517), ev(PROF, 540)],
    "delete-profile은 세션 profile-id 본인만 삭제 표시하며(소유 팀에 다른 참가자가 있으면 거부) 본인 세션을 모두 무효화한다. 대상 id를 본문에서 받지 않는다. " + R_SELF,
    "::auth 기본 → 세션 profile-id 본인 삭제; 참가자 있는 소유 팀이면 거부",
    fields=[])

add("update-profile-props", "Update own profile props",
    [block(PROF, 487), block(PROF, 467), WRAP_AUTH],
    "owner_match", 0.9,
    [ev(PROF, 491, 492), ev(PROF, 469), ev(PROF, 480, 483)],
    "update-profile-props는 세션 profile-id로 자기 프로필 props만 병합 갱신한다(system-managed :subscription 키는 무시). " + R_SELF,
    "::auth 기본 → 세션 profile-id 행 props 갱신",
    fields=[("props", "object", True)])

add("request-email-change", "Request change of own email",
    [block(PROF, 381), block(PROF, 395), WRAP_AUTH],
    "owner_match", 0.85,
    [ev(PROF, 384), ev(PROF, 387), ev(PROF, 400, 402)],
    "request-email-change는 세션 profile-id의 프로필을 조회해 그 프로필의 이메일만 바꾸거나(smtp 플래그 꺼짐) 그 프로필 주소로 확인 메일을 보낸다(smtp 켜짐). "
    "어느 분기든 대상은 본인 프로필이다. " + R_SELF,
    "::auth 기본 → 세션 profile-id 프로필 이메일 변경(즉시 또는 확인 메일)",
    fields=[("email", "email", True)], response_fields=["changed"])

add("leave-team", "Leave a team (remove own membership)",
    [block(TEAMS, 825), block(TEAMS, 766, elide=[(785, 806)]), block(TEAMS, 757), TEAM_SQL_PERMS],
    "owner_match", 0.75,
    [ev(TEAMS, 768), ev(TEAMS, 811, 814), ev(TEAMS, 816), ev(TEAMS, 763, 764)],
    "leave-team은 세션 profile-id 자신의 team_profile_rel·project/file 관계 행만 삭제한다(delete-team-rels conn profile-id id). 팀 구성원 행 조회(get-permissions)는 "
    "본인이 owner인지 확인해 owner는 reassign-to로 소유권을 넘기지 않으면 떠날 수 없게 하는 용도다. 처리 대상이 본인 구성원 행으로 고정되므로 owner_match(G4). "
    "reassign-to 분기는 owner만 다른 구성원에게 owner 역할을 넘기므로 그 부분만 보면 역할 조건이 섞인다(대안: manual).",
    "::auth 기본 → 본인 team_profile_rel 행 삭제; owner는 reassign-to 필요",
    fields=[("id", "uuid", True), ("reassign-to", "uuid", False)])

add("get-teams", "List teams the caller belongs to",
    [block(TEAMS, 194), block(TEAMS, 182), block(TEAMS, 126, 136)],
    "owner_match", 0.85,
    [ev(TEAMS, 197, 199), ev(TEAMS, 188), ev(TEAMS, 132, 135)],
    "get-teams는 세션 profile-id로 team_profile_rel을 조인해 본인이 구성원인 팀만 반환한다(WHERE tp.profile_id = ?). 대상 팀 id를 받지 않고 요청자 본인 목록으로 고정되므로 owner_match(G4).",
    "::auth 기본 → sql:get-teams-with-permissions WHERE tp.profile_id = 세션 profile-id",
    fields=[], response_fields=["id", "name", "is-default", "permissions", "features"])

add("get-all-projects", "List projects of teams where the caller can edit",
    [block(PROJ, 126), block(PROJ, 164), block(PROJ, 133, 162, elide=[(145, 161)])],
    "owner_match", 0.8,
    [ev(PROJ, 131), ev(PROJ, 137, 142), ev(PROJ, 166)],
    "get-all-projects는 세션 profile-id가 can_edit/is_owner/is_admin 구성원인 팀·프로젝트의 프로젝트만 반환한다(sql:all-projects, profile_id = ? 두 번). "
    "대상 그룹 id를 받지 않고 요청자 본인의 목록으로 고정되므로 owner_match(G4). (Umami GET /api/teams 선례)",
    "::auth 기본 → sql:all-projects: team_profile_rel/project_profile_rel.profile_id = 세션 profile-id AND 편집 플래그",
    fields=[], response_fields=["id", "name", "team-id", "team-name", "is-default-team"])

add("create-access-token", "Create own personal access token",
    [block(AT, 96), block(AT, 31, elide=[(37, 45), (57, 62)]), WRAP_AUTH],
    "owner_match", 0.85,
    [ev(AT, 99), ev(AT, 104), ev(AT, 46, 51)],
    "create-access-token은 세션 profile-id 명의로 access_token 행을 만든다(:profile-id profile-id, 본문에서 소유자를 받지 않음). 본인 명의 생성이므로 owner_match(G4). quota 검사는 인가 조건이 아니다.",
    "::auth 기본 → access_token.profile_id = 세션 profile-id로 생성",
    fields=[("name", "string", True), ("expiration", "string", False), ("type", "string", False)],
    response_fields=["id", "name", "token", "type", "created-at", "expires-at"])

add("delete-access-token", "Delete own access token",
    [block(AT, 110), WRAP_AUTH],
    "owner_match", 0.9,
    [ev(AT, 113, 114), ev(RPC, 173, 176)],
    "delete-access-token은 db/delete! :access-token {:id id :profile-id profile-id}로 세션 profile-id 소유 토큰만 삭제한다(타인 토큰은 0건). 소유자 == 요청자, 관리자 우회 없음이므로 owner_match(G4).",
    "::auth 기본 → DELETE access_token WHERE id = ? AND profile_id = 세션 profile-id",
    fields=[("id", "uuid", True)])

add("get-access-tokens", "List own access tokens",
    [block(AT, 120), WRAP_AUTH],
    "owner_match", 0.9,
    [ev(AT, 123, 125), ev(RPC, 173, 176)],
    "get-access-tokens는 db/query :access-token {:profile-id profile-id}로 세션 profile-id 소유 토큰만 조회한다. 대상이 본인으로 고정되므로 owner_match(G4).",
    "::auth 기본 → SELECT access_token WHERE profile_id = 세션 profile-id",
    fields=[], response_fields=["id", "name", "perms", "type", "created-at", "updated-at", "expires-at"])

add("create-upload-session", "Create own chunked-upload session",
    [block(MEDIA, 322), WRAP_AUTH],
    "owner_match", 0.7,
    [ev(MEDIA, 327), ev(MEDIA, 337, 338), ev(MEDIA, 341, 344)],
    "create-upload-session은 세션 profile-id 명의로 upload_session 행을 만든다(:profile-id profile-id). 대상 객체 없이 본인 명의 생성이므로 owner_match(G4) 초안. "
    "객체 없는 인증 전용으로 보면 manual_review_required가 대안이다.",
    "::auth 기본 → upload_session.profile_id = 세션 profile-id로 생성 (+quota)",
    fields=[("total-chunks", "integer", True)], response_fields=["session-id"])

add("upload-chunk", "Upload one chunk into own upload session",
    [block(MEDIA, 363), block(MEDIA, 389, elide=[(392, 415)])],
    "owner_match", 0.85,
    [ev(MEDIA, 368), ev(MEDIA, 391)],
    "upload-chunk는 check-upload-chunk-slot에서 db/get :upload-session {:id session-id :profile-id profile-id}로 세션 profile-id 소유 세션만 찾는다(타인 세션은 not-found). "
    "소유자 == 요청자, 관리자 우회 없음이므로 owner_match(G4).",
    "::auth 기본 → upload_session WHERE id = ? AND profile_id = 세션 profile-id",
    fields=[("session-id", "uuid", True), ("index", "integer", True), ("content", "object", True)],
    response_fields=["session-id", "index"])

add("mark-all-threads-as-read", "Mark comment threads as read for self",
    [block(COMM, 807), block(COMM, 199, 210), WRAP_AUTH],
    "owner_match", 0.6,
    [ev(COMM, 810), ev(COMM, 814, 815), ev(COMM, 206, 210)],
    "mark-all-threads-as-read는 전달된 thread id마다 comment_thread_status (thread_id, profile_id=세션 profile-id) 행만 upsert한다. 스레드·파일 접근 검사는 없지만 "
    "쓰는 대상이 본인 읽음 상태 행으로 고정되므로 owner_match(G4, 본인 플래그) 초안. 객체(thread) 관계 검사가 없는 점을 중시하면 manual이 대안이다.",
    "::auth 기본 → comment_thread_status upsert (thread_id, 세션 profile-id); 스레드 접근 검사 없음",
    fields=[("threads", "array", True, "uuid")])

add("create-team", "Create a team owned by the caller",
    [block(TEAMS, 530, elide=[(557, 565)]), block(TEAMS, 636), block(TEAMS, 666)],
    "owner_match", 0.6,
    [ev(TEAMS, 533, 536), ev(TEAMS, 540, 542), ev(TEAMS, 643, 647), ev(TEAMS, 666, 673)],
    "create-team은 기본 경로(organization-id 없음 또는 admin-console 플래그 꺼짐)에서 인증과 quota만 확인하고 생성된 팀의 owner 역할을 세션 profile-id에 부여한다(create-team-role :owner). "
    "본인 명의 생성(G4)이므로 owner_match 초안. organization-id가 있고 플래그가 켜지면 nitrate/assert-membership과 조직 권한(cto/allowed? :create-team)이 추가되며, "
    "객체 없는 인증 전용으로 보면 manual이 대안이다.",
    "::auth 기본 → quota 검사 후 팀 생성, 세션 profile-id를 owner로 등록; (플래그·organization-id) 조직 구성원·정책 검사 추가",
    fields=[("name", "string", True), ("features", "array", False, "string"), ("id", "uuid", False),
            ("organization-id", "uuid", False), ("is-default", "boolean", False)],
    response_fields=["id", "name", "is-default", "features", "default-project-id"])


# ============================================================================
# 5b 제외 48건 보조 파일 (candidates_5b_excluded.jsonl)
# ----------------------------------------------------------------------------
# read 권한이 teams/get-read-permissions · projects/get-read-permissions ·
# perms/get-file-read-permissions · teams/get-team(get-organization-owner-viewer-team)
# = (or <membership> <organization-owner viewer>) 를 지나는 명령. 결정 5b 로
# candidates.jsonl 에서는 제외했고, 여기서는 조직 소유자 viewer OR 경로를 무시한
# 것으로 가정해(admin-console 플래그 기본 꺼짐 → nitrate/organization-owner-of-team?
# 항상 false) 라벨 초안을 붙인다. records(주 산출)에는 추가하지 않는다.
# ============================================================================
NIT = "backend/src/app/nitrate.clj"
NITC = "backend/src/app/rpc/commands/nitrate.clj"
FTH = "backend/src/app/rpc/commands/files_thumbnails.clj"
VIEW = "backend/src/app/rpc/commands/viewer.clj"
SRCH = "backend/src/app/rpc/commands/search.clj"

records_5b = []
OUT_5B = os.path.join(HERE, "candidates_5b_excluded.jsonl")


def add5b(*args, **kw):
    add(*args, _out=records_5b, **kw)


ORG_OWNER = block(PERM, 136, 146)                                  # get-organization-owner-permissions (OR 경로)
ORG_OWNER_PRED = block(NIT, 562, 574)                              # nitrate/organization-owner-of-team? (admin-console 플래그 게이트)
TEAM_READ = block(TEAMS, 63, 84, elide=[(68, 72), (77, 81)])      # get-read-permissions + has-read-permissions? + check-read-permissions!
PROJ_READ = block(PROJ, 66, 81, elide=[(71, 72), (77, 78)])       # get-read-permissions + has-read-permissions? + check-read-permissions!
FILE_READ_FN = block(PERM, 148, 155)                               # perms/get-file-read-permissions (1·4-arity, OR 조직 소유자)
FILE_READ_PREDS = block(FILES, 86, 96, elide=[(89, 93)])          # has-read-permissions? + check-read-permissions!
FILE_EDIT_READ_PREDS = block(FILES, 83, 96, elide=[(89, 91)])     # has-edit/has-read + check-edition/check-read
FILE_COMMENT_PREDS = block(FILES, 86, 114, elide=[(92, 102)])     # has-read/has-comment + check-comment-permissions!
FILE_SQL_SHORT = block(BFC, 343, 399, elide=[(344, 355), (365, 376), (378, 386)])  # sql:file-permissions team_profile_rel 절 + get-file-permissions 1-arity
FILE_PERMS_MIN = block(BFC, 387, 399)                              # get-file-permissions 1-arity (행 있으면 can-read true)
FILE_SHARE = block(BFC, 401, 418, elide=[(407, 410)])             # get-file-permissions 4-arity (share_link 행 → :share-link)
FILE_SHARE_MIN = block(BFC, 401, 418, elide=[(404, 410)])

EV_ORG = ev(PERM, 141, 142)
EV_TEAM_READ_OR = ev(TEAMS, 63, 66)
EV_PROJ_READ_OR = ev(PROJ, 66, 69)
EV_FILE_READ_OR = ev(PERM, 148, 151)
EV_FILE_SHARE_OR = ev(PERM, 153, 155)
EV_TEAM_SQL = ev(TEAMS, 47, 48)
EV_PROJ_SQL = ev(PROJ, 37, 38)
EV_FILE_SQL = ev(BFC, 393, 398)
EV_SHARE_ROW = ev(BFC, 411, 414)
EV_COMMENT_PRED = ev(FILES, 105, 109)


def p5b(check, provider):
    return (f"5b 제외: {check}가 쓰는 {provider}는 (or <구성원 권한 행> (perms/get-organization-owner-permissions …)) 형태라 "
            "read 검사에 조직 소유자 viewer OR 경로(rpc/permissions.clj:136-146 get-organization-owner-permissions → "
            "nitrate/organization-owner-of-team?, nitrate.clj:562-574; admin-console 플래그가 꺼진 기본 설정에서는 항상 false)가 들어 있다. "
            "이 경로를 무시한 라벨: ")


P_TEAM = p5b("teams/check-read-permissions!", "teams/get-read-permissions(teams.clj:63-66)")
P_PROJ = p5b("projects/check-read-permissions!", "projects/get-read-permissions(projects.clj:66-69)")
P_FILE = p5b("files/check-read-permissions!", "perms/get-file-read-permissions(permissions.clj:148-151)")
P_FILE_SHARE = p5b("파일 read 검사", "perms/get-file-read-permissions 4-인자 형태(permissions.clj:153-155)")
P_COMMENT = p5b("files/check-comment-permissions!", "perms/get-file-read-permissions 4-인자 형태(permissions.clj:153-155)")

R_TEAM_M = ("teams/get-permissions는 team_profile_rel에서 (profile_id = 요청자, team_id = 요청 team-id) 행을 조회하고 행이 있으면 "
            "역할과 무관하게(viewer 포함) :can-read true를 준다. 요청이 대상 그룹(team-id)을 지정하고 (요청자, 그룹) 구성원 행 존재가 "
            "결정 조건이므로 membership_required(G2).")
R_PROJ_M = ("projects/get-permissions는 sql:project-permissions로 프로젝트 소속 팀의 team_profile_rel 행 또는 project_profile_rel 행"
            "(팀 구성원 존재 조건)을 조회하고 행이 있으면 역할과 무관하게 :can-read true를 준다. 대상 프로젝트가 속한 그룹의 구성원 관계가 "
            "결정 조건이므로 membership_required(G2).")
R_FILE_M = ("bfc/get-file-permissions(1-인자)는 sql:file-permissions로 file_profile_rel·team_profile_rel·project_profile_rel 행"
            "(모두 팀 구성원 존재 조건)을 조회하고 행이 있으면 역할과 무관하게 :can-read true를 준다. 대상 파일이 속한 팀의 구성원 관계가 "
            "결정 조건이므로 membership_required(G2).")
R_SHARE = ("share-id가 있으면 bfc/get-file-permissions 4-인자 형태가 구성원 행이 없을 때 share_link 행(id, file_id)으로 "
           "{:type :share-link :can-read true :pages …}를 돌려 허용한다(허용 페이지로 제한). 구성원 OR 공유 링크라는 서로 다른 유형의 "
           "조건이 OR로 분기하므로 manual_review_required(G6, 보충 규약 5).")
R_COMMENT = ("files/check-comment-permissions!는 perms/get-file-read-permissions(share-id 포함)로 구성원 행 또는 share_link 행을 얻고, "
             ":membership이면 can-read, :share-link면 who-comment=\"all\"일 때 허용한다. 구성원 OR 공유 링크(댓글 허용) 분기이므로 "
             "manual_review_required(G6, 보충 규약 5).")

A_TEAM_READ = "::auth 기본(세션/토큰 필수) → teams/check-read-permissions!: team_profile_rel 행 존재(can-read) OR [조직 소유자 viewer — 5b]"
A_PROJ_READ = "::auth 기본 → projects/check-read-permissions!: 팀/프로젝트 profile_rel 행 존재(can-read) OR [조직 소유자 viewer — 5b]"
A_FILE_READ = "::auth 기본 → files/check-read-permissions!: bfc/get-file-permissions 행 존재(can-read) OR [조직 소유자 viewer — 5b]"
A_FILE_SHARE = "::auth 기본 → perms/get-file-read-permissions(share-id): 구성원 행 OR share_link 행 OR [조직 소유자 viewer — 5b]"
A_COMMENT = "::auth 기본 → files/check-comment-permissions!(share-id): 구성원 can-read OR share-link who-comment=all OR [조직 소유자 viewer — 5b]"

# ---- teams/check-read-permissions! (15) --------------------------------------
add5b("get-team-members", "List members of a team",
      [block(TEAMS, 334), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(TEAMS, 339), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-members는 check-read-permissions!(cfg profile-id team-id)를 통과하면 team_profile_rel 전체를 반환한다. " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)],
      response_fields=["id", "email", "name", "fullname", "photo-id", "is-active", "is-owner", "is-admin", "can-edit"])

add5b("get-team-users", "List users of a team (by team-id or file-id)",
      [block(TEAMS, 357), block(TEAMS, 429, 440), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(TEAMS, 365), ev(TEAMS, 368), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-users는 team-id 분기와 file-id 분기(get-team-for-file로 팀 해석) 모두 teams/check-read-permissions!를 요구한다"
      "(같은 유형 조건 2회). " + R_TEAM_M,
      A_TEAM_READ + " (team-id 또는 file-id→team)", fields=[("team-id", "uuid", False), ("file-id", "uuid", False)],
      response_fields=["id", "fullname", "photo-id", "email"])

add5b("get-team-stats", "Project and file counts of a team",
      [block(TEAMS, 450), block(TEAMS, 458, 464), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(TEAMS, 455), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-stats는 check-read-permissions!(cfg profile-id team-id) 뒤 팀의 프로젝트·파일 수를 반환한다. " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)], response_fields=["projects", "files"])

add5b("get-team-invitations", "List pending invitations of a team",
      [block(TEAMS, 486), block(TEAMS, 472, 478), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.8,
      [ev(TEAMS, 491), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-invitations는 check-read-permissions!(cfg profile-id team-id)만 요구한다(초대 생성·삭제는 is-admin이지만 목록 조회는 "
      "구성원 read). " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)], response_fields=["email", "role", "expired"])

add5b("get-projects", "List projects of a team",
      [block(PROJ, 111), block(PROJ, 85, 105, elide=[(86, 92)]), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(PROJ, 116), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-projects는 teams/check-read-permissions!(cfg profile-id team-id) 뒤 팀의 프로젝트를 모두 반환한다(sql:projects의 "
      "profile_id 조인은 본인 핀 플래그 표시용이고 필터가 아니다). " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)],
      response_fields=["id", "name", "team-id", "is-pinned", "count", "total-count"])

add5b("get-team-shared-files", "List shared libraries of a team",
      [block(FILES, 610), block(FILES, 591, 604, elide=[(595, 603)]), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 593), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-shared-files는 teams/check-read-permissions!(cfg profile-id team-id) 뒤 팀의 is_shared 파일을 요약과 함께 반환한다. " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)], response_fields=["id", "library-summary", "library-file-ids"])

add5b("get-team-recent-files", "Recent files of a team",
      [block(FILES, 789), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 794), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-recent-files는 teams/check-read-permissions!(cfg profile-id team-id) 뒤 팀 프로젝트별 최근 파일 10개를 반환한다. " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)],
      response_fields=["id", "revn", "vern", "project-id", "name", "is-shared", "thumbnail-id", "team-id"])

add5b("get-team-deleted-files", "Recoverable deleted files of a team",
      [block(FILES, 835), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 840), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-team-deleted-files는 teams/check-read-permissions!(cfg profile-id team-id) 뒤 팀의 삭제 예정 파일을 반환한다. " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)],
      response_fields=["id", "revn", "vern", "project-id", "name", "will-be-deleted-at", "thumbnail-id", "team-id"])

add5b("get-unread-comment-threads", "Unread comment threads of a team for the caller",
      [block(COMM, 311), block(COMM, 295, 304), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.8,
      [ev(COMM, 315), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-unread-comment-threads는 teams/check-read-permissions!(cfg profile-id team-id) 뒤 팀 파일들의 스레드 중 본인 기준 미읽음만 "
      "반환한다(profile-id는 읽음 상태·알림 설정 계산용). 허용 결정은 팀 구성원 행이므로 membership_required(G2); 결과가 본인 미읽음에 "
      "한정되는 점을 중시하면 owner_match 대안. " + R_TEAM_M,
      A_TEAM_READ + "; 결과는 본인 미읽음 필터", fields=[("team-id", "uuid", True)])

add5b("get-webhooks", "List webhooks of a team",
      [block(WEBH, 168), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(WEBH, 173), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "get-webhooks는 teams/check-read-permissions!(cfg profile-id team-id)만 요구한다(생성·삭제는 can-edit). " + R_TEAM_M,
      A_TEAM_READ, fields=[("team-id", "uuid", True)],
      response_fields=["id", "team-id", "uri", "mtype", "is-active", "error-code", "error-count"])

add5b("search-files", "Search files by name inside a team",
      [block(SRCH, 77), block(SRCH, 17, 57, elide=[(43, 54)]), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.7,
      [ev(SRCH, 83), ev(SRCH, 21, 27), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "search-files는 teams/check-read-permissions!(conn profile-id team-id)를 통과해야 하고(여기서는 cfg 대신 raw conn을 넘겨 "
      "nitrate-client?가 false → 조직 소유자 경로가 실제로도 비활성), 그 뒤 sql:search-files가 요청자가 is_admin/is_owner/can_edit인 "
      "프로젝트의 파일만 돌려준다. 허용 게이트는 팀 구성원 행이므로 membership_required(G2) 초안; 결과 필터가 편집 역할 플래그라 "
      "role_required 대안(viewer는 빈 결과).",
      A_TEAM_READ + "; 결과는 편집 플래그 있는 프로젝트로 필터",
      fields=[("team-id", "uuid", True), ("search-term", "string", False)],
      response_fields=["id", "revn", "project-id", "name", "is-shared", "thumbnail-id"])

add5b("get-font-variants", "List team font variants (by team-id, project-id or file-id+share-id)",
      [block(FONTS, 64), TEAM_READ, PROJ_READ, FILE_READ_FN, ORG_OWNER],
      "manual_review_required", 0.7,
      [ev(FONTS, 72), ev(FONTS, 79), ev(FONTS, 87, 88), EV_FILE_SHARE_OR, EV_ORG],
      p5b("세 분기의 read 검사", "teams/projects/get-read-permissions와 perms/get-file-read-permissions")
      + "get-font-variants는 team-id 분기는 팀 구성원 read, project-id 분기는 프로젝트 구성원 read, file-id 분기는 share-id 겸용 "
      "파일 read(구성원 OR 공유 링크)로 쿼리 모드마다 정책이 다르다. 쿼리 모드별 정책 분기이자 공유 링크 OR가 포함되므로 "
      "manual_review_required(G6, 보충 규약 5; Flowise GET /workspace 선례). share-id를 빼면 membership_required.",
      "::auth 기본 → team-id: 팀 구성원 read / project-id: 프로젝트 구성원 read / file-id: 구성원 OR share_link; 모두 OR [조직 소유자 viewer — 5b]",
      fields=[("team-id", "uuid", False), ("file-id", "uuid", False), ("project-id", "uuid", False), ("share-id", "uuid", False)],
      response_fields=["id", "team-id", "font-id", "font-family", "font-weight", "font-style"])

add5b("download-font", "Download one font variant file",
      [block(FONTS, 370, elide=[(378, 387)]), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FONTS, 375, 376), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "download-font는 variant 행의 team-id로 teams/check-read-permissions!를 요구한 뒤 자산 URI를 돌려준다. " + R_TEAM_M,
      A_TEAM_READ + " (team_font_variant.team_id)", fields=[("id", "uuid", True)], response_fields=["id", "uri", "name"])

add5b("download-font-family", "Download a font family as zip",
      [block(FONTS, 394, elide=[(410, 433)]), TEAM_READ, TEAM_SQL_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FONTS, 408), EV_TEAM_READ_OR, EV_TEAM_SQL, EV_ORG],
      P_TEAM + "download-font-family는 font-id의 variant들이 속한 team-id로 teams/check-read-permissions!를 요구한다. " + R_TEAM_M,
      A_TEAM_READ + " (variants.team_id)", fields=[("font-id", "uuid", True)], response_fields=["id", "uri", "name"])

add5b("check-nitrate-sso", "Check whether organization SSO login is required",
      [block(NITC, 674, elide=[(677, 685), (701, 716)]), TEAM_READ, ORG_OWNER, ORG_OWNER_PRED],
      "manual_review_required", 0.7,
      [ev(NITC, 691, 693), ev(NITC, 696), ev(NITC, 717), EV_TEAM_READ_OR, EV_ORG],
      p5b("teams/has-read-permissions?", "teams/get-read-permissions(teams.clj:63-66)")
      + "check-nitrate-sso는 admin-console 플래그가 꺼져 있으면 인증만 확인하고 누구에게나 {:authorized true}를 돌려주며(객체 검사 없음), "
      "플래그가 켜져도 비구성원에게 거부 대신 {:authorized true :reason :no-team-access}를 반환해 구성원 여부가 접근 거부 조건이 아니다. "
      "설정에 따라 동작이 바뀌고 인증만 확인하는 경로가 기본이므로 manual_review_required(G6).",
      "::rpc/auth true(인증만); admin-console 플래그 꺼짐 → 항상 authorized; 켜짐 → has-read-permissions? 분기(거부 아님) + Nitrate SSO 세션 검사",
      fields=[("team-id", "uuid", False), ("organization-id", "uuid", False), ("url", "uri", True)],
      response_fields=["authorized", "reason", "redirect-uri"])

# ---- teams/get-team 의 조직 소유자 viewer 폴백 (1) ----------------------------
add5b("get-team", "Get a team by id (or by file-id) with the caller's permissions",
      [block(TEAMS, 241), block(TEAMS, 266, 310, elide=[(271, 278), (286, 302)]), block(TEAMS, 251, 264),
       block(TEAMS, 126, 136), ORG_OWNER_PRED],
      "membership_required", 0.85,
      [ev(TEAMS, 282, 284), ev(TEAMS, 134, 135), ev(TEAMS, 308), ev(TEAMS, 257), ev(NIT, 570, 574)],
      "5b 제외: teams/get-team은 구성원 행(sql:get-teams-with-permissions WHERE tp.profile_id = 요청자)이 없을 때 "
      "get-organization-owner-viewer-team(teams.clj:251-264 → nitrate/organization-owner-of-team?, nitrate.clj:562-574; admin-console 플래그가 "
      "꺼진 기본 설정에서는 항상 false)으로 조직 소유자 viewer 팀 행을 돌려주는 OR 경로를 포함한다. 이 경로를 무시한 라벨: "
      "get-team은 team_profile_rel을 조인한 팀 목록에서 요청 id(또는 file-id가 속한 팀)를 찾으므로 요청자의 구성원 행이 없으면 "
      "team-does-not-exist로 거부한다. (요청자, 그룹) 구성원 행 존재가 결정 조건이고 역할 플래그는 응답에 실릴 뿐이므로 membership_required(G2).",
      "::auth 기본 → sql:get-teams-with-permissions(tp.profile_id = 세션 profile-id) WHERE id = ? ; 없으면 [조직 소유자 viewer — 5b] 또는 not-found",
      fields=[("id", "uuid", False), ("file-id", "uuid", False)],
      response_fields=["id", "name", "is-default", "permissions", "features"])

# ---- projects/check-read-permissions! (3) ------------------------------------
add5b("get-project", "Get a project by id",
      [block(PROJ, 175), PROJ_READ, PROJ_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(PROJ, 182), EV_PROJ_READ_OR, EV_PROJ_SQL, EV_ORG],
      P_PROJ + "get-project는 check-read-permissions!(cfg profile-id id)를 통과하면 프로젝트 행을 반환한다. " + R_PROJ_M,
      A_PROJ_READ, fields=[("id", "uuid", True)], response_fields=["id", "name", "team-id", "is-default"])

add5b("update-project-pin", "Pin or unpin a project for the caller",
      [block(PROJ, 243), block(PROJ, 230, 235), PROJ_READ, PROJ_PERMS, ORG_OWNER],
      "membership_required", 0.65,
      [ev(PROJ, 252, 253), ev(PROJ, 232, 235), EV_PROJ_READ_OR, EV_PROJ_SQL, EV_ORG],
      P_PROJ + "update-project-pin은 check-read-permissions!(cfg profile-id id)만 요구하고(편집 권한 불필요) team_project_profile_rel의 "
      "(team_id, project_id, profile_id = 요청자) 행에 본인 핀 플래그만 쓴다. 허용 게이트가 프로젝트 구성원 read이므로 "
      "membership_required(G2) 초안; 쓰는 대상이 본인 플래그 행인 점을 중시하면 owner_match(G4) 대안.",
      A_PROJ_READ + "; 쓰기는 본인 (team, project, profile) 핀 행",
      fields=[("team-id", "uuid", True), ("is-pinned", "boolean", True), ("id", "uuid", True)])

add5b("get-project-files", "List files of a project",
      [block(FILES, 304), PROJ_READ, PROJ_PERMS, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 310), EV_PROJ_READ_OR, EV_PROJ_SQL, EV_ORG],
      P_PROJ + "get-project-files는 projects/check-read-permissions!(cfg profile-id project-id) 뒤 프로젝트의 파일을 모두 반환한다. " + R_PROJ_M,
      A_PROJ_READ, fields=[("project-id", "uuid", True)],
      response_fields=["id", "project-id", "name", "revn", "vern", "is-shared", "thumbnail-id", "team-id"])

# ---- files/check-read-permissions! · perms/get-file-read-permissions (16) ----
add5b("get-file", "Retrieve a file by id",
      [block(FILES, 172, elide=[(182, 187), (191, 221)]), block(FILES, 157, 161), FILE_READ_PREDS, FILE_READ_FN,
       FILE_PERMS_MIN, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 188, 190), ev(FILES, 160), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file은 perms/get-file-read-permissions(1-인자, share-id 없음)로 얻은 perms에 check-read-permissions!를 적용한다"
      "(ETag 조건부 요청 시 get-minimal-file-with-perms가 같은 함수로 미리 계산). 이후 teams/get-team은 feature 계산용 조회다. " + R_FILE_M,
      A_FILE_READ, fields=[("id", "uuid", True), ("features", "array", False, "string")],
      response_fields=["id", "features", "name", "revn", "vern", "modified-at", "is-shared", "project-id", "created-at", "data", "permissions"])

add5b("get-file-fragment", "Retrieve a file data fragment (member or share link; anonymous allowed)",
      [block(FILES, 256), FILE_READ_PREDS, FILE_READ_FN, FILE_SHARE, ORG_OWNER],
      "manual_review_required", 0.75,
      [ev(FILES, 259), ev(FILES, 264, 267), EV_FILE_SHARE_OR, EV_SHARE_ROW, EV_ORG],
      P_FILE_SHARE + "get-file-fragment는 ::rpc/auth false로 익명 호출을 받지만 perms가 nil이면 check-read-permissions!가 거부하므로 "
      "익명은 유효한 share-id가 있을 때만 허용된다(조건부 익명 → G7 public 아님). 로그인 사용자는 구성원 행으로도 허용된다. " + R_SHARE,
      "::rpc/auth false; perms/get-file-read-permissions(share-id): 구성원 행 OR share_link 행(허용 페이지 범위 검사) OR [조직 소유자 viewer — 5b]",
      fields=[("file-id", "uuid", True), ("fragment-id", "uuid", True), ("share-id", "uuid", False)], anonymous=True,
      response_fields=["id", "file-id", "created-at", "content"])

add5b("has-file-libraries", "Whether a file links any library",
      [block(FILES, 321), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 328), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "has-file-libraries는 check-read-permissions!(cfg profile-id file-id) 뒤 불리언만 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)])

add5b("get-library-usage", "Number of files using a library",
      [block(FILES, 354), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 361), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-library-usage는 check-read-permissions!(cfg profile-id file-id) 뒤 사용 파일 수를 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)], response_fields=["used-in"])

add5b("get-page", "Retrieve page data of a file (member or share link)",
      [block(FILES, 454, elide=[(455, 464)]), block(FILES, 402, 444, elide=[(405, 410), (422, 436)]),
       FILE_READ_PREDS, FILE_READ_FN, FILE_SHARE, ORG_OWNER],
      "manual_review_required", 0.75,
      [ev(FILES, 470), ev(FILES, 411), ev(FILES, 416, 420), EV_FILE_SHARE_OR, EV_SHARE_ROW],
      P_FILE_SHARE + "get-page는 check-read-permissions!(cfg profile-id file-id share-id)로 구성원 행 또는 share_link 행을 허용하고, "
      "share-link면 요청 페이지가 링크의 허용 페이지에 들어야 한다. " + R_SHARE,
      A_FILE_SHARE,
      fields=[("file-id", "uuid", True), ("page-id", "uuid", False), ("share-id", "uuid", False), ("object-id", "uuid", False),
              ("features", "array", False, "string")],
      response_fields=["id", "name", "objects", "options"])

add5b("get-file-summary", "Library summary of a file",
      [block(FILES, 630), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 636), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-summary는 check-read-permissions!(cfg profile-id id) 뒤 컴포넌트·색·타이포 요약을 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("id", "uuid", True)], response_fields=["name", "components", "variants", "colors", "typographies"])

add5b("get-file-stats", "Aggregate statistics of a file",
      [block(FILES, 696), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 707), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-stats는 check-read-permissions!(cfg profile-id id) 뒤 페이지·도형·컴포넌트 수를 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("id", "uuid", True)],
      response_fields=["file-id", "page-count", "shape-counts", "component-count", "color-count", "typography-count",
                       "library-count", "referenced-by-count", "revn", "updated-at"])

add5b("get-file-libraries", "Libraries used by a file",
      [block(FILES, 717), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 723), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-libraries는 파일 존재 확인 뒤 check-read-permissions!(cfg profile-id file-id)를 요구한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)], response_fields=["id", "name", "is-shared", "project-id"])

add5b("get-library-file-references", "Files that use a library",
      [block(FILES, 744), block(FILES, 728, 734), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FILES, 750), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-library-file-references는 check-read-permissions!(cfg profile-id file-id) 뒤 이 라이브러리를 쓰는 파일 id·이름을 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)], response_fields=["id", "name"])

add5b("export-binfile", "Export a file as penpot binary (SSE)",
      [block(BIN, 72), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(BIN, 79), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "export-binfile은 files/check-read-permissions!(cfg profile-id file-id)만 요구한다(내보내기는 read 권한). " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True), ("include-libraries", "boolean", True), ("embed-assets", "boolean", True)])

add5b("get-file-snapshots", "List visible snapshots (versions) of a file",
      [block(FSN, 33), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FSN, 38), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-snapshots는 files/check-read-permissions!(cfg profile-id file-id) 뒤 스냅샷 목록을 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)], response_fields=["id", "label", "revn", "created-at", "created-by", "profile-id"])

add5b("get-file-snapshot", "Read-only preview bundle of one snapshot",
      [block(FSN, 49, elide=[(59, 75)]), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FSN, 57, 58), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-snapshot은 perms/get-file-read-permissions(1-인자)로 얻은 perms에 files/check-read-permissions!를 적용한 뒤 스냅샷 데이터를 "
      "파일 형태로 돌려준다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True), ("id", "uuid", True), ("features", "array", False, "string")],
      response_fields=["id", "name", "revn", "vern", "data", "version", "features", "permissions"])

add5b("get-file-object-thumbnails", "Object thumbnails of a file",
      [block(FTH, 78), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FTH, 88), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-object-thumbnails는 files/check-read-permissions!(cfg profile-id file-id) 뒤 object-id→media-id 맵을 반환한다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True), ("tag", "string", False)])

add5b("get-file-data-for-thumbnail", "Page data used to render the file thumbnail",
      [block(FTH, 192, elide=[(202, 217)]), FILE_READ_PREDS, FILE_READ_FN, FILE_SQL_SHORT, ORG_OWNER],
      "membership_required", 0.85,
      [ev(FTH, 201), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      P_FILE + "get-file-data-for-thumbnail은 files/check-read-permissions!(cfg profile-id file-id)를 먼저 요구하고, 이후 teams/get-team은 "
      "feature 계산용 조회다. " + R_FILE_M,
      A_FILE_READ, fields=[("file-id", "uuid", True)], response_fields=["file-id", "revn", "page"])

add5b("clone-file-media-object", "Clone a media object from another file into a file",
      [block(MEDIA, 285), block(MEDIA, 293, 310, elide=[(301, 309)]), FILE_EDIT_READ_PREDS, FILE_READ_FN, FILE_PERMS_MIN, ORG_OWNER],
      "manual_review_required", 0.6,
      [ev(MEDIA, 290), ev(MEDIA, 300), EV_FILE_READ_OR, EV_FILE_SQL, EV_ORG],
      p5b("원본 미디어 파일의 files/check-read-permissions!", "perms/get-file-read-permissions(permissions.clj:148-151)")
      + "clone-file-media-object는 대상 file-id에 files/check-edition-permissions!(구성원 행의 can-edit 역할, G3) AND 원본 미디어 객체가 속한 "
      "파일에 files/check-read-permissions!(구성원 행, G2)를 요구한다(둘 다 raw conn을 넘겨 nitrate-client?가 false → 조직 소유자 경로는 실제로도 "
      "비활성). 서로 다른 두 객체에 대한 역할 조건과 구성원 조건이 독립 필수 조건으로 AND 결합돼 단일 라벨로 표현되지 않아 보류"
      "(프롬프트 '보류가 필수인 경우' 3). 대상 파일 기준이면 role_required 대안.",
      "::auth 기본 → check-edition-permissions!(대상 file-id, can_edit) AND check-read-permissions!(원본 media.file_id, 구성원 행)",
      fields=[("file-id", "uuid", True), ("is-local", "boolean", True), ("id", "uuid", True)],
      response_fields=["id", "file-id", "is-local", "name", "media-id", "thumbnail-id", "width", "height", "mtype"])

add5b("get-view-only-bundle", "View-only bundle of a file (member or share link; anonymous allowed)",
      [block(VIEW, 125), block(VIEW, 58, 117, elide=[(60, 68), (77, 115)]), FILE_READ_FN, FILE_SHARE, ORG_OWNER],
      "manual_review_required", 0.75,
      [ev(VIEW, 126), ev(VIEW, 132), ev(VIEW, 139, 142), EV_FILE_SHARE_OR, EV_SHARE_ROW],
      P_FILE_SHARE + "get-view-only-bundle은 ::rpc/auth false로 익명 호출을 받지만 perms가 nil이면 object-not-found로 거부하므로 익명은 유효한 "
      "share-id가 있을 때만 허용된다(조건부 익명 → G7 public 아님; share-link면 구성원 이메일 마스킹·허용 페이지 제한). 로그인 사용자는 구성원 "
      "행으로도 허용된다. " + R_SHARE,
      "::rpc/auth false; perms/get-file-read-permissions(share-id): 구성원 행 OR share_link 행 OR [조직 소유자 viewer — 5b]; nil이면 not-found",
      fields=[("file-id", "uuid", True), ("share-id", "uuid", False), ("features", "array", False, "string")], anonymous=True,
      response_fields=["users", "profiles", "fonts", "project", "share-links", "libraries", "file", "team", "permissions"])

# ---- files/check-comment-permissions! (share-id 겸용, 13) ---------------------
COMMENT_BLOCKS = [FILE_COMMENT_PREDS, FILE_READ_FN, FILE_SHARE_MIN, ORG_OWNER]
EV_COMMENT_COMMON = [EV_COMMENT_PRED, EV_FILE_SHARE_OR, EV_ORG]

add5b("get-comment-threads", "List comment threads of a file",
      [block(COMM, 229)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 234), ev(COMM, 236, 237)] + EV_COMMENT_COMMON,
      P_COMMENT + "get-comment-threads는 files/check-comment-permissions!(cfg profile-id file-id share-id)를 통과하면 파일의 스레드를 반환하고, "
      "share-link면 허용 페이지의 스레드만 남긴다. " + R_COMMENT,
      A_COMMENT, fields=[("file-id", "uuid", False), ("team-id", "uuid", False), ("share-id", "uuid", False)],
      response_fields=["id", "file-id", "page-id", "owner-id", "content", "count-comments", "count-unread-comments"])

add5b("get-comment-thread", "Get one comment thread",
      [block(COMM, 330)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 335), ev(COMM, 338, 339)] + EV_COMMENT_COMMON,
      P_COMMENT + "get-comment-thread는 files/check-comment-permissions!(cfg profile-id file-id share-id)를 통과한 뒤 스레드를 반환하고, "
      "share-link면 스레드의 page-id가 허용 페이지에 들어야 한다. " + R_COMMENT,
      A_COMMENT, fields=[("file-id", "uuid", True), ("id", "uuid", True), ("share-id", "uuid", False)],
      response_fields=["id", "file-id", "page-id", "owner-id", "content", "count-comments"])

add5b("get-comments", "List comments of a thread",
      [block(COMM, 355)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 360, 361), ev(COMM, 362, 363)] + EV_COMMENT_COMMON,
      P_COMMENT + "get-comments는 thread-id로 file-id를 해석한 뒤 files/check-comment-permissions!(cfg profile-id file-id share-id)를 요구하고, "
      "share-link면 스레드 페이지가 허용 페이지에 들어야 한다. " + R_COMMENT,
      A_COMMENT + " (thread→file)", fields=[("thread-id", "uuid", True), ("share-id", "uuid", False)],
      response_fields=["id", "thread-id", "owner-id", "content", "created-at", "file-id"])

add5b("get-profiles-for-file-comments", "Profiles participating in a file's comments",
      [block(COMM, 424)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 432)] + EV_COMMENT_COMMON,
      P_COMMENT + "get-profiles-for-file-comments는 files/check-comment-permissions!(cfg profile-id file-id share-id)를 통과하면 파일 댓글 참여자 "
      "프로필(+본인)을 반환한다. " + R_COMMENT,
      A_COMMENT, fields=[("file-id", "uuid", True), ("share-id", "uuid", False)],
      response_fields=["id", "email", "name", "fullname", "photo-id", "is-active"])

add5b("create-comment-thread", "Create a comment thread on a file page",
      [block(COMM, 468, elide=[(477, 488)])] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 475)] + EV_COMMENT_COMMON,
      P_COMMENT + "create-comment-thread는 files/check-comment-permissions!(cfg profile-id file-id share-id)를 먼저 요구하고 그 뒤 quota를 검사한다"
      "(생성 요청, owner-id = 요청자). " + R_COMMENT,
      A_COMMENT,
      fields=[("file-id", "uuid", True), ("position", "object", True), ("content", "string", True), ("page-id", "uuid", True),
              ("frame-id", "uuid", True), ("share-id", "uuid", False), ("mentions", "array", False, "uuid")],
      response_fields=["id", "file-id", "page-id", "owner-id", "seqn", "comment-id"])

add5b("update-comment-thread-status", "Mark a thread as read for the caller",
      [block(COMM, 555)] + COMMENT_BLOCKS,
      "manual_review_required", 0.7,
      [ev(COMM, 560, 562)] + EV_COMMENT_COMMON,
      P_COMMENT + "update-comment-thread-status는 스레드의 file-id로 files/check-comment-permissions!(share-id 겸용)를 요구한 뒤 "
      "(thread_id, 요청자 profile_id) 읽음 상태 행만 upsert한다. 허용 게이트가 구성원 OR 공유 링크 분기라 manual_review_required(G6, 보충 규약 5); "
      "쓰는 대상이 본인 상태 행인 점을 중시하면 owner_match 대안. " + R_COMMENT,
      A_COMMENT + "; 쓰기는 본인 읽음 상태 행", fields=[("id", "uuid", True), ("share-id", "uuid", False)])

add5b("update-comment-thread", "Resolve or unresolve a comment thread",
      [block(COMM, 573)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 578, 579), ev(COMM, 580, 582)] + EV_COMMENT_COMMON,
      P_COMMENT + "update-comment-thread는 스레드의 file-id로 files/check-comment-permissions!(share-id 겸용)만 요구하고 작성자 검사 없이 "
      "is-resolved를 갱신한다. " + R_COMMENT,
      A_COMMENT, fields=[("id", "uuid", True), ("is-resolved", "boolean", True), ("share-id", "uuid", False)])

add5b("create-comment", "Add a comment to a thread",
      [block(COMM, 595, elide=[(609, 652)])] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 601, 602), ev(COMM, 607)] + EV_COMMENT_COMMON,
      P_COMMENT + "create-comment는 thread-id→file-id를 해석한 뒤 files/check-comment-permissions!(cfg profile-id file-id share-id)를 요구하고 "
      "quota 검사 후 owner-id = 요청자로 댓글을 만든다. " + R_COMMENT,
      A_COMMENT + " (thread→file)",
      fields=[("thread-id", "uuid", True), ("content", "string", True), ("share-id", "uuid", False), ("mentions", "array", False, "uuid")],
      response_fields=["id", "thread-id", "owner-id", "content", "file-id"])

add5b("update-comment", "Edit own comment",
      [block(COMM, 667, elide=[(685, 700)])] + COMMENT_BLOCKS,
      "manual_review_required", 0.6,
      [ev(COMM, 678), ev(COMM, 680, 683)] + EV_COMMENT_COMMON,
      P_COMMENT + "update-comment는 files/check-comment-permissions!(share-id 겸용) AND comment.owner_id == 요청자(관리자 우회 없음)를 요구한다. "
      "접근 게이트가 구성원 OR 공유 링크 분기라 manual_review_required(G6, 보충 규약 5) 초안; 작성자 본인 조건을 결정 조건으로 보면 "
      "owner_match(G4) 대안(5b가 없었다면 owner_match 후보로 적었던 건). " + R_COMMENT,
      A_COMMENT + " AND comment.owner_id == 세션 profile-id",
      fields=[("id", "uuid", True), ("content", "string", True), ("share-id", "uuid", False), ("mentions", "array", False, "uuid")])

add5b("delete-comment-thread", "Delete own comment thread",
      [block(COMM, 711)] + COMMENT_BLOCKS,
      "manual_review_required", 0.6,
      [ev(COMM, 717), ev(COMM, 718, 720)] + EV_COMMENT_COMMON,
      P_COMMENT + "delete-comment-thread는 files/check-comment-permissions!(share-id 겸용) AND thread.owner_id == 요청자(관리자 우회 없음)를 "
      "요구한다. 접근 게이트가 구성원 OR 공유 링크 분기라 manual_review_required(G6, 보충 규약 5) 초안; 작성자 본인 조건을 결정 조건으로 보면 "
      "owner_match(G4) 대안. " + R_COMMENT,
      A_COMMENT + " AND comment_thread.owner_id == 세션 profile-id", fields=[("id", "uuid", True), ("share-id", "uuid", False)])

add5b("delete-comment", "Delete own comment",
      [block(COMM, 734)] + COMMENT_BLOCKS,
      "manual_review_required", 0.6,
      [ev(COMM, 745), ev(COMM, 746, 748)] + EV_COMMENT_COMMON,
      P_COMMENT + "delete-comment는 files/check-comment-permissions!(share-id 겸용) AND comment.owner_id == 요청자(관리자 우회 없음)를 요구한다. "
      "접근 게이트가 구성원 OR 공유 링크 분기라 manual_review_required(G6, 보충 규약 5) 초안; 작성자 본인 조건을 결정 조건으로 보면 "
      "owner_match(G4) 대안. " + R_COMMENT,
      A_COMMENT + " AND comment.owner_id == 세션 profile-id", fields=[("id", "uuid", True), ("share-id", "uuid", False)])

add5b("update-comment-thread-position", "Move a comment thread",
      [block(COMM, 764)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 769, 770)] + EV_COMMENT_COMMON,
      P_COMMENT + "update-comment-thread-position은 스레드의 file-id로 files/check-comment-permissions!(share-id 겸용)만 요구하고 작성자 검사 없이 "
      "position·frame-id를 갱신한다. " + R_COMMENT,
      A_COMMENT, fields=[("id", "uuid", True), ("position", "object", True), ("frame-id", "uuid", True), ("share-id", "uuid", False)])

add5b("update-comment-thread-frame", "Change the frame of a comment thread",
      [block(COMM, 788)] + COMMENT_BLOCKS,
      "manual_review_required", 0.75,
      [ev(COMM, 793, 794)] + EV_COMMENT_COMMON,
      P_COMMENT + "update-comment-thread-frame은 스레드의 file-id로 files/check-comment-permissions!(share-id 겸용)만 요구하고 작성자 검사 없이 "
      "frame-id를 갱신한다. " + R_COMMENT,
      A_COMMENT, fields=[("id", "uuid", True), ("frame-id", "uuid", True), ("share-id", "uuid", False)])


# ============================================================================
# write + validate
# ============================================================================
def main():
    paths = [r["path"] for r in records]
    assert len(paths) == len(set(paths)), "duplicate (method, path)"
    labels = {"public", "role_required", "membership_required", "tenant_match", "owner_match",
              "owner_or_admin", "manual_review_required"}
    counts = {}
    problems = []
    for r in records:
        assert r["draft_label"] in labels, r["path"]
        counts[r["draft_label"]] = counts.get(r["draft_label"], 0) + 1
        n = len(r["controller_text"])
        if n < 500 or n > 3000:
            problems.append((r["path"], n))
        for e in r["evidence"]:
            assert e["text"].strip(), f"empty evidence {r['path']} {e['location']}"
        assert 2 <= len(r["evidence"]) <= 5, r["path"]
        assert r["draft_reason"] and r["auth_summary"]
        if r["draft_reason"].startswith("EXCLUDE 후보"):
            assert r["draft_confidence"] <= 0.5, r["path"]
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    total = len(records)
    print(f"records: {total} -> {OUT}")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k:24s} {v:3d}  ({100.0 * v / total:.1f}%)")
    excl = [r["path"] for r in records if r["draft_reason"].startswith("EXCLUDE 후보")]
    print(f"EXCLUDE 후보: {len(excl)} {excl}")
    lens = sorted(len(r["controller_text"]) for r in records)
    print(f"controller_text len min/median/max: {lens[0]}/{lens[len(lens) // 2]}/{lens[-1]}")
    if problems:
        print("LENGTH VIOLATIONS (path, len):")
        for p in problems:
            print("  ", p)
    assert max(counts.values()) * 2 <= total, "a label exceeds 50%"
    assert 55 <= total <= 65, total
    write_5b(labels)
    return 0


def write_5b(labels):
    """Supplementary file: the 48 commands excluded by decision 5b, labelled as if the
    organization-owner viewer OR path were ignored. Not part of candidates.jsonl."""
    paths = [r["path"] for r in records_5b]
    assert len(paths) == len(set(paths)), "duplicate (method, path) in 5b"
    assert not (set(paths) & {r["path"] for r in records}), "5b path overlaps candidates.jsonl"
    counts = {}
    problems = []
    for r in records_5b:
        assert r["draft_label"] in labels, r["path"]
        counts[r["draft_label"]] = counts.get(r["draft_label"], 0) + 1
        n = len(r["controller_text"])
        if n < 500 or n > 3000:
            problems.append((r["path"], n))
        for e in r["evidence"]:
            assert e["text"].strip(), f"empty evidence {r['path']} {e['location']}"
        assert 2 <= len(r["evidence"]) <= 5, r["path"]
        assert r["draft_reason"].startswith("5b 제외: "), r["path"]
        assert r["auth_summary"]
        ct = r["controller_text"]
        assert "get-organization-owner-permissions" in ct or "get-organization-owner-viewer-team" in ct, r["path"]
        assert ("get-read-permissions" in ct or "get-file-read-permissions" in ct
                or "get-organization-owner-viewer-team" in ct), r["path"]
    with open(OUT_5B, "w", encoding="utf-8", newline="\n") as f:
        for r in records_5b:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    total = len(records_5b)
    print(f"5b records: {total} -> {OUT_5B}")
    for k, v in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {k:24s} {v:3d}  ({100.0 * v / total:.1f}%)")
    lens = sorted(len(r["controller_text"]) for r in records_5b)
    print(f"5b controller_text len min/median/max: {lens[0]}/{lens[len(lens) // 2]}/{lens[-1]}")
    if problems:
        print("5b LENGTH VIOLATIONS (path, len):")
        for p in problems:
            print("  ", p)
    assert total == 48, total


if __name__ == "__main__":
    sys.exit(main())
