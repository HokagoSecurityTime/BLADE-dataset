"""Static extraction of GlitchTip backend API authorization policy candidates (test_v6).

Read-only over the clone at datasets/blade/raw/opensource/test_v6_candidates/glitchtip-backend.
Writes candidates.jsonl next to this script. Run from C:\\BLADE with:
    python -I data/raw_v6/glitchtip/extract_glitchtip.py
No network, no LLM, no model inference. Labels are drafts for human review.
"""
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(
    os.path.join(HERE, "..", "..", "..", "datasets", "blade", "raw", "opensource",
                 "test_v6_candidates", "glitchtip-backend")
)
OUT = os.path.join(HERE, "candidates.jsonl")

PROJECT = "glitchtip"
SERVICE = "GlitchTip"
REPO_URL = "https://gitlab.com/glitchtip/glitchtip-backend"
COMMIT = "d3039088e913a591a8e6544a2d2fffc865a9711a"
TAG = "v6.2.6"
LICENSE = "MIT"

_cache = {}


def lines_of(rel):
    if rel not in _cache:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def py_end(rel, start):
    """End line (1-based, inclusive) of the Python function whose decorators/def begin at `start`.

    The def ends where the next non-blank line has indentation <= the def line's.
    Decorator lines above the def are included because `start` points at them.
    """
    ls = lines_of(rel)
    i = start - 1
    while not ls[i].lstrip().startswith(("def ", "async def ")):
        i += 1
        if i >= len(ls):
            raise RuntimeError(f"no def after {rel}:{start}")
    def_indent = len(ls[i]) - len(ls[i].lstrip())
    depth = 0
    j = i
    while True:
        depth += ls[j].count("(") - ls[j].count(")")
        if depth <= 0 and ls[j].rstrip().endswith(":"):
            break
        j += 1
    end = j
    k = j + 1
    while k < len(ls):
        line_ = ls[k]
        if line_.strip() == "":
            k += 1
            continue
        if len(line_) - len(line_.lstrip()) <= def_indent:
            break
        end = k
        k += 1
    return end + 1


def block(rel, start, end=None, elide=()):
    """Verbatim lines start..end (inclusive). `elide` = list of (a, b) line ranges replaced by '...'.
    b may be None to elide through the end of the block."""
    if end is None:
        end = py_end(rel, start)
    ls = lines_of(rel)
    elide = sorted((a, end if b is None else b) for a, b in elide)
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


def pyblock(rel, start, elide=()):
    return block(rel, start, py_end(rel, start), elide)


def line(rel, n):
    return lines_of(rel)[n - 1].strip()


def ev(rel, a, b=None):
    if b is None:
        return {"type": "code", "text": line(rel, a), "location": f"{rel}:{a}"}
    text = "\n".join(l.strip() for l in lines_of(rel)[a - 1:b])
    return {"type": "code", "text": text, "location": f"{rel}:{a}-{b}"}


# ---- files ----------------------------------------------------------------
APIPY = "glitchtip/api/api.py"
AUTHPY = "glitchtip/api/authentication.py"
PERM = "glitchtip/api/permissions.py"
URLS = "glitchtip/urls.py"
ORG = "apps/organizations_ext/api.py"
QU = "apps/organizations_ext/queryset_utils.py"
CONST = "apps/organizations_ext/constants.py"
UTILS = "apps/organizations_ext/utils.py"
SOC = "apps/organizations_ext/social_app_api.py"
TEAMS = "apps/teams/api.py"
PROJ = "apps/projects/api.py"
USERS = "apps/users/api.py"
TOK = "apps/api_tokens/api.py"
ALERTS = "apps/alerts/api.py"
ENV = "apps/environments/api.py"
REL = "apps/releases/api.py"
UP = "apps/uptime/api.py"
STATS = "apps/stats/api.py"
ISS = "apps/issue_events/api/issues.py"
EVT = "apps/issue_events/api/events.py"
COM = "apps/issue_events/api/comments.py"
SVC = "apps/issue_events/services.py"
ING = "apps/event_ingest/api.py"
INGAUTH = "apps/event_ingest/authentication.py"
VIEWS = "apps/event_ingest/views.py"
EMBED = "apps/event_ingest/embed_api.py"
FILES = "apps/files/api.py"
PERF = "apps/performance/api.py"
LOGS = "apps/logs/api.py"
IMP = "apps/importer/api.py"
WIZ = "apps/wizard/api.py"

# ---- shared blocks --------------------------------------------------------
API_AUTH = block(APIPY, 48, 54, elide=[(49, 51), (53, 53)])  # NinjaAPI(auth=[TokenAuth(), SessionAuth()])
SESSION_AUTH = block(AUTHPY, 35, 41)                 # SessionAuth.authenticate (session-only router records)
TOKEN_AUTH = block(AUTHPY, 63, 69)                   # TokenAuth.authenticate -> Auth(token.user_id, "token", data=token)
AUTH = [API_AUTH, TOKEN_AUTH]
AUTH_SESSION_ONLY = [API_AUTH, SESSION_AUTH]
HASPERM = block(PERM, 8, 28, elide=[(9, 18), (25, 27)])  # has_permission = token scope check only (docstring elided)
ROLE = block(CONST, 124, 128)                        # OrganizationUserRole MEMBER<ADMIN<MANAGER<OWNER
QS_ORG = block(QU, 16, 52, elide=[(32, 51)])         # get_organizations_queryset (+actor_role)
QS_ORGUSERS = block(QU, 55, 81, elide=[(66, 67), (79, 80)])  # get_organization_users_queryset
QS_ORG_FOR_USER = block(QU, 9, 13)                   # get_organization_for_user
TEAM_QS = block(TEAMS, 39, 79, elide=[(57, 78)])     # get_team_queryset
TEAM_QS_SHORT = block(TEAMS, 39, 79, elide=[(49, 54), (57, 78)])
PROJ_QS = block(PROJ, 45, 55)                        # get_projects_queryset
KEYS_QS = block(PROJ, 58, 68)                        # get_project_keys_queryset
SVC_QS = block(SVC, 87, 130, elide=[(111, 130)])     # issue_events.services.get_queryset
EVT_QS = block(EVT, 20, 34)                          # events.get_queryset
REL_QS = block(REL, 58, 74)                          # get_releases_queryset
ALERT_QS = block(ALERTS, 36, 41)                     # get_project_alert_queryset
MON_QS = block(UP, 67, 73)                           # get_monitor_queryset
MODIFY = block(TEAMS, 191, 235, elide=[(230, 235)])  # modify_member_for_team (open_membership)
ORG_OPEN = block(UTILS, 7, 11)                       # is_organization_creation_open
SSO_PLAN = block(UTILS, 14, 33, elide=[(15, 22)])    # organization_can_customize_sso
ORG_MGR = block(SOC, 84, 96)                         # get_organization_for_manager
SOC_QS = block(SOC, 99, 104)                         # get_social_apps_queryset
TOK_ROUTER = block(TOK, 10, 10)                      # Router(auth=SessionAuth())
TOK_QS = block(TOK, 13, 15)                          # api token queryset by user
USER_QS = block(USERS, 54, 58)
EMAIL_QS = block(USERS, 61, 65)
VALIDATE_TOKEN = block(ORG, 394, 404)                # invite token check
EVENT_AUTH = [
    block(ING, 27, 27),                              # router = Router(auth=event_auth)
    block(INGAUTH, 348, 358),                        # event_auth
    block(INGAUTH, 56, 81, elide=[(57, 66)]),        # auth_from_request (DSN key extraction)
    block(INGAUTH, 141, 241, elide=[(142, 146), (149, 154), (157, 163), (165, 185), (192, 206), (214, 240)]),  # get_project
]
EMBED_AUTH = [block(EMBED, 19, 38), block(EMBED, 41, 47)]

# ---- OAS helpers ----------------------------------------------------------
BEARER = [{"sessionOrToken": []}]
SESSION = [{"sessionCookie": []}]
DSN = [{"dsnKey": []}]
SEC_SCHEMES = {
    "sessionOrToken": {
        "type": "http", "scheme": "bearer",
        "description": "Session cookie or Bearer API token (glitchtip NinjaAPI auth=[TokenAuth(), SessionAuth()]); "
                       "DSN/sentry_key for ingest endpoints",
    },
    "sessionCookie": {
        "type": "apiKey", "in": "cookie", "name": "sessionid",
        "description": "Django session only (api_tokens router uses Router(auth=SessionAuth()); API tokens are rejected)",
    },
    "dsnKey": {
        "type": "apiKey", "in": "query", "name": "sentry_key",
        "description": "Project DSN public key via sentry_key/glitchtip_key query param, Authorization: Bearer, or "
                       "X-Sentry-Auth header (event_auth). Identifies a project key, not a user.",
    },
}
INT_PARAMS = {"member_id", "issue_id", "monitor_id", "alert_id", "social_app_id", "token_id",
              "org_user_id", "project_id", "comment_id", "file_id", "id"}
UUID_PARAMS = {"key_id", "endpoint_id", "event_id", "log_id"}


def p(name, where="path", typ="string", required=True, fmt=None, desc=None):
    s = {"type": typ}
    if fmt:
        s["format"] = fmt
    d = {"name": name, "in": where, "required": required, "schema": s}
    if desc:
        d["description"] = desc
    return d


def path_params(path):
    out = []
    for name in re.findall(r"\{(\w+)\}", path):
        if name in INT_PARAMS:
            out.append(p(name, "path", "integer"))
        elif name in UUID_PARAMS:
            out.append(p(name, "path", "string", True, "uuid"))
        elif name == "user_id":
            out.append(p(name, "path", "string", True, None, 'user id or "me"'))
        else:
            out.append(p(name, "path", "string"))
    return out


def q(name, typ="string", required=False):
    return p(name, "query", typ, required)


def body(keys, required=None, content_type="application/json"):
    props = {}
    for k in keys:
        if isinstance(k, tuple):
            props[k[0]] = {"type": k[1]}
        else:
            props[k] = {"type": "string"}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"required": True, "content": {content_type: {"schema": schema}}}


records = []


def add(method, path, summary, blocks, label, conf, evidence, reason, auth_summary,
        query=None, req_body=None, security=BEARER, response_fields=None, description="",
        permission_doc="", status="200"):
    texts = [b["text"] for b in blocks]
    controller_text = "\n\n".join(texts)
    locs = [{"file": b["file"], "start_line": b["start_line"], "end_line": b["end_line"]} for b in blocks]
    segs = [s for s in path.split("/") if s and s not in ("api", "0")]
    op = {
        "operationId": method.lower() + "".join(
            "".join(w.title() for w in seg.strip("{}").replace("-", "_").split("_")) for seg in segs),
        "summary": summary,
        "description": description,
        "parameters": path_params(path) + (query or []),
        "responses": {status: {"description": "OK" if status == "200" else "Created" if status == "201" else "No Content"}},
    }
    if security is not None and security != []:
        op["responses"]["401"] = {"description": "Unauthorized"}
    if req_body:
        op["requestBody"] = req_body
    if security is not None:
        op["security"] = security
    used = {k: v for k, v in SEC_SCHEMES.items() if any(k in s for s in (security or []))}
    rec = {
        "project": PROJECT, "service": SERVICE, "repository": REPO_URL,
        "commit": COMMIT, "tag": TAG, "license": LICENSE,
        "method": method, "path": path, "oas_status": "generated",
        "oas_operation": op,
        "oas_global_security": BEARER,
        "oas_security_schemes": used,
        "response_schema_fields": response_fields or [],
        "controller_text": controller_text,
        "source_locations": locs,
        "auth_summary": auth_summary,
        "permission_doc": permission_doc,
        "draft_label": label, "draft_confidence": conf,
        "evidence": evidence, "draft_reason": reason,
        "known_vulnerable": False, "advisory": None, "fix_commit": None,
    }
    records.append(rec)


# response field sets
ORG_FIELDS = ["id", "name", "slug", "dateCreated", "status", "avatar", "isEarlyAdopter", "require2fa",
              "isAcceptingEvents", "eventThrottleRate"]
ORG_DETAIL_FIELDS = ORG_FIELDS + ["projects", "teams", "access", "openMembership"]
ORGUSER_FIELDS = ["id", "role", "roleName", "dateCreated", "email", "user", "pending", "isOwner"]
TEAM_FIELDS = ["id", "slug", "dateCreated", "isMember", "memberCount"]
TEAM_PROJECT_FIELDS = TEAM_FIELDS + ["projects"]
PROJECT_FIELDS = ["id", "name", "slug", "platform", "dateCreated", "isMember", "firstEvent", "scrubIPAddresses",
                  "eventThrottleRate", "avatar", "color", "features", "hasAccess", "isBookmarked", "isInternal", "isPublic"]
KEY_FIELDS = ["id", "dateCreated", "dsn", "label", "public", "projectId", "rateLimit"]
ISSUE_FIELDS = ["id", "title", "culprit", "count", "type", "level", "status", "metadata", "project", "shortId",
                "numComments", "firstSeen", "lastSeen", "assignedTo", "statusDetails", "userCount", "firstRelease", "lastRelease"]
EVENT_FIELDS = ["id", "eventId", "projectId", "groupId", "dateCreated", "dateReceived", "title", "type", "message",
                "metadata", "tags", "entries", "contexts", "user", "sdk"]
COMMENT_FIELDS = ["id", "data", "type", "dateCreated", "user"]
RELEASE_FIELDS = ["version", "shortVersion", "dateCreated", "dateReleased", "ref", "url", "data", "commitCount",
                  "deployCount", "projects", "repository"]
ALERT_FIELDS = ["id", "name", "timespanMinutes", "quantity", "uptime", "alertRecipients"]
MONITOR_FIELDS = ["id", "monitorType", "endpointId", "created", "name", "url", "expectedStatus", "expectedBody",
                  "interval", "timeout", "confirmationThreshold", "projectId", "environmentId", "isUp", "lastChange",
                  "heartbeatEndpoint", "projectName", "envName", "checks", "organizationId"]
USER_FIELDS = ["id", "username", "email", "name", "options", "dateJoined", "hasPasswordAuth", "identities",
               "lastLogin", "isSuperuser", "isActive"]
EMAIL_FIELDS = ["email", "isPrimary", "isVerified"]
TOKEN_FIELDS = ["id", "label", "scopes", "token", "created"]

ORG_P = "/api/0/organizations/{organization_slug}"
MEMBERSHIP_NOTE = ("has_permission 데코레이터는 API 토큰 scope 검사이므로 근거로 쓰지 않는다. ")

# ============================================================================
# ORGANIZATIONS (apps/organizations_ext/api.py)
# ============================================================================
add("GET", "/api/0/organizations/", "List my organizations",
    AUTH + [HASPERM, pyblock(ORG, 53), QS_ORG],
    "owner_match", 0.75,
    [ev(ORG, 64), ev(QU, 19)],
    "get_organizations_queryset(request.auth.user_id)로 요청자가 구성원인 조직만 조회한다(Organization.objects.filter(users=user_id)). "
    "대상 그룹 지정이 없고 처리 대상이 인증 사용자 본인의 목록으로 고정되므로 owner_match(G4 본인 목록). " + MEMBERSHIP_NOTE +
    "대안: 구성원 관계가 필터 조건이라는 점에서 membership_required로 볼 여지.",
    "인증(세션/토큰) → Organization.objects.filter(users=request.auth.user_id) 본인 소속 조직 목록",
    query=[q("owner", "boolean"), q("query"), q("sortBy")], response_fields=ORG_FIELDS)

add("GET", ORG_P + "/", "Get organization detail",
    AUTH + [HASPERM, pyblock(ORG, 67), QS_ORG],
    "membership_required", 0.9,
    [ev(ORG, 75, 78), ev(QU, 19), ev(QU, 21, 22)],
    "경로의 organization_slug로 대상 조직을 지정하고 get_organizations_queryset이 Organization.objects.filter(users=user_id, slug=...)로 "
    "(요청자, 조직) 구성원 관계가 있을 때만 404가 아니다. 역할 조건 없음 → membership_required(G2). " + MEMBERSHIP_NOTE,
    "인증 → get_organizations_queryset(user_id, organization_slug): users=user_id 구성원 필터, 역할 검사 없음",
    response_fields=ORG_DETAIL_FIELDS)

add("POST", "/api/0/organizations/", "Create organization",
    AUTH + [HASPERM, pyblock(ORG, 82), ORG_OPEN],
    "manual_review_required", 0.7,
    [ev(ORG, 92, 93), ev(UTILS, 8, 11)],
    "is_organization_creation_open()(settings.ENABLE_ORGANIZATION_CREATION 또는 조직이 하나도 없음) OR user.is_superuser. "
    "설정값에 따라 허용 주체가 '인증된 모든 사용자'와 '슈퍼유저만' 사이에서 바뀌므로 G6(설정에 따라 허용 주체 변경) → manual_review_required. "
    "설정이 닫힌 배포만 보면 role_required(전역 superuser)가 대안.",
    "인증 → ENABLE_ORGANIZATION_CREATION 또는 첫 조직이면 누구나, 아니면 is_superuser만",
    req_body=body(["name"], ["name"]), response_fields=ORG_DETAIL_FIELDS, status="201",
    permission_doc="Create new organization. The first organization on a server is always allowed to be created. "
                   "Afterwards, ENABLE_OPEN_USER_REGISTRATION is checked. Superusers are always allowed to create organizations.")

add("PUT", ORG_P + "/", "Update organization",
    AUTH + [HASPERM, pyblock(ORG, 105), QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(ORG, 115, 122), ev(ORG, 123, 124), ev(CONST, 124, 128)],
    "get_organizations_queryset(role_required=True)로 구성원 확인 후 actor_role(조직 안 역할) < MANAGER면 403. "
    "구성원 확인 뒤 그룹 안 역할(MANAGER 이상)이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER(2) 필요",
    req_body=body(["name"]), response_fields=ORG_DETAIL_FIELDS)

add("DELETE", ORG_P + "/", "Delete organization",
    AUTH + [HASPERM, pyblock(ORG, 131), QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(ORG, 137, 143), ev(ORG, 144, 145), ev(CONST, 124, 128)],
    "구성원 필터 후 actor_role < MANAGER면 403. 조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER 필요",
    status="204")

add("GET", ORG_P + "/members/", "List organization members",
    AUTH + [HASPERM, pyblock(ORG, 150), QS_ORGUSERS],
    "membership_required", 0.9,
    [ev(ORG, 160), ev(QU, 62, 65)],
    "get_organization_users_queryset이 OrganizationUser.objects.filter(organization__users=user_id, organization__slug=...)로 "
    "요청자가 해당 조직 구성원일 때만 결과를 준다. 역할 조건 없음 → membership_required(G2). " + MEMBERSHIP_NOTE,
    "인증 → organization__users=request.auth.user_id 구성원 필터, 역할 검사 없음",
    response_fields=ORGUSER_FIELDS)

add("GET", "/api/0/teams/{organization_slug}/{team_slug}/members/", "List team members (organization users in team)",
    AUTH + [HASPERM, pyblock(ORG, 163), QS_ORGUSERS],
    "membership_required", 0.85,
    [ev(ORG, 176, 178), ev(QU, 62, 65), ev(QU, 69, 70)],
    "get_organization_users_queryset(user_id, organization_slug, team_slug)로 요청자가 조직 구성원이어야 하고 teams__slug로 팀을 필터한다. "
    "요청자의 팀 소속은 요구하지 않고 조직 구성원 관계만 조건 → membership_required(G2, 대상 그룹=조직). " + MEMBERSHIP_NOTE,
    "인증 → 조직 구성원 필터(organization__users=user_id) + 팀 slug 필터, 팀 소속·역할 검사 없음",
    response_fields=ORGUSER_FIELDS)

add("GET", ORG_P + "/members/{member_id}/", "Get organization member",
    AUTH + [HASPERM, pyblock(ORG, 181), QS_ORGUSERS],
    "membership_required", 0.9,
    [ev(ORG, 190, 194), ev(QU, 63, 65)],
    "조직 구성원 필터(organization__users=user_id) 안에서 pk=member_id를 조회한다. 요청자가 조직 구성원이면 다른 구성원 정보도 볼 수 있고 역할 조건 없음 → membership_required(G2).",
    "인증 → 조직 구성원 필터 → 구성원 레코드 조회, 역할 검사 없음",
    response_fields=ORGUSER_FIELDS + ["teams"])

add("POST", ORG_P + "/members/", "Invite organization member",
    AUTH + [HASPERM, pyblock(ORG, 197, elide=[(206, 217), (227, 275)]), QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(ORG, 218, 224), ev(ORG, 225, 226), ev(CONST, 124, 128)],
    "get_organizations_queryset(role_required=True).filter(organization_users__user=user)로 구성원 확인 후 actor_role < MANAGER면 403. "
    "조직 안 역할(MANAGER 이상)이 결정 조건 → role_required(G3). 이메일 인증·초대 제한·스로틀은 인가와 무관해 생략.",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER 필요(초대 생성)",
    req_body=body(["email", "orgRole", ("teamRoles", "array"), ("sendInvite", "boolean"), ("reinvite", "boolean")], ["email", "orgRole"]),
    response_fields=ORGUSER_FIELDS + ["inviteLink"], status="201")

add("DELETE", ORG_P + "/members/{member_id}/", "Remove organization member (or leave)",
    AUTH + [HASPERM, pyblock(ORG, 278, elide=[(303, 312)]), QS_ORGUSERS, ROLE],
    "owner_or_admin", 0.85,
    [ev(ORG, 298, 302), ev(ORG, 288, 293), ev(CONST, 124, 128)],
    "구성원 필터 후 `actor_role < MANAGER and not (org_user.user.id == user_id)`이면 403. 즉 대상 구성원 행이 본인(당사자)이면 허용 OR 조직 안 MANAGER 이상이면 허용. "
    "당사자 OR 관리자 우회가 실제 조건 → owner_or_admin(G5). 조직 소유자(OrganizationOwner)는 본인 삭제 불가(400).",
    "인증 → 조직 구성원 필터 → 본인 행이거나 actor_role >= MANAGER",
    status="204")

add("PUT", ORG_P + "/members/{member_id}/", "Update member role",
    AUTH + [HASPERM, pyblock(ORG, 317, elide=[(341, 352)]), QS_ORGUSERS, ROLE],
    "role_required", 0.9,
    [ev(ORG, 330, 338), ev(ORG, 339, 340), ev(CONST, 124, 128)],
    "get_organization_users_queryset(role_required=True)로 구성원 확인 후 member.actor_role(요청자 역할) < MANAGER면 403. 조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER 필요",
    req_body=body(["orgRole", ("teamRoles", "array")], ["orgRole"]), response_fields=ORGUSER_FIELDS + ["teams"])

add("POST", ORG_P + "/members/{member_id}/set_owner/", "Set organization primary owner",
    AUTH + [HASPERM, pyblock(ORG, 356, elide=[(387, 390)]), QS_ORGUSERS, ROLE],
    "role_required", 0.7,
    [ev(ORG, 379, 385), ev(ORG, 371, 376), ev(CONST, 128)],
    "조직 구성원 필터 뒤 `old_owner.user_id == user_id`(현 대표 소유자) OR 요청자의 조직 역할 == OWNER일 때만 허용. "
    "두 조건 모두 조직 안 OWNER 지위에 해당하므로 role_required(G3)로 두었다. 대안: 대표 소유자 신분 OR 역할의 OR 결합으로 보아 manual. "
    "docstring의 org:admin scope 문구는 토큰 scope 설명이며 코드에는 scope 우회가 없다.",
    "인증 → 조직 구성원 필터 → 현 primary owner 본인 또는 role == OWNER",
    response_fields=ORGUSER_FIELDS + ["teams"],
    permission_doc="Set this team member as the one and only one Organization owner. "
                   "Only an existing Owner or user with the \"org:admin\" scope is able to perform this.")

add("GET", "/api/0/accept/{org_user_id}/{token}/", "Preview organization invite (anonymous, token)",
    [API_AUTH, pyblock(ORG, 407), VALIDATE_TOKEN],
    "manual_review_required", 0.6,
    [ev(ORG, 407, 412), ev(ORG, 415), ev(ORG, 402, 403)],
    "auth=None으로 인증을 요구하지 않지만 InvitationTokenGenerator().check_token(org_user, token)이 유효해야 한다. "
    "익명 접근이 초대 토큰 소지라는 조건부로만 허용되므로 G7에 따라 public이 아니고, 토큰 소지는 6종으로 표현되지 않아 manual_review_required. 대안: public(토큰을 URL 비밀로 보면).",
    "auth=None; 초대 토큰(org_user_id, token) 검증만",
    security=[], response_fields=["acceptInvite", "orgUser"])

add("POST", "/api/0/accept/{org_user_id}/{token}/", "Accept organization invite",
    AUTH + [pyblock(ORG, 419), VALIDATE_TOKEN],
    "manual_review_required", 0.7,
    [ev(ORG, 428), ev(ORG, 402, 403), ev(ORG, 429, 432)],
    "인증된 사용자가 유효한 초대 토큰을 제시하면 org_user.user를 요청자로 설정한다. 요청자-조직 구성원 관계나 역할 검사는 없고 "
    "토큰 소지가 유일한 조건이므로 6종에 대응하지 않아 manual_review_required(Umami /api/teams/join accessCode 선례).",
    "인증 + 초대 토큰 검증(validate_token); 구성원·역할 검사 없음",
    req_body=body([("acceptInvite", "boolean")], ["acceptInvite"]), response_fields=["acceptInvite", "orgUser"])

# ============================================================================
# TEAMS (apps/teams/api.py)
# ============================================================================
add("GET", "/api/0/teams/{organization_slug}/{team_slug}/", "Get team",
    AUTH + [HASPERM, pyblock(TEAMS, 82), TEAM_QS],
    "membership_required", 0.9,
    [ev(TEAMS, 90, 98), ev(TEAMS, 55, 56)],
    "get_team_queryset(user_id=...)이 Team을 organization__users=user_id로 필터해 요청자가 팀의 조직 구성원일 때만 조회된다. "
    "팀 소속(is_member)은 annotate만 하고 조건이 아니다. 조직 구성원 관계가 결정 조건 → membership_required(G2).",
    "인증 → Team.filter(organization__slug, slug=team_slug, organization__users=user_id); 팀 소속·역할 검사 없음",
    response_fields=TEAM_PROJECT_FIELDS)

add("PUT", "/api/0/teams/{organization_slug}/{team_slug}/", "Update team slug",
    AUTH + [HASPERM, pyblock(TEAMS, 101), TEAM_QS],
    "membership_required", 0.7,
    [ev(TEAMS, 111, 119), ev(TEAMS, 55, 56), ev(TEAMS, 120, 121)],
    "조회와 동일하게 organization__users=user_id 구성원 필터만 통과하면 slug를 수정한다. 역할 조건이 코드에 없으므로 membership_required(G2). "
    "같은 파일의 delete_team은 ADMIN 이상을 요구하므로 수정에도 역할 의도가 있었을 가능성이 있어 confidence를 낮춤(검수자 확인).",
    "인증 → 조직 구성원 필터만, 역할 검사 없음(delete_team은 ADMIN 요구)",
    req_body=body(["slug"], ["slug"]), response_fields=TEAM_PROJECT_FIELDS)

add("DELETE", "/api/0/teams/{organization_slug}/{team_slug}/", "Delete team",
    AUTH + [HASPERM, pyblock(TEAMS, 125), TEAM_QS, ROLE],
    "role_required", 0.9,
    [ev(TEAMS, 132, 135), ev(CONST, 124, 128)],
    "구성원 필터에 더해 organization__organization_users__user_id=user_id AND role__gte=ADMIN을 만족하는 행만 삭제된다(아니면 404). "
    "조직 안 ADMIN 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 + organization_users__role >= ADMIN",
    status="204")

add("GET", ORG_P + "/teams/", "List organization teams",
    AUTH + [HASPERM, pyblock(TEAMS, 143), TEAM_QS],
    "membership_required", 0.9,
    [ev(TEAMS, 155, 160), ev(TEAMS, 55, 56)],
    "get_team_queryset(organization_slug, user_id)가 organization__users=user_id로 필터한다. 조직 구성원 관계만 조건 → membership_required(G2).",
    "인증 → 조직 구성원 필터, 역할 검사 없음",
    response_fields=TEAM_PROJECT_FIELDS)

add("POST", ORG_P + "/teams/", "Create team",
    AUTH + [HASPERM, pyblock(TEAMS, 163), ROLE],
    "role_required", 0.9,
    [ev(TEAMS, 173, 178), ev(CONST, 124, 128)],
    "aget_object_or_404(Organization, slug, users=user_id, organization_users__role__gte=ADMIN)로 조직 구성원이면서 ADMIN 이상 역할이어야 한다. "
    "조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → Organization(users=user_id, organization_users__role >= ADMIN)",
    req_body=body(["slug"], ["slug"]), response_fields=TEAM_PROJECT_FIELDS, status="201")

add("POST", ORG_P + "/members/{member_id}/teams/{team_slug}/", "Add member to team",
    AUTH + [HASPERM, pyblock(TEAMS, 238), MODIFY, ROLE],
    "manual_review_required", 0.8,
    [ev(TEAMS, 215, 218), ev(TEAMS, 219, 223), ev(TEAMS, 225, 228)],
    "modify_member_for_team: 조직 설정 open_membership이 켜져 있고 대상이 본인(me)이면 추가 검사 없이 허용, 아니면 요청자가 이미 팀원이면 ADMIN, 아니면 MANAGER 이상 역할 필요. "
    "조직 설정값에 따라 허용 주체가 바뀌고 본인 조건과 역할 조건이 분기 결합되므로 G6 → manual_review_required(사용자 결정 6).",
    "인증 → 조직 구성원 필터 → (open_membership AND 본인) OR 역할(팀원이면 ADMIN, 아니면 MANAGER)",
    response_fields=TEAM_PROJECT_FIELDS, status="201")

add("DELETE", ORG_P + "/members/{member_id}/teams/{team_slug}/", "Remove member from team",
    AUTH + [HASPERM, pyblock(TEAMS, 255), MODIFY, ROLE],
    "manual_review_required", 0.8,
    [ev(TEAMS, 215, 218), ev(TEAMS, 219, 223), ev(TEAMS, 225, 228)],
    "add_member_to_team과 같은 modify_member_for_team 분기: (open_membership AND 본인) OR 조직 안 역할(ADMIN/MANAGER). 설정 의존 + 분기 결합 → manual_review_required(G6).",
    "인증 → 조직 구성원 필터 → (open_membership AND 본인) OR 역할",
    response_fields=TEAM_PROJECT_FIELDS)

add("GET", "/api/0/projects/{organization_slug}/{project_slug}/teams/", "List project teams",
    AUTH + [HASPERM, pyblock(TEAMS, 269), TEAM_QS],
    "membership_required", 0.9,
    [ev(TEAMS, 284, 289), ev(TEAMS, 55, 56)],
    "get_team_queryset(..., user_id, project_slug)가 organization__users=user_id로 필터한다. 조직 구성원 관계가 조건 → membership_required(G2).",
    "인증 → 조직 구성원 필터 + projects__slug 필터",
    response_fields=TEAM_FIELDS)

add("POST", "/api/0/projects/{organization_slug}/{project_slug}/teams/{team_slug}/", "Add team to project",
    AUTH + [HASPERM, pyblock(TEAMS, 292), TEAM_QS, ROLE],
    "role_required", 0.9,
    [ev(TEAMS, 303, 309), ev(CONST, 124, 128)],
    "Project를 organization__users=user_id AND organization__organization_users__role__gte=MANAGER로 조회한다. 조직 안 MANAGER 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → Project(organization__users=user_id, organization_users__role >= MANAGER)",
    response_fields=PROJECT_FIELDS + ["teams"], status="201")

add("DELETE", "/api/0/projects/{organization_slug}/{project_slug}/teams/{team_slug}/", "Remove team from project",
    AUTH + [HASPERM, pyblock(TEAMS, 322), TEAM_QS, ROLE],
    "role_required", 0.9,
    [ev(TEAMS, 338, 344), ev(CONST, 124, 128)],
    "Project 조회 조건에 organization__organization_users__role__gte=MANAGER가 포함된다. 조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → Project(organization__users=user_id, organization_users__role >= MANAGER)",
    response_fields=PROJECT_FIELDS + ["teams"])

# ============================================================================
# PROJECTS (apps/projects/api.py)
# ============================================================================
add("GET", "/api/0/projects/", "List my projects",
    AUTH + [HASPERM, pyblock(PROJ, 71), PROJ_QS],
    "owner_match", 0.75,
    [ev(PROJ, 80, 84), ev(PROJ, 48, 50)],
    "get_projects_queryset(user_id)가 Project.undeleted_objects.filter(organization__users=user_id)로 요청자가 속한 조직들의 프로젝트만 돌려준다. "
    "대상 그룹 지정이 없고 본인 접근 가능 목록으로 고정 → owner_match(G4 본인 목록). 대안: membership_required(구성원 필터).",
    "인증 → organization__users=request.auth.user_id 본인 소속 조직 프로젝트 목록",
    response_fields=PROJECT_FIELDS + ["organization"])

add("GET", "/api/0/projects/{organization_slug}/{project_slug}/", "Get project",
    AUTH + [HASPERM, pyblock(PROJ, 87), PROJ_QS],
    "membership_required", 0.9,
    [ev(PROJ, 96, 101), ev(PROJ, 48, 50)],
    "get_projects_queryset(user_id, organization_slug)가 organization__users=user_id로 필터한다. 경로가 조직을 지정하고 (요청자, 조직) 구성원 관계가 조건 → membership_required(G2). is_member(팀 소속)는 annotate만.",
    "인증 → Project(organization__users=user_id, organization__slug, slug); 팀 소속·역할 검사 없음",
    response_fields=PROJECT_FIELDS + ["organization"])

add("PUT", "/api/0/projects/{organization_slug}/{project_slug}/", "Update project",
    AUTH + [HASPERM, pyblock(PROJ, 104), PROJ_QS],
    "membership_required", 0.7,
    [ev(PROJ, 116, 121), ev(PROJ, 48, 50), ev(PROJ, 122, 124)],
    "조회와 같은 organization__users=user_id 구성원 필터만 통과하면 속성을 갱신한다. 역할 조건이 없으므로 membership_required(G2). "
    "delete_project는 ADMIN 이상을 요구해 수정에 역할 의도가 있었을 가능성이 있어 confidence를 낮춤.",
    "인증 → 조직 구성원 필터만, 역할 검사 없음(delete는 ADMIN)",
    req_body=body(["name", "slug", "platform", ("eventThrottleRate", "integer")]), response_fields=PROJECT_FIELDS + ["organization"])

add("DELETE", "/api/0/projects/{organization_slug}/{project_slug}/", "Delete project",
    AUTH + [HASPERM, pyblock(PROJ, 128), PROJ_QS, ROLE],
    "role_required", 0.9,
    [ev(PROJ, 136, 141), ev(CONST, 124, 128)],
    "구성원 필터에 organization__organization_users__user_id=user_id AND role__gte=ADMIN을 추가한다. 조직 안 ADMIN 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 + organization_users__role >= ADMIN",
    status="204")

add("POST", "/api/0/teams/{organization_slug}/{team_slug}/projects/", "Create project in team",
    AUTH + [HASPERM, pyblock(PROJ, 165), ROLE],
    "role_required", 0.9,
    [ev(PROJ, 176, 182), ev(PROJ, 183, 188), ev(CONST, 124, 128)],
    "Team과 Organization을 모두 users=user_id AND organization_users__role__gte=ADMIN으로 조회한다. 조직 안 ADMIN 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → Team/Organization(users=user_id, organization_users__role >= ADMIN)",
    req_body=body(["name", "slug", "platform", ("eventThrottleRate", "integer")], ["name"]), response_fields=PROJECT_FIELDS, status="201")

add("GET", ORG_P + "/projects/", "List organization projects",
    AUTH + [HASPERM, pyblock(PROJ, 197, elide=[(220, 230)]), PROJ_QS],
    "membership_required", 0.9,
    [ev(PROJ, 215, 219), ev(PROJ, 48, 50)],
    "get_projects_queryset(user_id, organization_slug=...)가 organization__users=user_id로 필터한다. 조직 구성원 관계가 조건 → membership_required(G2).",
    "인증 → 조직 구성원 필터, 역할 검사 없음",
    query=[q("query")], response_fields=PROJECT_FIELDS + ["teams"])

add("POST", "/api/0/projects/{organization_slug}/{project_slug}/keys/", "Create project DSN key",
    AUTH + [HASPERM, pyblock(PROJ, 293), PROJ_QS],
    "membership_required", 0.7,
    [ev(PROJ, 306, 309), ev(PROJ, 48, 50)],
    "get_projects_queryset(user_id, organization_slug) 구성원 필터로 프로젝트를 찾으면 키를 생성한다. 역할 조건 없음 → membership_required(G2). "
    "delete_project_key는 ADMIN 이상을 요구하므로 생성에도 역할 의도가 있었을 수 있어 confidence를 낮춤.",
    "인증 → 조직 구성원 필터만, 역할 검사 없음(delete key는 ADMIN)",
    req_body=body(["name", ("rateLimit", "object")]), response_fields=KEY_FIELDS, status="201")

add("DELETE", "/api/0/projects/{organization_slug}/{project_slug}/keys/{key_id}/", "Delete project DSN key",
    AUTH + [HASPERM, pyblock(PROJ, 321), KEYS_QS, ROLE],
    "role_required", 0.9,
    [ev(PROJ, 329, 337), ev(CONST, 124, 128)],
    "get_project_keys_queryset 구성원 필터에 project__organization__organization_users__role__gte=ADMIN을 추가해 삭제한다(아니면 404). 조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 + organization_users__role >= ADMIN",
    status="204")

add("PUT", "/api/0/users/{user_id}/notifications/alerts/", "Update my per-project alert settings",
    AUTH + [pyblock(PROJ, 361, elide=[(368, 374)])],
    "owner_match", 0.9,
    [ev(PROJ, 365, 367), ev(PROJ, 376, 378)],
    "user_id가 request.auth.user_id 또는 'me'가 아니면 404이고, 이후 user_id = request.auth.user_id로 고정해 본인 UserProjectAlert만 변경한다. 관리자 우회 없음 → owner_match(G4).",
    "인증 → user_id == 본인 또는 'me' 강제, 본인 설정만 갱신",
    req_body=body([("<project_id>", "integer")]), status="204")

# ============================================================================
# USERS / API TOKENS
# ============================================================================
add("GET", "/api/0/users/{user_id}/", "Get user (self)",
    AUTH + [pyblock(USERS, 78), USER_QS],
    "owner_match", 0.8,
    [ev(USERS, 80, 81), ev(USERS, 55)],
    "경로 user_id 값과 무관하게 user_id = request.auth.user_id로 덮어쓰고 본인 User만 조회한다. 처리 대상이 인증 사용자 본인으로 고정 → owner_match(G4). "
    "타인 id를 넣어도 404가 아니라 본인이 반환되는 점은 검수 메모.",
    "인증 → 경로 user_id 무시, request.auth.user_id 본인만",
    response_fields=USER_FIELDS + ["chatwootIdentifierHash"])

add("PUT", "/api/0/users/{user_id}/", "Update user (self)",
    AUTH + [pyblock(USERS, 117), USER_QS],
    "owner_match", 0.9,
    [ev(USERS, 123, 126)],
    "user_id가 본인 id 또는 'me'가 아니면 404, 이후 본인 User만 수정한다. 관리자 우회 없음 → owner_match(G4).",
    "인증 → user_id == 본인 또는 'me' 강제",
    req_body=body(["name", ("options", "object")]), response_fields=USER_FIELDS)

add("DELETE", "/api/0/users/{user_id}/", "Delete user (self only)",
    AUTH + [pyblock(USERS, 84, elide=[(92, 106)]), USER_QS],
    "owner_match", 0.9,
    [ev(USERS, 86, 90), ev(USERS, 96, 98)],
    "주석 'Can only delete self'와 user_id == 본인/'me' 검사. 조직 소유자인 경우 400으로 거부하지만 허용 주체는 본인만 → owner_match(G4).",
    "인증 → 본인만 삭제, 조직 owner면 400",
    status="204")

add("GET", "/api/0/users/{user_id}/emails/", "List my email addresses",
    AUTH + [pyblock(USERS, 135), EMAIL_QS],
    "owner_match", 0.9,
    [ev(USERS, 139, 143), ev(USERS, 62)],
    "user_id == 본인 또는 'me' 검사 후 EmailAddress.objects.filter(user_id=본인)만 반환 → owner_match(G4).",
    "인증 → 본인 강제 → 본인 이메일 목록",
    response_fields=EMAIL_FIELDS)

add("POST", "/api/0/users/{user_id}/emails/", "Add my email address",
    AUTH + [pyblock(USERS, 146, elide=[(159, 163), (168, 172)])],
    "owner_match", 0.9,
    [ev(USERS, 156, 158), ev(USERS, 165, 167)],
    "user_id == 본인/'me' 검사 후 EmailAddress를 user_id=본인으로 생성한다(본인 명의 생성) → owner_match(G4).",
    "인증 → 본인 강제 → 본인 명의 이메일 생성",
    req_body=body(["email"], ["email"]), response_fields=EMAIL_FIELDS, status="201")

add("GET", "/api/0/users/{user_id}/notifications/", "Get my notification settings",
    AUTH + [pyblock(USERS, 222), USER_QS],
    "owner_match", 0.8,
    [ev(USERS, 228, 229), ev(USERS, 55)],
    "경로 user_id를 검사하지 않고 user_id = request.auth.user_id로 고정해 본인 설정만 반환한다. 대상이 본인으로 고정 → owner_match(G4).",
    "인증 → 경로 user_id 무시, 본인 설정만",
    response_fields=["subscribeByDefault"])

add("GET", "/api/0/api-tokens/", "List my API tokens",
    AUTH_SESSION_ONLY + [TOK_ROUTER, TOK_QS, pyblock(TOK, 18)],
    "owner_match", 0.9,
    [ev(TOK, 10), ev(TOK, 13, 15)],
    "Router(auth=SessionAuth())로 세션 인증만 받고 APIToken.objects.filter(user_id=request.auth.user_id) 본인 토큰만 조회 → owner_match(G4).",
    "세션 인증만(API 토큰 불가) → user_id=본인 필터",
    security=SESSION, response_fields=TOKEN_FIELDS)

add("POST", "/api/0/api-tokens/", "Create my API token",
    AUTH_SESSION_ONLY + [TOK_ROUTER, pyblock(TOK, 24)],
    "owner_match", 0.9,
    [ev(TOK, 10), ev(TOK, 26, 29)],
    "세션 인증 후 APIToken을 user_id=request.auth.user_id로 생성한다(본인 명의 생성) → owner_match(G4).",
    "세션 인증만 → user_id 본인 강제",
    security=SESSION, req_body=body(["label", ("scopes", "integer")], ["scopes"]), response_fields=TOKEN_FIELDS, status="201")

add("DELETE", "/api/0/api-tokens/{token_id}/", "Delete my API token",
    AUTH_SESSION_ONLY + [TOK_ROUTER, TOK_QS, pyblock(TOK, 32)],
    "owner_match", 0.9,
    [ev(TOK, 34, 36), ev(TOK, 13, 15)],
    "get_queryset(user_id=본인).filter(id=token_id).adelete()로 본인 소유 토큰만 삭제(타인 토큰은 404). 소유자 == 요청자, 관리자 우회 없음 → owner_match(G4).",
    "세션 인증만 → 본인 토큰만 삭제",
    security=SESSION, status="204")

# ============================================================================
# ISSUES / EVENTS / COMMENTS
# ============================================================================
add("GET", ORG_P + "/issues/", "List organization issues",
    AUTH + [HASPERM, pyblock(ISS, 341, elide=[(358, 380)]), SVC_QS],
    "membership_required", 0.9,
    [ev(ISS, 355, 357), ev(SVC, 96, 101)],
    "services.get_queryset이 aget_object_or_404(Organization, users=user_id, slug=organization_slug)로 요청자가 해당 조직 구성원일 때만 이슈를 조회한다. 역할 조건 없음 → membership_required(G2).",
    "인증 → Organization(users=user_id, slug) 구성원 확인 → 조직 이슈 필터",
    query=[q("query"), q("sort"), q("project"), q("environment"), q("start"), q("end")], response_fields=ISSUE_FIELDS)

add("PUT", ORG_P + "/issues/{issue_id}/", "Update organization issue",
    AUTH + [HASPERM, pyblock(ISS, 261), SVC_QS],
    "membership_required", 0.85,
    [ev(ISS, 273, 274), ev(SVC, 96, 101)],
    "get_queryset(user_id, organization_slug)의 Organization(users=user_id) 구성원 확인 뒤 해당 조직 이슈만 상태·담당자 변경. 역할 조건 없음 → membership_required(G2).",
    "인증 → 조직 구성원 확인 → 이슈 갱신(update_issue_status)",
    req_body=body(["status", ("statusDetails", "object"), ("merge", "integer"), "assignedTo"]), response_fields=ISSUE_FIELDS + ["userReportCount"])

add("GET", ORG_P + "/issues/{issue_id}/events/", "List issue events",
    AUTH + [HASPERM, pyblock(EVT, 222), EVT_QS],
    "membership_required", 0.9,
    [ev(EVT, 235, 241), ev(EVT, 27)],
    "Organization.objects.filter(slug, users=request.auth.user_id)로 구성원이 아니면 404, get_queryset도 issue__project__organization__users=user_id로 필터한다 → membership_required(G2).",
    "인증 → 조직 구성원 확인(users=user_id) → 이벤트 필터",
    response_fields=EVENT_FIELDS)

add("POST", ORG_P + "/issues/{issue_id}/comments/", "Add issue comment",
    AUTH + [HASPERM, pyblock(COM, 88)],
    "membership_required", 0.9,
    [ev(COM, 101, 105), ev(COM, 110, 114)],
    "Issue.objects.aget(id, project__organization__users=request.auth.user_id, project__organization__slug=...)로 요청자가 조직 구성원일 때만 댓글을 본인 명의로 생성한다. 역할 조건 없음 → membership_required(G2).",
    "인증 → 이슈 조직 구성원 확인 → 댓글 생성(user_id=본인)",
    req_body=body([("data", "object")], ["data"]), response_fields=COMMENT_FIELDS, status="201")

# ============================================================================
# RELEASES / ENVIRONMENTS / ALERTS
# ============================================================================
add("GET", ORG_P + "/releases/", "List releases",
    AUTH + [HASPERM, pyblock(REL, 153), REL_QS],
    "membership_required", 0.9,
    [ev(REL, 163), ev(REL, 65, 67)],
    "get_releases_queryset이 Release.objects.filter(organization__slug, organization__users=user_id)로 조직 구성원만 조회한다 → membership_required(G2).",
    "인증 → organization__users=user_id 구성원 필터",
    response_fields=RELEASE_FIELDS)

add("POST", ORG_P + "/releases/", "Create release",
    AUTH + [HASPERM, pyblock(REL, 97), REL_QS],
    "membership_required", 0.85,
    [ev(REL, 107, 109), ev(REL, 65, 67)],
    "aget_object_or_404(Organization, slug, users=user_id)로 조직 구성원이면 릴리스를 생성한다. 역할 조건 없음 → membership_required(G2).",
    "인증 → Organization(users=user_id) 구성원 확인 → 생성",
    req_body=body(["version", "ref", "dateReleased", ("projects", "array")], ["version", "projects"]),
    response_fields=RELEASE_FIELDS, status="201")

add("GET", ORG_P + "/environments/", "List organization environments",
    AUTH + [HASPERM, pyblock(ENV, 27)],
    "membership_required", 0.9,
    [ev(ENV, 39, 42)],
    "Environment.objects.filter(organization__users=request.auth.user_id, organization__slug=...)로 조직 구성원만 조회 → membership_required(G2).",
    "인증 → organization__users=user_id 구성원 필터",
    query=[q("visibility")], response_fields=["id", "name"])

add("POST", "/api/0/projects/{organization_slug}/{project_slug}/alerts/", "Create project alert",
    AUTH + [HASPERM, pyblock(ALERTS, 62, elide=[(86, 97)]), ROLE],
    "manual_review_required", 0.75,
    [ev(ALERTS, 75, 85), ev(CONST, 124, 128)],
    "Project를 Q(organization__users=user_id AND organization_users__role__gte=ADMIN) | Q(teams__members__user=user_id)로 조회한다. "
    "조직 안 ADMIN 역할 OR 프로젝트 팀 구성원이라는 서로 다른 유형의 조건이 OR로 결합되어 단일 라벨로 표현되지 않아 manual_review_required(G6). "
    "대안: membership_required(팀 구성원 관계 중심) 또는 role_required.",
    "인증 → (조직 ADMIN 이상) OR (프로젝트 팀 구성원)",
    req_body=body(["name", ("timespanMinutes", "integer"), ("quantity", "integer"), ("uptime", "boolean"), ("alertRecipients", "array")]),
    response_fields=ALERT_FIELDS, status="201")

add("PUT", "/api/0/projects/{organization_slug}/{project_slug}/alerts/{alert_id}/", "Update project alert",
    AUTH + [HASPERM, pyblock(ALERTS, 100, elide=[(125, 142)]), ALERT_QS],
    "membership_required", 0.7,
    [ev(ALERTS, 114, 117), ev(ALERTS, 37, 41)],
    "get_project_alert_queryset이 project__organization__users=user_id 구성원 필터만 적용한 뒤 알림을 수정한다. 역할 조건 없음 → membership_required(G2). "
    "생성은 ADMIN OR 팀원, 삭제는 ADMIN을 요구해 수정의 느슨함은 의도 확인 필요(confidence 하향).",
    "인증 → 조직 구성원 필터만, 역할 검사 없음",
    req_body=body(["name", ("timespanMinutes", "integer"), ("quantity", "integer"), ("uptime", "boolean"), ("alertRecipients", "array")]),
    response_fields=ALERT_FIELDS)

add("DELETE", "/api/0/projects/{organization_slug}/{project_slug}/alerts/{alert_id}/", "Delete project alert",
    AUTH + [HASPERM, pyblock(ALERTS, 149), ALERT_QS, ROLE],
    "role_required", 0.9,
    [ev(ALERTS, 158, 166), ev(CONST, 124, 128)],
    "구성원 필터에 project__organization__organization_users__role__gte=ADMIN을 추가해 삭제한다(아니면 404). 조직 안 ADMIN 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 + organization_users__role >= ADMIN",
    status="204")

# ============================================================================
# UPTIME / STATS / FILES / PERFORMANCE / LOGS
# ============================================================================
add("POST", ORG_P + "/heartbeat_check/{endpoint_id}/", "Heartbeat monitor check-in (anonymous)",
    [API_AUTH, pyblock(UP, 188, elide=[(205, 243)])],
    "public", 0.75,
    [ev(UP, 188, 192), ev(UP, 200, 204)],
    "auth=None으로 인증을 요구하지 않고 organization_slug와 UUID endpoint_id가 일치하는 모니터에 체크를 기록한다. 익명 접근이 코드로 허용되므로 public(G7). "
    "endpoint_id가 비밀 URL 역할을 하므로 '조건부 익명'으로 보아 manual로 볼 여지(Umami GET /api/share/{slug} 선례는 public).",
    "auth=None; organization_slug + endpoint_id(UUID) 일치만",
    security=[], response_fields=["id", "isUp", "reason", "responseTime", "isChange"])

add("GET", ORG_P + "/monitors/", "List uptime monitors",
    AUTH + [pyblock(UP, 246), MON_QS],
    "membership_required", 0.9,
    [ev(UP, 255), ev(UP, 69, 73)],
    "get_monitor_queryset이 Monitor을 organization__users=user_id, organization__slug=...로 필터한다. 조직 구성원 관계가 조건 → membership_required(G2). has_permission 데코레이터 없음.",
    "인증 → organization__users=user_id 구성원 필터",
    response_fields=MONITOR_FIELDS)

add("POST", ORG_P + "/monitors/", "Create uptime monitor",
    AUTH + [pyblock(UP, 274), MON_QS],
    "membership_required", 0.85,
    [ev(UP, 283, 285), ev(UP, 69, 73)],
    "aget_object_or_404(Organization, slug, users=user_id)로 조직 구성원이면 모니터를 생성한다. 역할 조건 없음 → membership_required(G2).",
    "인증 → Organization(users=user_id) 구성원 확인 → 생성",
    req_body=body(["monitorType", "name", "url", ("expectedStatus", "integer"), "expectedBody", ("interval", "integer"),
                   ("timeout", "integer"), ("confirmationThreshold", "integer"), "project"], ["monitorType", "name", "interval"]),
    response_fields=MONITOR_FIELDS, status="201")

add("GET", ORG_P + "/status-pages/", "List status pages",
    AUTH + [pyblock(UP, 359)],
    "membership_required", 0.5,
    [ev(UP, 369, 371), ev(UP, 359, 363)],
    "EXCLUDE 후보: 경로가 organization_slug를 받지만 핸들러는 StatusPage.objects.filter(organization__users=request.auth.user_id)만 적용하고 slug로 필터하지 않는다. "
    "요청자가 속한 모든 조직의 상태 페이지가 반환되어 경로 의도(대상 조직 구성원)와 구현(어느 조직이든 구성원)이 불일치한다(G8 의도·구현 충돌). "
    "경로 의도로는 membership_required.",
    "인증 → organization__users=user_id 필터, 경로 organization_slug 미사용",
    response_fields=["name", "slug", "isPublic", "monitors"])

add("GET", ORG_P + "/stats_v2/", "Organization event statistics (time series)",
    AUTH + [HASPERM, pyblock(STATS, 52, elide=[(57, 65), (83, 94)])],
    "membership_required", 0.9,
    [ev(STATS, 73, 76), ev(STATS, 79, 81)],
    "Project.objects.filter(organization__slug, organization__users=request.auth.user_id)로 요청자가 조직 구성원인 프로젝트만 집계하고, 없으면 404. 조직 구성원 관계가 조건 → membership_required(G2).",
    "인증 → organization__users=user_id 프로젝트 필터, 없으면 404",
    query=[q("start", required=True), q("end", required=True), q("interval"), q("category"), q("field"), q("project")],
    response_fields=["intervals", "groups"])

add("POST", ORG_P + "/chunk-upload/", "Upload gzipped file chunks",
    AUTH + [HASPERM, pyblock(FILES, 130, elide=[(146, 176)])],
    "membership_required", 0.9,
    [ev(FILES, 141, 144)],
    "주석 'Membership check'와 함께 aget_object_or_404(Organization, slug, users=request.auth.user_id)로 조직 구성원만 통과시킨다. 역할 조건 없음 → membership_required(G2).",
    "인증 → Organization(users=user_id) 구성원 확인만",
    req_body=body([("file_gzip", "array")], ["file_gzip"], "multipart/form-data"))

add("GET", ORG_P + "/transaction-groups/", "List performance transaction groups",
    AUTH + [HASPERM, pyblock(PERF, 78), QS_ORG_FOR_USER],
    "membership_required", 0.85,
    [ev(PERF, 91, 95), ev(QU, 13)],
    "get_organization_for_user(user_id, slug)=Organization.objects.filter(users=user_id, slug=...)가 비어 있으면 빈 결과를 반환하고, 있으면 그 조직의 TransactionGroup을 조회한다. 조직 구성원 관계가 조건 → membership_required(G2).",
    "인증 → Organization(users=user_id, slug) 구성원 확인(없으면 빈 목록)",
    query=[q("start"), q("end"), q("sort"), q("project"), q("query")])

add("GET", ORG_P + "/logs/", "List organization log events",
    AUTH + [HASPERM, pyblock(LOGS, 674, elide=[(686, 703), (708, 762)]), QS_ORG_FOR_USER],
    "membership_required", 0.9,
    [ev(LOGS, 704, 706), ev(QU, 13)],
    "aget_object_or_404(get_organization_for_user(user_id, slug))로 조직 구성원이 아니면 404, 이후 organization_id로 로그를 조회한다 → membership_required(G2).",
    "인증 → Organization(users=user_id, slug) 구성원 확인 → 조직 로그 조회",
    query=[q("project"), q("level"), q("service"), q("environment"), q("host"), q("traceId"), q("query"), q("start"), q("end"), q("cursor"), q("limit", "integer")])

# ============================================================================
# ORGANIZATION SSO (social_app_api.py), IMPORT
# ============================================================================
add("GET", ORG_P + "/social-apps/", "List organization SSO providers",
    AUTH + [HASPERM, pyblock(SOC, 156), ORG_MGR, QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(SOC, 165), ev(SOC, 87, 95), ev(CONST, 124, 128)],
    "get_organization_for_manager: 구성원 필터(role_required=True) 후 actor_role < MANAGER면 403. 목록 조회에도 조직 안 MANAGER 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER",
    response_fields=["id", "name", "provider", "clientId", "serverUrl", "brand"])

add("POST", ORG_P + "/social-apps/", "Create organization SSO provider",
    AUTH + [HASPERM, pyblock(SOC, 169, elide=[(181, 202)]), ORG_MGR, SSO_PLAN, ROLE],
    "manual_review_required", 0.6,
    [ev(SOC, 178), ev(SOC, 94, 95), ev(SOC, 179, 180), ev(UTILS, 23, 33)],
    "get_organization_for_manager(MANAGER 이상) AND organization_can_customize_sso(BILLING_ENABLED이면 allow_sso 플랜의 활성 구독 필요, 아니면 항상 True). "
    "역할 조건에 구독·플랜 조건이 AND로 결합되고 설정(BILLING_ENABLED)에 따라 조건이 바뀌므로 보류 규칙 1·3·G6 → manual_review_required. 셀프호스트(billing 비활성)만 보면 role_required.",
    "인증 → actor_role >= MANAGER AND (billing 비활성 OR SSO 허용 플랜 구독)",
    req_body=body(["name", "serverUrl", "clientId", "provider", "clientSecret"], ["name", "clientId", "clientSecret"]),
    response_fields=["id", "name", "provider", "clientId", "serverUrl", "brand"], status="201")

add("PUT", ORG_P + "/social-apps/{social_app_id}/", "Update organization SSO provider",
    AUTH + [HASPERM, pyblock(SOC, 205, elide=[(221, 236)]), ORG_MGR, QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(SOC, 217), ev(SOC, 94, 95), ev(SOC, 218, 220)],
    "get_organization_for_manager로 조직 구성원 확인 후 actor_role < MANAGER면 403, 그 조직에 연결된 SocialApp만 수정한다. 조직 안 역할이 결정 조건 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER → 조직 소속 social app",
    req_body=body(["name", "serverUrl", "clientId", "clientSecret"], ["name", "clientId"]),
    response_fields=["id", "name", "provider", "clientId", "serverUrl", "brand"])

add("DELETE", ORG_P + "/social-apps/{social_app_id}/", "Delete organization SSO provider",
    AUTH + [HASPERM, pyblock(SOC, 240), ORG_MGR, QS_ORG, ROLE],
    "role_required", 0.9,
    [ev(SOC, 248), ev(SOC, 94, 95), ev(SOC, 249, 251)],
    "get_organization_for_manager(actor_role >= MANAGER) 후 조직 소속 SocialApp만 삭제 → role_required(G3).",
    "인증 → 조직 구성원 필터 → actor_role >= MANAGER",
    status="204")

add("POST", "/api/0/import/", "Import data from another GlitchTip instance",
    AUTH + [HASPERM, pyblock(IMP, 15), ROLE],
    "role_required", 0.9,
    [ev(IMP, 18, 23), ev(CONST, 124, 128)],
    "본문 organization_slug의 Organization을 users=user_id AND organization_users__role__gte=ADMIN으로 조회한다. 대상 조직 안 ADMIN 이상 역할이 결정 조건 → role_required(G3).",
    "인증 → Organization(본문 slug, users=user_id, organization_users__role >= ADMIN)",
    req_body=body(["url", "auth_token", "organization_slug"], ["url", "auth_token", "organization_slug"]))

# ============================================================================
# EVENT INGEST (DSN key auth) / EMBED
# ============================================================================
add("POST", "/api/{project_id}/store/", "Store a single event (Sentry store API)",
    EVENT_AUTH + [pyblock(ING, 54, elide=[(64, 86)])],
    "manual_review_required", 0.85,
    [ev(INGAUTH, 348, 358), ev(INGAUTH, 155, 156), ev(INGAUTH, 186, 190)],
    "Router(auth=event_auth): 사용자 인증이 아니라 DSN 공개 키(sentry_key)가 경로 project_id의 유효한 ProjectKey인지 확인한다(docstring 'It does not include user authentication'). "
    "요청 주체가 사용자가 아닌 프로젝트 키이고 스로틀 상태에 따라 거부되므로 6종 라벨로 표현되지 않아 manual_review_required.",
    "DSN 키(sentry_key) ↔ project_id 일치 + 조직/프로젝트 스로틀; 사용자 인증 없음",
    security=DSN, req_body=body(["event_id", "timestamp", "platform", "message", ("exception", "object"), ("user", "object")], ["event_id"]),
    response_fields=["event_id", "task_id"])

add("POST", "/api/{project_id}/envelope/", "Ingest Sentry envelope",
    [block(URLS, 28, 28)] + EVENT_AUTH[1:] + [block(VIEWS, 82, py_end(VIEWS, 82), elide=[(102, None)])],
    "manual_review_required", 0.85,
    [ev(VIEWS, 87, 88), ev(INGAUTH, 348, 358), ev(INGAUTH, 186, 190)],
    "Django 뷰(csrf_exempt)가 직접 event_auth(request)를 호출해 DSN 키가 project_id의 유효 ProjectKey인지 검증하고 실패 시 403. 사용자 인증·구성원·역할 검사 없이 프로젝트 키 소지가 조건이므로 manual_review_required(6종 아님).",
    "DSN 키 ↔ project_id 일치(event_auth) + 스로틀; 사용자 인증 없음",
    security=DSN, req_body=body([("envelope", "string")], ["envelope"], "application/x-sentry-envelope"),
    response_fields=["id"])

add("POST", "/api/embed/error-page/", "Submit user feedback via embedded error page",
    EMBED_AUTH + [pyblock(EMBED, 139)],
    "manual_review_required", 0.8,
    [ev(EMBED, 26, 33), ev(EMBED, 36, 37), ev(EMBED, 150)],
    "Router(auth=embed_auth): 쿼리 dsn의 public_key와 project_id로 Project를 찾고(스로틀 100%면 거부) report.project_id를 그 프로젝트로 고정한다. "
    "사용자 인증이 아닌 DSN 소지 기반이라 6종으로 표현되지 않아 manual_review_required. DSN은 브라우저에 노출되는 공개 키이므로 사실상 익명에 가깝지만 조건부(유효 DSN) → public 아님(G7).",
    "쿼리 dsn(public_key + project_id) 검증(embed_auth); 사용자 인증 없음",
    security=DSN, query=[q("dsn", required=True), q("eventId", required=True), q("name"), q("email")],
    req_body=body(["name", "email", "comments"], None, "application/x-www-form-urlencoded"))

# ============================================================================
# INSTANCE / SETTINGS / WIZARD (auth=None)
# ============================================================================
add("GET", "/api/settings/", "Instance public settings and login options",
    [API_AUTH, block(APIPY, 174, py_end(APIPY, 174), elide=[(188, None)])],
    "public", 0.95,
    [ev(APIPY, 174), ev(APIPY, 176, 184)],
    "@api.get(\"settings/\", auth=None)으로 인증 없이 누구나 호출 가능하고 공개 소셜 앱·등록 가능 여부 등 인스턴스 설정을 반환한다. 조건 없는 익명 허용 → public(G7).",
    "auth=None; 조건 없음",
    security=[], response_fields=["socialApps", "billingEnabled", "iPaidForGlitchTip", "enableUserRegistration",
                                  "enableSocialAppsUserRegistration", "enableOrganizationCreation", "version", "enabledFeatures"])

add("GET", "/api/settings/{organization_slug}/", "Organization login page sign-in options",
    [API_AUTH, pyblock(APIPY, 244)],
    "public", 0.9,
    [ev(APIPY, 244, 249), ev(APIPY, 257, 262)],
    "auth=None으로 익명 호출을 허용하고 slug에 연결된 소셜 앱만 반환하며 미존재 slug에도 200 빈 목록을 준다(열거 방지 docstring). 조건 없는 익명 허용 → public(G7).",
    "auth=None; 조건 없음(미존재 slug도 200)",
    security=[], response_fields=["socialApps"],
    permission_doc="Sign-in options for one organization's own login page, including social apps hidden from the instance-wide "
                   "login page. Responds 200 with an empty list for unknown slugs so anonymous requests cannot enumerate which organizations exist.")

add("GET", "/api/0/", "API root: server version and current user",
    [API_AUTH, pyblock(APIPY, 298, elide=[(309, 326)])],
    "public", 0.8,
    [ev(APIPY, 298), ev(APIPY, 303, 304)],
    "auth=None으로 익명 요청도 200(version만)이고, 세션 또는 Bearer 토큰이 있으면 본인 user·auth 정보를 추가로 돌려준다. 익명 접근 자체는 조건 없이 허용되므로 public(G7). "
    "인증 시 본인 정보를 반환하는 부분은 owner_match 성격이나 접근 조건은 아니다.",
    "auth=None; 익명 허용, 인증 시 본인 정보 포함",
    security=[], response_fields=["version", "user", "auth"])

add("GET", "/api/0/wizard/", "Start sentry-wizard setup (issue random hash)",
    [API_AUTH, pyblock(WIZ, 45)],
    "public", 0.95,
    [ev(WIZ, 45), ev(WIZ, 51, 56)],
    "auth=None으로 인증 없이 64자 랜덤 해시를 생성해 캐시에 저장하고 반환한다. 조건 없는 익명 허용 → public(G7).",
    "auth=None; 조건 없음",
    security=[], response_fields=["hash"])

add("POST", "/api/0/wizard-set-token/", "Attach my projects and API token to a wizard hash",
    AUTH + [pyblock(WIZ, 86, elide=[(98, 106)])],
    "manual_review_required", 0.5,
    [ev(WIZ, 93, 95), ev(WIZ, 97), ev(WIZ, 107, 110)],
    "EXCLUDE 후보: 인증 후 본문 hash가 캐시에 존재하는지만 확인하고(없으면 400) 요청자 본인의 프로젝트와 본인 API 토큰을 그 해시에 저장한다. "
    "저장되는 데이터는 본인 것(owner_match 성격)이지만 접근 조건은 '인증 + 임의 해시 소지'라 6종으로 확정하기 어렵다. 대안: owner_match.",
    "인증 → 캐시에 hash 존재 확인 → 본인 프로젝트·토큰 저장",
    req_body=body(["hash"], ["hash"]))


# ============================================================================
# write + validate
# ============================================================================
def main():
    records.sort(key=lambda r: (r["path"], r["method"]))
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    labels = {"public", "role_required", "membership_required", "tenant_match", "owner_match",
              "owner_or_admin", "manual_review_required"}
    keys = [(r["method"], r["path"]) for r in records]
    dup = [k for k, c in Counter(keys).items() if c > 1]
    counts = Counter(r["draft_label"] for r in records)
    n = len(records)
    problems = []
    if dup:
        problems.append(f"duplicate (method, path): {dup}")
    if not 65 <= n <= 75:
        problems.append(f"record count {n} outside 65-75")
    for lbl, c in counts.items():
        if lbl not in labels:
            problems.append(f"unknown label {lbl}")
        if c / n > 0.5:
            problems.append(f"label {lbl} exceeds 50% ({c}/{n})")
    short, long_ = [], []
    for r in records:
        L = len(r["controller_text"])
        if L < 500:
            short.append((r["method"], r["path"], L))
        if L > 3000:
            long_.append((r["method"], r["path"], L))
        for e in r["evidence"]:
            if not e["text"].strip():
                problems.append(f"empty evidence {e['location']} in {r['method']} {r['path']}")
        if not (0 < r["draft_confidence"] <= 1):
            problems.append(f"bad confidence {r['method']} {r['path']}")
        if r["draft_reason"].startswith("EXCLUDE 후보") and r["draft_confidence"] > 0.5:
            problems.append(f"EXCLUDE 후보 confidence > 0.5: {r['method']} {r['path']}")
    if long_:
        problems.append(f"controller_text > 3000: {long_}")
    excl = [(r["method"], r["path"]) for r in records if r["draft_reason"].startswith("EXCLUDE 후보")]
    lens = sorted(len(r["controller_text"]) for r in records)
    print(f"records: {n} -> {OUT}")
    print("labels:", dict(sorted(counts.items(), key=lambda x: -x[1])))
    print(f"EXCLUDE 후보: {len(excl)} {excl}")
    print(f"controller_text chars: min {lens[0]} median {lens[n // 2]} max {lens[-1]}")
    print(f"<500 chars: {short}")
    if problems:
        print("PROBLEMS:")
        for pr in problems:
            print("  -", pr)
        sys.exit(1)
    print("validation OK")


if __name__ == "__main__":
    main()
