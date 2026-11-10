"""Static extraction of Seafile seahub API authorization policy candidates (test_v6).

Read-only over the clone at datasets/blade/raw/opensource/test_v6_candidates/seahub.
Writes candidates.jsonl next to this script. Run with:
    python -I data/raw_v6/seahub/extract_seahub.py
No LLM/API call, no model inference. Labels are drafts for human review.
"""
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, "..", "..", "..", "datasets", "blade", "raw", "opensource",
                                     "test_v6_candidates", "seahub"))
OUT = os.path.join(HERE, "candidates.jsonl")

PROJECT = "seahub"
SERVICE = "Seafile seahub"
REPO_URL = "https://github.com/haiwen/seahub"
COMMIT = "0841826c7ce738caf92121d94d7741ba0f2373d5"
TAG = "v14.0.9-server"
LICENSE = "Apache-2.0"

LABELS = {"public", "role_required", "membership_required", "tenant_match",
          "owner_match", "owner_or_admin", "manual_review_required"}

_cache = {}


def lines_of(rel):
    if rel not in _cache:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def func_end(rel, start):
    """End line (1-based, inclusive) of the Python block that starts at `start`.

    `start` is a `def` line or a decorator line directly above it. The block ends
    before the first non-blank line whose indentation is <= the start line's.
    """
    ls = lines_of(rel)
    first = ls[start - 1]
    indent = len(first) - len(first.lstrip())
    last = start
    in_header = True  # decorator lines and the def line share the indentation
    for i in range(start, len(ls)):
        line = ls[i]
        if not line.strip():
            continue
        ind = len(line) - len(line.lstrip())
        if ind <= indent:
            if in_header and (line.lstrip().startswith("@") or line.lstrip().startswith("def ")):
                last = i + 1
                continue
            break
        in_header = False
        last = i + 1
    if last == start:
        raise RuntimeError(f"no block body {rel}:{start}")
    return last


def block(rel, start, end=None, elide=()):
    """Verbatim lines start..end (inclusive). `elide` = list of (a, b) line ranges
    replaced by one '...' line; b=None means 'up to end-1' (keep the final line)."""
    if end is None:
        end = func_end(rel, start)
    ls = lines_of(rel)
    norm = []
    for a, b in elide:
        if b is None:
            b = end - 1
        if not (start <= a <= b <= end):
            raise RuntimeError(f"bad elide {rel}:{start}-{end} {a}-{b}")
        norm.append((a, b))
    norm.sort()
    out = []
    i = start
    while i <= end:
        hit = [e for e in norm if e[0] == i]
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


def hdr(rel, a, b):
    """Class header lines (class line, authentication_classes, permission_classes...)."""
    return block(rel, a, b)


def line(rel, n):
    return lines_of(rel)[n - 1].strip()


def ev(rel, a, b=None):
    if b is None:
        return {"type": "code", "text": line(rel, a), "location": f"{rel}:{a}"}
    text = "\n".join(l.strip() for l in lines_of(rel)[a - 1:b])
    return {"type": "code", "text": text, "location": f"{rel}:{a}-{b}"}


# ---- files -----------------------------------------------------------------
V = "seahub/api2/views.py"
VM = "seahub/api2/views_misc.py"
AU = "seahub/api2/utils.py"
AP = "seahub/api2/permissions.py"
AUTH = "seahub/api2/authentication.py"
ST = "seahub/settings.py"
VI = "seahub/views/__init__.py"
GU = "seahub/group/utils.py"
SU = "seahub/share/utils.py"
SM = "seahub/share/models.py"
UR = "seahub/utils/repo.py"
RTU = "seahub/repo_api_tokens/utils.py"
SBU = "seahub/subscription/utils.py"
OP = "seahub/organizations/api/permissions.py"
OU = "seahub/organizations/api/utils.py"
OI = "seahub/organizations/api/admin/info.py"
OL = "seahub/organizations/api/admin/links.py"
OLG = "seahub/organizations/api/admin/logs.py"
OUS = "seahub/organizations/api/admin/users.py"
OG = "seahub/organizations/api/admin/groups.py"
OR = "seahub/organizations/api/admin/repos.py"
OD = "seahub/organizations/api/admin/devices.py"
OGM = "seahub/organizations/api/group_members.py"
E = "seahub/api2/endpoints/"
EU = E + "utils.py"
GM = E + "group_members.py"
GR = E + "groups.py"
GL = E + "group_libraries.py"
GOL = E + "group_owned_libraries.py"
SR = E + "shared_repos.py"
BSR = E + "be_shared_repo.py"
DSI = E + "dir_shared_items.py"
WH = E + "webhook.py"
RAD = E + "repo_auto_delete.py"
RTR = E + "repo_trash.py"
RCR = E + "repo_commit_revert.py"
RAT = E + "repo_api_tokens.py"
WK = E + "wikis.py"
US = E + "user.py"
SI = E + "starred_items.py"
UA = E + "user_avatar.py"
WS = E + "webdav_secret.py"
SL = E + "share_links.py"
NT = E + "notifications.py"
DR = E + "deleted_repos.py"
AC = E + "activities.py"
IV = E + "invitation.py"
DP = E + "departments.py"
DI = E + "dir.py"
FH = E + "file_history.py"
SML = E + "smart_link.py"
SU2 = E + "search_user.py"
SB = E + "subscription.py"
ABG = E + "address_book/groups.py"
AUS = E + "admin/users.py"
ALB = E + "admin/libraries.py"
AGR = E + "admin/groups.py"
ASI = E + "admin/sysinfo.py"
AOR = E + "admin/organizations.py"
ASL = E + "admin/share_links.py"
ALC = E + "admin/license.py"
AWS = E + "admin/web_settings.py"

# ---- shared helper blocks ------------------------------------------------------
IS_GROUP_MEMBER = block(GU, 57, 72)
IS_GROUP_ADMIN = block(GU, 74, 75)
IS_GROUP_OWNER = block(GU, 77, 82)
IS_GROUP_ADMIN_OR_OWNER = block(GU, 84, 89)
API_CHECK_GROUP = block(EU, 34, 53)
API_GROUP_CHECK = block(AU, 113, 149, elide=[(114, 123)])  # docstring elided
CHECK_FOLDER_PERMISSION = block(VI, 121, 143)
IS_REPO_ADMIN = block(SU, 39, 73)
GET_REPO_OWNER = block(UR, 128, 141)
IS_GROUP_REPO_STAFF = block(UR, 350, 359)
PERM_CHECK_ADMIN_OWNER = block(RTU, 24, 37)
IS_ORG_ADMIN = block(OP, 3, 12)
IS_ORG_ADMIN_USER = block(AP, 98, 105)
IS_PRO_VERSION = block(AP, 90, 96)
IS_REPO_ACCESSIBLE = block(AP, 32, 40)
CAN_GENERATE_SHARE_LINK = block(AP, 71, 75)
CAN_INVITE_GUEST = block(AP, 63, 68)
CHECK_ORG_ADMIN = block(OU, 5, 19)
REST_SETTINGS = block(ST, 558, 570)
TOKEN_AUTH = block(AUTH, 54, 71)
FS_IS_OWNER = block(SM, 408, 409)
CAN_CLEAN_TRASH = block(DR, 25, 38)
SUB_PERM_CHECK = block(SBU, 74, 80)
INVITATION_OWNER_CHECK = block(IV, 27, 37)

TOKEN = [{"tokenAuth": []}]
SEC_SCHEMES = {
    "tokenAuth": {"type": "apiKey", "in": "header", "name": "Authorization",
                  "description": "Token <api-token> (seahub.api2.authentication.TokenAuthentication) or session cookie"}
}


def p(name, where="path", typ="string", required=True):
    return {"name": name, "in": where, "required": required, "schema": {"type": typ}}


def q(name, typ="string"):
    return p(name, "query", typ, False)


GROUP_ID = p("group_id", typ="integer")
REPO_ID = p("repo_id")
ORG_ID = p("org_id", typ="integer")
PAGING = [q("page", "integer"), q("per_page", "integer")]


def body(keys, required=None, media="application/json"):
    props = {}
    for k in keys:
        if isinstance(k, tuple):
            props[k[0]] = {"type": k[1]}
        else:
            props[k] = {"type": "string"}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"required": True, "content": {media: {"schema": schema}}}


records = []


def add(method, path, summary, blocks, label, conf, evidence, reason, auth_summary,
        params=None, req_body=None, security=TOKEN, response_fields=None, description=""):
    assert label in LABELS, label
    controller_text = "\n\n".join(b["text"] for b in blocks)
    locs = [{"file": b["file"], "start_line": b["start_line"], "end_line": b["end_line"]} for b in blocks]
    segs = [s.strip("{}") for s in path.split("/") if s and s not in ("api2", "api", "v2.1")]
    op = {
        "operationId": method.lower() + "".join(w.title() for s in segs for w in s.replace("-", "_").split("_")),
        "summary": summary,
        "description": description,
        "parameters": params or [],
        "responses": {"200": {"description": "OK"}, "403": {"description": "Permission denied"}},
    }
    if req_body:
        op["requestBody"] = req_body
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


MEMBER_FIELDS = ["group_id", "name", "email", "contact_email", "login_id", "avatar_url", "is_admin", "role"]
GROUP_FIELDS = ["id", "parent_group_id", "name", "owner", "created_at", "admins"]
RPC_NOTE = ("check_folder_permission은 seafile_api.check_permission_by_path(seaf-server RPC)로 소유·개인 공유·그룹 공유·"
            "공개 공유·폴더 권한을 합산한 결과만 돌려준다. 요청자-객체 관계가 외부 인가에 있어 6종 하나로 환원할 수 없다 → "
            "manual_review_required(G6, test_v6 보충 3: check_folder_permission만이면 manual).")
IS_REPO_ADMIN_NOTE = ("is_repo_admin(share/utils.py)은 ① admin 권한으로 공유받은 사용자 ② admin 권한으로 공유된 그룹의 그룹 관리자 "
                      "③ 저장소 소유자 ④ 부서 소유 저장소의 부서 관리자를 모두 True로 돌려준다. ")

# ============================================================================
# membership_required (G2)
# ============================================================================
add("GET", "/api/v2.1/groups/{group_id}/", "Get group info",
    [hdr(GR, 263, 267), block(GR, 269), API_CHECK_GROUP, IS_GROUP_MEMBER],
    "membership_required", 0.9,
    [ev(GR, 275, 278), ev(GU, 70), ev(GU, 72)],
    "api_check_group 데코레이터는 그룹 존재만 확인한다. 핸들러가 is_group_member(group_id, request.user.username)이 거짓이면 403을 돌려주고 "
    "다른 조건은 없다. 요청이 대상 그룹을 경로로 지정하고 (요청자, 그룹) 구성원 행 조회(ccnet_api.is_group_user)가 유일한 결정 조건이므로 membership_required(G2).",
    "IsAuthenticated → api_check_group(그룹 존재) → is_group_member(group_id, username) 아니면 403",
    params=[GROUP_ID, q("avatar_size", "integer")], response_fields=GROUP_FIELDS)

add("GET", "/api/v2.1/groups/{group_id}/members/", "List group members",
    [hdr(GM, 43, 46), block(GM, 48, elide=[(76, 86)]), API_CHECK_GROUP, IS_GROUP_MEMBER],
    "membership_required", 0.9,
    [ev(GM, 64, 67), ev(GU, 70)],
    "주석 'only group member can get info of all group members' 아래에서 is_group_member(group_id, request.user.username) 거짓이면 403. "
    "대상 그룹 지정 + 구성원 행 조회가 결정 조건 → membership_required(G2).",
    "IsAuthenticated → api_check_group → is_group_member 아니면 403",
    params=[GROUP_ID] + PAGING + [q("is_admin")], response_fields=MEMBER_FIELDS)

add("GET", "/api/v2.1/groups/{group_id}/search-member/", "Search group members",
    [hdr(GM, 137, 141), block(GM, 143), API_CHECK_GROUP, IS_GROUP_MEMBER],
    "membership_required", 0.9,
    [ev(GM, 154, 156), ev(GU, 70)],
    "q 인자 검증 뒤 is_group_member(group_id, request.user.username) 거짓이면 403. 그룹 구성원만 그룹 안 검색 가능 → membership_required(G2).",
    "IsAuthenticated → api_check_group → is_group_member 아니면 403",
    params=[GROUP_ID, q("q")], response_fields=MEMBER_FIELDS)

add("GET", "/api/v2.1/groups/{group_id}/members/{email}/", "Get a group member",
    [hdr(GM, 169, 172), block(GM, 174), API_CHECK_GROUP, IS_GROUP_MEMBER],
    "membership_required", 0.9,
    [ev(GM, 180, 183), ev(GM, 185, 187)],
    "요청자가 그룹 구성원이 아니면 403, 대상 email이 구성원이 아니면 400. 결정 조건은 (요청자, 그룹) 구성원 관계 → membership_required(G2).",
    "IsAuthenticated → api_check_group → is_group_member(요청자) 아니면 403",
    params=[GROUP_ID, p("email")], response_fields=MEMBER_FIELDS)

add("GET", "/api/v2.1/groups/{group_id}/libraries/", "List group libraries",
    [hdr(GL, 62, 66), block(GL, 68, elide=[(82, 170)]), API_CHECK_GROUP, IS_GROUP_MEMBER],
    "membership_required", 0.9,
    [ev(GL, 76, 80), ev(GU, 70)],
    "docstring 'Permission checking: 1. is group member;' 그대로 is_group_member(group_id, username) 거짓이면 403. "
    "그룹 소속 저장소 목록을 그룹 구성원만 조회 → membership_required(G2).",
    "IsAuthenticated → api_check_group → is_group_member 아니면 403",
    params=[GROUP_ID] + PAGING,
    response_fields=["repo_id", "repo_name", "mtime", "permission", "size", "encrypted", "is_admin", "owner_email", "starred", "monitored"])

add("POST", "/api/v2.1/groups/{group_id}/libraries/", "Create a library shared to the group",
    [hdr(GL, 62, 66), block(GL, 173, elide=[(182, 198), (208, 264)]), IS_GROUP_MEMBER],
    "membership_required", 0.6,
    [ev(GL, 177, 179), ev(GL, 199, 206)],
    "request.user.permissions.can_add_repo()(전역 역할의 기능 권한) AND is_group_member(group_id, username) 두 검사를 모두 통과해야 한다. "
    "객체(그룹)에 대한 관계 조건은 구성원 여부이고 can_add_repo는 저장소 생성 기능 권한이므로 G1의 'RBAC 기능 권한 병존' 취지에 따라 membership_required로 초안. "
    "독립 조건 AND로 보면 manual_review_required(보류 3)도 가능해 confidence를 낮춤.",
    "can_add_repo(역할 기능 권한) AND is_group_member(group_id, username)",
    params=[GROUP_ID], req_body=body(["repo_name", "password", "permission", "library_template"], ["repo_name"]),
    response_fields=["repo_id", "repo_name", "permission", "owner_email"])

add("GET", "/api2/groups/{group_id}/repos/", "List group repos (api2)",
    [hdr(V, 4802, 4805), block(V, 4907, elide=[(4915, 4970)]), API_GROUP_CHECK, IS_GROUP_MEMBER],
    "membership_required", 0.8,
    [ev(AU, 132, 136), ev(AU, 137, 140), ev(AU, 147), ev(V, 4911, 4913)],
    "api_group_check 데코레이터: is_group_member면 통과, 아니면 request.user.is_staff(시스템 관리자)만 통과, group.is_pub는 항상 False로 두므로 그 외는 403 "
    "'Forbid to access this group.'. 구성원 OR 시스템 관리자 우회 → membership_required(G2: 구성원 OR 관리자 우회도 membership_required). "
    "핸들러 안 is_pub 분기는 도달하지 않는다.",
    "api_group_check: is_group_member(group_id, username) OR request.user.is_staff, 아니면 403",
    params=[GROUP_ID, q("from")],
    response_fields=["id", "name", "size", "mtime", "encrypted", "permission", "owner", "share_from_me", "is_admin", "group_name"])

# membership_required 보충(사용자 결정 2026-11-03, 상한 93→110): is_group_member/api_group_check가 결정 조건인 엔드포인트를 추가.
# 같은 뷰 클래스 GroupRepos의 GET(위)과 POST(아래) 두 메서드를 모두 넣었다(SOURCE.md 명시).
add("POST", "/api2/groups/{group_id}/repos/", "Create a library and share it to the group (api2)",
    [hdr(V, 4802, 4805), block(V, 4807, elide=[(4811, 4832), (4836, 4876), (4879, 4904)]), API_GROUP_CHECK, IS_GROUP_MEMBER],
    "membership_required", 0.7,
    [ev(V, 4807, 4808), ev(AU, 132, 136), ev(AU, 137, 140), ev(AU, 147)],
    "api_group_check 데코레이터가 유일한 인가 검사다: is_group_member(group_id, request.user.username)이면 통과, 아니면 request.user.is_staff(시스템 관리자)만 통과, "
    "그 외는 403 'Forbid to access this group.'. 핸들러 본문에는 역할·소유자 검사가 없고(can_add_repo 검사도 없음) 요청자 명의로 저장소를 만들어 경로의 그룹에 공유한다. "
    "대상 그룹을 경로로 지정하고 (요청자, 그룹) 구성원 행 조회가 결정 조건, 시스템 관리자 우회 포함 → membership_required(G2: 구성원 OR 관리자 우회). "
    "생성 요청이지만 대상 객체(그룹)가 경로에 있어 test_v5 Ghost POST /posts(객체 없음, EXCLUDE)와 다르다고 보았다. 생성 요청으로 보는 검수자는 EXCLUDE 가능해 confidence를 낮춤.",
    "api_group_check: is_group_member(group_id, username) OR request.user.is_staff, 아니면 403; 본문에 추가 검사 없음",
    params=[GROUP_ID], req_body=body(["name", "desc", "passwd", "permission", "storage_id", "library_template"], ["name"]),
    response_fields=["id", "name", "desc", "size", "mtime", "encrypted", "permission", "owner", "share_from_me"])

# ============================================================================
# owner_or_admin (G5)
# ============================================================================
add("DELETE", "/api/v2.1/groups/{group_id}/members/{email}/", "Leave group or remove a member",
    [hdr(GM, 169, 172), block(GM, 233, elide=[(243, 246), (257, 262), (264, 267), (275, 280), (288, 293), (303, 306)]),
     IS_GROUP_OWNER, IS_GROUP_ADMIN, IS_GROUP_ADMIN_OR_OWNER],
    "owner_or_admin", 0.85,
    [ev(GM, 251), ev(GM, 271), ev(GM, 283, 285), ev(GM, 299, 301)],
    "username == email이면 본인 탈퇴로 즉시 허용(당사자). 그렇지 않으면 그룹 소유자는 누구나 제거, 그룹 관리자는 소유자·관리자가 아닌 구성원만 제거, 그 외 403. "
    "당사자 본인 OR 그룹 관리자 역할 우회가 실제 조건 → owner_or_admin(G5). 지시문의 GroupMember.delete 패턴.",
    "username == email(본인) OR is_group_owner OR (is_group_admin AND 대상이 owner/admin 아님)",
    params=[GROUP_ID, p("email")], response_fields=["success"])

add("DELETE", "/api/v2.1/groups/{group_id}/libraries/{repo_id}/", "Unshare a library from the group",
    [hdr(GL, 268, 271), block(GL, 273, elide=[(310, 325)]), IS_GROUP_ADMIN, IS_REPO_ADMIN],
    "owner_or_admin", 0.8,
    [ev(GL, 300, 308), ev(SU, 63, 64)],
    "is_group_admin(group_id, username) OR repo_owner == username OR is_repo_admin(username, repo_id)이 아니면 403. " + IS_REPO_ADMIN_NOTE +
    "저장소 소유자 OR 관리자 역할(그룹 관리자·저장소 admin 권한) 우회 → owner_or_admin(G5). 대안: 저장소 admin 권한 레벨을 역할로 보면 role_required.",
    "is_group_admin OR repo_owner == username OR is_repo_admin",
    params=[GROUP_ID, REPO_ID], response_fields=["success"])

add("DELETE", "/api2/groups/{group_id}/repos/{repo_id}/", "Unshare a repo from group (api2)",
    [hdr(V, 4973, 4976), block(V, 4978, elide=[(4988, 5005)]), API_GROUP_CHECK, IS_REPO_ADMIN],
    "owner_or_admin", 0.75,
    [ev(V, 4983, 4986), ev(AU, 132, 136), ev(SU, 63, 64)],
    "api_group_check로 그룹 구성원(또는 시스템 관리자)만 진입한 뒤, group.is_staff(그룹 관리자) OR repo_owner == username OR is_repo_admin이 아니면 403. "
    "소유자 OR 관리자 역할 우회가 결정 조건 → owner_or_admin(G5). 구성원 선행 조건이 있으나 그룹 저장소 소유자는 통상 구성원이라 별도 조건으로 보지 않았다.",
    "api_group_check(구성원 OR is_staff) → group.is_staff OR repo_owner == username OR is_repo_admin",
    params=[GROUP_ID, REPO_ID], response_fields=["success"])

add("DELETE", "/api2/shared-repos/{repo_id}/", "Unshare a library (api2)",
    [hdr(V, 4368, 4374), block(V, 4376, elide=[(4400, 4432)])],
    "owner_or_admin", 0.9,
    [ev(V, 4378, 4379), ev(V, 4391, 4393)],
    "docstring 'Repo owner and system admin can perform this operation.' 그대로 request.user.is_staff(시스템 관리자)도 아니고 username == repo_owner도 아니면 403. "
    "소유자 OR 전역 관리자 우회 → owner_or_admin(G5).",
    "request.user.is_staff OR username == repo_owner",
    params=[REPO_ID, q("share_type"), q("user"), q("group_id", "integer")], response_fields=["success"])

add("DELETE", "/api/v2.1/shared-repos/{repo_id}/", "Unshare a library",
    [hdr(SR, 119, 122), block(SR, 243, elide=[(252, 266), (278, 360)])],
    "owner_or_admin", 0.7,
    [ev(SR, 249, 250), ev(SR, 274, 276)],
    "request.user.permissions.can_share_repo()(역할 기능 권한)를 먼저 요구하고, request.user.is_staff도 username == repo_owner도 아니면 403. "
    "객체 관계 조건은 소유자 OR 시스템 관리자 우회이므로 owner_or_admin(G5). can_share_repo는 기능 권한으로 보았으나 독립 AND로 보면 manual도 가능.",
    "can_share_repo(기능 권한) AND (request.user.is_staff OR username == repo_owner)",
    params=[REPO_ID, q("share_type"), q("user"), q("group_id", "integer")], response_fields=["success"])

add("POST", "/api2/repos/{repo_id}/dir/shared_items/", "Update share permission of a folder/library",
    [hdr(DSI, 48, 54), block(DSI, 225, elide=[(236, 245), (250, 311)]), block(DSI, 174, 178), IS_REPO_ACCESSIBLE, IS_REPO_ADMIN],
    "owner_or_admin", 0.7,
    [ev(DSI, 246, 248), ev(AP, 36, 40), ev(SU, 43, 46), ev(SU, 63, 64)],
    "permission_classes의 IsRepoAccessible(check_permission ≠ None)로 저장소 접근자만 진입하고 can_share_repo 기능 권한을 요구한 뒤, "
    "repo_owner != username AND not is_repo_admin이면 403. " + IS_REPO_ADMIN_NOTE +
    "소유자 OR 저장소 admin 권한(관리자 역할) 우회가 결정 조건 → owner_or_admin(G5). 선행 외부 권한 검사와 AND라 manual 대안 있음.",
    "IsRepoAccessible AND can_share_repo AND (repo_owner == username OR is_repo_admin)",
    params=[REPO_ID, q("p"), q("share_type"), q("username"), q("group_id", "integer")],
    req_body=body(["permission"], ["permission"], media="application/x-www-form-urlencoded"), response_fields=["success"])

# ---- is_repo_admin 단독 검사 3건: owner_or_admin → manual_review_required (사용자 결정 2026-11-03, 보충 규약 2 seahub 동일 적용) ----
IS_REPO_ADMIN_ALONE_NOTE = (
    "핸들러에 별도의 명시적 소유자 비교(is_repo_owner, repo_owner == username)가 없고 is_repo_admin만이 결정 조건이다. "
    "is_repo_admin(share/utils.py:39-73) = 소유자 OR ACL 공유 관리 권한(admin 권한으로 공유받은 사용자·admin 권한으로 공유된 그룹의 그룹 관리자) OR 부서 관리자 — "
    "서로 다른 유형의 OR(G6, 보충 규약 2 seahub 동일 적용, 사용자 결정 2026-11-03) → manual_review_required. "
    "이전 초안 owner_or_admin(G5)은 소유자가 OR 안에 포함된다는 점만 본 것이며, Redash require_object_modify_permission(owner OR admin OR ACL 공유)과 같은 구조로 처리한다.")

add("GET", "/api/v2.1/repos/{repo_id}/webhooks/", "List repo webhooks",
    [hdr(WH, 21, 24), block(WH, 26), IS_REPO_ADMIN],
    "manual_review_required", 0.8,
    [ev(WH, 38, 40), ev(SU, 43, 46), ev(SU, 63, 64), ev(SU, 67, 71)],
    "유일한 인가 검사는 is_repo_admin(request.user.username, repo_id). " + IS_REPO_ADMIN_ALONE_NOTE,
    "is_repo_admin(username, repo_id)만: 소유자 OR ACL admin 공유 OR 부서 관리자 (OR 유형 상이 → manual)",
    params=[REPO_ID], response_fields=["webhook_list"])

add("PUT", "/api/v2.1/repos/{repo_id}/auto-delete/", "Set auto-delete days of a repo",
    [hdr(RAD, 22, 25), block(RAD, 50), IS_REPO_ADMIN],
    "manual_review_required", 0.8,
    [ev(RAD, 77, 80), ev(SU, 43, 46), ev(SU, 63, 64), ev(SU, 67, 71)],
    "docstring 'perm: repo admin'. is_repo_admin(username, repo_id)이 거짓이면 403이 유일한 인가 검사. " + IS_REPO_ADMIN_ALONE_NOTE,
    "is_repo_admin(username, repo_id)만: 소유자 OR ACL admin 공유 OR 부서 관리자 (OR 유형 상이 → manual)",
    params=[REPO_ID], req_body=body([("auto_delete_days", "integer")], ["auto_delete_days"]), response_fields=["auto_delete_days"])

add("DELETE", "/api/v2.1/repos/{repo_id}/trash/", "Clean library trash",
    [hdr(RTR, 32, 36), block(RTR, 207, elide=[(247, 257)]), IS_REPO_ADMIN],
    "manual_review_required", 0.8,
    [ev(RTR, 231, 237), ev(RTR, 242, 246), ev(SU, 43, 46), ev(SU, 63, 64)],
    "config.ENABLE_USER_CLEAN_TRASH가 꺼져 있으면 모두 403(기능 on/off), 조직 설정 DISABLE_ORG_USER_CLEAN_TRASH가 켜져 있으면 다시 403(설정에 따라 허용 여부 변경). "
    "그 사이의 주체 조건은 is_repo_admin(username, repo_id)뿐이다(docstring '1. repo owner 2. is group admin'은 is_repo_admin 안의 분기). " + IS_REPO_ADMIN_ALONE_NOTE +
    " 설정 게이트까지 겹쳐 manual 근거가 둘이다.",
    "ENABLE_USER_CLEAN_TRASH AND is_repo_admin(소유자 OR ACL admin 공유 OR 부서 관리자) AND NOT org DISABLE_ORG_USER_CLEAN_TRASH",
    params=[REPO_ID], req_body=body([("keep_days", "integer")]), response_fields=["success"])

add("POST", "/api/v2.1/repos/{repo_id}/commits/{commit_id}/revert/", "Revert repo to a commit",
    [hdr(RCR, 24, 27), block(RCR, 29, elide=[(61, 75)]), GET_REPO_OWNER, IS_GROUP_ADMIN],
    "owner_or_admin", 0.5,
    [ev(RCR, 49, 58), ev(UR, 140, 141)],
    "EXCLUDE 후보: is_repo_owner(request, repo.id, username)이면 허용, 아니면 저장소 소유자가 '@seafile_group'(부서 소유)일 때만 그 부서의 is_group_admin이면 허용. "
    "개인 저장소는 소유자 전용(owner_match), 부서 저장소는 부서 관리자 전용이다. 부서 관리자를 '관리자 우회'(G5)로 볼지 그룹 소유 저장소의 소유자 대리(G4)로 볼지 경계라 "
    "owner_or_admin으로 두고 검수자 판단에 맡긴다. 대안 owner_match.",
    "is_repo_owner OR (부서 소유 저장소 AND is_group_admin(부서))",
    params=[REPO_ID, p("commit_id")], response_fields=["success"])

add("GET", "/api/v2.1/repos/{repo_id}/repo-api-tokens/", "List repo API tokens",
    [hdr(RAT, 36, 39), block(RAT, 41), PERM_CHECK_ADMIN_OWNER, GET_REPO_OWNER, IS_GROUP_REPO_STAFF],
    "owner_or_admin", 0.5,
    [ev(RAT, 49, 52), ev(RTU, 34, 37), ev(UR, 355, 357)],
    "EXCLUDE 후보: permission_check_admin_owner = is_repo_owner OR is_group_repo_staff(저장소 소유자가 부서일 때 그 부서의 staff). "
    "revert와 같은 '소유자 OR 부서 소유 저장소의 부서 관리자' 패턴으로 owner_or_admin과 owner_match의 경계. owner_or_admin으로 두고 검수자 판단.",
    "permission_check_admin_owner: is_repo_owner OR is_group_repo_staff",
    params=[REPO_ID], response_fields=["repo_api_tokens"])

add("POST", "/api/v2.1/wikis/", "Publish a library as wiki",
    [hdr(WK, 27, 30), block(WK, 75, elide=[(84, 92), (111, 140)]), IS_REPO_ADMIN, IS_GROUP_REPO_STAFF],
    "owner_or_admin", 0.5,
    [ev(WK, 95, 97), ev(WK, 99, 109)],
    "EXCLUDE 후보: can_create_wiki() AND can_generate_share_link()(두 역할 기능 권한)를 먼저 요구하고, 저장소 소유자 OR is_repo_admin OR is_group_repo_staff가 아니면 403. "
    "객체 관계는 소유자 OR 관리자 우회(owner_or_admin)지만 전역 역할 기능 권한 두 개가 AND로 결합돼 보류 3(독립 조건 AND)에 걸릴 수 있어 경계. 대안 manual.",
    "can_create_wiki AND can_generate_share_link AND (is_repo_owner OR is_repo_admin OR is_group_repo_staff)",
    req_body=body(["repo_id"], ["repo_id"], media="application/x-www-form-urlencoded"),
    response_fields=["id", "name", "username", "repo_id", "permission"])

# ============================================================================
# tenant_match (G1, test_v6 보충 4: org 관리 API)
# ============================================================================
TENANT_NOTE_NOPATH = ("IsOrgAdmin(request.user.org.is_staff)을 통과한 뒤 대상 조직은 경로·본문에 없고 request.user.org(요청자의 현재 테넌트)로 고정된다. "
                      "조직 관리자 역할 검사는 기능 권한으로 보고(G1), 자원이 요청자 테넌트로 필터·고정되는 구조이므로 tenant_match(보충 4).")
TENANT_NOTE_PATH = ("IsOrgAdminUser(api2/permissions.py)는 request.user.org.is_staff AND request.user.org.org_id == 경로 org_id를 요구한다. "
                    "경로에 테넌트 id가 있지만 결정 조건은 '요청자 테넌트 == 대상 테넌트'이고 역할 검사는 기능 권한이다 → tenant_match(G1, 보충 4 'org 관리 API → tenant_match').")

add("GET", "/api/v2.1/org/admin/info/", "Get my organization info (org admin)",
    [hdr(OI, 110, 114), block(OI, 116), IS_ORG_ADMIN, IS_PRO_VERSION],
    "tenant_match", 0.85,
    [ev(OI, 114), ev(OP, 9, 11), ev(OI, 120, 123)],
    TENANT_NOTE_NOPATH, "IsProVersion AND IsOrgAdmin(org.is_staff); org = request.user.org",
    response_fields=["org_id", "org_name", "ctime", "org_url_prefix", "max_user_number", "quota", "file_ext_white_list"])

add("PUT", "/api/v2.1/org/admin/info/", "Update my organization info (org admin)",
    [hdr(OI, 110, 114), block(OI, 129, elide=[(135, 154)]), IS_ORG_ADMIN],
    "tenant_match", 0.85,
    [ev(OI, 133), ev(OP, 9, 11)],
    TENANT_NOTE_NOPATH + " 변경 대상 org_id = request.user.org.org_id.",
    "IsProVersion AND IsOrgAdmin; org_id = request.user.org.org_id",
    req_body=body(["org_name", ("user_default_quota", "integer")]), response_fields=["org_id", "org_name"])

add("GET", "/api/v2.1/org/admin/links/", "List organization share links (org admin)",
    [hdr(OL, 25, 29), block(OL, 31, elide=[(49, 72)]), IS_ORG_ADMIN],
    "tenant_match", 0.85,
    [ev(OL, 45, 46), ev(OP, 9, 11)],
    TENANT_NOTE_NOPATH + " OrgFileShare.objects.filter(org_id=request.user.org.org_id)로 요청자 조직의 링크만 조회.",
    "IsProVersion AND IsOrgAdmin; OrgFileShare.filter(org_id=request.user.org.org_id)",
    params=PAGING, response_fields=["link_list", "page", "page_next"])

add("DELETE", "/api/v2.1/org/admin/links/{token}/", "Delete an organization share link (org admin)",
    [hdr(OL, 80, 84), block(OL, 86), IS_ORG_ADMIN],
    "tenant_match", 0.85,
    [ev(OL, 87), ev(OL, 98, 99), ev(OP, 9, 11)],
    TENANT_NOTE_NOPATH + " 링크가 요청자 조직의 OrgFileShare(org_id=org_id, file_share=fs)에 있을 때만 삭제한다.",
    "IsProVersion AND IsOrgAdmin; OrgFileShare.filter(org_id=요청자 org, file_share=fs) 있으면 삭제",
    params=[p("token")], response_fields=["success"])

add("GET", "/api/v2.1/org/admin/logs/file-access/", "Organization file access logs (org admin)",
    [hdr(OLG, 30, 34), block(OLG, 36, elide=[(61, 96)]), IS_ORG_ADMIN],
    "tenant_match", 0.85,
    [ev(OLG, 58, 59), ev(OP, 9, 11)],
    TENANT_NOTE_NOPATH + " get_file_audit_events(..., org_id=request.user.org.org_id, ...)로 요청자 조직 로그만 조회.",
    "IsProVersion AND IsOrgAdmin; events filtered by request.user.org.org_id",
    params=PAGING + [q("email"), q("repo_id")], response_fields=["log_list", "page", "page_next"])

add("GET", "/api/v2.1/org/{org_id}/admin/users/", "List organization users (org admin)",
    [hdr(OUS, 52, 56), block(OUS, 100, elide=[(114, None)]), IS_ORG_ADMIN_USER, IS_PRO_VERSION],
    "tenant_match", 0.8,
    [ev(AP, 102, 105), ev(OUS, 110, 112)],
    TENANT_NOTE_PATH + " 핸들러도 request.user.org.org_id != org.org_id이면 403으로 다시 비교한다.",
    "IsProVersion AND IsOrgAdminUser(org.is_staff AND org.org_id == path org_id); 핸들러 재비교",
    params=[ORG_ID] + PAGING + [q("is_staff"), q("order_by"), q("direction")], response_fields=["user_list", "page", "page_next"])

add("GET", "/api/v2.1/org/{org_id}/admin/users/{email}/", "Get an organization user (org admin)",
    [hdr(OUS, 313, 317), block(OUS, 319), IS_ORG_ADMIN_USER],
    "tenant_match", 0.75,
    [ev(AP, 102, 105), ev(OUS, 336, 338)],
    TENANT_NOTE_PATH + " 대상 사용자가 그 조직 구성원(ccnet_api.org_user_exists)이 아니면 404.",
    "IsProVersion AND IsOrgAdminUser; org_user_exists(org_id, email)",
    params=[ORG_ID, p("email")], response_fields=["email", "name", "contact_email", "quota_usage", "quota_total", "avatar_url"])

add("GET", "/api/v2.1/org/{org_id}/admin/groups/", "List organization groups (org admin)",
    [hdr(OG, 32, 36), block(OG, 38, elide=[(47, 81)]), IS_ORG_ADMIN_USER],
    "tenant_match", 0.75,
    [ev(AP, 102, 105), ev(OG, 55, 56)],
    TENANT_NOTE_PATH + " get_org_groups(org_id, ...)로 해당 조직 그룹만 나열.",
    "IsProVersion AND IsOrgAdminUser",
    params=[ORG_ID] + PAGING, response_fields=["groups", "page", "per_page", "page_next"])

add("GET", "/api/v2.1/org/{org_id}/admin/repos/", "List organization libraries (org admin)",
    [hdr(OR, 33, 37), block(OR, 39, elide=[(54, 122)]), IS_ORG_ADMIN_USER],
    "tenant_match", 0.75,
    [ev(AP, 102, 105), ev(OR, 49, 52)],
    TENANT_NOTE_PATH + " seafile_api.get_org_repo_list(org_id, ...)로 해당 조직 저장소만 나열.",
    "IsProVersion AND IsOrgAdminUser",
    params=[ORG_ID] + PAGING + [q("order_by")], response_fields=["repo_list", "page", "page_next"])

add("GET", "/api/v2.1/org/{org_id}/admin/devices/", "List organization devices (org admin)",
    [hdr(OD, 26, 30), block(OD, 32, elide=[(69, None)]), IS_ORG_ADMIN_USER],
    "tenant_match", 0.75,
    [ev(AP, 102, 105), ev(OD, 51, 52), ev(OD, 66, 67)],
    TENANT_NOTE_PATH + " TokenV2를 조직 사용자 목록(user__in=org_user_emails)으로 필터.",
    "IsProVersion AND IsOrgAdminUser; devices.filter(user__in=org users)",
    params=[ORG_ID] + PAGING + [q("platform")], response_fields=["devices", "has_next_page"])

add("GET", "/api/v2.1/org/{org_id}/admin/groups/{group_id}/members/", "List members of an organization group (org admin)",
    [hdr(OGM, 27, 31), block(OGM, 33, elide=[(53, None)]), CHECK_ORG_ADMIN, IS_ORG_ADMIN],
    "tenant_match", 0.75,
    [ev(OU, 9, 13), ev(OGM, 47, 51)],
    "IsOrgAdmin(org.is_staff) + check_org_admin 데코레이터(org.is_staff AND 경로 org_id == request.user.org.org_id)로 요청자 테넌트와 대상 테넌트가 같아야 하고, "
    "그룹이 그 조직에 속하지 않으면(get_org_id_by_group != org_id) 404. 그룹 구성원 여부가 아니라 테넌트 일치가 결정 조건 → tenant_match(G1, 보충 4).",
    "IsOrgAdmin AND check_org_admin(path org_id == request.user.org.org_id) AND group ∈ org",
    params=[ORG_ID, GROUP_ID] + PAGING, response_fields=["group_id", "group_name", "members", "page_info"])

# ============================================================================
# role_required (G3)
# ============================================================================
SYSADMIN_NOTE = ("permission_classes의 IsAdminUser(DRF 기본 클래스, request.user.is_staff)로 시스템 관리자만 진입하고, 핸들러가 "
                 "request.user.admin_permissions.{perm}()(관리자 역할별 권한)이 거짓이면 403. 전역 역할·관리자 권한이 결정 조건 → role_required(G3).")

add("GET", "/api/v2.1/admin/users/", "List all users (sysadmin)",
    [hdr(AUS, 508, 512), block(AUS, 597, elide=[(607, None)])],
    "role_required", 0.9,
    [ev(AUS, 511), ev(AUS, 604, 605)],
    SYSADMIN_NOTE.format(perm="can_manage_user"), "IsAdminUser AND admin_permissions.can_manage_user()",
    params=PAGING + [q("is_active"), q("role"), q("source")], response_fields=["data", "total_count"])

add("GET", "/api/v2.1/admin/libraries/", "List all libraries (sysadmin)",
    [hdr(ALB, 83, 86), block(ALB, 88, elide=[(98, None)])],
    "role_required", 0.9,
    [ev(ALB, 86), ev(ALB, 95, 96)],
    SYSADMIN_NOTE.format(perm="can_manage_library"), "IsAdminUser AND admin_permissions.can_manage_library()",
    params=PAGING + [q("order_by"), q("name"), q("owner")], response_fields=["repos", "page_info"])

add("DELETE", "/api/v2.1/admin/libraries/{repo_id}/", "Delete a library (sysadmin)",
    [hdr(ALB, 255, 259), block(ALB, 280, elide=[(290, None)])],
    "role_required", 0.9,
    [ev(ALB, 259), ev(ALB, 287, 288)],
    SYSADMIN_NOTE.format(perm="can_manage_library"), "IsAdminUser AND admin_permissions.can_manage_library()",
    params=[REPO_ID], response_fields=["success"])

add("GET", "/api/v2.1/admin/groups/", "List/search all groups (sysadmin)",
    [hdr(AGR, 52, 56), block(AGR, 58, elide=[(68, None)])],
    "role_required", 0.9,
    [ev(AGR, 56), ev(AGR, 65, 66)],
    SYSADMIN_NOTE.format(perm="can_manage_group"), "IsAdminUser AND admin_permissions.can_manage_group()",
    params=PAGING + [q("name")], response_fields=["groups", "page_info"])

add("GET", "/api/v2.1/admin/sysinfo/", "System info (sysadmin)",
    [hdr(ASI, 28, 33), block(ASI, 35, elide=[(47, None)])],
    "role_required", 0.9,
    [ev(ASI, 33), ev(ASI, 37, 38)],
    SYSADMIN_NOTE.format(perm="can_view_system_info"), "IsAdminUser AND admin_permissions.can_view_system_info()",
    response_fields=["users_count", "repos_count", "groups_count", "is_pro", "version"])

add("GET", "/api/v2.1/admin/organizations/", "List all organizations (sysadmin)",
    [hdr(AOR, 163, 167), block(AOR, 169, elide=[(183, None)]), IS_PRO_VERSION],
    "role_required", 0.9,
    [ev(AOR, 166), ev(AOR, 180, 181)],
    SYSADMIN_NOTE.format(perm="other_permission") + " IsProVersion·MULTI_TENANCY는 기능 활성 여부이며 허용 주체를 바꾸지 않는다.",
    "IsAdminUser AND IsProVersion AND admin_permissions.other_permission()",
    params=PAGING, response_fields=["organizations", "page", "page_next"])

add("GET", "/api/v2.1/admin/share-links/", "List all share links (sysadmin)",
    [hdr(ASL, 92, 95), block(ASL, 97, elide=[(107, None)])],
    "role_required", 0.9,
    [ev(ASL, 94), ev(ASL, 104, 105)],
    SYSADMIN_NOTE.format(perm="other_permission"), "IsAdminUser AND admin_permissions.other_permission()",
    params=PAGING + [q("order_by"), q("direction")], response_fields=["share_link_list", "page_info"])

add("POST", "/api/v2.1/admin/license/", "Upload license (sysadmin)",
    [hdr(ALC, 24, 27), block(ALC, 29, elide=[(39, None)])],
    "role_required", 0.9,
    [ev(ALC, 27), ev(ALC, 31, 32)],
    SYSADMIN_NOTE.format(perm="can_config_system"), "IsAdminUser AND admin_permissions.can_config_system()",
    req_body=body([("license", "string")], ["license"], media="multipart/form-data"), response_fields=["success"])

add("GET", "/api/v2.1/admin/web-settings/", "Get web settings (sysadmin)",
    [hdr(AWS, 38, 41), block(AWS, 43)],
    "role_required", 0.9,
    [ev(AWS, 41), ev(AWS, 45, 46)],
    SYSADMIN_NOTE.format(perm="can_config_system"), "IsAdminUser AND admin_permissions.can_config_system()")

add("GET", "/api2/accounts/", "List all accounts (sysadmin, api2)",
    [hdr(V, 250, 256), block(V, 258, elide=[(265, 293)])],
    "role_required", 0.9,
    [ev(V, 251, 252), ev(V, 255)],
    "docstring 'Administrator permission is required.' permission_classes = (IsAdminUser,)만으로 request.user.is_staff인 시스템 관리자만 허용. 전역 역할 → role_required(G3).",
    "IsAdminUser(request.user.is_staff)",
    params=[q("start", "integer"), q("limit", "integer"), q("scope")], response_fields=["email", "source"])

add("POST", "/api2/organization/", "Create an organization (sysadmin, api2)",
    [hdr(V, 5129, 5132), block(V, 5134, elide=[(5147, None)])],
    "role_required", 0.85,
    [ev(V, 5131), ev(V, 5136, 5138)],
    "permission_classes = (IsAdminUser,)로 시스템 관리자만 허용. CLOUD_MODE·MULTI_TENANCY는 기능 on/off이며 허용 주체를 바꾸지 않는다. 전역 역할 → role_required(G3).",
    "IsAdminUser(request.user.is_staff); CLOUD_MODE AND MULTI_TENANCY",
    req_body=body(["username", "password", "org_name", "prefix", "quota", "member_limit"], ["username", "password", "org_name", "prefix", "quota"],
                  media="application/x-www-form-urlencoded"))

add("POST", "/api/v2.1/groups/{group_id}/members/", "Add a group member",
    [hdr(GM, 43, 46), block(GM, 89, elide=[(101, 133)]), API_CHECK_GROUP, IS_GROUP_ADMIN_OR_OWNER, IS_GROUP_ADMIN, IS_GROUP_OWNER],
    "role_required", 0.85,
    [ev(GM, 96, 99), ev(GU, 84, 89)],
    "주석 'only group owner/admin can add a group member'. is_group_admin_or_owner(group_id, username)(ccnet check_group_staff OR creator_name == username)이 거짓이면 403. "
    "그룹 안 역할(owner/admin)이 결정 조건 → role_required(G3: 그룹 안 역할).",
    "api_check_group → is_group_admin_or_owner(group_id, username)",
    params=[GROUP_ID], req_body=body(["email"], ["email"]), response_fields=MEMBER_FIELDS)

add("PUT", "/api/v2.1/groups/{group_id}/members/{email}/", "Set/unset a member as group admin",
    [hdr(GM, 169, 172), block(GM, 198), API_CHECK_GROUP, IS_GROUP_OWNER],
    "role_required", 0.9,
    [ev(GM, 207, 210), ev(GU, 77, 82)],
    "주석 'only group owner can set/unset a specific group member as admin'. is_group_owner(group_id, username)(group.creator_name == email) 거짓이면 403. 그룹 안 역할(소유자) → role_required(G3).",
    "api_check_group → is_group_owner(group_id, username)",
    params=[GROUP_ID, p("email")], req_body=body(["is_admin"], ["is_admin"]), response_fields=MEMBER_FIELDS)

add("PUT", "/api/v2.1/groups/{group_id}/", "Rename / transfer group, toggle wiki",
    [hdr(GR, 263, 267), block(GR, 293, elide=[(308, 319), (335, 352), (368, 376)]), IS_GROUP_ADMIN_OR_OWNER, IS_GROUP_OWNER],
    "role_required", 0.85,
    [ev(GR, 303, 306), ev(GR, 330, 333), ev(GR, 363, 366)],
    "name 변경은 is_group_admin_or_owner, owner 이전은 is_group_owner, wiki_enabled는 is_group_admin_or_owner가 각각 거짓이면 403. 세 분기 모두 그룹 안 역할(owner/admin) 조건 → role_required(G3).",
    "name: is_group_admin_or_owner / owner: is_group_owner / wiki_enabled: is_group_admin_or_owner",
    params=[GROUP_ID], req_body=body(["name", "owner", "wiki_enabled"]), response_fields=GROUP_FIELDS)

add("DELETE", "/api/v2.1/groups/{group_id}/", "Dismiss a group",
    [hdr(GR, 263, 267), block(GR, 382), API_CHECK_GROUP, IS_GROUP_OWNER],
    "role_required", 0.9,
    [ev(GR, 393, 396), ev(GU, 77, 82)],
    "주석 'only group owner can dismiss a group'. is_group_owner(group_id, username) 거짓이면 403. 그룹 안 역할(소유자) → role_required(G3).",
    "api_check_group → is_group_owner(group_id, username)",
    params=[GROUP_ID], response_fields=["success"])

add("POST", "/api/v2.1/groups/{group_id}/members/bulk/", "Bulk add group members",
    [hdr(GM, 309, 312), block(GM, 314, elide=[(329, 406)]), API_CHECK_GROUP, IS_GROUP_ADMIN_OR_OWNER],
    "role_required", 0.85,
    [ev(GM, 321, 323), ev(GU, 84, 89)],
    "is_group_admin_or_owner(group_id, username) 거짓이면 403. 그룹 안 역할 → role_required(G3).",
    "api_check_group → is_group_admin_or_owner",
    params=[GROUP_ID], req_body=body(["emails"], ["emails"]), response_fields=["success", "failed"])

add("GET", "/api/v2.1/groups/{group_id}/invite-links/", "List group invite links",
    [hdr(GM, 597, 600), block(GM, 602), API_CHECK_GROUP, IS_GROUP_ADMIN_OR_OWNER],
    "role_required", 0.85,
    [ev(GM, 619, 621), ev(GU, 84, 89)],
    "MULTI_TENANCY면 기능 비활성(400), 부서 그룹이면 400, 그 뒤 is_group_admin_or_owner(group_id, email) 거짓이면 403. 그룹 안 역할이 결정 조건 → role_required(G3).",
    "api_check_group → is_group_admin_or_owner(group_id, username)",
    params=[GROUP_ID], response_fields=["group_invite_link_list"])

add("POST", "/api/v2.1/groups/{group_id}/group-owned-libraries/", "Create a group-owned (department) library",
    [hdr(GOL, 84, 87), block(GOL, 89, elide=[(99, 123), (133, 183)]), IS_GROUP_ADMIN, IS_PRO_VERSION],
    "role_required", 0.75,
    [ev(GOL, 125, 131), ev(GU, 74, 75)],
    "docstring 'Permission checking: 1. role permission, can_add_repo; 1. is group admin;'. request.user.permissions.can_add_repo()(전역 역할 기능 권한) AND is_group_admin(group_id, username)(그룹 안 역할). "
    "두 조건 모두 역할 조건이므로 role_required(G3)로 초안. 전역 역할과 그룹 역할의 AND 결합이라 manual 대안 있음(test_v5 Umami POST /api/websites 선례와 같은 처리).",
    "can_add_repo(전역 역할) AND is_group_admin(group_id, username)",
    params=[GROUP_ID], req_body=body(["name", "passwd", "permission", "library_template", "storage_id"], ["name"]),
    response_fields=["repo_id", "repo_name", "owner", "permission", "size", "encrypted"])

add("PUT", "/api/v2.1/groups/{group_id}/group-owned-libraries/{repo_id}/", "Rename a group-owned library",
    [hdr(GOL, 186, 189), block(GOL, 191, elide=[(221, 230)]), API_CHECK_GROUP, IS_GROUP_ADMIN],
    "role_required", 0.9,
    [ev(GOL, 215, 219), ev(GU, 74, 75)],
    "docstring 'Permission checking: 1. is group admin;'. is_group_admin(group_id, username)(ccnet check_group_staff) 거짓이면 403. 그룹 안 역할 → role_required(G3).",
    "api_check_group → is_group_admin(group_id, username)",
    params=[GROUP_ID, REPO_ID], req_body=body(["name"], ["name"]), response_fields=["repo_id", "repo_name", "owner"])

add("PUT", "/api/v2.1/groups/{group_id}/group-owned-libraries/{repo_id}/transfer/", "Transfer a group-owned library",
    [hdr(GOL, 1420, 1423), block(GOL, 1426, elide=[(1438, 1463), (1500, None)]), IS_GROUP_ADMIN, IS_GROUP_MEMBER],
    "role_required", 0.75,
    [ev(GOL, 1464, 1467), ev(GOL, 1485, 1487)],
    "is_group_admin(current_group_id, username) 거짓이면 403이 결정 조건(그룹 안 역할). 다른 부서로 이전할 때만 추가로 요청자가 대상 부서 구성원이어야 한다. "
    "기본 조건이 현재 그룹의 관리자 역할이므로 role_required(G3); 부서 이전 분기의 추가 구성원 조건 때문에 confidence를 낮춤.",
    "is_group_admin(현재 그룹) [AND 부서 이전 시 is_group_member(대상 부서)]",
    params=[GROUP_ID, REPO_ID], req_body=body(["email", ("reshare", "boolean")], ["email"]), response_fields=["success"])

add("GET", "/api/v2.1/group-owned-libraries/{repo_id}/user-folder-permission/", "List user folder permissions of a department library",
    [hdr(GOL, 268, 271), block(GOL, 285, elide=[(310, 326)]), IS_GROUP_ADMIN, GET_REPO_OWNER],
    "role_required", 0.85,
    [ev(GOL, 298, 299), ev(GOL, 304, 308)],
    "저장소 소유자(그룹 '<id>@seafile_group')에서 group_id를 구한 뒤 is_group_admin(group_id, username) 거짓이면 403. 소유 부서의 관리자 역할이 결정 조건 → role_required(G3).",
    "is_group_admin(저장소 소유 부서, username)",
    params=[REPO_ID, q("folder_path")], response_fields=["repo_id", "user_email", "user_name", "folder_path", "folder_name", "permission"])

add("GET", "/api/v2.1/address-book/groups/{group_id}/sub-groups/", "List sub groups of an address-book group",
    [hdr(ABG, 36, 39), block(ABG, 41), API_CHECK_GROUP, IS_GROUP_ADMIN],
    "role_required", 0.85,
    [ev(ABG, 46, 48), ev(GU, 74, 75)],
    "api_check_group(그룹 존재) 뒤 is_group_admin(group_id, request.user.username) 거짓이면 403. 구성원 여부가 아니라 그룹 안 관리자 역할이 결정 조건 → role_required(G3).",
    "IsProVersion → api_check_group → is_group_admin(group_id, username)",
    params=[GROUP_ID], response_fields=["id", "name", "owner", "created_at", "parent_group_id", "quota"])

# ============================================================================
# owner_match (G4)
# ============================================================================
add("GET", "/api/v2.1/user/", "Get my user info",
    [hdr(US, 39, 45), block(US, 47, 59), block(US, 80)],
    "owner_match", 0.9,
    [ev(US, 40), ev(US, 81, 82)],
    "docstring 'Query/update user info of myself.' email = request.user.username으로 고정해 본인 프로필만 반환. 처리 대상이 인증 사용자 본인 → owner_match(G4).",
    "self only: email = request.user.username",
    response_fields=["email", "name", "contact_email", "telephone", "login_id", "list_in_address_book"])

add("PUT", "/api/v2.1/user/", "Update my user info",
    [hdr(US, 39, 45), block(US, 85, elide=[(93, 148)])],
    "owner_match", 0.9,
    [ev(US, 87), ev(US, 152)],
    "email = request.user.username으로 고정하고 _update_user_info(info_dict, email)로 본인 프로필만 갱신. ENABLE_UPDATE_USER_INFO 등은 기능 on/off. owner_match(G4).",
    "self only: email = request.user.username",
    req_body=body(["name", "contact_email", "telephone", "list_in_address_book"]),
    response_fields=["email", "name", "contact_email", "telephone", "login_id", "list_in_address_book"])

add("POST", "/api/v2.1/user/reset-password/", "Change my password",
    [hdr(US, 213, 216), block(US, 218)],
    "owner_match", 0.85,
    [ev(US, 234, 236), ev(US, 243, 247)],
    "user = request.user 본인에 대해 old_password 확인 후 set_password. 대상이 인증 사용자 본인으로 고정 → owner_match(G4).",
    "self only: request.user.set_password",
    req_body=body(["old_password", "new_password"], ["new_password"]), response_fields=["success"])

add("GET", "/api/v2.1/starred-items/", "List my starred items",
    [hdr(SI, 33, 37), block(SI, 76, elide=[(86, 121)])],
    "owner_match", 0.9,
    [ev(SI, 79, 80), ev(SI, 83, 84)],
    "UserStarredFiles.objects.filter(email=request.user.username)으로 본인 즐겨찾기만 조회. 본인 목록 → owner_match(G4).",
    "self only: UserStarredFiles.filter(email=request.user.username)",
    response_fields=["starred_item_list"])

add("GET", "/api2/devices/", "List my devices",
    [hdr(V, 3014, 3017), block(V, 3019)],
    "owner_match", 0.9,
    [ev(V, 3020), ev(V, 3026, 3027)],
    "TokenV2.objects.get_user_devices(request.user.username)으로 본인 기기만 조회. 본인 기기 목록 → owner_match(G4).",
    "self only: get_user_devices(request.user.username)",
    response_fields=["platform", "device_id", "device_name", "client_version", "last_accessed", "is_desktop_client"])

add("POST", "/api/v2.1/user-avatar/", "Upload my avatar",
    [hdr(UA, 26, 29), block(UA, 31, elide=[(39, 46)])],
    "owner_match", 0.9,
    [ev(UA, 48, 49), ev(UA, 55, 58)],
    "Avatar(emailuser=request.user.username)으로 본인 명의 아바타만 생성. 대상이 본인으로 고정 → owner_match(G4).",
    "self only: Avatar(emailuser=request.user.username)",
    req_body=body([("avatar", "string")], ["avatar"], media="multipart/form-data"), response_fields=["avatar_url"])

add("PUT", "/api/v2.1/webdav-secret/", "Set my WebDAV password",
    [hdr(WS, 23, 26), block(WS, 40)],
    "owner_match", 0.85,
    [ev(WS, 42, 44), ev(WS, 46, 47)],
    "ENABLE_WEBDAV_SECRET 꺼짐은 기능 on/off. username = request.user.username으로 본인 UserOptions의 webdav secret만 설정/해제 → owner_match(G4).",
    "self only: UserOptions for request.user.username",
    req_body=body(["secret"]), response_fields=["secret"])

add("GET", "/api/v2.1/share-links/", "List my share links",
    [hdr(SL, 174, 178), block(SL, 180, elide=[(207, None)]), CAN_GENERATE_SHARE_LINK],
    "owner_match", 0.75,
    [ev(SL, 196), ev(SL, 203, 204), ev(AP, 74, 75)],
    "permission_classes의 CanGenerateShareLink(역할 기능 권한)를 통과한 뒤 FileShare.objects.filter(username=username)으로 본인이 만든 링크만 조회(repo_id·path 필터도 username 기준). "
    "본인 목록 → owner_match(G4). 기능 권한은 허용 범위를 바꾸지 않는다.",
    "CanGenerateShareLink(기능 권한) → FileShare.filter(username=request.user.username)",
    params=PAGING + [q("repo_id"), q("path")], response_fields=["token", "repo_id", "path", "username", "ctime", "expire_date", "permissions"])

add("DELETE", "/api/v2.1/share-links/{token}/", "Delete my share link",
    [hdr(SL, 622, 626), block(SL, 799, elide=[(812, 818), (825, 827)]), FS_IS_OWNER, CAN_GENERATE_SHARE_LINK],
    "owner_match", 0.85,
    [ev(SL, 820, 823), ev(SM, 408, 409)],
    "docstring 'Permission checking: 2. link owner;'. fs.is_owner(username)(owner == self.username) 거짓이면 403, 관리자 우회 없음. 객체 소유자 == 요청자 → owner_match(G4).",
    "CanGenerateShareLink → FileShare.is_owner(username)",
    params=[p("token")], response_fields=["success"])

add("GET", "/api/v2.1/notifications/", "List my notifications",
    [hdr(NT, 26, 30), block(NT, 32, elide=[(54, None)])],
    "owner_match", 0.9,
    [ev(NT, 40), ev(NT, 52)],
    "UserNotification.objects.get_user_notifications(request.user.username)으로 본인 알림만 조회 → owner_match(G4).",
    "self only: get_user_notifications(request.user.username)",
    params=PAGING, response_fields=["notification_list", "unseen_count", "count"])

add("PUT", "/api/v2.1/notification/", "Mark a notification seen",
    [hdr(NT, 106, 110), block(NT, 112)],
    "owner_match", 0.9,
    [ev(NT, 131), ev(NT, 138, 141)],
    "notice.to_user != request.user.username이면 403, 관리자 우회 없음. 알림 수신자 본인만 → owner_match(G4).",
    "notice.to_user == request.user.username",
    req_body=body([("notice_id", "integer")], ["notice_id"]), response_fields=["success"])

add("GET", "/api/v2.1/deleted-repos/", "List my deleted libraries",
    [hdr(DR, 41, 44), block(DR, 46, elide=[(55, 66)])],
    "owner_match", 0.9,
    [ev(DR, 48), ev(DR, 51, 53)],
    "seafile_api.get_trash_repos_by_owner(request.user.username)으로 본인이 소유했던 휴지통 저장소만 조회 → owner_match(G4).",
    "self only: get_trash_repos_by_owner(request.user.username)",
    response_fields=["repo_id", "owner_email", "repo_name", "del_time", "size"])

add("POST", "/api/v2.1/deleted-repos/", "Restore a deleted library",
    [hdr(DR, 41, 44), block(DR, 70)],
    "owner_match", 0.9,
    [ev(DR, 78), ev(DR, 82, 87)],
    "seafile_api.get_trash_repo_owner(repo_id) != request.user.username이면 403, 관리자 우회 없음. 객체 소유자 == 요청자 → owner_match(G4).",
    "trash repo owner == request.user.username",
    req_body=body(["repo_id"], ["repo_id"], media="application/x-www-form-urlencoded"), response_fields=["success"])

add("GET", "/api/v2.1/shared-repos/", "List libraries I shared out",
    [hdr(SR, 29, 33), block(SR, 35, elide=[(59, 115)])],
    "owner_match", 0.85,
    [ev(SR, 42), ev(SR, 46, 53)],
    "get_share_out_repo_list(username) / get_group_repos_by_owner(username) / list_inner_pub_repos_by_owner(username) 모두 request.user.username 기준으로 본인이 공유한 저장소만 조회 → owner_match(G4).",
    "self only: *_by_owner(request.user.username)",
    response_fields=["repo_id", "repo_name", "share_type", "share_permission", "user_email", "group_id", "is_admin"])

add("GET", "/api/v2.1/groups/", "List my groups",
    [hdr(GR, 78, 82), block(GR, 87, elide=[(99, 221)])],
    "owner_match", 0.8,
    [ev(GR, 88), ev(GR, 92, 97)],
    "ccnet_api.get_groups(username) 또는 get_org_groups_by_user(org_id, username)으로 요청자가 가입한 그룹만 나열. 대상 그룹 지정 없이 본인 소속 목록 → owner_match(G4, test_v5 Umami GET /api/teams 선례).",
    "self only: get_groups(request.user.username)",
    params=[q("avatar_size", "integer"), q("with_repos", "integer")], response_fields=GROUP_FIELDS + ["repos"])

add("GET", "/api/v2.1/activities/", "List my activities",
    [hdr(AC, 23, 26), block(AC, 28, elide=[(56, None)])],
    "owner_match", 0.8,
    [ev(AC, 25), ev(AC, 47, 50)],
    "get_user_activities(request.user.username, ...)으로 본인 활동 스트림만 조회(EVENTS_ENABLED는 기능 on/off) → owner_match(G4).",
    "self only: get_user_activities(request.user.username)",
    params=PAGING + [q("op_user")], response_fields=["events"])

add("DELETE", "/api2/repos/{repo_id}/", "Delete a library",
    [hdr(V, 1519, 1522), block(V, 1633, elide=[(1652, 1667)])],
    "owner_match", 0.9,
    [ev(V, 1641, 1645), ev(V, 1647, 1650)],
    "username != repo_owner(seafile_api.get_repo_owner / get_org_repo_owner)이면 403, 관리자 우회 없음. 객체 소유자 == 요청자 → owner_match(G4).",
    "username == repo_owner",
    params=[REPO_ID])

add("GET", "/api2/repos/{repo_id}/owner/", "Get repo owner",
    [hdr(V, 1839, 1842), block(V, 1844)],
    "owner_match", 0.9,
    [ev(V, 1855, 1858), ev(V, 1860, 1862)],
    "request.user.username != repo_owner이면 403. 소유자 본인만 → owner_match(G4).",
    "request.user.username == repo_owner",
    params=[REPO_ID], response_fields=["owner"])

add("PUT", "/api2/repos/{repo_id}/owner/", "Transfer repo to another user",
    [hdr(V, 1839, 1842), block(V, 1867, elide=[(1909, None)])],
    "owner_match", 0.9,
    [ev(V, 1870, 1871), ev(V, 1905, 1907)],
    "docstring 'only repo owner can transfer repo.' username != repo_owner이면 403, 관리자 우회 없음 → owner_match(G4).",
    "username == repo_owner",
    params=[REPO_ID], req_body=body(["owner", ("reshare", "boolean")], ["owner"]))

add("DELETE", "/api/v2.1/invitations/{token}/", "Delete my guest invitation",
    [hdr(IV, 40, 43), INVITATION_OWNER_CHECK, block(IV, 57), CAN_INVITE_GUEST],
    "owner_match", 0.85,
    [ev(IV, 31, 33), ev(AP, 67, 68)],
    "CanInviteGuest(ENABLE_GUEST_INVITATION 설정 AND 역할 기능 권한) 통과 뒤 invitation_owner_check 데코레이터가 i.inviter != request.user.username이면 403. 초대자 본인만, 관리자 우회 없음 → owner_match(G4).",
    "CanInviteGuest → invitation.inviter == request.user.username",
    params=[p("token")])

add("GET", "/api2/account/info/", "Get my account info",
    [hdr(V, 297, 302), block(V, 304, elide=[(309, 359)]), block(V, 362, 363)],
    "owner_match", 0.85,
    [ev(V, 306), ev(V, 362, 363)],
    "_get_account_info가 email = request.user.username으로 본인 프로필·쿼터만 조회해 반환. 대상이 본인으로 고정 → owner_match(G4).",
    "self only: email = request.user.username",
    response_fields=["email", "name", "avatar_url", "total", "usage", "login_id", "department", "contact_email", "is_staff"])

add("PUT", "/api/v2.1/shared-repos/{repo_id}/", "Update share permission of my library",
    [hdr(SR, 119, 122), block(SR, 124, elide=[(134, 156), (168, 240)])],
    "owner_match", 0.7,
    [ev(SR, 131, 132), ev(SR, 164, 166)],
    "docstring 'Only repo owner can update.' can_share_repo()(역할 기능 권한) 뒤 username != repo_owner이면 403, 관리자 우회 없음. 객체 소유자 == 요청자 → owner_match(G4). "
    "기능 권한과의 AND를 독립 조건으로 보면 manual 대안.",
    "can_share_repo(기능 권한) AND username == repo_owner",
    params=[REPO_ID], req_body=body(["permission", "share_type", "user", ("group_id", "integer")], ["permission", "share_type"]), response_fields=["success"])

add("GET", "/api/v2.1/departments/", "List departments I belong to",
    [hdr(DP, 25, 29), block(DP, 31, elide=[(69, None)]), IS_GROUP_MEMBER, IS_GROUP_ADMIN],
    "owner_match", 0.65,
    [ev(DP, 35, 36), ev(DP, 61, 67)],
    "전체 부서(ccnet_api.list_all_departments) 중 요청자가 is_group_member인(can_admin=true면 is_group_admin인) 부서만 남긴다. 요청이 대상 그룹을 지정하지 않고 "
    "본인 소속 목록을 돌려주는 구조라 owner_match(G4)로 초안. 구성원 조회가 필터 조건이라 membership_required로 볼 수도 있어 confidence를 낮춤.",
    "IsProVersion 아니면 403; 결과를 is_group_member/is_group_admin(department, username)으로 필터",
    params=[q("avatar_size", "integer"), q("can_admin")], response_fields=["id", "email", "parent_group_id", "name", "owner", "created_at"])

# ============================================================================
# public (G7)
# ============================================================================
DRF_DEFAULT_NOTE = ("authentication_classes/permission_classes를 선언하지 않아 DRF 기본값을 쓰며, settings.REST_FRAMEWORK에 DEFAULT_PERMISSION_CLASSES가 없으므로 "
                    "DRF 기본 AllowAny가 적용돼 익명 요청도 처리된다. ")

add("GET", "/api2/ping/", "Ping",
    [block(V, 158, 171), REST_SETTINGS],
    "public", 0.9,
    [ev(V, 158, 160), ev(V, 164, 168), ev(ST, 558, 561)],
    "docstring에 'curl http://127.0.0.1:8000/api2/ping/'로 인증 없는 호출을 예시한다. " + DRF_DEFAULT_NOTE + "익명 허용의 긍정 근거 → public(G7).",
    "no authentication/permission classes (DRF default AllowAny)", security=[])

add("POST", "/api2/auth-token/", "Obtain auth token",
    [block(V, 187, 247, elide=[(205, 244)])],
    "public", 0.95,
    [ev(V, 193, 194), ev(V, 198, 203)],
    "permission_classes = ()로 인가 없이 username/password를 AuthTokenSerializer로 검증해 토큰을 발급한다. 로그인·토큰 발급 엔드포인트의 조건 없는 익명 허용 → public(G7).",
    "permission_classes = (); credential check only", security=[],
    req_body=body(["username", "password"], ["username", "password"], media="application/x-www-form-urlencoded"), response_fields=["token"])

add("GET", "/api2/server-info/", "Server info",
    [block(VM, 10, 59, elide=[(21, 57)]), REST_SETTINGS],
    "public", 0.85,
    [ev(VM, 10, 15), ev(ST, 558, 561)],
    "ServerInfoView는 seahub.api2.base.APIView를 상속하며 인증·권한 클래스를 지정하지 않는다. " + DRF_DEFAULT_NOTE + "서버 버전·기능 목록을 익명에게 반환 → public(G7).",
    "no authentication/permission classes (DRF default AllowAny)", security=[],
    response_fields=["version", "features", "encrypted_library_version"])

add("GET", "/api/v2.1/group-members-import-example/", "Download member import example xlsx",
    [block(GM, 570, 594), REST_SETTINGS],
    "public", 0.8,
    [ev(GM, 570, 574), ev(ST, 558, 561)],
    "throttle_classes만 선언하고 authentication_classes/permission_classes가 없다. " + DRF_DEFAULT_NOTE + "고정된 예시 파일을 익명에게도 내려준다 → public(G7). "
    "같은 파일의 다른 뷰는 모두 IsAuthenticated를 선언하므로 누락이 아니라 의도로 보았다.",
    "no authentication/permission classes (DRF default AllowAny)", security=[])

# ============================================================================
# manual_review_required (G6)
# ============================================================================
add("GET", "/api2/repos/{repo_id}/", "Get library info",
    [hdr(V, 1519, 1522), block(V, 1524, elide=[(1541, 1570)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(V, 1530, 1532), ev(VI, 137)],
    "유일한 인가 검사 check_folder_permission(request, repo_id, '/'). " + RPC_NOTE,
    "check_folder_permission(repo_id, '/') 아니면 403",
    params=[REPO_ID], response_fields=["id", "owner", "name", "mtime", "size", "encrypted", "permission"])

add("GET", "/api2/repos/{repo_id}/dir/", "List directory entries (api2)",
    [hdr(V, 3840, 3847), block(V, 3849, elide=[(3851, 3875), (3884, 3911)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(V, 3877, 3882), ev(VI, 137)],
    "check_folder_permission(request, repo_id, path) 결과의 can_download가 False이고 웹 요청이 아니면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, path).can_download",
    params=[REPO_ID, q("p"), q("recursive"), q("t"), q("oid")])

add("GET", "/api2/repos/{repo_id}/file/", "Get file download link (api2)",
    [hdr(V, 3102, 3110), block(V, 3112, elide=[(3127, 3150)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(V, 3122, 3125), ev(VI, 137)],
    "check_folder_permission(request, repo_id, parent_dir) is None이면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, parent_dir) 아니면 403",
    params=[REPO_ID, q("p"), q("op"), q("reuse")])

add("GET", "/api/v2.1/repos/{repo_id}/dir/", "List directory entries",
    [hdr(DI, 198, 205), block(DI, 221, elide=[(228, 258), (280, None)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(DI, 274, 278), ev(VI, 137)],
    "docstring 'user with either r or rw permission'. check_folder_permission(request, repo_id, parent_dir)이 비어 있으면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, parent_dir) 아니면 403",
    params=[REPO_ID, q("p"), q("recursive"), q("t"), q("with_thumbnail"), q("with_parents")], response_fields=["dirent_list", "user_perm", "dir_id"])

add("GET", "/api/v2.1/repos/{repo_id}/file/history/", "File history",
    [hdr(FH, 72, 75), block(FH, 77, elide=[(111, None)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(FH, 107, 109), ev(VI, 137)],
    "check_folder_permission(request, repo_id, '/')이 비어 있으면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, '/') 아니면 403",
    params=[REPO_ID, q("path"), q("commit_id")], response_fields=["data", "next_start_commit"])

add("GET", "/api/v2.1/repos/{repo_id}/trash/", "List library trash",
    [hdr(RTR, 32, 36), block(RTR, 59, elide=[(91, None)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(RTR, 87, 89), ev(VI, 137)],
    "check_folder_permission(request, repo_id, path) is None이면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, path) 아니면 403",
    params=[REPO_ID, q("path"), q("show_days", "integer"), q("scan_stat")], response_fields=["data", "more", "scan_stat"])

add("GET", "/api/v2.1/repos/{repo_id}/repo-notification-jwt-token/", "Get repo notification JWT",
    [hdr(RAT, 163, 166), block(RAT, 168, elide=[(182, 192)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(RAT, 177, 180), ev(VI, 137)],
    "check_folder_permission(request, repo_id, '/')이 비어 있으면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, '/') 아니면 403",
    params=[REPO_ID], response_fields=["token"])

add("GET", "/api/v2.1/smart-link/", "Get smart link of a file/dir",
    [hdr(SML, 36, 40), block(SML, 42, elide=[(46, 66), (88, None)]), CHECK_FOLDER_PERMISSION],
    "manual_review_required", 0.85,
    [ev(SML, 84, 86), ev(VI, 137)],
    "check_folder_permission(request, repo_id, '/')이 비어 있으면 403. " + RPC_NOTE,
    "check_folder_permission(repo_id, '/') 아니면 403",
    params=[q("repo_id"), q("path"), q("is_dir")], response_fields=["smart_link", "smart_link_token", "name"])

add("DELETE", "/api2/beshared-repos/{repo_id}/", "Remove a library shared to me",
    [hdr(BSR, 20, 23), block(BSR, 25, elide=[(41, 59)])],
    "manual_review_required", 0.7,
    [ev(BSR, 32), ev(BSR, 72, 74), ev(BSR, 88, 89), ev(BSR, 95, 97)],
    "share_type 쿼리값마다 조건이 다르다: personal은 인가 검사 없이 요청자 본인에게 온 공유를 제거, group은 그룹 staff OR 저장소 소유자, "
    "public은 조직 staff(또는 시스템 is_staff) OR 저장소 소유자. 쿼리 모드별로 허용 주체가 바뀌므로 manual_review_required(G6, test_v31_supp Flowise GET /workspace 선례).",
    "share_type=personal: 검사 없음 / group: check_group_staff OR is_repo_owner / public: org.is_staff|is_staff OR is_repo_owner",
    params=[REPO_ID, q("share_type"), q("from"), q("group_id", "integer")], response_fields=["success"])

add("GET", "/api2/auth/ping/", "Authenticated ping",
    [block(V, 173, 184), TOKEN_AUTH],
    "manual_review_required", 0.85,
    [ev(V, 179, 180), ev(V, 183, 184)],
    "TokenAuthentication + IsAuthenticated만 있고 대상 객체도 역할·관계 검사도 없다. 인증만 확인(객체 없음) → manual_review_required(G6, 보류 6).",
    "IsAuthenticated only; no object",
    response_fields=[])

add("GET", "/api/v2.1/share-links/{token}/dirents/", "List dirents of a folder share link",
    [block(SL, 914, 916), block(SL, 918, elide=[(927, 933), (963, None)])],
    "manual_review_required", 0.8,
    [ev(SL, 938, 941), ev(SL, 951, 953), ev(SL, 955, 957)],
    "authentication/permission 클래스가 없어 익명 접근이 가능하지만, SHARE_LINK_LOGIN_REQUIRED 설정이면 인증 필요, 링크가 암호화돼 있으면 check_share_link_access(비밀번호 세션) 필요, "
    "check_share_link_access_by_scope(scope별 인증)도 통과해야 한다. 조건부 익명이라 public이 아니고(G7) 설정·링크 속성에 따라 허용 주체가 바뀜 → manual_review_required(G6).",
    "anonymous allowed unless SHARE_LINK_LOGIN_REQUIRED; encrypted → password session; scope check", security=[],
    params=[p("token"), q("thumbnail_size", "integer"), q("path")], response_fields=["dirent_list"])

add("PUT", "/api2/repos/{repo_id}/dir/shared_items/", "Share a folder/library to users or groups",
    [block(DSI, 48, 54, elide=[(49, 51)]), block(DSI, 315, elide=[(321, 335), (340, 344), (347, 444), (446, 462), (482, None)]),
     block(SU, 39, 73, elide=[(48, 55)]), block(GU, 57, 72, elide=[(61, 63), (66, 69)])],
    "manual_review_required", 0.75,
    [ev(DSI, 336, 338), ev(DSI, 463, 469), ev(DSI, 474, 480)],
    "IsRepoAccessible + can_share_repo + (repo_owner == username OR is_repo_admin)을 통과한 뒤, 그룹 공유는 ENABLE_SHARE_TO_ALL_GROUPS가 꺼져 있으면 요청자가 대상 그룹 구성원이어야 하고 "
    "부서면 ENABLE_SHARE_TO_DEPARTMENT AND is_group_admin이어야 한다. 소유자/관리자 조건과 구성원·부서 관리자 조건이 설정값에 따라 AND로 결합되는 분기 → manual_review_required(G6).",
    "(owner OR is_repo_admin) AND [group: is_group_member unless ENABLE_SHARE_TO_ALL_GROUPS; department: is_group_admin]",
    params=[REPO_ID, q("p")], req_body=body(["share_type", "permission", "username", ("group_id", "integer")], ["share_type"], media="application/x-www-form-urlencoded"),
    response_fields=["success", "failed"])

add("GET", "/api/v2.1/search-user/", "Search users",
    [hdr(SU2, 51, 56), block(SU2, 58, 60), block(SU2, 62, elide=[(74, None)])],
    "manual_review_required", 0.7,
    [ev(SU2, 55), ev(SU2, 71)],
    "IsAuthenticated만 있고 대상 객체가 없다. can_use_global_address_book()(역할 기능 권한) 여부에 따라 검색 범위(전체/조직/연락처)가 바뀌지만 거부 조건은 아니다. "
    "인증만 확인(객체 없음) → manual_review_required(G6).",
    "IsAuthenticated; scope varies by can_use_global_address_book()",
    params=[q("q")], response_fields=["users"])

add("GET", "/api/v2.1/subscription/", "Get subscription",
    [hdr(SB, 22, 25), block(SB, 27, elide=[(40, 55)]), SUB_PERM_CHECK],
    "manual_review_required", 0.7,
    [ev(SB, 35, 37), ev(SBU, 75, 78)],
    "subscription_permission_check: 조직 컨텍스트면 request.user.org.is_staff만 허용, 개인 컨텍스트면 인증만으로 허용(본인 customer_id). 요청자 컨텍스트에 따라 허용 주체가 바뀌고 "
    "구독 기능이라 보류 1·G6에 해당 → manual_review_required.",
    "org context: org.is_staff / personal: authenticated self",
    response_fields=["subscription"])


# ============================================================================
# validation + output
# ============================================================================
def validate(recs):
    problems = []
    keys = [(r["method"], r["path"]) for r in recs]
    dup = [k for k, c in collections.Counter(keys).items() if c > 1]
    if dup:
        problems.append(f"duplicate (method, path): {dup}")
    # 상한 93→110 (사용자 결정 2026-11-03, membership_required 보충); 하한은 목표 90-5
    if not (85 <= len(recs) <= 110):
        problems.append(f"record count {len(recs)} outside 85-110")
    counts = collections.Counter(r["draft_label"] for r in recs)
    for lab, c in counts.items():
        if lab not in LABELS:
            problems.append(f"bad label {lab}")
        if c > len(recs) * 0.5:
            problems.append(f"label {lab} exceeds 50%: {c}")
    short, long_ = [], []
    for r in recs:
        n = len(r["controller_text"])
        if n < 500:
            short.append((r["method"], r["path"], n))
        if n > 3000:
            long_.append((r["method"], r["path"], n))
        if not (2 <= len(r["evidence"]) <= 4):
            problems.append(f"evidence count {len(r['evidence'])} for {r['method']} {r['path']}")
        if r["draft_reason"].startswith("EXCLUDE 후보") and r["draft_confidence"] > 0.5:
            problems.append(f"EXCLUDE candidate with confidence > 0.5: {r['method']} {r['path']}")
        for e in r["evidence"]:
            rel, span = e["location"].rsplit(":", 1)
            a, _, b = span.partition("-")
            a = int(a)
            b = int(b) if b else a
            src = [l.strip() for l in lines_of(rel)[a - 1:b]]
            if src != e["text"].split("\n"):
                problems.append(f"evidence mismatch {e['location']}")
        for loc in r["source_locations"]:
            if loc["start_line"] > loc["end_line"]:
                problems.append(f"bad source_location {loc}")
    if long_:
        problems.append(f"controller_text > 3000 chars: {long_}")
    return problems, counts, short


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    problems, counts, short = validate(records)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"wrote {len(records)} records -> {OUT}")
    for lab in sorted(counts, key=lambda k: -counts[k]):
        print(f"  {lab:24s} {counts[lab]:3d}")
    n_excl = sum(1 for r in records if r["draft_reason"].startswith("EXCLUDE 후보"))
    print(f"EXCLUDE 후보: {n_excl}")
    lens = sorted(len(r["controller_text"]) for r in records)
    print(f"controller_text chars: min {lens[0]} median {lens[len(lens)//2]} max {lens[-1]}")
    if short:
        print("controller_text < 500 chars:")
        for m, pth, n in short:
            print(f"  {m} {pth} ({n})")
    if problems:
        print("PROBLEMS:")
        for pr in problems:
            print("  " + pr)
        sys.exit(1)
    print("validation OK")


if __name__ == "__main__":
    main()
