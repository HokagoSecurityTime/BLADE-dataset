"""Static extraction of Redash API authorization policy candidates (test_v6).

Read-only over the clone at datasets/blade/raw/opensource/test_v6_candidates/redash.
Writes candidates.jsonl next to this script. Run with:
    python -I data/raw_v6/redash/extract_redash.py
No LLM API, no model runs, no repository modification.
"""
import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(
    os.path.join(HERE, "..", "..", "..", "datasets", "blade", "raw", "opensource", "test_v6_candidates", "redash")
)
OUT = os.path.join(HERE, "candidates.jsonl")

PROJECT = "redash"
SERVICE = "Redash"
REPO_URL = "https://github.com/getredash/redash"
COMMIT = "42fdf9d4a0fdb83841130ab78f69899a224f281b"
TAG = "v26.9.0"
LICENSE = "BSD-2-Clause"

_cache = {}


def lines_of(rel):
    if rel not in _cache:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            _cache[rel] = f.read().split("\n")
    return _cache[rel]


def _indent(s):
    return len(s) - len(s.lstrip())


def func_end(rel, start):
    """Return end line (1-based, inclusive) of a Python def/class block whose first line
    (decorator or def/class) is `start`. The block ends before the next non-blank line whose
    indentation is <= the def/class line's indentation. Trailing blank lines are excluded."""
    ls = lines_of(rel)
    i = start - 1
    while ls[i].strip().startswith("@"):
        i += 1
    head = ls[i]
    base = _indent(head)
    if not head.lstrip().startswith(("def ", "class ", "async def ")):
        raise RuntimeError(f"not a def/class at {rel}:{i + 1}: {head!r}")
    end = i + 1
    j = i + 1
    while j < len(ls):
        line = ls[j]
        if line.strip():
            if _indent(line) <= base:
                break
            end = j + 1
        j += 1
    return end


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


def mblk(rel, cls_line, a, b, elide=()):
    """Class header line + '...' + verbatim method lines a..b (for model classmethods)."""
    inner = block(rel, a, b, elide=elide)
    ls = lines_of(rel)
    text = ls[cls_line - 1] + "\n    ...\n" + inner["text"]
    return {"file": rel, "start_line": cls_line, "end_line": b, "text": text}


def line(rel, n):
    return lines_of(rel)[n - 1].strip()


def ev(rel, a, b=None):
    if b is None:
        return {"type": "code", "text": line(rel, a), "location": f"{rel}:{a}"}
    text = "\n".join(l.strip() for l in lines_of(rel)[a - 1:b])
    return {"type": "code", "text": text, "location": f"{rel}:{a}-{b}"}


# ---- files ----------------------------------------------------------------
BASE = "redash/handlers/base.py"
P = "redash/permissions.py"
U = "redash/models/users.py"
M = "redash/models/__init__.py"
MX = "redash/models/mixins.py"
ORGRES = "redash/authentication/org_resolving.py"
AUTH = "redash/authentication/__init__.py"
A = "redash/handlers/alerts.py"
D = "redash/handlers/dashboards.py"
FV = "redash/handlers/favorites.py"
DS = "redash/handlers/data_sources.py"
DE = "redash/handlers/destinations.py"
EV = "redash/handlers/events.py"
G = "redash/handlers/groups.py"
PM = "redash/handlers/permissions.py"
Q = "redash/handlers/queries.py"
QR = "redash/handlers/query_results.py"
QS = "redash/handlers/query_snippets.py"
ST = "redash/handlers/settings.py"
US = "redash/handlers/users.py"
V = "redash/handlers/visualizations.py"
W = "redash/handlers/widgets.py"
AU = "redash/handlers/authentication.py"
ORG = "redash/handlers/organization.py"
ADM = "redash/handlers/admin.py"
HI = "redash/handlers/__init__.py"

# ---- shared blocks ----------------------------------------------------------
BASE_CLS = block(BASE, 21, 39, elide=[(24, 36)])          # class BaseResource: decorators=[login_required], current_org
GET404 = block(BASE, 70, 77)
RECORD_EVENT = block(BASE, 50, 61)
MIXIN = block(MX, 20, 28)                                 # BelongsToOrgMixin.get_by_id_and_org
ORG_RESOLVE = block(ORGRES, 9, 20)                        # current_org from org_slug / default

HAS_ACCESS = block(P, 17, 21)
HAS_ACCESS_OBJ = block(P, 24, 31)
HAS_ACCESS_GROUPS = block(P, 34, 49)
REQUIRE_ACCESS = block(P, 52, 54)
REQ_PERMS = block(P, 57, 75)
REQ_PERM = block(P, 78, 79)
REQ_ANY = block(P, 82, 83)
REQ_ADMIN = block(P, 86, 87)
REQ_SUPER = block(P, 90, 91)
HAS_PERM_OR_OWNER = block(P, 94, 95)
IS_ADMIN_OR_OWNER = block(P, 98, 99)
REQ_PERM_OR_OWNER = block(P, 102, 104)
REQ_ADMIN_OR_OWNER = block(P, 107, 109)
CAN_MODIFY = block(P, 112, 113)
REQ_OBJ_MODIFY = block(P, 116, 118)

PERM_MIXIN = block(U, 63, 74)                             # PermissionsCheckMixin.has_permission(s)
USER_PERMS = mblk(U, 78, 172, 175)                        # User.permissions = union of group permissions
USER_HAS_ACCESS = mblk(U, 78, 232, 233)                   # User.has_access -> AccessPermission.exists
ACL_EXISTS = mblk(U, 304, 346, 348)
GROUP_MEMBERS = mblk(U, 246, 293, 295)
USER_ALL = mblk(U, 78, 193, 195)
APIKEY_LOADER = block(AUTH, 154, 162)

ALERT_GBIO = mblk(M, 982, 1011, 1013)
ALERT_ALL = mblk(M, 982, 1002, 1009)
DS_ALL = mblk(M, 112, 183, 190)
Q_BY_USER = mblk(M, 446, 572, 574)
Q_FAV = mblk(M, 446, 546, 555)
DASH_ALL = mblk(M, 1116, 1144, 1162)
DASH_FAV = mblk(M, 1116, 1188, 1204)
DASH_BY_USER = mblk(M, 1116, 1206, 1208)
DEST_ALL = mblk(M, 1390, 1431, 1435)
SNIP_ALL = mblk(M, 1490, 1502, 1504)
APIKEY_GET = mblk(M, 1356, 1370, 1372)

ADMIN_CHAIN = [REQ_ADMIN, REQ_PERM, REQ_PERMS]   # PERM_MIXIN·USER_PERMS는 아래 with_perm_resolution이 일괄 추가
RBAC_CHAIN = [REQ_PERM, REQ_PERMS]

# 그룹 권한 해석 블록(PermissionsCheckMixin.has_permission(s) users.py:63-74 + User.permissions users.py:172-175)의
# 포함 규칙(2026-11-03 사용자 지시, label과 무관하게 코드 메커니즘만으로 결정):
#   레코드의 블록 원문에 require_permissions 체인(require_admin / require_super_admin / require_permission /
#   require_any_of_permission — require_admin_or_owner·require_permission_or_owner 포함) 또는 그 체인이 호출하는
#   has_permission(s) 호출이 있으면 두 블록을 정확히 한 번, 마지막 permissions.py 헬퍼 블록 바로 뒤(없으면 끝)에 넣는다.
#   없으면 넣지 않는다. 순서: 핸들러 → permissions.py 헬퍼 → users.py 권한 해석 → 나머지(모델·mixin).
CHAIN_RX = re.compile(r"require_admin|require_super_admin|require_permission|require_any_of_permission|has_permission")
PERM_RESOLVE = (PERM_MIXIN, USER_PERMS)


def uses_perm_chain(blocks):
    return any(CHAIN_RX.search(b["text"]) for b in blocks if b not in PERM_RESOLVE)


def with_perm_resolution(blocks):
    core = [b for b in blocks if b not in PERM_RESOLVE]
    if not uses_perm_chain(core):
        return core
    last_p = max((i for i, b in enumerate(core) if b["file"] == P), default=len(core) - 1)
    return core[: last_p + 1] + list(PERM_RESOLVE) + core[last_p + 1:]
ACL_CHAIN = [REQUIRE_ACCESS, HAS_ACCESS, HAS_ACCESS_GROUPS]
OWNER_ADMIN_CHAIN = [REQ_ADMIN_OR_OWNER, IS_ADMIN_OR_OWNER, HAS_PERM_OR_OWNER]
OBJ_MODIFY_CHAIN = [REQ_OBJ_MODIFY, CAN_MODIFY, IS_ADMIN_OR_OWNER, HAS_PERM_OR_OWNER, USER_HAS_ACCESS, ACL_EXISTS]

# ---- OAS helpers ------------------------------------------------------------
APIKEY_SEC = [{"apiKeyOrSession": []}]
SEC_SCHEMES = {
    "apiKeyOrSession": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "Key <api_key> (user or query API key; also ?api_key=) or session cookie; redash.authentication (flask-login login_required on BaseResource)",
    }
}


def p(name, where="path", typ="integer", required=True):
    return {"name": name, "in": where, "required": required, "schema": {"type": typ}}


def qp(name, typ="string"):
    return p(name, "query", typ, False)


PAGING = [qp("page", "integer"), qp("page_size", "integer"), qp("order"), qp("q"), qp("tags")]


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


def form(keys, required=None):
    props = {k: {"type": "string"} for k in keys}
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return {"required": True, "content": {"application/x-www-form-urlencoded": {"schema": schema}}}


records = []


def add(method, path, summary, blocks, label, conf, evidence, reason, auth_summary,
        params=None, req_body=None, security=APIKEY_SEC, response_fields=None, description=""):
    blocks = with_perm_resolution(blocks)
    texts = [b["text"] for b in blocks]
    controller_text = "\n\n".join(texts)
    locs = [{"file": b["file"], "start_line": b["start_line"], "end_line": b["end_line"]} for b in blocks]
    op = {
        "operationId": method.lower() + "".join(seg.strip("{}").title().replace("_", "") for seg in path.split("/") if seg and seg != "api"),
        "summary": summary,
        "description": description,
        "parameters": params or [],
        "responses": {"200": {"description": "OK"}, "403": {"description": "Forbidden"}, "404": {"description": "Not found (also returned for unauthenticated /api/ requests)"}},
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


ORG_NOTE = ("get_by_id_and_org(id, self.current_org)는 요청자의 현재 조직(org_slug 또는 default)으로 대상을 필터한다. "
            "경로·본문에 대상 조직 ID가 없다.")
RBAC_NOTE = "@require_permission의 기능 권한은 G1에 따라 기능 권한으로 보고 tenant_match 판정을 바꾸지 않는다."
ACL_NOTE = ("require_access → has_access_to_groups: admin 권한이면 통과, 아니면 대상의 data source 그룹과 요청자 group_ids의 교집합 및 "
            "view_only 레벨로 결정(데이터소스·그룹 ACL 합산). 보충 규약 2에 따라 manual_review_required(G6, 외부 ACL).")
OBJMOD_NOTE = ("require_object_modify_permission → can_modify = is_admin_or_owner(obj.user_id) OR user.has_access(obj, 'modify')(AccessPermission ACL 공유). "
               "소유자 OR 관리자 OR ACL 공유의 OR 결합이라 보충 규약 2에 따라 manual_review_required(G6).")
OA_NOTE = "require_admin_or_owner → int(object_owner_id) == current_user.id OR current_user.has_permission('admin'). 소유자 OR 관리자 우회가 실제 조건이므로 owner_or_admin(G5, 보충 규약 2)."
# G1-b (정지 지점 2 결정 2026-11-03): @require_admin은 @require_permission과 같은 조직 그룹 권한 메커니즘이므로
# current_org 필터·강제가 함께 있으면 tenant_match. 메커니즘 근거 줄은 아래 상수에 고정한다.
ADMIN_MECH = ("@require_admin = require_permission('admin')(permissions.py:86-87)이고 require_permissions.__call__는 current_user.has_permission(s)만 검사한다(permissions.py:57-75). "
              "User.permissions는 요청자 소속 그룹 permissions의 합집합(models/users.py:173-175)이며 Group은 org_id로 조직에 귀속된다(users.py:268; ADMIN_PERMISSIONS=['admin','super_admin'] users.py:261). "
              "따라서 @require_admin은 @require_permission과 같은 조직 그룹 권한 메커니즘이고, G1('RBAC 권한이 함께 있어도 기능 권한으로 보고 tenant_match')에 따라 판정을 바꾸지 않는다. ")
ADMIN_TENANT_TAIL = " 경로·본문에 대상 조직 ID가 없다 → tenant_match(G1-b, 보충 규약 1)."
ADMIN_ONLY_NOTE = ("@require_admin = require_permission('admin')(permissions.py:86-87): 요청자 소속 그룹 권한 합(models/users.py:173-175)에 'admin'이 있어야 통과. "
                   "이 핸들러는 대상 객체도 current_org 필터·강제도 없어 보충 규약 1 G1-b가 적용되지 않고, 객체 없는 기능에 그룹 권한만 있으므로 role_required(G3).")

# ============================================================================
# ALERTS
# ============================================================================
add("GET", "/api/alerts/{alert_id}", "Get alert",
    [BASE_CLS, block(A, 23, 28), GET404, ALERT_GBIO, MIXIN] + ACL_CHAIN,
    "manual_review_required", 0.85,
    [ev(A, 25, 26), ev(P, 52, 54), ev(P, 37, 38), ev(P, 40, 43)],
    "alert를 현재 조직으로 조회한 뒤 require_access(alert, user, view_only)가 결정한다. " + ACL_NOTE,
    "login_required → Alert.get_by_id_and_org(org) → require_access(alert, view_only): admin 또는 data source 그룹 교집합",
    params=[p("alert_id")], response_fields=["id", "name", "query", "user", "options", "state", "rearm"])

add("POST", "/api/alerts/{alert_id}", "Update alert",
    [BASE_CLS, block(A, 23, 23), block(A, 30, 48, elide=[(43, 48)])] + OWNER_ADMIN_CHAIN + ACL_CHAIN,
    "manual_review_required", 0.6,
    [ev(A, 34), ev(A, 40), ev(P, 107, 109), ev(P, 52, 54)],
    "require_admin_or_owner(alert.user.id)(소유자 OR 관리자)와 require_access(query, view_only)(대상 쿼리의 data source 그룹 ACL)가 AND로 모두 통과해야 한다. "
    "서로 다른 유형의 독립 필수 조건 결합이라 보류(프롬프트 보류 3). 대안: owner_or_admin(alert 자체의 결정 조건만 보면).",
    "require_admin_or_owner(alert.user.id) AND require_access(query, view_only)",
    params=[p("alert_id")], req_body=body([("options", "object"), "name", ("query_id", "integer"), ("rearm", "integer")]),
    response_fields=["id", "name", "query", "user", "options", "state"])

add("DELETE", "/api/alerts/{alert_id}", "Delete alert",
    [BASE_CLS, block(A, 23, 23), block(A, 50, 54)] + OWNER_ADMIN_CHAIN + [ALERT_GBIO, MIXIN],
    "owner_or_admin", 0.9,
    [ev(A, 51, 52), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE + " 현재 조직 필터(get_by_id_and_org)는 함께 적용된다.",
    "Alert.get_by_id_and_org(org) → require_admin_or_owner(alert.user_id)",
    params=[p("alert_id")])

add("POST", "/api/alerts/{alert_id}/mute", "Mute alert",
    [BASE_CLS, block(A, 73, 81)] + OWNER_ADMIN_CHAIN + [ALERT_GBIO, MIXIN],
    "owner_or_admin", 0.9,
    [ev(A, 75, 76), ev(P, 107, 109), ev(P, 98, 99), ev(P, 94, 95)],
    OA_NOTE + " (unmute DELETE는 같은 조건이라 제외.)",
    "Alert.get_by_id_and_org(org) → require_admin_or_owner(alert.user.id)",
    params=[p("alert_id")])

add("GET", "/api/alerts", "List alerts",
    [BASE_CLS, block(A, 93, 93), block(A, 117, 120)] + RBAC_CHAIN + [ALERT_ALL],
    "role_required", 0.65,
    [ev(A, 117, 118), ev(A, 120), ev(P, 78, 79), ev(P, 68, 73)],
    "@require_permission('list_alerts')가 유일한 거부 조건이다(그룹 권한 문자열). 결과는 Alert.all(group_ids)로 요청자 그룹의 data source에 걸린 알림만 반환하는 범위 필터이며 거부 조건이 아니다. "
    "객체 없는 목록 기능에 RBAC 권한만 있으므로 role_required(G3). Alert.all(group_ids)(models/__init__.py:1002-1009)에는 current_org 필터가 없어 보충 규약 1(G1-b) 대상이 아니다. 대안: 그룹 ACL 필터를 결정 조건으로 보면 manual.",
    "@require_permission('list_alerts'); 결과 Alert.all(group_ids=current_user.group_ids)로 범위 제한",
    response_fields=["id", "name", "query", "user", "state"])

add("DELETE", "/api/alerts/{alert_id}/subscriptions/{subscriber_id}", "Unsubscribe from alert",
    [BASE_CLS, block(A, 159, 166)] + OWNER_ADMIN_CHAIN,
    "owner_or_admin", 0.85,
    [ev(A, 161, 162), ev(P, 107, 109), ev(P, 94, 95)],
    "구독을 subscriber_id로 전역 조회(query.get_or_404, 조직·alert 일치 검사 없음)한 뒤 require_admin_or_owner(subscription.user.id). "
    "구독 소유자 본인 OR 관리자이므로 owner_or_admin(G5). 조직 필터가 없는 점은 검수 참고.",
    "AlertSubscription.query.get_or_404 → require_admin_or_owner(subscription.user.id)",
    params=[p("alert_id"), p("subscriber_id")])

# ============================================================================
# DASHBOARDS
# ============================================================================
add("GET", "/api/dashboards", "List dashboards",
    [BASE_CLS, block(D, 38, 62, elide=[(41, 51)])] + RBAC_CHAIN + [DASH_ALL],
    "manual_review_required", 0.6,
    [ev(D, 39), ev(D, 62), ev(M, 1153, 1157), ev(M, 1160)],
    "@require_permission('list_dashboards') 뒤 Dashboard.all(org, group_ids, user_id)가 반환 범위를 정한다: 조직 일치 AND (위젯 쿼리의 data source 그룹 ∈ 요청자 그룹 OR 소유자 본인) AND (draft는 소유자만). "
    "가시성이 그룹 ACL OR 소유자로 분기하는 OR 결합이라 보류(G6). 대안: tenant_match(조직 필터 기준) 또는 role_required(RBAC 기준).",
    "@require_permission('list_dashboards'); Dashboard.all: org == current_org AND (group ACL OR owner); drafts owner-only",
    params=PAGING, response_fields=["count", "page", "page_size", "results"])

add("POST", "/api/dashboards", "Create dashboard",
    [BASE_CLS, block(D, 38, 38), block(D, 88, 107, elide=[(90, 96)])] + RBAC_CHAIN,
    "tenant_match", 0.65,
    [ev(D, 88, 89), ev(D, 98, 104), ev(P, 78, 79), ev(ORGRES, 16, 18)],
    "@require_permission('create_dashboard')(기능 권한)만이 거부 조건이고, 생성 대상의 org를 self.current_org로 강제한다(dashboards.py:98-104; G1 '생성 시 자원 테넌트를 요청자 테넌트로 강제'). "
    "보충 규약 1(G1-b)을 기능 권한만 있는 생성에도 일관 적용해 tenant_match(G1; POST /api/data_sources·POST /api/users와 같은 구조). " + RBAC_NOTE +
    " user=self.current_user도 함께 고정되어 G4 '본인 명의 생성'(owner_match) 해석이 있고, RBAC만 거부 조건으로 보면 role_required라 confidence를 낮춘다.",
    "@require_permission('create_dashboard'); Dashboard(org=current_org, user=current_user)",
    req_body=body(["name"], ["name"]), response_fields=["id", "name", "slug", "user_id", "is_draft"])

add("GET", "/api/dashboards/my", "List my dashboards",
    [BASE_CLS, block(D, 110, 139, elide=[(113, 123), (130, 139)])] + [REQ_PERM, DASH_BY_USER],
    "owner_match", 0.85,
    [ev(D, 111), ev(D, 126, 128), ev(M, 1207, 1208)],
    "Dashboard.by_user(self.current_user) / search_by_user로 요청자가 만든 대시보드만 조회한다. 처리 대상이 인증 사용자 본인으로 고정되므로 owner_match(G4). "
    "@require_permission('list_dashboards')는 기능 권한.",
    "@require_permission('list_dashboards'); Dashboard.by_user(current_user)",
    params=PAGING, response_fields=["count", "page", "page_size", "results"])

add("GET", "/api/dashboards/{dashboard_id}", "Get dashboard",
    [BASE_CLS, block(D, 142, 201, elide=[(145, 178), (185, 201)]), GET404, MIXIN, ORG_RESOLVE] + [REQ_PERM, REQ_PERMS],
    "tenant_match", 0.85,
    [ev(D, 143, 144), ev(D, 182, 184), ev(MX, 22, 28), ev(ORGRES, 16, 18)],
    "대상 대시보드를 Dashboard.get_by_id_and_org(dashboard_id, self.current_org)로만 조회하고 소유자·그룹 ACL 검사가 없다. " + ORG_NOTE + " 보충 규약 1에 따라 tenant_match(G1). " + RBAC_NOTE +
    " (can_edit 계산은 응답 필드이지 접근 조건이 아니다.)",
    "@require_permission('list_dashboards'); Dashboard.get_by_id_and_org(id, current_org)만 적용",
    params=[p("dashboard_id"), qp("legacy")], response_fields=["id", "name", "slug", "user_id", "widgets", "can_edit", "public_url"])

add("POST", "/api/dashboards/{dashboard_id}", "Update dashboard",
    [BASE_CLS, block(D, 142, 142), block(D, 203, 254, elide=[(205, 214), (221, 254)])] + OBJ_MODIFY_CHAIN,
    "manual_review_required", 0.85,
    [ev(D, 203), ev(D, 217, 219), ev(P, 116, 118), ev(P, 112, 113)],
    OBJMOD_NOTE + " (DELETE /api/dashboards/{id}는 같은 조건이라 제외.)",
    "@require_permission('edit_dashboard') → require_object_modify_permission(dashboard): owner OR admin OR ACL modify",
    params=[p("dashboard_id")], req_body=body(["name", ("layout", "array"), ("version", "integer"), ("tags", "array"), ("is_draft", "boolean"), ("is_archived", "boolean"), ("dashboard_filters_enabled", "boolean"), ("options", "object")]),
    response_fields=["id", "name", "slug", "version", "widgets"])

add("GET", "/api/dashboards/public/{token}", "Get public dashboard by token",
    [BASE_CLS, block(D, 278, 297, elide=[(282, 287)]), GET404, APIKEY_GET, block(AUTH, 139, 151), block(AUTH, 109, 136, elide=[(113, 121), (126, 135)])],
    "manual_review_required", 0.8,
    [ev(D, 288, 289), ev(D, 291, 293), ev(AUTH, 148, 149), ev(AUTH, 123, 124)],
    "경로 token이 API 키로 로드돼(get_api_key_from_request view_args['token'] → ApiKey → ApiUser) 익명 요청자가 토큰만으로 해당 대시보드를 본다. 조직 설정 disable_public_urls면 400. "
    "익명 허용이 토큰(capability) 소지라는 조건부이므로 G7의 public이 아니고, 설정 의존이 있어 manual_review_required(G6/G7).",
    "login_required이지만 path token이 ApiKey→ApiUser로 인증됨; disable_public_urls 설정 시 400",
    params=[p("token", typ="string")], security=[], response_fields=["widgets", "name", "layout"])

add("POST", "/api/dashboards/{dashboard_id}/share", "Enable public sharing (create API key)",
    [BASE_CLS, block(D, 300, 330, elide=[(302, 308), (315, 330)])] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.9,
    [ev(D, 309, 310), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE,
    "Dashboard.get_by_id_and_org(org) → require_admin_or_owner(dashboard.user_id)",
    params=[p("dashboard_id")], response_fields=["public_url", "api_key"])

add("DELETE", "/api/dashboards/{dashboard_id}/share", "Disable public sharing",
    [BASE_CLS, block(D, 300, 300), block(D, 332, 353, elide=[(333, 337), (340, 353)])] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.9,
    [ev(D, 338, 339), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE,
    "Dashboard.get_by_id_and_org(org) → require_admin_or_owner(dashboard.user_id)",
    params=[p("dashboard_id")])

add("GET", "/api/dashboards/favorites", "List my favorite dashboards",
    [BASE_CLS, block(D, 366, 405, elide=[(381, 405)]), DASH_FAV],
    "owner_match", 0.8,
    [ev(D, 377), ev(D, 379), ev(M, 1203)],
    "Dashboard.favorites(self.current_user)가 Favorite.user_id == user.id로 요청자 본인의 즐겨찾기만 반환한다. 대상이 본인으로 고정되므로 owner_match(G4). "
    "기본 범위는 Dashboard.all(가시성 필터)이지만 추가 거부 조건은 아니다.",
    "login_required; Dashboard.favorites(current_user): Favorite.user_id == current_user.id",
    params=PAGING, response_fields=["count", "page", "page_size", "results"])

# ============================================================================
# FAVORITES
# ============================================================================
add("POST", "/api/dashboards/{object_id}/favorite", "Favorite a dashboard",
    [BASE_CLS, block(FV, 40, 60, elide=[(54, 60)]), GET404, MIXIN],
    "owner_match", 0.6,
    [ev(FV, 42, 43), ev(MX, 22, 28)],
    "대시보드는 get_by_id_and_org(현재 조직)로만 조회하고 접근 검사가 없다. 생성되는 Favorite는 user=self.current_user로 본인 명의로 고정된다(G4 '본인 명의 생성'). "
    "대안: 대시보드 쪽 조건만 보면 tenant_match(G1).",
    "login_required; Dashboard.get_by_id_and_org(org) → Favorite(user=current_user) 생성",
    params=[p("object_id")])

add("DELETE", "/api/dashboards/{object_id}/favorite", "Unfavorite a dashboard",
    [BASE_CLS, block(FV, 40, 40), block(FV, 62, 75, elide=[(69, 75)]), GET404, MIXIN],
    "owner_match", 0.7,
    [ev(FV, 63, 67), ev(MX, 22, 28)],
    "Favorite.user == self.current_user 조건으로 요청자 본인의 즐겨찾기 행만 삭제한다. 관리자 우회 없음 → owner_match(G4). 대시보드는 현재 조직 필터만 적용.",
    "login_required; Favorite filter(object == dashboard, user == current_user).delete()",
    params=[p("object_id")])

# ============================================================================
# DATA SOURCES
# ============================================================================
add("GET", "/api/data_sources/types", "List data source types",
    [BASE_CLS, block(DS, 31, 34)] + ADMIN_CHAIN,
    "role_required", 0.9,
    [ev(DS, 32, 33), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_ONLY_NOTE + " 반환값은 전역 query_runners 목록이다. (destinations/types GET은 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); 대상 객체·current_org 필터 없음", response_fields=["type", "name", "configuration_schema"])

add("GET", "/api/data_sources/{data_source_id}", "Get data source",
    [BASE_CLS, block(DS, 37, 50), GET404, MIXIN] + ACL_CHAIN,
    "manual_review_required", 0.85,
    [ev(DS, 39, 40), ev(P, 52, 54), ev(P, 37, 43), ev(P, 45, 49)],
    "현재 조직으로 조회한 데이터소스에 require_access(data_source, user, view_only)를 적용한다. " + ACL_NOTE + " (schema GET·databricks 3건은 같은 조건이라 제외.)",
    "DataSource.get_by_id_and_org(org) → require_access(view_only): admin 또는 그룹 교집합",
    params=[p("data_source_id")], response_fields=["id", "name", "type", "options", "view_only"])

add("POST", "/api/data_sources/{data_source_id}", "Update data source",
    [BASE_CLS, block(DS, 37, 37), block(DS, 52, 83, elide=[(57, 79)])] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(DS, 52, 54), ev(P, 86, 87), ev(U, 173, 175), ev(MX, 22, 28)],
    ADMIN_MECH + "대상 데이터소스를 DataSource.get_by_id_and_org(data_source_id, self.current_org)(data_sources.py:54)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " (DELETE·pause·resume은 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); DataSource.get_by_id_and_org(current_org)",
    params=[p("data_source_id")], req_body=body(["type", "name", ("options", "object")], ["type", "name", "options"]),
    response_fields=["id", "name", "type", "options"])

add("GET", "/api/data_sources", "List data sources",
    [BASE_CLS, block(DS, 101, 129, elide=[(109, 129)])] + RBAC_CHAIN + [DS_ALL],
    "tenant_match", 0.7,
    [ev(DS, 102, 107), ev(M, 185), ev(P, 78, 79), ev(ORGRES, 16, 18)],
    "@require_permission('list_data_sources')(기능 권한) 뒤 DataSource.all(self.current_org[, group_ids])(data_sources.py:104-107 → models/__init__.py:185 cls.org == org)가 요청자 현재 조직의 데이터소스만 반환한다. 경로에 조직 ID 없음. "
    "보충 규약 1(G1-b)을 기능 권한만 있는 목록에도 일관 적용해 tenant_match(G1; GET /api/users와 같은 구조). " + RBAC_NOTE +
    " 비관리자는 요청자 group_ids로 범위를 더 좁히지만 거부 조건은 아니다. 대안: RBAC를 결정으로 보면 role_required, 그룹 범위 필터를 결정으로 보면 manual.",
    "@require_permission('list_data_sources'); DataSource.all(current_org) (비관리자는 group_ids로 추가 범위 제한)",
    response_fields=["id", "name", "type", "view_only"])

add("POST", "/api/data_sources", "Create data source",
    [BASE_CLS, block(DS, 101, 101), block(DS, 131, 167, elide=[(136, 143), (149, 167)])] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(DS, 131, 132), ev(DS, 145, 147), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "생성되는 데이터소스의 org를 self.current_org로 강제한다(data_sources.py:145-147; G1 '생성 시 자원 테넌트를 요청자 테넌트로 강제')." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); DataSource.create_with_group(org=current_org)",
    req_body=body(["name", "type", ("options", "object")], ["options", "name", "type"]), response_fields=["id", "name", "type", "options"])

add("POST", "/api/data_sources/{data_source_id}/test", "Test data source connection",
    [BASE_CLS, block(DS, 223, 248, elide=[(228, 248)]), GET404] + ADMIN_CHAIN,
    "tenant_match", 0.8,
    [ev(DS, 224, 226), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 데이터소스를 get_object_or_404(DataSource.get_by_id_and_org, data_source_id, self.current_org)(data_sources.py:226)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); DataSource.get_by_id_and_org(current_org)",
    params=[p("data_source_id")], response_fields=["message", "ok"])

# ============================================================================
# DESTINATIONS
# ============================================================================
add("GET", "/api/destinations/{destination_id}", "Get alert destination",
    [BASE_CLS, block(DE, 21, 33, elide=[(26, 33)])] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(DE, 22, 24), ev(P, 86, 87), ev(U, 173, 175), ev(MX, 22, 28)],
    ADMIN_MECH + "대상 목적지를 NotificationDestination.get_by_id_and_org(destination_id, self.current_org)(destinations.py:24)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " 조회에도 admin 권한이 필요하다(to_dict(all=True)로 비밀 옵션 포함). (POST·DELETE는 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); NotificationDestination.get_by_id_and_org(current_org)",
    params=[p("destination_id")], response_fields=["id", "name", "type", "options"])

add("GET", "/api/destinations", "List alert destinations",
    [BASE_CLS, block(DE, 80, 100, elide=[(84, 100)]), DEST_ALL, ORG_RESOLVE],
    "tenant_match", 0.85,
    [ev(DE, 81, 82), ev(M, 1432, 1433), ev(ORGRES, 16, 18)],
    "권한 데코레이터 없이 NotificationDestination.all(self.current_org)로 요청자의 현재 조직 목적지만 반환한다. 경로에 조직 ID 없음. 보충 규약 1에 따라 tenant_match(G1).",
    "login_required; NotificationDestination.all(current_org) 필터만",
    response_fields=["id", "name", "type", "icon"])

add("POST", "/api/destinations", "Create alert destination",
    [BASE_CLS, block(DE, 80, 80), block(DE, 102, 134, elide=[(107, 113), (123, 134)])] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(DE, 102, 103), ev(DE, 115, 121), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "생성되는 목적지의 org를 self.current_org로 강제한다(destinations.py:115-121; G1 '생성 시 자원 테넌트를 요청자 테넌트로 강제'; user=self.current_user는 작성자 기록)." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); NotificationDestination(org=current_org, user=current_user)",
    req_body=body(["name", "type", ("options", "object")], ["options", "name", "type"]), response_fields=["id", "name", "type", "options"])

# ============================================================================
# EVENTS
# ============================================================================
add("POST", "/api/events", "Record client events",
    [BASE_CLS, block(EV, 59, 63), RECORD_EVENT, APIKEY_LOADER],
    "manual_review_required", 0.75,
    [ev(EV, 60, 63), ev(BASE, 22), ev(BASE, 50, 54)],
    "login_required 외에 아무 검사가 없다. 임의 이벤트 목록을 record_event로 기록하며 요청자-객체 관계·역할 검사가 없다(사용자·조직 정보는 기록에 덧붙여질 뿐). 인증만 확인(객체 없음) → manual_review_required(G6, 프롬프트 보류 6).",
    "login_required only; record_event(current_org, current_user, event)",
    req_body={"required": True, "content": {"application/json": {"schema": {"type": "array", "items": {"type": "object"}}}}})

add("GET", "/api/events", "List organization events",
    [BASE_CLS, block(EV, 59, 59), block(EV, 65, 69)] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(EV, 65, 66), ev(EV, 69), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "결과를 self.current_org.events(events.py:69)로 요청자 현재 조직의 이벤트만 반환한다(current_org 목록 필터)." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); paginate(current_org.events)",
    params=[qp("page", "integer"), qp("page_size", "integer")], response_fields=["count", "page", "page_size", "results"])

# ============================================================================
# GROUPS
# ============================================================================
add("POST", "/api/groups", "Create group",
    [BASE_CLS, block(G, 9, 19)] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(G, 10, 11), ev(G, 13), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "생성되는 그룹의 org를 self.current_org로 강제한다(groups.py:13; G1 '생성 시 자원 테넌트를 요청자 테넌트로 강제')." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); Group(org=current_org)",
    req_body=body(["name"], ["name"]), response_fields=["id", "name", "permissions", "type"])

add("GET", "/api/groups", "List groups",
    [BASE_CLS, block(G, 9, 9), block(G, 21, 29)],
    "owner_or_admin", 0.5,
    [ev(G, 22, 25), ev(U, 64, 65)],
    "EXCLUDE 후보: 거부 조건이 없고 범위만 분기한다 — admin 권한이면 조직 전체 그룹, 아니면 요청자가 속한 그룹(group_ids)만 반환. 본인 구성원 그룹 목록 OR 관리자 전체 열람이라 owner_or_admin에 가장 가깝지만, "
    "목록 범위 분기를 접근 정책으로 볼지 경계가 있어 G8 제외 후보. 대안: owner_match(본인 목록) / manual.",
    "login_required; admin → Group.all(org) else Group.id in current_user.group_ids",
    response_fields=["id", "name", "permissions", "type"])

add("POST", "/api/groups/{group_id}", "Rename group",
    [BASE_CLS, block(G, 32, 45)] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(G, 33, 35), ev(P, 86, 87), ev(U, 173, 175), ev(MX, 22, 28)],
    ADMIN_MECH + "대상 그룹을 Group.get_by_id_and_org(group_id, self.current_org)(groups.py:35)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " 빌트인 그룹은 400. (DELETE /api/groups/{id}는 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); Group.get_by_id_and_org(current_org)",
    params=[p("group_id")], req_body=body(["name"], ["name"]), response_fields=["id", "name", "permissions", "type"])

add("GET", "/api/groups/{group_id}", "Get group",
    [BASE_CLS, block(G, 32, 32), block(G, 47, 55), MIXIN],
    "membership_required", 0.85,
    [ev(G, 48, 49), ev(G, 51), ev(U, 64, 65)],
    "요청이 대상 그룹(group_id)을 지정하고, int(group_id) in self.current_user.group_ids로 (요청자, 그룹) 구성원 관계를 확인한다. admin 권한은 우회. "
    "구성원 OR 관리자 우회이므로 membership_required(G2). 이후 현재 조직 필터(get_by_id_and_org) 동반.",
    "admin OR group_id in current_user.group_ids; Group.get_by_id_and_org(org)",
    params=[p("group_id")], response_fields=["id", "name", "permissions", "type"])

add("POST", "/api/groups/{group_id}/members", "Add group member",
    [BASE_CLS, block(G, 72, 89, elide=[(81, 88)])] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(G, 73, 74), ev(G, 76, 78), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 사용자와 그룹을 모두 get_by_id_and_org(..., self.current_org)(groups.py:76-77)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); User/Group.get_by_id_and_org(current_org)",
    params=[p("group_id")], req_body=body([("user_id", "integer")], ["user_id"]), response_fields=["id", "name", "email", "groups"])

add("GET", "/api/groups/{group_id}/members", "List group members",
    [BASE_CLS, block(G, 72, 72), block(G, 91, 97)] + RBAC_CHAIN + [GROUP_MEMBERS],
    "membership_required", 0.85,
    [ev(G, 91, 94), ev(U, 294, 295)],
    "@require_permission('list_users')(기능 권한) 뒤 int(group_id) in self.current_user.group_ids(구성원) OR admin이 결정한다. 대상 그룹 지정 + (요청자, 그룹) 구성원 확인이므로 membership_required(G2). "
    "참고: Group.members(group_id)는 조직 필터 없이 group_id로만 조회한다.",
    "@require_permission('list_users'); admin OR group_id in current_user.group_ids",
    params=[p("group_id")], response_fields=["id", "name", "email", "groups"])

add("DELETE", "/api/groups/{group_id}/members/{user_id}", "Remove group member",
    [BASE_CLS, block(G, 100, 114, elide=[(107, 114)])] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(G, 101, 104), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 사용자를 User.get_by_id_and_org(user_id, self.current_org)(groups.py:103)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " 그룹 id는 조직 검증 없이 group_ids에서 제거(구현 특이점, 검수 참고).",
    "@require_admin(조직 그룹 권한 'admin'); User.get_by_id_and_org(current_org).group_ids.remove(group_id)",
    params=[p("group_id"), p("user_id")])

add("POST", "/api/groups/{group_id}/data_sources", "Grant group access to data source",
    [BASE_CLS, block(G, 123, 142, elide=[(133, 142)])] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(G, 124, 128), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 데이터소스와 그룹을 모두 get_by_id_and_org(..., self.current_org)(groups.py:127-128)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " (GET 목록·POST/DELETE {data_source_id}는 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); DataSource/Group.get_by_id_and_org(current_org) → data_source.add_group(group)",
    params=[p("group_id")], req_body=body([("data_source_id", "integer")], ["data_source_id"]), response_fields=["id", "name", "type", "view_only"])

# ============================================================================
# OBJECT PERMISSIONS (ACL)
# ============================================================================
add("GET", "/api/{object_type}/{object_id}/acl", "List object ACL grants",
    [BASE_CLS, block(PM, 15, 22), block(PM, 25, 40, elide=[(32, 40)]), GET404] + OBJ_MODIFY_CHAIN,
    "manual_review_required", 0.85,
    [ev(PM, 28, 30), ev(P, 116, 118), ev(P, 112, 113)],
    OBJMOD_NOTE + " object_type은 queries|dashboards.",
    "model.get_by_id_and_org(org) → require_object_modify_permission(obj): owner OR admin OR ACL modify",
    params=[p("object_type", typ="string"), p("object_id")], response_fields=["view", "modify", "delete"])

add("POST", "/api/{object_type}/{object_id}/acl", "Grant object permission",
    [BASE_CLS, block(PM, 15, 22), block(PM, 25, 25), block(PM, 42, 73, elide=[(48, 73)]), GET404] + OWNER_ADMIN_CHAIN,
    "owner_or_admin", 0.9,
    [ev(PM, 44, 46), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE + " grantee는 현재 조직 사용자여야 한다.",
    "model.get_by_id_and_org(org) → require_admin_or_owner(obj.user_id); grantee User.get_by_id_and_org(org)",
    params=[p("object_type", typ="string"), p("object_id")], req_body=body(["access_type", ("user_id", "integer")], ["access_type", "user_id"]),
    response_fields=["id", "object_id", "object_type", "access_type", "grantor", "grantee"])

add("DELETE", "/api/{object_type}/{object_id}/acl", "Revoke object permission",
    [BASE_CLS, block(PM, 25, 25), block(PM, 75, 100, elide=[(81, 100)]), GET404] + OWNER_ADMIN_CHAIN,
    "owner_or_admin", 0.9,
    [ev(PM, 77, 79), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE,
    "model.get_by_id_and_org(org) → require_admin_or_owner(obj.user_id)",
    params=[p("object_type", typ="string"), p("object_id")], req_body=body([("user_id", "integer"), "access_type"], ["user_id", "access_type"]))

add("GET", "/api/{object_type}/{object_id}/acl/{access_type}", "Check my permission on object",
    [BASE_CLS, block(PM, 15, 22), block(PM, 103, 110), GET404, MIXIN, ACL_EXISTS, ORG_RESOLVE],
    "tenant_match", 0.7,
    [ev(PM, 105, 106), ev(PM, 108), ev(MX, 22, 28)],
    "대상 객체를 model.get_by_id_and_org(object_id, self.current_org)로만 조회하고 접근 거부 조건이 없다(AccessPermission.exists 결과는 응답 값이지 검사가 아니다). "
    + ORG_NOTE + " 보충 규약 1에 따라 tenant_match(G1). 조회 결과가 요청자 본인의 권한 여부라는 점에서 owner_match 해석도 가능해 confidence를 낮춘다.",
    "login_required; model.get_by_id_and_org(org)만; returns AccessPermission.exists(obj, access_type, current_user)",
    params=[p("object_type", typ="string"), p("object_id"), p("access_type", typ="string")], response_fields=["response"])

# ============================================================================
# QUERIES
# ============================================================================
add("GET", "/api/queries/recent", "Recent queries of current user",
    [BASE_CLS, block(Q, 98, 108, elide=[(101, 106)])] + [REQ_PERM, REQ_PERMS, Q_BY_USER],
    "owner_match", 0.85,
    [ev(Q, 99), ev(Q, 107), ev(M, 573, 574)],
    "Query.by_user(self.current_user)로 요청자 본인이 만든 쿼리만(Query.user == user) 조회한다. 대상이 본인으로 고정되므로 owner_match(G4). @require_permission('view_query')는 기능 권한.",
    "@require_permission('view_query'); Query.by_user(current_user)",
    response_fields=["id", "name", "query", "user", "updated_at"])

add("POST", "/api/queries", "Create query",
    [BASE_CLS, block(Q, 186, 249, elide=[(189, 220), (226, 249)]), block(Q, 169, 183)] + ACL_CHAIN + [REQ_PERM],
    "manual_review_required", 0.8,
    [ev(Q, 187), ev(Q, 222, 224), ev(P, 52, 54), ev(P, 40, 49)],
    "@require_permission('create_query') 뒤 대상 data source에 require_access(data_source, user, not_view_only)(그룹 ACL, 쓰기 레벨)와 드롭다운 쿼리 그룹 ACL을 요구한다. " + ACL_NOTE,
    "@require_permission('create_query'); require_access(data_source, not_view_only) + require_access_to_dropdown_queries",
    req_body=body([("data_source_id", "integer"), "query", "name", "description", ("schedule", "object"), ("options", "object")], ["data_source_id", "query"]),
    response_fields=["id", "name", "query", "data_source_id", "user_id", "is_draft", "api_key"])

add("GET", "/api/queries/my", "List my queries",
    [BASE_CLS, block(Q, 272, 311, elide=[(275, 284), (295, 311)])] + [REQ_PERM, Q_BY_USER],
    "owner_match", 0.85,
    [ev(Q, 273), ev(Q, 287, 293), ev(M, 573, 574)],
    "Query.by_user(self.current_user) / search_by_user로 요청자가 만든 쿼리만 조회한다. owner_match(G4). @require_permission('view_query')는 기능 권한.",
    "@require_permission('view_query'); Query.by_user(current_user)",
    params=PAGING, response_fields=["count", "page", "page_size", "results"])

add("POST", "/api/queries/{query_id}", "Update query",
    [BASE_CLS, block(Q, 314, 314), block(Q, 315, 374, elide=[(317, 329), (336, 374)]), GET404] + OBJ_MODIFY_CHAIN,
    "manual_review_required", 0.85,
    [ev(Q, 315), ev(Q, 330), ev(Q, 333), ev(P, 116, 118)],
    OBJMOD_NOTE + " 추가로 data_source_id 변경 시 require_access(not_view_only), 드롭다운 쿼리 ACL도 요구한다.",
    "@require_permission('edit_query') → require_object_modify_permission(query): owner OR admin OR ACL modify (+ data source ACL)",
    params=[p("query_id")], req_body=body([("data_source_id", "integer"), "query", "name", "description", ("schedule", "object"), ("options", "object"), ("version", "integer"), ("tags", "array")]),
    response_fields=["id", "name", "query", "data_source_id", "user_id", "version"])

add("GET", "/api/queries/{query_id}", "Get query",
    [BASE_CLS, block(Q, 314, 314), block(Q, 376, 397, elide=[(378, 384), (388, 397)]), GET404] + ACL_CHAIN + [HAS_ACCESS_OBJ],
    "manual_review_required", 0.85,
    [ev(Q, 376), ev(Q, 385, 386), ev(P, 17, 21), ev(P, 37, 43)],
    "현재 조직으로 조회한 쿼리에 require_access(q, user, view_only)를 적용한다. has_access는 쿼리 API 키 사용자면 obj.api_key 일치(또는 대시보드 공유 키), 아니면 data source 그룹 ACL로 분기한다. " + ACL_NOTE,
    "@require_permission('view_query'); Query.get_by_id_and_org(org) → require_access(q, view_only): api_key match | admin | group ACL",
    params=[p("query_id")], response_fields=["id", "name", "query", "data_source_id", "user_id", "visualizations", "can_edit", "api_key"])

add("DELETE", "/api/queries/{query_id}", "Archive query",
    [BASE_CLS, block(Q, 314, 314), block(Q, 400, 409, elide=[(401, 405)]), GET404] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.9,
    [ev(Q, 406, 407), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE + " (권한 데코레이터 없음, 현재 조직 필터 동반.)",
    "Query.get_by_id_and_org(org) → require_admin_or_owner(query.user_id)",
    params=[p("query_id")])

add("POST", "/api/queries/{query_id}/regenerate_api_key", "Regenerate query API key",
    [BASE_CLS, block(Q, 412, 429, elide=[(420, 429)]), GET404] + [REQ_PERM] + OWNER_ADMIN_CHAIN,
    "owner_or_admin", 0.85,
    [ev(Q, 413), ev(Q, 415, 416), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE + " @require_permission('edit_query')는 기능 권한으로 보고 판정을 바꾸지 않는다.",
    "@require_permission('edit_query'); Query.get_by_id_and_org(org) → require_admin_or_owner(query.user_id)",
    params=[p("query_id")], response_fields=["id", "name", "api_key"])

add("GET", "/api/queries/favorites", "List my favorite queries",
    [BASE_CLS, block(Q, 485, 531, elide=[(501, 531)]), Q_FAV],
    "owner_match", 0.8,
    [ev(Q, 497), ev(Q, 499), ev(M, 555)],
    "Query.favorites(self.current_user)가 Favorite.user_id == user.id로 요청자 본인의 즐겨찾기만 반환한다. 대상이 본인으로 고정되므로 owner_match(G4). 기본 범위 all_queries(그룹 ACL 가시성)는 추가 거부가 아니다.",
    "login_required; Query.favorites(current_user): Favorite.user_id == current_user.id",
    params=PAGING, response_fields=["count", "page", "page_size", "results"])

# ============================================================================
# QUERY RESULTS / JOBS
# ============================================================================
add("POST", "/api/query_results", "Execute ad-hoc query",
    [BASE_CLS, block(QR, 149, 194, elide=[(152, 163), (166, 177)]), REQ_PERM, HAS_ACCESS, HAS_ACCESS_OBJ, HAS_ACCESS_GROUPS],
    "manual_review_required", 0.85,
    [ev(QR, 150), ev(QR, 180), ev(QR, 184, 185), ev(P, 34, 49)],
    "@require_permission('execute_query') 뒤 본문 data_source_id의 데이터소스를 현재 조직으로 조회하고 has_access(data_source, user, not_view_only)(그룹 ACL, 쓰기 레벨)가 결정한다. " + ACL_NOTE,
    "@require_permission('execute_query'); DataSource.get_by_id_and_org(org); has_access(data_source, not_view_only) else 403",
    req_body=body(["query", ("max_age", "integer"), ("query_id", "integer"), ("parameters", "object"), ("data_source_id", "integer"), ("apply_auto_limit", "boolean")], ["query"]),
    response_fields=["job", "query_result"])

add("GET", "/api/queries/{query_id}/results", "Get latest query result",
    # 길이 3,000 유지용 추가 생략(2026-11-03): 298-324 docstring·주석·초기화·query_result_id 분기(이 경로는 query_id만 바인딩되어
    # 도달하지 않음), 335-338 API 키 사용자의 query_hash 불일치 404(캐시 신선도 검사, 접근 결정 아님). 인가 줄(326, 328-333, 339-340)은 유지.
    [BASE_CLS, block(QR, 226, 226), block(QR, 296, 400, elide=[(298, 324), (335, 338), (341, 400)]), REQ_ANY] + ACL_CHAIN + [HAS_ACCESS_OBJ],
    "manual_review_required", 0.85,
    [ev(QR, 296), ev(QR, 326), ev(QR, 335, 337), ev(QR, 340)],
    "view_query 또는 execute_query 권한 뒤, 쿼리를 현재 조직으로 조회하고 결과의 data source에 require_access(view_only)를 적용한다. 쿼리 API 키 사용자는 query_hash 일치도 필요. "
    "그룹 ACL(또는 API 키 일치)이 결정 조건이므로 " + ACL_NOTE + " (/api/query_results/{id}, results.{filetype} 변형과 POST 실행은 같은 조건이라 제외.)",
    "@require_any_of_permission(view_query|execute_query); Query.get_by_id_and_org(org); require_access(query_result.data_source, view_only)",
    params=[p("query_id")], response_fields=["query_result"])

add("GET", "/api/jobs/{job_id}", "Get query job status",
    [BASE_CLS, block(QR, 424, 430), APIKEY_LOADER, block(AUTH, 217, 225)],
    "manual_review_required", 0.8,
    [ev(QR, 425, 430), ev(BASE, 22)],
    "login_required 외에 검사가 없다. Job.fetch(job_id)로 임의 작업을 조회하며 요청자-작업 관계(실행자·조직)를 확인하지 않는다. 인증만 확인 → manual_review_required(G6, 프롬프트 보류 6). (DELETE 취소도 같은 조건이라 제외.)",
    "login_required only; Job.fetch(job_id)",
    params=[p("job_id", typ="string")], response_fields=["job"])

# ============================================================================
# QUERY SNIPPETS
# ============================================================================
add("GET", "/api/query_snippets/{snippet_id}", "Get query snippet",
    [BASE_CLS, block(QS, 13, 19), GET404, MIXIN, ORG_RESOLVE],
    "tenant_match", 0.9,
    [ev(QS, 14, 15), ev(MX, 22, 28), ev(ORGRES, 16, 18)],
    "권한 데코레이터·소유자 검사 없이 QuerySnippet.get_by_id_and_org(snippet_id, self.current_org)만 적용한다. " + ORG_NOTE + " 보충 규약 1에 따라 tenant_match(G1).",
    "login_required; QuerySnippet.get_by_id_and_org(org)만",
    params=[p("snippet_id")], response_fields=["id", "trigger", "description", "snippet", "user"])

add("POST", "/api/query_snippets/{snippet_id}", "Update query snippet",
    [BASE_CLS, block(QS, 13, 13), block(QS, 21, 31), GET404] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.9,
    [ev(QS, 24, 25), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE,
    "QuerySnippet.get_by_id_and_org(org) → require_admin_or_owner(snippet.user.id)",
    params=[p("snippet_id")], req_body=body(["trigger", "description", "snippet"]), response_fields=["id", "trigger", "description", "snippet"])

add("DELETE", "/api/query_snippets/{snippet_id}", "Delete query snippet",
    [BASE_CLS, block(QS, 13, 13), block(QS, 33, 45, elide=[(39, 45)]), GET404] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.9,
    [ev(QS, 34, 35), ev(P, 107, 109), ev(P, 94, 95)],
    OA_NOTE,
    "QuerySnippet.get_by_id_and_org(org) → require_admin_or_owner(snippet.user.id)",
    params=[p("snippet_id")])

add("POST", "/api/query_snippets", "Create query snippet",
    [BASE_CLS, block(QS, 48, 72, elide=[(64, 71)]), ORG_RESOLVE],
    "tenant_match", 0.5,
    [ev(QS, 53, 59), ev(ORGRES, 16, 18)],
    "EXCLUDE 후보: 권한 검사가 없고 생성 레코드의 user=self.current_user, org=self.current_org로 둘 다 요청자 값으로 강제된다. "
    "G1(생성 시 자원 테넌트를 요청자 테넌트로 강제 → tenant_match)과 G4(본인 명의 생성 → owner_match)가 동시에 해당해 두 label 사이 경계. 가장 가까운 값으로 tenant_match를 적되 검수자가 G8 판단.",
    "login_required; QuerySnippet(user=current_user, org=current_org) 생성",
    req_body=body(["trigger", "description", "snippet"], ["trigger", "description", "snippet"]), response_fields=["id", "trigger", "description", "snippet"])

add("GET", "/api/query_snippets", "List query snippets",
    [BASE_CLS, block(QS, 48, 48), block(QS, 74, 76), SNIP_ALL, ORG_RESOLVE],
    "tenant_match", 0.85,
    [ev(QS, 76), ev(M, 1503, 1504), ev(ORGRES, 16, 18)],
    "권한 데코레이터 없이 QuerySnippet.all(org=self.current_org)로 요청자 현재 조직의 스니펫 전체를 반환한다. 보충 규약 1에 따라 tenant_match(G1).",
    "login_required; QuerySnippet.all(org=current_org) 필터만",
    response_fields=["id", "trigger", "description", "snippet", "user"])

# ============================================================================
# SETTINGS
# ============================================================================
add("POST", "/api/settings/organization", "Update organization settings",
    [BASE_CLS, block(ST, 28, 66, elide=[(42, 50), (54, 66)])] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(ST, 35, 37), ev(ST, 39, 40), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "수정 대상이 self.current_org.settings(settings.py:39-40), 즉 요청자 현재 조직 자체로 고정된다(current_org 고정)." + ADMIN_TENANT_TAIL + " (GET은 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); current_org.set_setting(k, v)",
    req_body={"required": True, "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}},
    response_fields=["settings"])

# ============================================================================
# USERS
# ============================================================================
add("GET", "/api/users", "List users",
    # 길이 3,000 유지용 추가 생략(2026-11-03): get() 본문 99-125(page·page_size·그룹 이름 직렬화·q/disabled/pending 파싱)는 인가와 무관.
    # 인가 줄(97-98 데코레이터, 70-74 User.all(current_org), 126 get_users 호출)은 유지.
    [BASE_CLS, block(US, 67, 68), block(US, 70, 95, elide=[(76, 95)]), block(US, 97, 128, elide=[(99, 125)]), REQ_PERM, REQ_PERMS, USER_ALL, ORG_RESOLVE],
    "tenant_match", 0.75,
    [ev(US, 97, 98), ev(US, 71, 74), ev(U, 194, 195), ev(ORGRES, 16, 18)],
    "@require_permission('list_users')(기능 권한) 뒤 User.all(self.current_org)/all_disabled(current_org)로 요청자 현재 조직의 사용자만 반환한다. 경로에 조직 ID 없음. 보충 규약 1에 따라 tenant_match(G1). " + RBAC_NOTE +
    " 대안: RBAC를 결정으로 보면 role_required.",
    "@require_permission('list_users'); User.all(current_org) 필터",
    params=[qp("page", "integer"), qp("page_size", "integer"), qp("order"), qp("q"), qp("disabled"), qp("pending")],
    response_fields=["count", "page", "page_size", "results"])

add("POST", "/api/users", "Create (invite) user",
    [BASE_CLS, block(US, 67, 68), block(US, 130, 158, elide=[(135, 137), (147, 158)])] + ADMIN_CHAIN,
    "tenant_match", 0.75,
    [ev(US, 130, 131), ev(US, 139, 145), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "생성되는 사용자의 org를 self.current_org로, 그룹을 current_org.default_group으로 강제한다(users.py:139-145; G1 '생성 시 자원 테넌트를 요청자 테넌트로 강제')." + ADMIN_TENANT_TAIL,
    "@require_admin(조직 그룹 권한 'admin'); User(org=current_org, ...)",
    req_body=body(["name", "email"], ["name", "email"]), response_fields=["id", "name", "email", "groups", "invite_link"])

add("POST", "/api/users/{user_id}/reset_password", "Send password reset link (admin)",
    [BASE_CLS, block(US, 168, 176)] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(US, 169, 171), ev(P, 86, 87), ev(U, 173, 175), ev(MX, 22, 28)],
    ADMIN_MECH + "대상 사용자를 User.get_by_id_and_org(user_id, self.current_org)(users.py:171)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " (invite POST는 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); User.get_by_id_and_org(current_org)",
    params=[p("user_id")], response_fields=["reset_link"])

add("POST", "/api/users/{user_id}/regenerate_api_key", "Regenerate user API key",
    [BASE_CLS, block(US, 179, 192), IS_ADMIN_OR_OWNER, HAS_PERM_OR_OWNER, MIXIN],
    "owner_or_admin", 0.9,
    [ev(US, 181), ev(US, 184, 185), ev(P, 98, 99), ev(P, 94, 95)],
    "is_admin_or_owner(user_id): int(user_id) == current_user.id OR has_permission('admin'). 본인 OR 관리자 우회가 실제 조건이므로 owner_or_admin(G5). 대상 사용자는 현재 조직 필터.",
    "User.get_by_id_and_org(org); is_admin_or_owner(user_id) else 403",
    params=[p("user_id")], response_fields=["id", "name", "email", "api_key"])

add("GET", "/api/users/{user_id}", "Get user",
    [BASE_CLS, block(US, 195, 204), REQ_PERM_OR_OWNER, HAS_PERM_OR_OWNER, IS_ADMIN_OR_OWNER, GET404, MIXIN],
    "owner_or_admin", 0.5,
    [ev(US, 199, 200), ev(P, 102, 104), ev(P, 94, 95)],
    "EXCLUDE 후보: require_permission_or_owner('list_users', user_id) = 본인 OR 'list_users' 권한 보유자. 우회 조건이 관리자 역할이 아니라 기본 그룹에도 포함되는 기능 권한(list_users)이어서 "
    "owner_or_admin(G5)·role_required(G3) 어느 쪽도 정확히 맞지 않는 경계. 가장 가까운 owner_or_admin으로 두고 검수자가 G8 판단. api_key 노출은 is_admin_or_owner일 때만.",
    "require_permission_or_owner('list_users', user_id): self OR has_permission('list_users'); User.get_by_id_and_org(org)",
    params=[p("user_id")], response_fields=["id", "name", "email", "groups", "api_key"])

add("POST", "/api/users/{user_id}", "Update user",
    [BASE_CLS, block(US, 195, 196), block(US, 206, 274, elide=[(210, 223), (237, 274)])] + OWNER_ADMIN_CHAIN + [MIXIN],
    "owner_or_admin", 0.85,
    [ev(US, 206, 208), ev(US, 224, 226), ev(P, 107, 109), ev(P, 94, 95)],
    "require_admin_or_owner(user_id): 본인 OR admin. group_ids 변경은 추가로 admin만 가능하지만 접근 자체의 조건은 본인 OR 관리자이므로 owner_or_admin(G5). 대상 사용자는 현재 조직 필터.",
    "require_admin_or_owner(user_id); group_ids 변경은 admin만; User.get_by_id_and_org(org)",
    params=[p("user_id")], req_body=body(["email", "name", "password", "old_password", ("group_ids", "array")]),
    response_fields=["id", "name", "email", "groups", "api_key"])

add("DELETE", "/api/users/{user_id}", "Delete pending user",
    [BASE_CLS, block(US, 195, 196), block(US, 276, 296)] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(US, 276, 278), ev(US, 281, 282), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 사용자를 User.get_by_id_and_org(user_id, self.current_org)(users.py:278)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " 추가로 본인 삭제·활성 사용자 삭제는 403(제한이지 허용 조건이 아님).",
    "@require_admin(조직 그룹 권한 'admin'); User.get_by_id_and_org(current_org); self-delete and activated users rejected",
    params=[p("user_id")], response_fields=["id", "name", "email"])

add("POST", "/api/users/{user_id}/disable", "Disable user",
    [BASE_CLS, block(US, 299, 314)] + ADMIN_CHAIN + [MIXIN],
    "tenant_match", 0.8,
    [ev(US, 300, 302), ev(US, 305, 306), ev(P, 86, 87), ev(U, 173, 175)],
    ADMIN_MECH + "대상 사용자를 User.get_by_id_and_org(user_id, self.current_org)(users.py:302)로 요청자 현재 조직으로만 조회한다." + ADMIN_TENANT_TAIL + " 본인 비활성화는 403. (DELETE disable=enable은 같은 조건이라 제외.)",
    "@require_admin(조직 그룹 권한 'admin'); User.get_by_id_and_org(current_org).disable()",
    params=[p("user_id")], response_fields=["id", "name", "email", "is_disabled"])

# ============================================================================
# VISUALIZATIONS / WIDGETS
# ============================================================================
add("POST", "/api/visualizations", "Create visualization",
    [BASE_CLS, block(V, 12, 25), GET404, REQ_PERM] + OBJ_MODIFY_CHAIN,
    "manual_review_required", 0.85,
    [ev(V, 13), ev(V, 17, 18), ev(P, 116, 118), ev(P, 112, 113)],
    "본문 query_id의 쿼리를 현재 조직으로 조회한 뒤 require_object_modify_permission(query, user)가 결정한다. " + OBJMOD_NOTE + " (visualizations/{id} POST·DELETE는 같은 조건이라 제외.)",
    "@require_permission('edit_query'); Query.get_by_id_and_org(org) → require_object_modify_permission(query)",
    req_body=body([("query_id", "integer"), "type", "name", "description", ("options", "object")], ["query_id", "type", "name", "options"]),
    response_fields=["id", "type", "name", "description", "options"])

add("POST", "/api/widgets", "Add widget to dashboard",
    [BASE_CLS, block(W, 14, 47, elide=[(17, 27), (41, 47)]), REQ_PERM] + OBJ_MODIFY_CHAIN + [REQUIRE_ACCESS],
    "manual_review_required", 0.85,
    [ev(W, 15), ev(W, 29, 30), ev(W, 36, 37), ev(P, 112, 113)],
    "대시보드에 require_object_modify_permission(owner OR admin OR ACL modify) AND 시각화의 쿼리에 require_access(view_only)(그룹 ACL)를 요구한다. OR 결합과 외부 ACL의 AND라 보류(G6). (widgets/{id} POST·DELETE는 대시보드 object modify만 적용, 같은 계열이라 제외.)",
    "@require_permission('edit_dashboard'); require_object_modify_permission(dashboard) AND require_access(visualization.query_rel, view_only)",
    req_body=body([("dashboard_id", "integer"), ("visualization_id", "integer"), ("options", "object"), "text", ("width", "integer")], ["dashboard_id", "visualization_id", "options", "width"]),
    response_fields=["id", "width", "options", "dashboard_id", "text", "visualization"])

# ============================================================================
# AUTH / MISC (function-based routes)
# ============================================================================
add("GET", "/api/config", "Client configuration",
    [block(AU, 318, 320), block(BASE, 110, 111), ORG_RESOLVE],
    "public", 0.9,
    [ev(AU, 318, 320), ev(ORGRES, 16, 18)],
    "@routes.route만 있고 login_required·권한 데코레이터가 없다. 익명 요청자도 조직 slug와 client_config를 받는다. 조건 없는 익명 허용이 코드로 드러나므로 public(G7).",
    "no login_required; returns org_slug + client_config()",
    security=[], response_fields=["org_slug", "client_config"])

add("GET", "/api/session", "Current session user",
    [block(AU, 323, 345), APIKEY_LOADER, block(AUTH, 217, 225)],
    "owner_match", 0.8,
    [ev(AU, 323, 325), ev(AU, 326, 336)],
    "@login_required 뒤 current_user 본인의 id·email·groups·permissions만 반환한다. 처리 대상이 인증 사용자 본인으로 고정되므로 owner_match(G4). 대안: 객체 없는 인증 전용으로 보면 manual(G6).",
    "@login_required; returns current_user (self) profile",
    security=APIKEY_SEC, response_fields=["user", "messages", "org_slug", "client_config"])

add("GET", "/api/organization/status", "Organization object counters",
    [block(ORG, 9, 22), ORG_RESOLVE, USER_ALL],
    "tenant_match", 0.6,
    [ev(ORG, 9, 11), ev(ORG, 13), ev(ORG, 17, 19)],
    "@login_required만 있고 객체 ID가 없다. 집계는 User.all(current_org)·Dashboard.org == current_org 등 요청자 현재 조직으로 필터되고 일부(alerts·data_sources·queries)는 요청자 group_ids로도 좁힌다. "
    "현재 테넌트 필터가 유일한 범위 조건이라 tenant_match(G1)로 두되, 객체 없는 인증 전용(G6 manual) 해석도 가능해 confidence를 낮춘다.",
    "@login_required; counters filtered by current_org (and current_user.group_ids)",
    response_fields=["object_counters"])

add("GET", "/api/admin/queries/outdated", "Outdated scheduled queries (super admin)",
    [block(ADM, 13, 41, elide=[(17, 27), (28, 35)]), REQ_SUPER, REQ_PERM, REQ_PERMS, PERM_MIXIN],
    "role_required", 0.95,
    [ev(ADM, 13, 16), ev(P, 90, 91), ev(P, 68, 73)],
    "@require_super_admin = require_permission('super_admin')(permissions.py:90-91): 그룹 권한에 super_admin이 있어야 통과. 조직 횡단 시스템 상태 기능(handlers/admin.py)이고 current_org 필터·대상 객체가 없어 보충 규약 1(G1-b)대로 role_required(G3). (rq_status GET은 같은 조건이라 제외.)",
    "@require_super_admin @login_required",
    response_fields=["queries", "updated_at"])

add("GET", "/ping", "Health check",
    [block(HI, 11, 14)],
    "public", 0.95,
    [ev(HI, 11, 14)],
    "@routes.route만 있고 인증·권한 데코레이터가 없다(talisman force_https=False). 조건 없는 익명 허용이 코드로 드러나므로 public(G7). controller_text가 짧은 것은 핸들러 전체가 4줄이기 때문.",
    "no auth; returns 'PONG.'",
    security=[])

add("POST", "/login", "Password login",
    [block(AU, 176, 220, elide=[(179, 180), (207, 220)])],
    "public", 0.85,
    [ev(AU, 176, 178), ev(AU, 192, 198)],
    "login_required 없이 익명 요청이 email/password 폼으로 세션을 발급받는 로그인 엔드포인트. 조직 설정 auth_password_login_enabled가 꺼져 있으면 폼 로그인은 안내만 하지만 접근 자체는 누구나 가능하다. 익명 허용 로그인이므로 public(G7).",
    "no login_required; verifies email/password → login_user",
    req_body=form(["email", "password", "remember"], ["email", "password"]), security=[], params=[qp("next")])

add("POST", "/forgot", "Request password reset email",
    [block(AU, 145, 165)],
    "public", 0.75,
    [ev(AU, 145, 148), ev(AU, 152, 157)],
    "login_required 없이 익명 요청이 email로 비밀번호 재설정 메일을 요청한다. 조직 설정 auth_password_login_enabled가 꺼지면 404이지만 이는 기능 플래그이고 요청자 조건은 아니다. 익명 허용이 코드로 드러나 public(G7); 설정 의존이 있어 confidence를 낮춘다.",
    "no login_required; 404 if password login disabled; sends reset email",
    req_body=form(["email"], ["email"]), security=[])


# ============================================================================
# write + validate
# ============================================================================
LABELS = {"public", "role_required", "membership_required", "tenant_match", "owner_match", "owner_or_admin", "manual_review_required"}


def main():
    keys = Counter((r["method"], r["path"]) for r in records)
    dup = [k for k, c in keys.items() if c > 1]
    assert not dup, f"duplicate (method, path): {dup}"
    assert all(r["draft_label"] in LABELS for r in records), "bad label"
    n = len(records)
    assert 65 <= n <= 75, f"record count {n} outside 65-75"
    labels = Counter(r["draft_label"] for r in records)
    assert max(labels.values()) <= n * 0.5, f"a label exceeds 50%: {labels}"
    chain_by_label = Counter()
    block_by_label = Counter()
    for r in records:
        for e in r["evidence"]:
            assert e["text"].strip(), f"empty evidence {r['method']} {r['path']} {e['location']}"
        ct = r["controller_text"]
        assert len(ct) <= 3000, f"controller_text > 3000: {r['method']} {r['path']} ({len(ct)})"
        assert r["draft_reason"] and r["auth_summary"]
        if r["draft_reason"].startswith("EXCLUDE 후보"):
            assert r["draft_confidence"] <= 0.5, f"EXCLUDE 후보 confidence > 0.5: {r['path']}"
        # 그룹 권한 해석 블록 포함 규칙 검증: 체인 사용 <=> PERM_MIXIN·USER_PERMS 각 정확히 1회
        n_mixin = ct.count(PERM_MIXIN["text"])
        n_perms = ct.count(USER_PERMS["text"])
        uses = bool(CHAIN_RX.search(ct.replace(PERM_MIXIN["text"], "").replace(USER_PERMS["text"], "")))
        assert n_mixin == n_perms == (1 if uses else 0), f"perm-resolution rule violated: {r['method']} {r['path']} uses={uses} mixin={n_mixin} perms={n_perms}"
        if uses:
            i_p = max((ct.find(b["text"]) for b in [REQ_ADMIN, REQ_SUPER, REQ_PERM, REQ_ANY, REQ_PERMS, HAS_PERM_OR_OWNER, IS_ADMIN_OR_OWNER,
                                                     REQ_PERM_OR_OWNER, REQ_ADMIN_OR_OWNER, CAN_MODIFY, REQ_OBJ_MODIFY, REQUIRE_ACCESS,
                                                     HAS_ACCESS, HAS_ACCESS_OBJ, HAS_ACCESS_GROUPS] if b["text"] in ct), default=-1)
            assert i_p < ct.find(PERM_MIXIN["text"]) < ct.find(USER_PERMS["text"]), f"perm-resolution order: {r['method']} {r['path']}"
        chain_by_label[r["draft_label"]] += uses
        block_by_label[r["draft_label"]] += n_perms > 0
    assert chain_by_label == block_by_label, (chain_by_label, block_by_label)

    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    short = [(r["method"], r["path"], len(r["controller_text"])) for r in records if len(r["controller_text"]) < 500]
    longest = sorted(((len(r["controller_text"]), r["method"], r["path"]) for r in records), reverse=True)[:5]
    print(f"wrote {n} records -> {OUT}")
    print("labels:", dict(labels.most_common()))
    print("EXCLUDE 후보:", sum(1 for r in records if r["draft_reason"].startswith("EXCLUDE 후보")))
    print("perm chain uses / has User.permissions block (by label):",
          {L: f"{chain_by_label[L]}/{block_by_label[L]}" for L in labels}, "total", sum(chain_by_label.values()))
    print("controller_text < 500:", short)
    print("longest:", longest)
    print("min/max length:", min(len(r["controller_text"]) for r in records), max(len(r["controller_text"]) for r in records))


if __name__ == "__main__":
    main()
