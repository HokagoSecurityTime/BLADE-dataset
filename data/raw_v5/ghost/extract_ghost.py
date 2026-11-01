"""Static extractor for Ghost Admin API test_v5 candidates.

Usage: python -I extract_ghost.py <clone_root> <out_dir>
Reads the Ghost clone (read-only) and writes candidates.jsonl.
All quoted code is copied verbatim from the files by line range.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])
COMMIT = "5794cfd8daca61fd60cd8659acd6591ece3b7956"
TAG = "v6.73.0"
PREFIX = "/ghost/api/admin"

S = "ghost/core/server/"
R = S + "web/api/endpoints/admin/routes.js"
MW = S + "web/api/endpoints/admin/middleware.js"
PD = S + "services/permissions/permissions-data.ts"
CT = S + "services/permissions/can-this.js"
UP = S + "api/endpoints/utils/permissions.js"
PCX = S + "services/permissions/parse-context.js"
POST = S + "models/post.js"
AUTH = S + "models/relations/authors.js"
USER = S + "models/user.js"
ROLE = S + "models/role.js"
INV = S + "models/invite.js"
INTEG = S + "models/integration.js"
SESSMW = S + "auth/session/middleware.js"
FIX = S + "data/schema/fixtures/fixtures.json"
E = S + "api/endpoints/"

_cache = {}


def lines(f):
    if f not in _cache:
        _cache[f] = (ROOT / f).read_text(encoding="utf-8").splitlines()
    return _cache[f]


def seg(f, a, b):
    """1-based inclusive line range -> text."""
    ls = lines(f)
    assert 1 <= a <= b <= len(ls), (f, a, b, len(ls))
    return "\n".join(ls[a - 1 : b])


def ranges_text(f, ranges, gap="      ..."):
    """Concatenate several ranges of one file, inserting a gap marker between non-adjacent ranges."""
    parts = []
    prev_end = None
    for a, b in ranges:
        if prev_end is not None and a > prev_end + 1:
            parts.append(gap)
        parts.append(seg(f, a, b))
        prev_end = b
    return "\n".join(parts)


def find_block(f, key):
    ls = lines(f)
    pat = re.compile(r"^  (?:async )?" + re.escape(key) + r"\s*(?::|\()")
    start = None
    for i, l in enumerate(ls, 1):
        if pat.match(l):
            start = i
            break
    assert start, (f, key)
    for j in range(start + 1, len(ls) + 1):
        if re.match(r"^  \},?\s*$", ls[j - 1]):
            return start, j
    raise AssertionError((f, key, "no end"))


DROP_KEYS = ("headers", "validation", "options", "data", "response", "statusCode")


def trim_block(f, start, end, drop_query=False):
    ls = lines(f)[start - 1 : end]
    out = []
    i = 0
    while i < len(ls):
        l = ls[i]
        m = re.match(r"^    (\w+): [\[{]\s*$", l)
        if m and m.group(1) in DROP_KEYS:
            # skip until closing at indent 4
            j = i + 1
            while j < len(ls) and not re.match(r"^    [\]}],?\s*$", ls[j]):
                j += 1
            out.append("    ...")
            i = j + 1
            continue
        if re.match(r"^    (\w+): .*,\s*$", l) and re.match(r"^    (\w+)", l).group(1) in DROP_KEYS:
            i += 1
            continue
        if drop_query and re.match(r"^    (?:async )?query\(", l):
            j = i + 1
            while j < len(ls) and not re.match(r"^    \},?\s*$", ls[j]):
                j += 1
            out.append(l)
            out.append("      ...")
            out.append(ls[j] if j < len(ls) else "    },")
            i = j + 1
            continue
        out.append(l)
        i += 1
    collapsed = []
    for l in out:
        if l.strip() == "..." and collapsed and collapsed[-1].strip() == "...":
            continue
        collapsed.append(l)
    return "\n".join(collapsed)


def route_stmt(api_ref):
    ls = lines(R)
    idx = None
    for i, l in enumerate(ls, 1):
        if f"http(api.{api_ref})" in l:
            idx = i
            break
    assert idx, api_ref
    a = idx
    while not ls[a - 1].lstrip().startswith("router.") and not ls[a - 1].lstrip().startswith("appsRouter.") and not ls[a - 1].lstrip().startswith("metafieldsRouter."):
        a -= 1
    b = idx
    while not ls[b - 1].rstrip().endswith(");"):
        b += 1
    return a, b


def perm_lines(f, start, end):
    """Within a controller block, locate the permissions sub-block (for evidence)."""
    ls = lines(f)
    for i in range(start, end + 1):
        l = ls[i - 1]
        if re.match(r"^    (?:async )?permissions\s*[:(]", l):
            if re.match(r"^    permissions: (true|false|\w+),\s*$", l):
                return i, i
            for j in range(i + 1, end + 1):
                if re.match(r"^    \},?\s*$", ls[j - 1]):
                    return i, j
    raise AssertionError((f, start, end, "no permissions"))


# ---- permissions-data.ts parsing ----
def pd_entries(obj):
    ls = lines(PD)
    res = []
    cur = None
    cur_line = None
    for i, l in enumerate(ls, 1):
        if i < 65:
            continue
        m = re.match(r"^  ('?[\w -]+'?): \{\s*$", l)
        if m:
            cur, cur_line = m.group(1), i
            continue
        m2 = re.match(r"^    (\w+): ", l)
        if m2 and m2.group(1) == obj and cur:
            res.append((cur.strip("'"), cur_line, i, l))
    return res


def pd_def_line(obj):
    ls = lines(PD)
    for i in range(13, 58):
        if re.match(r"^  " + re.escape(obj) + r": \[", ls[i - 1]):
            return i
    raise AssertionError(obj)


def pd_text(obj, roles_filter=None):
    d = pd_def_line(obj)
    parts = [seg(PD, 13, 13), seg(PD, d, d), "  ...", seg(PD, 65, 65)]
    for role, hl, l, txt in pd_entries(obj):
        if roles_filter and role not in roles_filter:
            continue
        parts.append(seg(PD, hl, hl))
        parts.append(txt)
    parts.append("  ...")
    return "\n".join(parts)


def pd_roles(obj):
    return [r for r, _, _, _ in pd_entries(obj)]


def pd_locs(obj):
    d = pd_def_line(obj)
    locs = [{"file": PD, "start_line": d, "end_line": d}]
    for role, hl, l, txt in pd_entries(obj):
        locs.append({"file": PD, "start_line": l, "end_line": l})
    return locs


def fixture_role_doc(roles):
    """Quote fixture Role description entries for the given role names."""
    ls = lines(FIX)
    out = []
    for i in range(76, 119):
        l = ls[i - 1]
        m = re.match(r'^\s*"name": "([^"]+)",\s*$', l)
        if m and m.group(1) in roles:
            out.append(l.strip() + " " + ls[i].strip())
    return "\n".join(out)


MW_AUTH = (MW, 110, 118)
MW_URL = (MW, 126, 134)
MW_PUB = (MW, 141, 146)
CT_CORE = [(CT, 35, 40), (CT, 110, 121)]
UP_PUBLIC = [(UP, 94, 107)]
PCX_CORE = [(PCX, 8, 16), (PCX, 23, 32)]

SEC_AUTH = [{"adminApiKey": []}, {"sessionCookie": []}]
SEC_URL = [{"adminApiKeyUrl": []}]
SEC_SCHEMES = {
    "adminApiKey": {"type": "http", "scheme": "Ghost", "description": "Admin API key JWT (Authorization: Ghost <token>) for integrations or staff tokens"},
    "sessionCookie": {"type": "apiKey", "in": "cookie", "name": "ghost-admin-api-session"},
    "adminApiKeyUrl": {"type": "apiKey", "in": "query", "name": "key", "description": "Admin API key token passed in the URL (scheduler endpoints)"},
}


def oas_path(route):
    p = re.sub(r":(\w+)", r"{\1}", route)
    if not p.endswith("/"):
        p += "/"
    return PREFIX + p


def params(path):
    return [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in re.findall(r"\{(\w+)\}", path)]


records = []


def add(method, route, api_ref, ctrl_file, ctrl_key, *, obj=None, label, conf, reason, auth_summary,
        extra=(), evidence_extra=(), pre_ranges=(), drop_query=False, mw="auth", body_keys=None,
        summary=None, public_path=False, roles_doc=None, skip_ct=False, ctrl_ranges=None, response_fields=None,
        mw_text=True, pd_roles_filter=None):
    f = E + ctrl_file
    ra, rb = route_stmt(api_ref)
    pieces = [seg(R, ra, rb)]
    locs = [{"file": R, "start_line": ra, "end_line": rb}]
    if not mw_text:
        pass
    elif mw == "auth":
        pieces.append(seg(*MW_AUTH)); locs.append({"file": MW, "start_line": 110, "end_line": 118})
    elif mw == "url":
        pieces.append(seg(*MW_URL)); locs.append({"file": MW, "start_line": 126, "end_line": 134})
    elif mw == "pub":
        pieces.append(seg(*MW_PUB)); locs.append({"file": MW, "start_line": 141, "end_line": 146})
    for a, b in pre_ranges:
        pieces.append(seg(f, a, b)); locs.append({"file": f, "start_line": a, "end_line": b})
    bs, be = find_block(f, ctrl_key)
    if ctrl_ranges:
        pieces.append(ranges_text(f, ctrl_ranges))
        for a, b in ctrl_ranges:
            locs.append({"file": f, "start_line": a, "end_line": b})
    else:
        pieces.append(trim_block(f, bs, be, drop_query=drop_query))
        locs.append({"file": f, "start_line": bs, "end_line": be})
    evidence = []
    try:
        pa, pb = perm_lines(f, bs, be)
        evidence.append({"type": "code", "text": seg(f, pa, pb), "location": f"{f}:{pa}-{pb}"})
    except AssertionError:
        pass
    if obj:
        if not skip_ct:
            for _f, a, b in CT_CORE:
                pieces.append(seg(CT, a, b)); locs.append({"file": CT, "start_line": a, "end_line": b})
        pieces.append(pd_text(obj, pd_roles_filter))
        locs.extend(pd_locs(obj))
        for role, hl, l, txt in pd_entries(obj):
            evidence.append({"type": "code", "text": seg(PD, hl, hl) + "\n" + txt, "location": f"{PD}:{hl},{l}"})
    for ex in extra:
        ef, eranges = ex[0], ex[1]
        pieces.append(ranges_text(ef, eranges))
        for a, b in eranges:
            locs.append({"file": ef, "start_line": a, "end_line": b})
    for ef, a, b in evidence_extra:
        evidence.append({"type": "code", "text": seg(ef, a, b), "location": f"{ef}:{a}-{b}"})
    text = "\n\n".join(pieces)
    path = oas_path(route)
    sec = [] if mw == "none" or mw == "pub" else (SEC_URL if mw == "url" else SEC_AUTH)
    op = {
        "operationId": api_ref.replace(".", "_"),
        "summary": summary or f"{ctrl_key} {ctrl_file.rsplit('.', 1)[0]}",
        "description": "",
        "parameters": params(path),
        "responses": {"200": {"description": "OK"}},
        "security": sec,
    }
    if body_keys:
        op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": {k: {"type": "array"} for k in body_keys}}}}}
    perm_doc = fixture_role_doc(roles_doc) if roles_doc else (fixture_role_doc(pd_roles(obj)) if obj else "")
    rec = {
        "project": "ghost",
        "service": "Ghost",
        "repository": "https://github.com/TryGhost/Ghost",
        "commit": COMMIT,
        "tag": TAG,
        "license": "MIT",
        "method": method,
        "path": path,
        "oas_status": "generated",
        "oas_operation": op,
        "oas_global_security": [],
        "oas_security_schemes": SEC_SCHEMES,
        "response_schema_fields": response_fields or (body_keys or []),
        "controller_text": text,
        "source_locations": locs,
        "auth_summary": auth_summary,
        "permission_doc": perm_doc,
        "draft_label": label,
        "draft_confidence": conf,
        "evidence": evidence,
        "draft_reason": reason,
        "known_vulnerable": False,
        "advisory": None,
        "fix_commit": None,
    }
    records.append(rec)


# ---------------- model snippets ----------------
AUTH_EDIT = (AUTH, [(340, 340), (352, 352), (377, 391), (400, 421)])
AUTH_DESTROY = (AUTH, [(340, 340), (352, 352), (377, 379), (400, 402), (411, 421), (423, 424)])
AUTH_ADD = (AUTH, [(340, 340), (352, 352), (377, 379), (393, 398), (411, 421), (423, 424)])
POST_EDIT = (POST, [(1530, 1530), (1539, 1543), (1549, 1551), (1557, 1559), (1568, 1570), (1577, 1579)])
POST_DESTROY = (POST, [(1530, 1530), (1539, 1539), (1549, 1551), (1557, 1559), (1574, 1579)])
POST_ADD = (POST, [(1530, 1530), (1539, 1539), (1545, 1547), (1553, 1559), (1571, 1573), (1577, 1579)])
USER_EDIT = (USER, [(876, 876), (888, 888), (938, 949), (971, 973), (982, 990), (1074, 1082)])
USER_DESTROY = (USER, [(876, 876), (888, 888), (951, 969), (1074, 1082)])
ROLE_ASSIGN = (ROLE, [(47, 47), (74, 96), (98, 116)])
INV_ADD = (INV, [(56, 56), (65, 65), (79, 84), (92, 98), (110, 138)])
INTEG_PERM = (INTEG, [(96, 116)])

POSTS_PRE = [(24, 24), (52, 52)]
PAGES_PRE = [(16, 16), (26, 26)]
STAFF_ROLES = ["Administrator", "Admin Integration", "Super Editor", "Editor", "Author", "Contributor"]
STAFF_ROLES_EDIT = ["Administrator", "Admin Integration", "Editor", "Author", "Contributor"]
# tokenPermissionCheck: staff-token blocklist / integration allowlist head
MW_TOKEN = (MW, [(17, 21), (54, 56), (84, 101)])

# =============== owner_or_admin ===============
add("PUT", "/posts/:id", "posts.edit", "posts.js", "edit", obj="post", label="owner_or_admin", conf=0.85,
    pre_ranges=POSTS_PRE, drop_query=True, skip_ct=True, extra=[AUTH_EDIT, POST_EDIT], mw_text=False, pd_roles_filter=STAFF_ROLES_EDIT, body_keys=["posts"],
    evidence_extra=[(AUTH, 411, 421), (POST, 1568, 1579)],
    auth_summary="authAdminApi → canThis(context).edit.post(id, {status,authors,visibility}) → authors.permissible: Contributor/Author는 isCoAuthor()인 글만(저자 변경 불가), Editor/Super Editor/Administrator/Owner/Admin Integration은 역할 권한으로 모든 글; Post.permissible: Contributor는 draft만·status 변경 불가",
    reason="Contributor·Author는 자신이 공동 저자인 글만 수정할 수 있고(isCoAuthor), Editor 이상·Administrator·Owner는 post:edit 역할 권한으로 모든 글을 수정한다. 소유자 OR 상위 역할 우회 구조라 owner_or_admin.")
add("DELETE", "/posts/:id", "posts.destroy", "posts.js", "destroy", obj="post", label="owner_or_admin", conf=0.85,
    pre_ranges=POSTS_PRE, drop_query=True, skip_ct=True, extra=[AUTH_DESTROY, POST_DESTROY], mw_text=False, pd_roles_filter=STAFF_ROLES,
    evidence_extra=[(AUTH, 415, 416), (POST, 1574, 1579)],
    auth_summary="authAdminApi → canThis.destroy.post(id) → authors.permissible: Contributor/Author는 isPrimaryAuthor()인 글만(Contributor는 draft만), Editor 이상은 모든 글",
    reason="Contributor·Author는 자신이 1저자인 글만 삭제(Contributor는 draft만), Editor 이상·Administrator·Owner는 역할 권한으로 모든 글 삭제. 소유자 OR 상위 역할이므로 owner_or_admin.")
add("PUT", "/pages/:id", "pages.edit", "pages.js", "edit", obj="post", label="owner_or_admin", conf=0.85,
    pre_ranges=PAGES_PRE, drop_query=True, skip_ct=True, extra=[AUTH_EDIT, POST_EDIT], mw_text=False, pd_roles_filter=STAFF_ROLES_EDIT, body_keys=["pages"],
    evidence_extra=[(AUTH, 411, 421), (POST, 1568, 1579)],
    auth_summary="pages는 docName 'posts'로 권한 검사 → canThis.edit.post → authors.permissible/Post.permissible (posts edit와 동일)",
    reason="페이지는 posts와 같은 post 객체 권한으로 검사된다. Contributor·Author는 공동 저자인 페이지만, Editor 이상은 모든 페이지를 수정하므로 owner_or_admin.")
add("DELETE", "/pages/:id", "pages.destroy", "pages.js", "destroy", obj="post", label="owner_or_admin", conf=0.85,
    pre_ranges=PAGES_PRE, drop_query=True, skip_ct=True, extra=[AUTH_DESTROY, POST_DESTROY], mw_text=False, pd_roles_filter=STAFF_ROLES,
    evidence_extra=[(AUTH, 415, 416), (POST, 1574, 1579)],
    auth_summary="docName 'posts' → canThis.destroy.post → Contributor/Author는 1저자인 페이지만, Editor 이상 모든 페이지",
    reason="Contributor·Author는 자신이 1저자인 페이지만 삭제, Editor 이상은 모든 페이지 삭제. owner_or_admin.")
add("PUT", "/users/:id", "users.edit", "users.js", "edit", obj="user", label="owner_or_admin", conf=0.85,
    drop_query=True, extra=[USER_EDIT], body_keys=["users"], mw_text=False,
    evidence_extra=[(USER, 938, 949)],
    auth_summary="authAdminApi → canThis.edit.user(id, {status,roles}) → User.permissible: context.user === 대상 id면 허용(self), Owner 대상은 Owner만, Editor는 Author/Contributor 대상만, Administrator는 user:edit 역할 권한으로 모두",
    reason="본인(context.user === userModel.id)이면 역할과 무관하게 허용되고, 그 외는 Administrator(user:edit 권한)·Owner·Editor(하위 역할 대상)만 허용한다. 본인 OR 관리자 우회 구조라 owner_or_admin.")
add("PUT", "/users/password", "users.changePassword", "users.js", "changePassword", obj="user", label="owner_or_admin", conf=0.8,
    drop_query=True, extra=[USER_EDIT], body_keys=["password"], mw_text=False,
    evidence_extra=[(USER, 938, 949)],
    auth_summary="permissions: {docName:'user', method:'edit', identifier: body password[0].user_id} → User.permissible edit: 본인이면 허용, 아니면 Administrator/Owner/Editor(하위 역할 대상) 권한",
    reason="비밀번호 변경 대상 user_id에 대해 users edit와 같은 User.permissible이 적용된다. 본인이면 허용, 타인은 Administrator·Owner·Editor(하위 역할만)여야 하므로 owner_or_admin.")
add("POST", "/posts", "posts.add", "posts.js", "add", obj="post", label="owner_or_admin", conf=0.6,
    pre_ranges=POSTS_PRE, drop_query=True, skip_ct=True, extra=[AUTH_ADD, POST_ADD], mw_text=False, pd_roles_filter=STAFF_ROLES, body_keys=["posts"],
    evidence_extra=[(AUTH, 393, 398), (AUTH, 413, 414), (POST, 1571, 1573)],
    auth_summary="canThis.add.post(undefined, {status,authors,visibility}) → authors.permissible: Contributor/Author는 isOwner() 즉 요청 authors[0].id === context.user(본인 명의)일 때만, Editor 이상은 임의 저자 지정 가능; Contributor는 draft만",
    reason="Contributor·Author는 요청의 authors[0]이 본인일 때만 생성(본인 명의 생성), Editor 이상·Administrator는 역할 권한으로 다른 저자 명의도 가능하다. 본인 명의 OR 상위 역할이라 owner_or_admin으로 두되, 생성 요청이라 '소유자' 개념이 약해 role_required(모든 역할이 post:add 보유)로 볼 여지도 있다.")
add("POST", "/pages", "pages.add", "pages.js", "add", obj="post", label="owner_or_admin", conf=0.6,
    pre_ranges=PAGES_PRE, drop_query=True, skip_ct=True, extra=[AUTH_ADD, POST_ADD], mw_text=False, pd_roles_filter=STAFF_ROLES, body_keys=["pages"],
    evidence_extra=[(AUTH, 393, 398), (AUTH, 413, 414), (POST, 1571, 1573)],
    auth_summary="docName 'posts' → canThis.add.post → Contributor/Author는 본인 명의(authors[0].id === context.user)만, Editor 이상은 제한 없음",
    reason="posts add와 동일: Contributor·Author는 본인 명의로만 생성, Editor 이상은 제한 없음. owner_or_admin(대안 role_required).")
add("PUT", "/webhooks/:id", "webhooks.edit", "webhooks.js", "edit", obj="webhook", label="owner_or_admin", conf=0.5,
    body_keys=["webhooks"],
    auth_summary="permissions.before: integration 키 요청이면 webhook.integration_id === context.integration.id 필수; 그 다음 canThis.edit.webhook → webhook:edit 권한은 Administrator·Admin Integration만. 세션 Administrator는 모든 webhook",
    reason="Administrator 세션 사용자는 모든 webhook을 수정하지만, 통합(API 키) 요청은 자기 integration이 만든 webhook만 수정할 수 있다(소유 통합 OR 관리자). 소유자가 사용자가 아닌 integration이고 역할 권한 AND 소유 검사가 겹쳐 있어 manual_review_required로 볼 여지가 크다.")
add("DELETE", "/webhooks/:id", "webhooks.destroy", "webhooks.js", "destroy", obj="webhook", label="owner_or_admin", conf=0.5,
    auth_summary="permissions.before: integration 키면 webhook.integration_id 일치 필수; canThis.destroy.webhook → Administrator·Admin Integration",
    reason="webhooks edit와 동일 구조: Administrator 세션은 모든 webhook 삭제, integration 키는 자기 integration의 webhook만. owner_or_admin(소유 주체가 integration) 또는 manual_review_required.")

# =============== owner_match ===============
add("GET", "/users/:id/token", "users.readStaffToken", "users.js", "readStaffToken", label="owner_match", conf=0.9,
    pre_ranges=[(19, 32)], evidence_extra=[(E + "users.js", 19, 28)], response_fields=["apiKey"],
    auth_summary="permissions: permissionOnlySelf → getTargetId(frame)(id 'me'는 본인) !== frame.user.id면 NoPermissionError. 역할 우회 없음",
    reason="대상 id가 인증 사용자 본인(frame.user.id)과 같을 때만 허용하고 관리자 우회가 없다(permissionOnlySelf). owner_match.")
add("PUT", "/users/:id/token", "users.regenerateStaffToken", "users.js", "regenerateStaffToken", label="owner_match", conf=0.9,
    pre_ranges=[(19, 32)], evidence_extra=[(E + "users.js", 19, 28)], response_fields=["apiKey"],
    auth_summary="permissions: permissionOnlySelf → 본인 id만, 역할 우회 없음",
    reason="readStaffToken과 같은 permissionOnlySelf 검사로 본인 스태프 토큰만 재발급한다. owner_match.")
add("DELETE", "/session", "session.delete", "session.js", "delete", label="owner_match", conf=0.6,
    extra=[(SESSMW, [(32, 43)])], evidence_extra=[(E + "session.js", 74, 78), (SESSMW, 32, 35)],
    auth_summary="authAdminApi(세션 인증) → auth.session.logout → sessionService.removeUserForSession(req) 현재 요청의 세션만 제거. 대상 객체는 요청자 본인 세션으로 고정",
    reason="처리 대상이 요청자의 현재 세션으로 고정된 로그아웃이다(타인 세션 지정 불가). 본인 고정이라 owner_match으로 두지만, 객체 지정 없는 인증 전용 동작으로 보면 manual_review_required.")

# =============== public ===============
add("GET", "/site", "site.read", "site.js", "read", label="public", conf=0.95, mw="pub",
    extra=[UP_PUBLIC and (UP, [(94, 107)])], evidence_extra=[(E + "site.js", 11, 11), (MW, 141, 146)], response_fields=["site"],
    auth_summary="mw.publicAdminApi(인증 미들웨어 없음) + permissions: false → 누구나",
    reason="라우트에 인증 미들웨어가 없고(publicAdminApi) 컨트롤러도 permissions: false로 권한 검사를 생략한다. 익명 허용이 코드로 드러나므로 public.")
add("POST", "/session", "session.add", "session.js", "add", label="public", conf=0.9, mw="none", body_keys=["username", "password"],
    evidence_extra=[(R, 443, 449)],
    auth_summary="라우트 주석 'We don't need auth when creating a new session (logging in)'; brute 제한만. 자격증명 검사 후 세션 생성",
    reason="로그인 엔드포인트로 인증 미들웨어 없이 익명 요청을 받는다(brute-force 제한만). 명시적 익명 허용이므로 public.")
add("GET", "/authentication/setup", "authentication.isSetup", "authentication.js", "isSetup", label="public", conf=0.9, mw="none",
    evidence_extra=[(E + "authentication.js", 124, 124), (R, 478, 478)], response_fields=["setup"], extra=[(PCX, [(8, 16), (23, 32)])],
    auth_summary="인증 미들웨어 없음 + permissions: false → 설정 완료 여부 조회를 누구나",
    reason="인증 미들웨어가 없고 permissions: false다. 설정 완료 여부만 반환하는 익명 조회라 public.")
add("POST", "/authentication/password_reset", "authentication.generateResetToken", "authentication.js", "generateResetToken", label="public", conf=0.85, mw="none",
    body_keys=["password_reset"], extra=[(UP, [(94, 107)]), (PCX, [(8, 16), (23, 32)])],
    evidence_extra=[(R, 462, 467), (UP, 100, 104), (PCX, 15, 15)],
    auth_summary="인증 미들웨어 없음(brute 제한만). permissions: true지만 user/api_key 없는 context는 parseContext에서 public=true → permissions.handle의 public pass-through",
    reason="비밀번호 재설정 메일 요청은 인증 없이 받는다. permissions: true여도 익명 context는 public=true로 통과하므로 익명 허용이 코드로 확인된다. public.")
add("PUT", "/authentication/password_reset", "authentication.resetPassword", "authentication.js", "resetPassword", label="public", conf=0.8, mw="none",
    body_keys=["password_reset"], evidence_extra=[(E + "authentication.js", 173, 173), (R, 468, 473)],
    auth_summary="인증 미들웨어 없음(initSession만) + permissions: false. 본문의 재설정 토큰으로 사용자 확인",
    reason="인증 없이 재설정 토큰(본문)으로 비밀번호를 바꾼다. 세션 인증이 필요 없고 permissions: false라 익명 허용이 명시적이다. 토큰 자체가 자격증명이라는 점에서 보류 여지가 있으나 public.")
add("GET", "/authentication/invitation", "authentication.isInvitation", "authentication.js", "isInvitation", label="public", conf=0.85, mw="none",
    evidence_extra=[(E + "authentication.js", 230, 230), (R, 475, 475)], response_fields=["invitation"], extra=[(PCX, [(8, 16), (23, 32)])],
    auth_summary="인증 미들웨어 없음 + permissions: false → 이메일로 초대 존재 여부 조회",
    reason="인증 없이 이메일 쿼리로 초대 존재 여부를 조회한다. permissions: false. public.")
add("POST", "/authentication/invitation", "authentication.acceptInvitation", "authentication.js", "acceptInvitation", label="public", conf=0.7, mw="none",
    body_keys=["invitation"], evidence_extra=[(E + "authentication.js", 215, 215), (R, 474, 474)], extra=[(PCX, [(8, 16), (23, 32)])],
    auth_summary="인증 미들웨어 없음 + permissions: false → 본문 초대 토큰으로 계정 생성",
    reason="초대 수락은 인증 없이 본문 토큰으로 처리된다(permissions: false). 익명 허용이 명시적이라 public이나, 초대 토큰이 자격증명 역할을 하므로 검수에서 manual 판단 가능.")
add("POST", "/authentication/setup", "authentication.setup", "authentication.js", "setup", label="public", conf=0.5, mw="none",
    body_keys=["setup"], evidence_extra=[(E + "authentication.js", 36, 36), (E + "authentication.js", 44, 47)],
    auth_summary="인증 미들웨어 없음 + permissions: false. assertSetupCompleted(false)로 설정 미완료 상태에서만 동작",
    reason="최초 설정은 익명으로 허용되지만 사이트가 아직 설정되지 않았을 때만 동작한다(assertSetupCompleted(false)). 요청자 조건은 없으나 사이트 상태 조건부라 public 0.5, 대안 manual_review_required.")

# =============== manual_review_required (auth only / permission held by every role) ===============
add("GET", "/posts", "posts.browse", "posts.js", "browse", obj="post", label="manual_review_required", conf=0.6,
    pre_ranges=POSTS_PRE, drop_query=True, response_fields=["posts"],
    auth_summary="canThis.browse.post → post:browse 권한을 Administrator·Editor·Author·Contributor·모든 통합이 보유. 서버에 본인 글 필터 없음(authors.permissible은 edit/add/destroy만 제한)",
    reason="post:browse는 Contributor를 포함한 모든 스태프 역할과 통합 키가 보유하고, 서버에서 본인 글로 제한하는 필터가 없다. 인증된 스태프면 누구나 가능해 특정 역할 조건이 아니므로 manual_review_required(인증 전용). 대안 role_required.")
add("GET", "/posts/:id", "posts.read", "posts.js", "read", obj="post", label="manual_review_required", conf=0.6,
    pre_ranges=POSTS_PRE, drop_query=True, extra=[(AUTH, [(419, 421)])], response_fields=["posts"],
    auth_summary="canThis.read.post(id) → post:read는 모든 역할 보유; authors.permissible else 분기 hasUserPermission || isPrimaryAuthor()로 역할 권한이 이미 true",
    reason="post:read 권한을 모든 역할이 가져 사실상 인증만 조건이다. 1저자 우회 분기가 있으나 역할 권한이 이미 참이라 결정 조건이 아니다. manual_review_required(인증 전용), 대안 role_required.")
add("GET", "/users", "users.browse", "users.js", "browse", obj="user", label="manual_review_required", conf=0.6, response_fields=["users"],
    auth_summary="canThis.browse.user → user:browse를 모든 역할(Contributor 포함)·Admin Integration·Editor가 보유",
    reason="user:browse 권한을 모든 스태프 역할이 보유해 인증 외 추가 조건이 없다. manual_review_required(인증 전용).")
add("GET", "/config", "config.read", "config.js", "read", label="manual_review_required", conf=0.7, response_fields=["config"],
    evidence_extra=[(E + "config.js", 11, 11)], extra=[MW_TOKEN],
    auth_summary="authAdminApi 인증 필수, permissions: false → 인가 검사 없음",
    reason="인증(세션 또는 Admin API 키)은 필요하지만 permissions: false로 인가 검사가 없다. 인증만 확인하므로 manual_review_required.")
add("POST", "/images/upload", "images.upload", "images.js", "upload", label="manual_review_required", conf=0.7, response_fields=["images"],
    evidence_extra=[(E + "images.js", 17, 17)], extra=[MW_TOKEN], mw_text=False, drop_query=True,
    auth_summary="authAdminApi 인증 필수, permissions: false. tokenPermissionCheck 허용목록 images: ['POST']",
    reason="인증은 필요하나 permissions: false로 역할·객체 조건이 없다. 인증만 확인하므로 manual_review_required.")
add("GET", "/slugs/:type/:name", "slugs.generate", "slugs.js", "generate", obj="slug", label="manual_review_required", conf=0.6, response_fields=["slugs"],
    auth_summary="canThis.generate.slug → slug: 'all'을 모든 역할이 보유",
    reason="slug:generate 권한을 Contributor까지 모든 역할이 가진다. 인증만이 실질 조건이므로 manual_review_required.")
add("GET", "/roles/", "roles.browse", "roles.js", "browse", obj="role", label="manual_review_required", conf=0.6, response_fields=["roles"],
    auth_summary="canThis.browse.role → role:browse를 모든 역할이 보유. ?permissions=assign이면 Role.findAll이 호출자가 할당 가능한 역할로 필터",
    reason="role:browse를 모든 역할이 보유해 인증만이 조건이고, 쿼리 모드(permissions=assign)에 따라 결과 정책이 달라진다. manual_review_required.")
add("GET", "/tags", "tags.browse", "tags.js", "browse", obj="tag", label="manual_review_required", conf=0.6, response_fields=["tags"],
    auth_summary="canThis.browse.tag → tag:browse를 모든 역할(Contributor 포함)이 보유",
    reason="tag:browse를 모든 스태프 역할이 보유해 인증 외 조건이 없다. manual_review_required(인증 전용).")

# =============== role_required ===============
add("POST", "/posts/:id/copy", "posts.copy", "posts.js", "copy", obj="post", label="role_required", conf=0.7,
    pre_ranges=POSTS_PRE, skip_ct=True, extra=[AUTH_ADD], evidence_extra=[(AUTH, 393, 398), (AUTH, 413, 414)], response_fields=["posts"],
    auth_summary="permissions: {method:'add'} (unsafeAttrs 없음) → authors.permissible add 분기: Contributor/Author는 isOwner()가 unsafeAttrs.authors 부재로 false → 거부. Editor/Super Editor/Administrator/Owner/Admin Integration만 허용",
    reason="복제는 add 권한으로 검사되는데 unsafeAttrs가 없어 Contributor·Author의 isOwner()가 항상 false가 된다. 결과적으로 Editor 이상 역할만 가능하므로 role_required.")
add("DELETE", "/posts", "posts.bulkDestroy", "posts.js", "bulkDestroy", obj="post", label="role_required", conf=0.7,
    pre_ranges=POSTS_PRE, skip_ct=True, extra=[AUTH_DESTROY], evidence_extra=[(AUTH, 415, 416)], mw_text=False,
    auth_summary="permissions: {method:'destroy'} id 없음 → authors.permissible: Contributor/Author는 Boolean(postModel) && isPrimaryAuthor()가 false → 거부. Editor 이상만 필터 기반 일괄 삭제",
    reason="일괄 삭제는 대상 모델 없이 destroy 권한을 검사해 Contributor·Author 분기가 false가 되고 Editor 이상 역할만 허용된다. role_required.")
add("POST", "/pages/:id/copy", "pages.copy", "pages.js", "copy", obj="post", label="role_required", conf=0.7,
    pre_ranges=PAGES_PRE, skip_ct=True, extra=[AUTH_ADD], evidence_extra=[(AUTH, 393, 398), (AUTH, 413, 414)], response_fields=["pages"],
    auth_summary="docName 'posts', method 'add', unsafeAttrs 없음 → Contributor/Author 거부, Editor 이상 허용",
    reason="posts copy와 동일: Contributor·Author는 isOwner()가 false가 되어 거부되고 Editor 이상만 허용. role_required.")
add("DELETE", "/users/:id", "users.destroy", "users.js", "destroy", obj="user", label="role_required", conf=0.55,
    extra=[USER_DESTROY], evidence_extra=[(USER, 951, 969)],
    auth_summary="canThis.destroy.user(id) → user:destroy 권한은 Administrator·Editor·Super Editor·Admin Integration. User.permissible: Owner는 삭제 불가, Editor는 본인 또는 Author/Contributor만. Author/Contributor는 권한 없음(본인 삭제도 불가)",
    reason="삭제는 user:destroy 역할 권한이 있어야 하며(Administrator·Editor), Editor는 본인 또는 하위 역할로 제한된다. Author·Contributor는 본인도 삭제하지 못해 일반적 소유자 경로가 없으므로 role_required로 두되, Editor의 본인 경로 때문에 owner_or_admin 판단 가능.")
add("PUT", "/users/owner", "users.transferOwnership", "users.js", "transferOwnership", obj="role", label="role_required", conf=0.9,
    extra=[ROLE_ASSIGN], evidence_extra=[(E + "users.js", 244, 247), (ROLE, 76, 96)], body_keys=["owner"], mw_text=False,
    roles_doc=["Owner"],
    auth_summary="permissions(frame): canThis.assign.role(Owner role) → Role.permissible assign: isOwner만 'Owner'를 checkAgainst에 포함, API 키는 Owner 할당 불가. 스태프 토큰은 tokenPermissionCheck에서 차단",
    reason="Owner 역할 할당 권한은 Role.permissible에서 Owner 역할 보유자에게만 주어진다. 특정 역할(Owner)만 가능하므로 role_required.")
add("PUT", "/authentication/setup", "authentication.updateSetup", "authentication.js", "updateSetup", label="role_required", conf=0.85,
    body_keys=["setup"], drop_query=True, evidence_extra=[(E + "authentication.js", 95, 100)], roles_doc=["Owner"],
    auth_summary="permissions(frame): Owner 역할 사용자 조회 후 owner.id !== context.user면 NoPermissionError",
    reason="요청자가 Owner 역할 사용자와 같아야만 허용한다. Owner 역할 보유가 결정 조건이라 role_required.")
add("POST", "/authentication/reset", "authentication.reset", "authentication.js", "reset", obj="authentication", label="role_required", conf=0.85,
    drop_query=True, evidence_extra=[(MW, 32, 44)],
    auth_summary="canThis.reset.authentication → authentication: ['reset']은 Administrator만(Owner는 canThis 우회). 스태프 토큰은 tokenPermissionCheck에서 차단, 통합 키 허용목록에 없음",
    reason="authentication:reset 권한은 Administrator 역할만 보유한다(Owner는 전역 우회). role_required.")
add("GET", "/members", "members.browse", "members.js", "browse", obj="member", label="role_required", conf=0.85, response_fields=["members"],
    auth_summary="canThis.browse.member → member:browse는 Administrator·Super Editor·Admin Integration·DB Backup Integration. Editor/Author/Contributor 없음",
    reason="member:browse 권한은 Administrator·Super Editor와 일부 통합 역할만 가진다. 역할 보유가 조건이므로 role_required.")
add("POST", "/members", "members.add", "members.js", "add", obj="member", label="role_required", conf=0.85, body_keys=["members"], drop_query=True,
    auth_summary="canThis.add.member → Administrator·Super Editor·Admin Integration·Self-Serve Migration Integration",
    reason="member:add 권한은 Administrator·Super Editor·일부 통합 역할만 보유. role_required.")
add("PUT", "/members/:id", "members.edit", "members.js", "edit", obj="member", label="role_required", conf=0.85, body_keys=["members"],
    auth_summary="canThis.edit.member(id) → Administrator·Super Editor·Admin Integration. 객체 소유 검사 없음(Member 모델에 permissible 없음)",
    reason="member:edit 권한은 Administrator·Super Editor·Admin Integration만 보유하고 객체 단위 검사는 없다. role_required.")
add("DELETE", "/members/:id", "members.destroy", "members.js", "destroy", obj="member", label="role_required", conf=0.85,
    auth_summary="canThis.destroy.member(id) → Administrator·Super Editor·Admin Integration",
    reason="member:destroy 권한은 Administrator·Super Editor·Admin Integration만 보유. role_required.")
add("POST", "/tags", "tags.add", "tags.js", "add", obj="tag", label="role_required", conf=0.8, body_keys=["tags"],
    auth_summary="canThis.add.tag → tag:add는 Administrator·Editor·Super Editor·Author·Admin Integration. Contributor는 browse/read만",
    reason="tag:add 권한은 Author 이상 역할이 보유하고 Contributor는 없다. 역할 보유가 조건이라 role_required.")
add("PUT", "/tags/:id", "tags.edit", "tags.js", "edit", obj="tag", label="role_required", conf=0.85, body_keys=["tags"], drop_query=True,
    auth_summary="canThis.edit.tag(id) → tag:edit는 Administrator·Editor·Super Editor·Admin Integration. Author/Contributor 없음. 소유 검사 없음",
    reason="tag:edit 권한은 Editor 이상 역할만 보유하고 객체 소유 검사가 없다. role_required.")
add("DELETE", "/tags/:id", "tags.destroy", "tags.js", "destroy", obj="tag", label="role_required", conf=0.85,
    auth_summary="canThis.destroy.tag(id) → Editor 이상·Admin Integration",
    reason="tag:destroy 권한은 Editor 이상 역할만 보유. role_required.")
add("PUT", "/labels/:id", "labels.edit", "labels.js", "edit", obj="label", label="role_required", conf=0.85, body_keys=["labels"], drop_query=True,
    auth_summary="canThis.edit.label(id) → label:edit는 Administrator·Super Editor·Admin Integration. Editor/Author는 browse/read만",
    reason="label:edit 권한은 Administrator·Super Editor·Admin Integration만 보유. role_required.")
add("DELETE", "/labels/:id", "labels.destroy", "labels.js", "destroy", obj="label", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.destroy.label(id) → Administrator·Super Editor·Admin Integration",
    reason="label:destroy 권한은 Administrator·Super Editor·Admin Integration만 보유. role_required.")
add("PUT", "/settings", "settings.edit", "settings.js", "edit", obj="setting", label="role_required", conf=0.85, body_keys=["settings"], drop_query=True,
    auth_summary="canThis.edit.setting(undefined, labs 항목) → setting:edit는 Administrator·Admin Integration만. Editor/Author/Contributor는 browse/read. Settings 모델에 permissible 없음",
    reason="setting:edit 권한은 Administrator(및 Admin Integration)만 보유한다. role_required.")
add("POST", "/tiers", "tiers.add", "tiers.js", "add", obj="product", label="role_required", conf=0.85, body_keys=["tiers"],
    auth_summary="permissions docName 'products' → canThis.add.product → product:add는 Administrator·Admin Integration",
    reason="product(tier):add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("PUT", "/tiers/:id", "tiers.edit", "tiers.js", "edit", obj="product", label="role_required", conf=0.85, body_keys=["tiers"],
    auth_summary="canThis.edit.product(id) → Administrator·Admin Integration",
    reason="product(tier):edit 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/newsletters", "newsletters.add", "newsletters.js", "add", obj="newsletter", label="role_required", conf=0.85, body_keys=["newsletters"], drop_query=True,
    auth_summary="canThis.add.newsletter → newsletter:add는 Administrator·Admin Integration. Editor/Author는 browse/read만",
    reason="newsletter:add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/webhooks", "webhooks.add", "webhooks.js", "add", obj="webhook", label="role_required", conf=0.85, body_keys=["webhooks"],
    auth_summary="canThis.add.webhook → webhook:add는 Administrator·Admin Integration만",
    reason="webhook:add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/integrations", "integrations.add", "integrations.js", "add", obj="integration", label="role_required", conf=0.85, body_keys=["integrations"], drop_query=True,
    extra=[INTEG_PERM],
    auth_summary="canThis.add.integration → integration:add는 Administrator만(Admin Integration 역할에는 integration 권한 없음). Integration.permissible은 limit 검사 후 역할 플래그만 확인",
    reason="integration:add 권한은 Administrator 역할만 보유하고 Integration.permissible도 역할 플래그만 확인한다. role_required.")
add("DELETE", "/integrations/:id", "integrations.destroy", "integrations.js", "destroy", obj="integration", label="role_required", conf=0.85,
    extra=[INTEG_PERM],
    auth_summary="canThis.destroy.integration(id) → Administrator만",
    reason="integration:destroy 권한은 Administrator 역할만 보유. role_required.")
add("POST", "/invites", "invites.add", "invites.js", "add", obj="invite", label="role_required", conf=0.8, body_keys=["invites"], drop_query=True,
    pre_ranges=[(8, 8)], extra=[INV_ADD], evidence_extra=[(INV, 110, 126)], mw_text=False,
    auth_summary="canThis.add.invite(undefined, {role_id}) → invite:add는 Administrator·Editor·Super Editor·Admin Integration. Invite.permissible: Owner/Admin은 Administrator~Contributor 초대, Editor는 Author/Contributor만, Owner 초대 불가",
    reason="초대는 invite:add 역할 권한(Administrator·Editor 계열)이 있어야 하고 초대 가능한 역할이 요청자 역할에 따라 제한된다. 역할이 결정 조건이라 role_required.")
add("DELETE", "/invites/:id", "invites.destroy", "invites.js", "destroy", obj="invite", label="role_required", conf=0.85,
    extra=[(INV, [(56, 77)])],
    auth_summary="canThis.destroy.invite(id) → invite:destroy는 Administrator·Editor·Super Editor·Admin Integration. Invite.permissible은 add 외 역할 플래그만 확인",
    reason="invite:destroy 권한은 Administrator·Editor 계열 역할만 보유하고 객체 소유 검사가 없다. role_required.")
add("PUT", "/themes/:name/activate", "themes.activate", "themes.js", "activate", obj="theme", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.activate.theme → theme:activate는 Administrator·Admin Integration. Editor/Author는 browse/readActive만",
    reason="theme:activate 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/themes/upload", "themes.upload", "themes.js", "upload", obj="theme", label="role_required", conf=0.85, drop_query=True,
    auth_summary="permissions: {method:'add'} → canThis.add.theme → Administrator·Admin Integration",
    reason="theme:add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("DELETE", "/themes/:name", "themes.destroy", "themes.js", "destroy", obj="theme", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.destroy.theme → Administrator·Admin Integration",
    reason="theme:destroy 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/redirects/upload", "redirects.upload", "redirects.js", "upload", obj="redirect", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.upload.redirect → redirect: 'all'은 Administrator·Admin Integration만",
    reason="redirect:upload 권한은 Administrator·Admin Integration만 보유. role_required.")
add("GET", "/db", "db.exportContent", "db.js", "exportContent", obj="db", label="role_required", conf=0.85, drop_query=True, response_fields=["db"],
    auth_summary="canThis.exportContent.db → db: 'all'은 Administrator·DB Backup Integration만",
    reason="db:exportContent 권한은 Administrator와 DB Backup Integration 역할만 보유. role_required.")
add("DELETE", "/db", "db.deleteAllContent", "db.js", "deleteAllContent", obj="db", label="role_required", conf=0.85, drop_query=True,
    evidence_extra=[(MW, 31, 44)],
    auth_summary="canThis.deleteAllContent.db → Administrator·DB Backup Integration. 스태프 토큰은 tokenPermissionCheck에서 차단, 통합 허용목록 db: ['GET','POST']라 통합 키 DELETE 불가",
    reason="db:deleteAllContent 권한은 Administrator(및 DB Backup 역할)만 보유하고 통합 키·스태프 토큰은 미들웨어에서 차단된다. role_required.")
add("POST", "/notifications", "notifications.add", "notifications.js", "add", obj="notification", label="role_required", conf=0.85, body_keys=["notifications"], drop_query=True,
    auth_summary="canThis.add.notification → notification:add는 Administrator·Admin Integration. Editor는 browse/destroy만",
    reason="notification:add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("POST", "/snippets", "snippets.add", "snippets.js", "add", obj="snippet", label="role_required", conf=0.85, body_keys=["snippets"], drop_query=True,
    auth_summary="canThis.add.snippet → snippet:add는 Administrator·Editor·Super Editor·Admin Integration. Author/Contributor는 browse/read만",
    reason="snippet:add 권한은 Editor 이상 역할만 보유. role_required.")
add("DELETE", "/snippets/:id", "snippets.destroy", "snippets.js", "destroy", obj="snippet", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.destroy.snippet(id) → Editor 이상·Admin Integration",
    reason="snippet:destroy 권한은 Editor 이상 역할만 보유. role_required.")
add("PUT", "/comments/:id", "comments.edit", "comments.js", "edit", obj="comment", label="role_required", conf=0.8, body_keys=["comments"],
    auth_summary="canThis.edit.comment(id) → comment: 'all'은 Administrator·Super Editor·Editor·Admin Integration. Author/Contributor 없음. objectTypeModelMap에 comment가 있으나 Comment 모델 permissible 유무는 발췌에 없음",
    reason="관리자 측 댓글 수정은 comment:edit 역할 권한(Editor 이상)이 조건이며 Author·Contributor는 없다. role_required. Comment 모델의 permissible 존재 여부는 확인하지 못해 0.8.")
add("PUT", "/emails/:id/retry", "emails.retry", "emails.js", "retry", obj="email", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.retry.email(id) → email: 'all'은 Administrator·Editor·Super Editor·Admin Integration. Author/Contributor는 read만",
    reason="email:retry 권한은 Editor 이상 역할만 보유. role_required.")
add("POST", "/offers", "offers.add", "offers.js", "add", obj="offer", label="role_required", conf=0.85, body_keys=["offers"], drop_query=True,
    auth_summary="canThis.add.offer → offer:add는 Administrator·Admin Integration. Editor/Author는 browse/read만",
    reason="offer:add 권한은 Administrator·Admin Integration만 보유. role_required.")
add("DELETE", "/recommendations/:id", "recommendations.destroy", "recommendations.js", "destroy", obj="recommendation", label="role_required", conf=0.85, drop_query=True,
    auth_summary="canThis.destroy.recommendation(id) → recommendation: 'all'은 Administrator·Admin Integration",
    reason="recommendation:destroy 권한은 Administrator·Admin Integration만 보유. role_required.")
add("GET", "/identities", "identities.read", "identities.js", "read", obj="identity", label="role_required", conf=0.85, response_fields=["identities"],
    auth_summary="canThis.read.identity → identity: ['read']는 Administrator만",
    reason="identity:read 권한은 Administrator 역할만 보유. role_required.")
add("POST", "/upgrades/", "upgrades.add", "upgrades.ts", "add", obj="upgrade", label="role_required", conf=0.8, body_keys=["upgrades"],
    evidence_extra=[(E + "upgrades.ts", 80, 83)],
    auth_summary="canThis.add.upgrade → upgrade: ['browse','read','add']는 Administrator만. query에서 context.user 없으면(통합 키) 'Only staff users can request updates.'",
    reason="upgrade:add 권한은 Administrator 역할만 보유하고 통합 키는 추가로 거부된다. role_required.")
add("PUT", "/gifts/flush_reminders", "gifts.flushReminders", "gifts.js", "flushReminders", obj="gift", label="role_required", conf=0.8, mw="url",
    auth_summary="authAdminApiWithUrl(URL의 Admin API 키) → canThis.flushReminders.gift → gift 권한은 Scheduler Integration 역할만",
    reason="gift:flushReminders 권한은 Scheduler Integration 역할만 보유한다. 특정 역할(통합 역할) 보유가 조건이므로 role_required.")
add("PUT", "/schedules/:resource/:id", "schedules.publish", "schedules.js", "publish", obj="post", label="role_required", conf=0.6, mw="url", drop_query=True,
    skip_ct=True, extra=[(AUTH, [(340, 352), (377, 379), (419, 424)])], evidence_extra=[(E + "schedules.js", 40, 51)],
    auth_summary="authAdminApiWithUrl(URL Admin API 키) → canThis.publish.post(id) → post:publish는 Administrator·Editor·Super Editor·Admin Integration·Scheduler Integration. authors.permissible else 분기 hasUserPermission || isPrimaryAuthor()는 사용자 세션이 없는 이 라우트에서는 실질적으로 역할 권한만 작동",
    reason="예약 발행은 URL Admin API 키 인증 전용이며 post:publish 역할 권한(Scheduler Integration 등)이 조건이다. 모델에는 1저자 우회 분기가 있으나 사용자 세션이 없는 라우트라 역할만 결정 조건으로 보아 role_required. 스태프 토큰 사용 시 1저자 우회가 가능할 수 있어 0.6.")
add("GET", "/posts/:id/gift_links", "giftLinks.browse", "gift-links.ts", "browse", obj="gift_link", label="role_required", conf=0.55, drop_query=True,
    pre_ranges=[(14, 18)], evidence_extra=[(E + "gift-links.ts", 14, 18)], response_fields=["gift_links"],
    auth_summary="assertCanEditAndGift: canThis.manage.gift_link(id) AND canThis.edit.post(id). gift_link:manage는 Administrator·Admin Integration·Super Editor·Editor만 → 이 역할들은 edit.post를 모든 글에 보유",
    reason="gift_link:manage 역할 권한(Editor 이상) AND post edit 권한을 모두 요구한다. Editor 이상은 모든 글 수정 권한을 가지므로 실질 조건은 역할이라 role_required로 두지만, 독립 조건 AND 결합이라 manual_review_required 판단 가능.")
add("POST", "/email_previews/posts/:id", "email_previews.sendTestEmail", "email-previews.js", "sendTestEmail", obj="email_preview", label="role_required", conf=0.85, body_keys=["emails"], drop_query=True,
    auth_summary="canThis.sendTestEmail.email_preview(id) → email_preview: 'all'은 Administrator·Editor·Super Editor·Admin Integration. Author/Contributor는 read만",
    reason="email_preview:sendTestEmail 권한은 Editor 이상 역할만 보유. role_required.")

# ---------------- validation ----------------
REQUIRED = ["project", "service", "repository", "commit", "tag", "license", "method", "path", "oas_status", "oas_operation",
            "oas_global_security", "oas_security_schemes", "response_schema_fields", "controller_text", "source_locations",
            "auth_summary", "permission_doc", "draft_label", "draft_confidence", "evidence", "draft_reason", "known_vulnerable",
            "advisory", "fix_commit"]
seen = set()
for r in records:
    for k in REQUIRED:
        assert k in r, (k, r["path"])
    key = (r["method"], r["path"])
    assert key not in seen, key
    seen.add(key)
    n = len(r["controller_text"])
    assert 1 <= n <= 3000, (key, n)
    if n < 500:
        print("WARN short", key, n)
    assert r["evidence"], key
    assert 0 <= r["draft_confidence"] <= 1
    assert r["draft_label"] in {"public", "role_required", "membership_required", "tenant_match", "owner_match", "owner_or_admin", "manual_review_required"}

OUT.mkdir(parents=True, exist_ok=True)
with (OUT / "candidates.jsonl").open("w", encoding="utf-8") as fh:
    for r in records:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")

from collections import Counter
c = Counter(r["draft_label"] for r in records)
print("total", len(records), dict(c))
for r in records:
    print(f'{len(r["controller_text"]):5d} {r["draft_label"]:24s} {r["method"]:6s} {r["path"]}')
