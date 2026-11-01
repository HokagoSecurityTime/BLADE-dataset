# -*- coding: utf-8 -*-
"""Static extraction of training candidates from taiga-back 6.10.2.

Read-only over the clone. Emits candidates.jsonl in the EXTRACTION_SPEC format
plus `auth_checks` (one entry per permission primitive, `|`/`&` structure kept
in `name`). Labels are NOT assigned here.

Run:  C:/BLADE/.python/python.exe -I extract_taiga.py
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path("C:/BLADE/datasets/blade/raw/opensource/taigaio_taiga-back")
OUT_DIR = Path("C:/BLADE/data/raw_v5_train/taiga")
OUT = OUT_DIR / "candidates.jsonl"

REPO = "https://github.com/taigaio/taiga-back"
COMMIT = "4b023d8414fc675780c6aae9d541b538c5c71369"
TAG = "6.10.2"
LICENSE = "MPL-2.0"
MAX_TEXT = 3000

# ----------------------------------------------------------------------------
# source helpers (all line numbers 1-based, ranges inclusive)
# ----------------------------------------------------------------------------
_cache = {}


def lines(f):
    if f not in _cache:
        _cache[f] = (ROOT / f).read_text(encoding="utf-8").split("\n")
    return _cache[f]


def text(f, s, e):
    return "\n".join(lines(f)[s - 1:e])


def find(f, pattern, start=1, end=None):
    ls = lines(f)
    end = end or len(ls)
    rx = re.compile(pattern)
    for i in range(start, end + 1):
        if rx.search(ls[i - 1]):
            return i
    raise KeyError(f"{pattern!r} not found in {f} [{start},{end}]")


def _strip_trailing_blank(f, s, e):
    ls = lines(f)
    while e > s and ls[e - 1].strip() == "":
        e -= 1
    return s, e


def block_class(f, cls):
    ls = lines(f)
    s = find(f, rf"^class {re.escape(cls)}\b")
    e = len(ls)
    for i in range(s + 1, len(ls) + 1):
        if re.match(r"^(class |def |@|[A-Za-z_])", ls[i - 1]):
            e = i - 1
            break
    return _strip_trailing_blank(f, s, e)


def block_method(f, cls, meth):
    cs, ce = block_class(f, cls)
    d = find(f, rf"^    def {re.escape(meth)}\(", cs, ce)
    s = d
    while s - 1 >= cs and lines(f)[s - 2].startswith("    @"):
        s -= 1
    e = ce
    for i in range(d + 1, ce + 1):
        if re.match(r"^    (def |@|[A-Za-z_])", lines(f)[i - 1]):
            e = i - 1
            break
    return _strip_trailing_blank(f, s, e)


def block_func(f, name):
    ls = lines(f)
    s = find(f, rf"^def {re.escape(name)}\(")
    e = len(ls)
    for i in range(s + 1, len(ls) + 1):
        if re.match(r"^(class |def |@|[A-Za-z_])", ls[i - 1]):
            e = i - 1
            break
    return _strip_trailing_blank(f, s, e)


def attr_line(f, cls, name):
    cs, ce = block_class(f, cls)
    n = find(f, rf"^    {re.escape(name)}\s*=", cs, ce)
    return n, lines(f)[n - 1]


def has_attr(f, cls, name):
    try:
        attr_line(f, cls, name)
        return True
    except KeyError:
        return False


def block_header(f, cls):
    """class line(s) .. permission_classes line (or class line .. +2)."""
    cs, ce = block_class(f, cls)
    try:
        pe = find(f, r"^    permission_classes\s*=", cs, ce)
    except KeyError:
        pe = min(cs + 2, ce)
    return cs, pe


# ----------------------------------------------------------------------------
# piece builders
# ----------------------------------------------------------------------------
# piece kinds: ('hdr', f, Class) ('meth', f, Class, meth[, maxlines])
#              ('func', f, name) ('cls', f, Class) ('range', f, s, e)
#              ('perm', f, Class, action)   -> class line + enough/global + action line


def resolve(piece):
    k = piece[0]
    if k == "hdr":
        f = piece[1]
        s, e = block_header(f, piece[2])
        # class signature line(s) ... permission_classes line (skip unrelated attrs)
        sig_end = s
        while not lines(f)[sig_end - 1].rstrip().endswith(":"):
            sig_end += 1
        if e - sig_end > 2 and lines(f)[e - 1].lstrip().startswith("permission_classes"):
            return [(f, s, sig_end, None), (f, e, e, None)]
        return [(f, s, e, None)]
    if k == "meth":
        s, e = block_method(piece[1], piece[2], piece[3])
        mx = piece[4] if len(piece) > 4 else None
        return [(piece[1], s, e, mx)]
    if k == "func":
        s, e = block_func(piece[1], piece[2])
        return [(piece[1], s, e, None)]
    if k == "cls":
        s, e = block_class(piece[1], piece[2])
        return [(piece[1], s, e, None)]
    if k == "range":
        return [(piece[1], piece[2], piece[3], None)]
    if k == "perm":
        f, cls, action = piece[1], piece[2], piece[3]
        cs, _ = block_class(f, cls)
        out = [(f, cs, cs, None)]
        for a in ("enough_perms", "global_perms"):
            if has_attr(f, cls, a):
                n, _t = attr_line(f, cls, a)
                out.append((f, n, n, None))
        n, _t = attr_line(f, cls, f"{action}_perms")
        out.append((f, n, n, None))
        return out
    raise ValueError(piece)


def render(frag):
    f, s, e, mx = frag
    t = text(f, s, e)
    if mx and (e - s + 1) > mx:
        block = lines(f)[s - 1:e]
        # never cut an authorization line: extend the cut past the last one
        auth_idx = [i for i, x in enumerate(block) if "check_permissions" in x or "_perms" in x]
        if auth_idx and auth_idx[-1] + 1 > mx:
            mx = auth_idx[-1] + 1
        if len(block) <= mx:
            return t
        kept = block[:mx]
        rest = block[mx:]
        assert not any("check_permissions" in x or "_perms" in x for x in rest), (f, s, e)
        indent = re.match(r"^(\s*)", kept[-1]).group(1) or "        "
        t = "\n".join(kept) + "\n" + indent + "..."
    return t


def assemble(required, optional):
    """required: list of pieces always included; optional: pieces appended in
    order while total length stays <= MAX_TEXT. Returns text, locations, omitted."""
    chunks, locs, omitted = [], [], []
    for p in required:
        frags = resolve(p)
        sub = []
        last = None
        for fr in frags:
            if last and fr[0] == last[0] and fr[1] > last[2] + 1:
                sub.append("    ...")
            sub.append(render(fr))
            locs.append({"file": fr[0], "start_line": fr[1], "end_line": fr[2]})
            last = fr
        chunks.append("\n".join(sub))
    body = "\n\n".join(chunks)
    for p in optional:
        frags = resolve(p)
        t = "\n".join(render(fr) for fr in frags)
        if len(body) + 2 + len(t) <= MAX_TEXT:
            body = body + "\n\n" + t
            for fr in frags:
                locs.append({"file": fr[0], "start_line": fr[1], "end_line": fr[2]})
        else:
            omitted.append(f"{p[1]}:{p[2]}")
    assert 1 <= len(body) <= MAX_TEXT, (len(body), required[0])
    return body, locs, omitted


# ----------------------------------------------------------------------------
# auth_checks
# ----------------------------------------------------------------------------
PERM_BASE = "taiga/base/api/permissions.py"
PERM_PKG = "taiga/permissions/permissions.py"
SVC = "taiga/permissions/services.py"

PRIM = {
    "IsSuperUser": ("cls", PERM_BASE, "IsSuperUser"),
    "IsAuthenticated": ("cls", PERM_BASE, "IsAuthenticated"),
    "AllowAny": ("cls", PERM_BASE, "AllowAny"),
    "DenyAll": ("cls", PERM_BASE, "DenyAll"),
    "HasProjectPerm": ("cls", PERM_BASE, "HasProjectPerm"),
    "IsProjectAdmin": ("cls", PERM_BASE, "IsProjectAdmin"),
    "IsObjectOwner": ("cls", PERM_BASE, "IsObjectOwner"),
    "HasProjectPerm.pkg": ("cls", PERM_PKG, "HasProjectPerm"),
    "IsProjectAdmin.pkg": ("cls", PERM_PKG, "IsProjectAdmin"),
    "CommentAndOrUpdatePerm": ("cls", PERM_PKG, "CommentAndOrUpdatePerm"),
    "user_has_perm": ("func", SVC, "user_has_perm"),
    "calculate_permissions": ("func", SVC, "calculate_permissions"),
    "get_user_project_permissions": ("func", SVC, "get_user_project_permissions"),
    "is_project_admin": ("func", SVC, "is_project_admin"),
    "_get_user_project_membership": ("func", SVC, "_get_user_project_membership"),
    "TaigaResourcePermission": ("cls", PERM_BASE, "TaigaResourcePermission"),
    "ResourcePermission.check": ("meth", PERM_BASE, "ResourcePermission", "check_permissions"),
}

VIEW_PERMS = {"view_project", "view_milestones", "view_epics", "view_us", "view_tasks",
              "view_issues", "view_wiki_pages", "view_wiki_links"}
MEMBER_ONLY_PERMS = {"add_milestone", "modify_milestone", "delete_milestone", "add_epic",
                     "modify_epic", "comment_epic", "delete_epic", "add_us", "modify_us",
                     "comment_us", "delete_us", "add_task", "modify_task", "comment_task",
                     "delete_task", "add_issue", "modify_issue", "comment_issue", "delete_issue",
                     "add_wiki_page", "modify_wiki_page", "comment_wiki_page", "delete_wiki_page",
                     "add_wiki_link", "modify_wiki_link", "delete_wiki_link"}


def chk(kind, name, f, cls, attr, **extra):
    n, t = attr_line(f, cls, attr)
    d = {"kind": kind, "name": name, "file": f, "line": n, "text": t.strip()}
    d.update(extra)
    return d


def chk_line(kind, name, f, pattern, **extra):
    n = find(f, pattern)
    d = {"kind": kind, "name": name, "file": f, "line": n, "text": lines(f)[n - 1].strip()}
    d.update(extra)
    return d


def bypass_checks(f, cls):
    """enough_perms OR-bypass: own class attr or inherited TaigaResourcePermission."""
    if has_attr(f, cls, "enough_perms"):
        n, t = attr_line(f, cls, "enough_perms")
        rhs = t.split("=", 1)[1].strip()
        via = f"{cls}.enough_perms"
        src = f
    else:
        n, t = attr_line(PERM_BASE, "TaigaResourcePermission", "enough_perms")
        rhs = t.split("=", 1)[1].strip()
        via = "TaigaResourcePermission.enough_perms (inherited)"
        src = PERM_BASE
    out = []
    for part in [p.strip() for p in rhs.split("|")]:
        if part == "IsSuperUser()":
            kind = "global_role"
        elif part == "IsProjectAdmin()":
            kind = "group_role"
        elif part == "IsAuthenticated()":
            kind = "auth_only"
        else:
            kind = "setting_dependent"
        out.append({"kind": kind, "name": part, "file": src, "line": n, "text": t.strip(),
                    "via": via, "bypass": True})
    return rhs, out


def hp_kind(perm):
    """HasProjectPerm('<perm>') kind."""
    if perm in VIEW_PERMS:
        return "visibility_branch"
    if perm in MEMBER_ONLY_PERMS:
        return "group_role"
    if perm == "add_us_to_project":
        return "group_role"
    return "group_role"


def hp_note(perm):
    if perm in VIEW_PERMS:
        return ("view_* perm: calculate_permissions() also grants it via project.public_permissions "
                "(any authenticated user) / project.anon_permissions (anonymous) when the project "
                "is public; members get it through ANON/MEMBERS lists + role.permissions")
    if perm in MEMBER_ONLY_PERMS:
        return ("not in ANON_PERMISSIONS; granted only when membership.role.permissions contains it "
                "(or membership.is_admin -> MEMBERS_PERMISSIONS, or superuser) -> depends on member role")
    if perm == "add_us_to_project":
        return "perm codename not in choices; only a custom role.permissions entry or admin/superuser"
    return ""


# ----------------------------------------------------------------------------
# record builder
# ----------------------------------------------------------------------------
RECORDS = []
SEEN = set()
SEC_BEARER = [{"bearerAuth": []}]
SCHEMES = {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                          "description": "Authorization: Bearer <access token> (taiga.auth.authentication)"}}


def P(name, loc="path", typ="integer", required=True, desc=None):
    d = {"name": name, "in": loc, "required": required, "schema": {"type": typ}}
    if desc:
        d["description"] = desc
    return d


def rec(method, path, summary, *, viewset, handler, perm, action, dominant, checks,
        auth_summary, primitives=(), optional=(), params=(), security=True, body=None,
        responses=None, description="", extra=None, unlocated=False):
    key = (method, path)
    assert key not in SEEN, key
    SEEN.add(key)
    f_perm, cls_perm = perm
    required = [("hdr",) + tuple(viewset)] + list(handler)
    if action is not None:
        required.append(("perm", f_perm, cls_perm, action))
    opt = [PRIM[p] if isinstance(p, str) else p for p in primitives] + list(optional)
    if dominant == "visibility_branch" and PRIM["calculate_permissions"] in opt:
        # the public_permissions / anon_permissions branch must be quoted first
        opt.remove(PRIM["calculate_permissions"])
        opt.insert(1, PRIM["calculate_permissions"])
    ctext, locs, omitted = assemble(required, opt)
    if action is not None:
        n, t = attr_line(f_perm, cls_perm, f"{action}_perms")
        expr = t.split("=", 1)[1].strip()
        bypass_rhs, bchecks = bypass_checks(f_perm, cls_perm)
        effective = f"({bypass_rhs}) | ({expr})"
        perm_ref = f"{f_perm}:{n} {cls_perm}.{action}_perms"
    else:
        expr, bypass_rhs, bchecks, effective, perm_ref = None, None, [], None, None
    all_checks = list(checks) + bchecks
    assert all_checks, key
    op_id = re.sub(r"[^a-zA-Z0-9]+", "_", f"{method.lower()}_{path.replace('/api/v1/', '')}").strip("_")
    op = {"operationId": op_id, "summary": summary, "description": description,
          "parameters": list(params), "responses": responses or {"200": {"description": "OK"}},
          "security": SEC_BEARER if security else []}
    if body:
        op["requestBody"] = body
    r = {
        "project": "taiga", "service": "Taiga", "repository": REPO, "commit": COMMIT,
        "tag": TAG, "license": LICENSE, "method": method, "path": path,
        "oas_status": "generated", "oas_operation": op,
        "oas_global_security": SEC_BEARER, "oas_security_schemes": SCHEMES,
        "response_schema_fields": [], "controller_text": ctext, "source_locations": locs,
        "auth_summary": auth_summary, "permission_doc": "",
        "permission_class": f"{f_perm}:{cls_perm}",
        "permission_action": action, "permission_expression": expr,
        "permission_ref": perm_ref, "enough_perms_bypass": bypass_rhs,
        "effective_expression": effective,
        "dominant_kind": dominant, "auth_checks": all_checks,
        "omitted_blocks": omitted, "unlocated": unlocated,
    }
    if extra:
        r.update(extra)
    RECORDS.append(r)
    return r


# ----------------------------------------------------------------------------
# common pieces
# ----------------------------------------------------------------------------
MIX = "taiga/base/api/mixins.py"
M_RETRIEVE = ("meth", MIX, "RetrieveModelMixin", "retrieve", 6)
M_CREATE = ("meth", MIX, "CreateModelMixin", "create", 8)
M_UPDATE = ("meth", MIX, "UpdateModelMixin", "update", 9)
M_DESTROY = ("meth", MIX, "DestroyModelMixin", "destroy", 8)
NOTIF = "taiga/projects/notifications/mixins.py"
VOTES = "taiga/projects/votes/mixins/viewsets.py"
LIKES = "taiga/projects/likes/mixins/viewsets.py"
M_WATCH = ("meth", NOTIF, "WatchedResourceMixin", "watch")
M_UNWATCH = ("meth", NOTIF, "WatchedResourceMixin", "unwatch")
M_UPVOTE = ("meth", VOTES, "VotedResourceMixin", "upvote")
M_DOWNVOTE = ("meth", VOTES, "VotedResourceMixin", "downvote")
M_WATCHERS_LIST = ("meth", NOTIF, "WatchersViewSetMixin", "list")
M_VOTERS_LIST = ("meth", VOTES, "VotersViewSetMixin", "list")
M_FANS_LIST = ("meth", LIKES, "FansViewSetMixin", "list")
M_LIKE = ("meth", LIKES, "LikedResourceMixin", "like")
M_UNLIKE = ("meth", LIKES, "LikedResourceMixin", "unlike")
M_BULK_ORDER = ("meth", "taiga/projects/mixins/ordering.py", "BulkUpdateOrderMixin", "bulk_update_order", 15)
M_PROMOTE = ("meth", "taiga/projects/mixins/promote.py", "PromoteToUserStoryMixin", "promote_to_user_story", 9)
M_BYREF = ("meth", "taiga/projects/mixins/by_ref.py", "ByRefMixin", "by_ref", 6)

HP_PRIMS = ["HasProjectPerm", "user_has_perm", "calculate_permissions", "get_user_project_permissions"]
HP_PRIMS_PKG = ["HasProjectPerm.pkg", "user_has_perm", "calculate_permissions", "get_user_project_permissions"]
ADMIN_PRIMS = ["IsProjectAdmin", "is_project_admin", "_get_user_project_membership"]
ADMIN_PRIMS_PKG = ["IsProjectAdmin.pkg", "is_project_admin", "_get_user_project_membership"]
SUPER_PRIMS = ["IsSuperUser", "TaigaResourcePermission", "ResourcePermission.check"]


def hp_check(f, cls, action, perm, name=None):
    return chk(hp_kind(perm), name or f"HasProjectPerm('{perm}')", f, cls, f"{action}_perms",
               note=hp_note(perm))


def admin_check(f, cls, action, name="IsProjectAdmin()"):
    return chk("group_role", name, f, cls, f"{action}_perms",
               note="is_project_admin(): superuser, or project membership row with is_admin=True")


def auth_check(f, cls, action, name="IsAuthenticated()"):
    return chk("auth_only", name, f, cls, f"{action}_perms")


def any_check(f, cls, action):
    return chk("anonymous", "AllowAny()", f, cls, f"{action}_perms")


def super_check(f, cls, action):
    return chk("global_role", "IsSuperUser()", f, cls, f"{action}_perms")


ID = P("id")
PROJ_Q = P("project", "query", "integer", False)

# ============================================================================
# 1. HISTORY (owner_or_privileged)
# ============================================================================
HAPI = "taiga/projects/history/api.py"
HPERM = "taiga/projects/history/permissions.py"
HIST = [("epic", "EpicHistory", "EpicHistoryPermission", "epic"),
        ("userstory", "UserStoryHistory", "UserStoryHistoryPermission", "user story"),
        ("task", "TaskHistory", "TaskHistoryPermission", "task"),
        ("issue", "IssueHistory", "IssueHistoryPermission", "issue"),
        ("wiki", "WikiHistory", "WikiHistoryPermission", "wiki page")]
H_PRIMS = [("cls", HPERM, "IsCommentProjectAdmin"), ("cls", HPERM, "IsCommentOwner"),
           "is_project_admin", "_get_user_project_membership"]
HID = P("id", desc="pk of the parent object (epic/userstory/task/issue/wikipage)")
HEID = P("id", "query", "integer", True, "history entry id (comment)")

for slug, vs, pc, label in HIST:
    base = f"/api/v1/history/{slug}/{{id}}"
    rec("POST", base + "/edit_comment", f"Edit a comment on a {label} history entry",
        viewset=(HAPI, vs), handler=[("meth", HAPI, "HistoryViewSet", "edit_comment", 20)],
        perm=(HPERM, pc), action="edit_comment", dominant="owner_or_privileged",
        checks=[chk("owner_or_privileged", "IsCommentProjectAdmin() | IsCommentOwner()", HPERM, pc, "edit_comment_perms"),
                chk("group_role", "IsCommentProjectAdmin()", HPERM, pc, "edit_comment_perms",
                    note="resolves the parent object's project and calls is_project_admin()"),
                chk("owner_field", "IsCommentOwner()", HPERM, pc, "edit_comment_perms",
                    note="history_entry.user['pk'] == request.user.pk")],
        auth_summary=f"{pc}.edit_comment_perms = IsCommentProjectAdmin() | IsCommentOwner(): comment author OR project admin (plus inherited IsSuperUser enough_perms)",
        primitives=H_PRIMS, params=[HID, HEID],
        body={"content": {"application/json": {"schema": {"type": "object", "properties": {"comment": {"type": "string"}}}}}})
    rec("POST", base + "/delete_comment", f"Soft-delete a comment on a {label} history entry",
        viewset=(HAPI, vs), handler=[("meth", HAPI, "HistoryViewSet", "delete_comment", 12)],
        perm=(HPERM, pc), action="delete_comment", dominant="owner_or_privileged",
        checks=[chk("owner_or_privileged", "IsCommentProjectAdmin() | IsCommentOwner()", HPERM, pc, "delete_comment_perms"),
                chk("group_role", "IsCommentProjectAdmin()", HPERM, pc, "delete_comment_perms"),
                chk("owner_field", "IsCommentOwner()", HPERM, pc, "delete_comment_perms")],
        auth_summary=f"{pc}.delete_comment_perms = IsCommentProjectAdmin() | IsCommentOwner(): comment author OR project admin",
        primitives=H_PRIMS, params=[HID, HEID])
    rec("POST", base + "/undelete_comment", f"Restore a deleted comment on a {label} history entry",
        viewset=(HAPI, vs), handler=[("meth", HAPI, "HistoryViewSet", "undelete_comment", 12)],
        perm=(HPERM, pc), action="undelete_comment", dominant="owner_or_privileged",
        checks=[chk("owner_or_privileged", "IsCommentProjectAdmin() | IsCommentDeleter()", HPERM, pc, "undelete_comment_perms"),
                chk("group_role", "IsCommentProjectAdmin()", HPERM, pc, "undelete_comment_perms"),
                chk("owner_field", "IsCommentDeleter()", HPERM, pc, "undelete_comment_perms",
                    note="history_entry.delete_comment_user['pk'] == request.user.pk (the user who deleted it)")],
        auth_summary=f"{pc}.undelete_comment_perms = IsCommentProjectAdmin() | IsCommentDeleter(): user who deleted the comment OR project admin",
        primitives=[("cls", HPERM, "IsCommentProjectAdmin"), ("cls", HPERM, "IsCommentDeleter"),
                    "is_project_admin", "_get_user_project_membership"], params=[HID, HEID])
    rec("GET", base + "/comment_versions", f"List previous versions of a comment on a {label} history entry",
        viewset=(HAPI, vs), handler=[("meth", HAPI, "HistoryViewSet", "comment_versions", 13)],
        perm=(HPERM, pc), action="comment_versions", dominant="owner_or_privileged",
        checks=[chk("owner_or_privileged", "IsCommentProjectAdmin() | IsCommentOwner()", HPERM, pc, "comment_versions_perms"),
                chk("group_role", "IsCommentProjectAdmin()", HPERM, pc, "comment_versions_perms"),
                chk("owner_field", "IsCommentOwner()", HPERM, pc, "comment_versions_perms")],
        auth_summary=f"{pc}.comment_versions_perms = IsCommentProjectAdmin() | IsCommentOwner(): comment author OR project admin",
        primitives=H_PRIMS, params=[HID, HEID])
    rec("GET", base, f"Get the change history of a {label}",
        viewset=(HAPI, vs), handler=[("meth", HAPI, "HistoryViewSet", "retrieve", 8)],
        perm=(HPERM, pc), action="retrieve", dominant="visibility_branch",
        checks=[hp_check(HPERM, pc, "retrieve", "view_project")],
        auth_summary=f"{pc}.retrieve_perms = HasProjectPerm('view_project'): project member, or any/anonymous user when the project is public (public_permissions/anon_permissions)",
        primitives=HP_PRIMS, params=[HID])

# ============================================================================
# 2. ATTACHMENTS (owner OR role perm)
# ============================================================================
AAPI = "taiga/projects/attachments/api.py"
APERM = "taiga/projects/attachments/permissions.py"
ATT = [("epics", "EpicAttachmentViewSet", "EpicAttachmentPermission", "modify_epic", "view_epics", "comment_epic", "epic"),
       ("userstories", "UserStoryAttachmentViewSet", "UserStoryAttachmentPermission", "modify_us", "view_us", "comment_us", "user story"),
       ("tasks", "TaskAttachmentViewSet", "TaskAttachmentPermission", "modify_task", "view_tasks", "comment_task", "task"),
       ("issues", "IssueAttachmentViewSet", "IssueAttachmentPermission", "modify_issue", "view_issues", "comment_issue", "issue"),
       ("wiki", "WikiAttachmentViewSet", "WikiAttachmentPermission", "modify_wiki_page", "view_wiki_pages", "comment_wiki_page", "wiki page")]
A_OWNER = ("cls", APERM, "IsAttachmentOwnerPerm")
for pfx, vs, pc, modp, viewp, comp, label in ATT:
    base = f"/api/v1/{pfx}/attachments/{{id}}"
    for m, act, summ in (("PATCH", "partial_update", f"Update a {label} attachment (partial)"),
                         ("DELETE", "destroy", f"Delete a {label} attachment")):
        h = [("meth", AAPI, "BaseAttachmentViewSet", "update"), M_UPDATE] if m == "PATCH" else [M_DESTROY]
        rec(m, base, summ, viewset=(AAPI, vs), handler=h, perm=(APERM, pc), action=act,
            dominant="owner_or_privileged",
            checks=[chk("owner_or_privileged", f"HasProjectPerm('{modp}') | IsAttachmentOwnerPerm()", APERM, pc, f"{act}_perms"),
                    hp_check(APERM, pc, act, modp),
                    chk("owner_field", "IsAttachmentOwnerPerm()", APERM, pc, f"{act}_perms",
                        note="request.user == attachment.owner (owner set to request.user in pre_save)")],
            auth_summary=f"{pc}.{act}_perms = HasProjectPerm('{modp}') | IsAttachmentOwnerPerm(): attachment uploader OR member whose role has {modp}",
            primitives=[A_OWNER] + HP_PRIMS, params=[ID])
    if pfx in ("userstories", "issues"):
        rec("GET", base, f"Get a {label} attachment", viewset=(AAPI, vs), handler=[M_RETRIEVE],
            perm=(APERM, pc), action="retrieve", dominant="owner_or_privileged",
            checks=[chk("owner_or_privileged", f"HasProjectPerm('{viewp}') | IsAttachmentOwnerPerm()", APERM, pc, "retrieve_perms"),
                    hp_check(APERM, pc, "retrieve", viewp),
                    chk("owner_field", "IsAttachmentOwnerPerm()", APERM, pc, "retrieve_perms")],
            auth_summary=f"{pc}.retrieve_perms = HasProjectPerm('{viewp}') | IsAttachmentOwnerPerm(): uploader OR anyone who can view {label}s (public project branch applies)",
            primitives=[A_OWNER] + HP_PRIMS, params=[ID])
    if pfx in ("userstories", "wiki"):
        rec("POST", f"/api/v1/{pfx}/attachments", f"Upload a {label} attachment", viewset=(AAPI, vs),
            handler=[("meth", AAPI, "BaseAttachmentViewSet", "pre_save", 6), M_CREATE],
            perm=(APERM, pc), action="create", dominant="group_role",
            checks=[chk("group_role", f"HasProjectPerm('{modp}') | (CommentAttachmentPerm() & HasProjectPerm('{comp}'))", APERM, pc, "create_perms"),
                    hp_check(APERM, pc, "create", modp),
                    chk("compound_and", f"CommentAttachmentPerm() & HasProjectPerm('{comp}')", APERM, pc, "create_perms",
                        note="attachment flagged from_comment only needs the comment_* role perm"),
                    hp_check(APERM, pc, "create", comp)],
            auth_summary=f"{pc}.create_perms = HasProjectPerm('{modp}') | (CommentAttachmentPerm() & HasProjectPerm('{comp}')): member role perm {modp}, or {comp} when attached from a comment",
            primitives=[("cls", APERM, "CommentAttachmentPerm")] + HP_PRIMS,
            body={"content": {"multipart/form-data": {"schema": {"type": "object", "properties": {"project": {"type": "integer"}, "object_id": {"type": "integer"}, "attached_file": {"type": "string", "format": "binary"}}}}}})

# ============================================================================
# 3. USERS
# ============================================================================
UAPI = "taiga/users/api.py"
UPERM = "taiga/users/permissions.py"
UVS = (UAPI, "UsersViewSet")
UP = "UserPermission"
SAME = ("cls", UPERM, "IsTheSameUser")

rec("GET", "/api/v1/users/{id}", "Get a user profile", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "retrieve")], perm=(UPERM, UP), action="retrieve",
    dominant="setting_dependent",
    checks=[chk("setting_dependent", "CanRetrieveUser()", UPERM, UP, "retrieve_perms",
                note="settings.PRIVATE_USER_PROFILES: authenticated only; otherwise anyone")],
    auth_summary="UserPermission.retrieve_perms = CanRetrieveUser(): anonymous allowed unless settings.PRIVATE_USER_PROFILES (then any authenticated user)",
    primitives=[("cls", UPERM, "CanRetrieveUser")], params=[ID], security=False)
rec("GET", "/api/v1/users/by_username", "Get a user profile by username", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "by_username"), ("meth", UAPI, "UsersViewSet", "retrieve")],
    perm=(UPERM, UP), action="by_username", dominant="setting_dependent",
    checks=[chk("setting_dependent", "CanRetrieveUser()", UPERM, UP, "by_username_perms",
                note="by_username_perms = retrieve_perms = CanRetrieveUser()"),
            chk("setting_dependent", "CanRetrieveUser()", UPERM, UP, "retrieve_perms")],
    auth_summary="UserPermission.by_username_perms = retrieve_perms = CanRetrieveUser() (setting-dependent)",
    primitives=[("cls", UPERM, "CanRetrieveUser")], params=[P("username", "query", "string")], security=False)
for m, act, summ, h in (("PATCH", "update", "Update own user profile (partial)", [("meth", UAPI, "UsersViewSet", "partial_update", 8)]),
                        ("PUT", "update", "Update own user profile", [M_UPDATE]),
                        ("DELETE", "destroy", "Cancel (delete) own user account", [("meth", UAPI, "UsersViewSet", "destroy")])):
    rec(m, "/api/v1/users/{id}", summ, viewset=UVS, handler=h, perm=(UPERM, UP), action=act,
        dominant="self_target",
        checks=[chk("self_target", "IsTheSameUser()", UPERM, UP, f"{act}_perms",
                    note="request.user.pk == obj.pk; UserPermission.enough_perms = IsSuperUser() is OR-ed (superuser bypass)")],
        auth_summary=f"UserPermission.{act}_perms = IsTheSameUser() (target user == request.user); enough_perms IsSuperUser() bypass",
        primitives=[SAME, "IsSuperUser"], params=[ID])
for act, summ, h in (("me", "Get the authenticated user", [("meth", UAPI, "UsersViewSet", "me")]),
                     ("change_password", "Change the authenticated user's password", [("meth", UAPI, "UsersViewSet", "change_password", 12)]),
                     ("change_avatar", "Change the authenticated user's avatar", [("meth", UAPI, "UsersViewSet", "change_avatar", 12)]),
                     ("remove_avatar", "Remove the authenticated user's avatar", [("meth", UAPI, "UsersViewSet", "remove_avatar")]),
                     ("send_verification_email", "Send verification mail for the authenticated user's new email", [("meth", UAPI, "UsersViewSet", "send_verification_email")])):
    rec("GET" if act == "me" else "POST", f"/api/v1/users/{act}", summ, viewset=UVS, handler=h,
        perm=(UPERM, UP), action=act, dominant="self_target",
        checks=[chk("self_target", "IsAuthenticated()", UPERM, UP, f"{act}_perms",
                    note="object fixed to request.user in the handler (no target id)")],
        auth_summary=f"UserPermission.{act}_perms = IsAuthenticated(); handler operates only on request.user",
        primitives=["IsAuthenticated"])
rec("POST", "/api/v1/users/change_email", "Confirm an email change with the mailed token", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "change_email", 16)], perm=(UPERM, UP), action="change_email",
    dominant="anonymous",
    checks=[any_check(UPERM, UP, "change_email"),
            chk_line("owner_field", "User.objects.get(email_token=...)", UAPI, r"email_token=validator\.data\[\"email_token\"\]",
                     note="possession of the one-time email_token selects the user; no session check")],
    auth_summary="UserPermission.change_email_perms = AllowAny(); user resolved by the secret email_token in the body",
    primitives=["AllowAny"], security=False,
    body={"content": {"application/json": {"schema": {"type": "object", "properties": {"email_token": {"type": "string"}}}}}})
rec("POST", "/api/v1/users/cancel", "Cancel an account with a cancel token", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "cancel")], perm=(UPERM, UP), action=None, dominant="anonymous",
    checks=[chk_line("anonymous", "no check_permissions; CancelToken(token=...) selects the user", UAPI,
                     r"validated_token = CancelToken\(token=validator\.data\[\"cancel_token\"\]\)",
                     note="token-bearer action; viewset permission class not consulted")],
    auth_summary="No check_permissions call; the signed cancel_token identifies the user", security=False,
    body={"content": {"application/json": {"schema": {"type": "object", "properties": {"cancel_token": {"type": "string"}}}}}})
rec("POST", "/api/v1/users/password_recovery", "Request a password recovery mail", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "password_recovery", 10)], perm=(UPERM, UP), action="password_recovery",
    dominant="anonymous", checks=[any_check(UPERM, UP, "password_recovery")],
    auth_summary="UserPermission.password_recovery_perms = AllowAny()", primitives=["AllowAny"], security=False)
rec("POST", "/api/v1/users/change_password_from_recovery", "Set a new password with a recovery token", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "change_password_from_recovery", 12)], perm=(UPERM, UP),
    action="change_password_from_recovery", dominant="anonymous",
    checks=[any_check(UPERM, UP, "change_password_from_recovery")],
    auth_summary="UserPermission.change_password_from_recovery_perms = AllowAny(); recovery token in body", primitives=["AllowAny"], security=False)
for act, summ in (("contacts", "List a user's contacts (users sharing projects)"), ("stats", "Get a user's public stats"),
                  ("watched", "List objects watched by a user"), ("liked", "List projects liked by a user"),
                  ("voted", "List objects voted by a user")):
    pa = "liked" if act == "voted" else act
    rec("GET", f"/api/v1/users/{{id}}/{act}", summ, viewset=UVS, handler=[("meth", UAPI, "UsersViewSet", act, 8)],
        perm=(UPERM, UP), action=pa, dominant="anonymous",
        checks=[any_check(UPERM, UP, pa)] + ([chk_line("anonymous", "check_permissions(request, 'liked', for_user) in voted()", UAPI,
                                                         r"self\.check_permissions\(request, 'liked', for_user\)")] if act == "voted" else []),
        auth_summary=f"UserPermission.{pa}_perms = AllowAny(); services filter the listed content by the accessing user's view permissions",
        primitives=["AllowAny"], params=[ID], security=False)
rec("GET", "/api/v1/users", "List users (optionally filtered by project membership)", viewset=UVS,
    handler=[("meth", UAPI, "UsersViewSet", "list")], perm=(UPERM, UP), action="list", dominant="anonymous",
    checks=[any_check(UPERM, UP, "list")],
    auth_summary="UserPermission.list_perms = AllowAny(); MembersFilterBackend filters by ?project", primitives=["AllowAny"],
    params=[PROJ_Q], security=False)

# ============================================================================
# 4. AUTH
# ============================================================================
AUAPI = "taiga/auth/api.py"
AUPERM = "taiga/auth/permissions.py"
rec("POST", "/api/v1/auth", "Login (obtain JWT tokens)", viewset=(AUAPI, "AuthViewSet"),
    handler=[("meth", AUAPI, "AuthViewSet", "create", 14)], perm=(AUPERM, "AuthPermission"), action="get_token",
    dominant="anonymous", checks=[any_check(AUPERM, "AuthPermission", "get_token")],
    auth_summary="AuthPermission.get_token_perms = AllowAny()", primitives=["AllowAny"], security=False,
    body={"content": {"application/json": {"schema": {"type": "object", "properties": {"type": {"type": "string"}, "username": {"type": "string"}, "password": {"type": "string"}}}}}})
rec("POST", "/api/v1/auth/refresh", "Refresh an access token", viewset=(AUAPI, "AuthViewSet"),
    handler=[("meth", AUAPI, "AuthViewSet", "refresh")], perm=(AUPERM, "AuthPermission"), action="refresh_token",
    dominant="anonymous", checks=[any_check(AUPERM, "AuthPermission", "refresh_token")],
    auth_summary="AuthPermission.refresh_token_perms = AllowAny(); refresh token in body", primitives=["AllowAny"], security=False)
rec("POST", "/api/v1/auth/register", "Register a new user (public or by invitation)", viewset=(AUAPI, "AuthViewSet"),
    handler=[("meth", AUAPI, "AuthViewSet", "register"), ("meth", AUAPI, "AuthViewSet", "_public_register", 4)],
    perm=(AUPERM, "AuthPermission"), action="register", dominant="anonymous",
    checks=[any_check(AUPERM, "AuthPermission", "register"),
            chk_line("setting_dependent", "settings.PUBLIC_REGISTER_ENABLED", AUAPI, r"if not settings\.PUBLIC_REGISTER_ENABLED:",
                     note="public type only when the site setting allows it; private type needs invitation token")],
    auth_summary="AuthPermission.register_perms = AllowAny(); public registration gated by settings.PUBLIC_REGISTER_ENABLED",
    primitives=["AllowAny"], security=False)

# ============================================================================
# 5. PROJECTS
# ============================================================================
PAPI = "taiga/projects/api.py"
PPERM = "taiga/projects/permissions.py"
PVS = (PAPI, "ProjectViewSet")
PP = "ProjectPermission"
TAG_API = "taiga/projects/tagging/api.py"

rec("GET", "/api/v1/projects/{id}", "Get a project", viewset=PVS, handler=[("meth", PAPI, "ProjectViewSet", "retrieve")],
    perm=(PPERM, PP), action="retrieve", dominant="visibility_branch",
    checks=[hp_check(PPERM, PP, "retrieve", "view_project")],
    auth_summary="ProjectPermission.retrieve_perms = HasProjectPerm('view_project'): member of the project, or anyone (incl. anonymous) if the project is public",
    primitives=HP_PRIMS_PKG, params=[ID])
rec("GET", "/api/v1/projects/by_slug", "Get a project by slug", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "by_slug"), ("meth", PAPI, "ProjectViewSet", "retrieve")],
    perm=(PPERM, PP), action="by_slug", dominant="visibility_branch",
    checks=[hp_check(PPERM, PP, "by_slug", "view_project"),
            chk_line("visibility_branch", "filters.get_filter_expression_can_view_projects(request.user)", PAPI,
                     r"flt = filters\.get_filter_expression_can_view_projects\(request\.user\)")],
    auth_summary="ProjectPermission.by_slug_perms = HasProjectPerm('view_project') + queryset pre-filtered to projects the user can view",
    primitives=HP_PRIMS_PKG, params=[P("slug", "query", "string")])
rec("POST", "/api/v1/projects", "Create a project (owner = requester)", viewset=PVS,
    handler=[M_CREATE, ("meth", PAPI, "ProjectViewSet", "pre_save", 4)], perm=(PPERM, PP), action="create",
    dominant="auth_only", checks=[auth_check(PPERM, PP, "create"),
                                  chk_line("self_target", "obj.owner = self.request.user", PAPI, r"^\s+obj\.owner = self\.request\.user$")],
    auth_summary="ProjectPermission.create_perms = IsAuthenticated(); owner forced to request.user in pre_save",
    primitives=["IsAuthenticated"])
for m, act, h in (("PATCH", "partial_update", [M_UPDATE]), ("PUT", "update", [M_UPDATE])):
    rec(m, "/api/v1/projects/{id}", f"Update a project ({'partial' if m == 'PATCH' else 'full'})", viewset=PVS, handler=h,
        perm=(PPERM, PP), action=act, dominant="group_role", checks=[admin_check(PPERM, PP, act)],
        auth_summary=f"ProjectPermission.{act}_perms = IsProjectAdmin(): membership.is_admin in this project (or superuser)",
        primitives=ADMIN_PRIMS_PKG, params=[ID])
rec("DELETE", "/api/v1/projects/{id}", "Delete a project", viewset=PVS, handler=[("meth", PAPI, "ProjectViewSet", "destroy", 8)],
    perm=(PPERM, PP), action="destroy", dominant="group_role", checks=[admin_check(PPERM, PP, "destroy")],
    auth_summary="ProjectPermission.destroy_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS_PKG, params=[ID])
for m in ("GET", "PATCH"):
    rec(m, "/api/v1/projects/{id}/modules", f"{'Get' if m == 'GET' else 'Update'} project modules configuration", viewset=PVS,
        handler=[("meth", PAPI, "ProjectViewSet", "modules")], perm=(PPERM, PP), action="modules", dominant="group_role",
        checks=[admin_check(PPERM, PP, "modules")], auth_summary="ProjectPermission.modules_perms = IsProjectAdmin() (both GET and PATCH)",
        primitives=ADMIN_PRIMS_PKG, params=[ID])
for act, summ in (("stats", "Get project stats"), ("member_stats", "Get project member stats"), ("issues_stats", "Get project issue stats")):
    rec("GET", f"/api/v1/projects/{{id}}/{act}", summ, viewset=PVS, handler=[("meth", PAPI, "ProjectViewSet", act)],
        perm=(PPERM, PP), action=act, dominant="visibility_branch", checks=[hp_check(PPERM, PP, act, "view_project")],
        auth_summary=f"ProjectPermission.{act}_perms = HasProjectPerm('view_project') (public project branch applies)",
        primitives=HP_PRIMS_PKG, params=[ID])
rec("GET", "/api/v1/projects/{id}/tags_colors", "Get project tag colors", viewset=PVS,
    handler=[("meth", TAG_API, "TagsColorsResourceMixin", "tags_colors")], perm=(PPERM, PP), action="tags_colors",
    dominant="visibility_branch", checks=[hp_check(PPERM, PP, "tags_colors", "view_project")],
    auth_summary="ProjectPermission.tags_colors_perms = HasProjectPerm('view_project')", primitives=HP_PRIMS_PKG, params=[ID])
for act, summ in (("create_tag", "Create a project tag"), ("delete_tag", "Delete a project tag"), ("mix_tags", "Merge project tags")):
    rec("POST", f"/api/v1/projects/{{id}}/{act}", summ, viewset=PVS, handler=[("meth", TAG_API, "TagsColorsResourceMixin", act, 10)],
        perm=(PPERM, PP), action=act, dominant="group_role", checks=[admin_check(PPERM, PP, act)],
        auth_summary=f"ProjectPermission.{act}_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS_PKG, params=[ID])
for act, summ in (("change_logo", "Change the project logo"), ("remove_logo", "Remove the project logo"),
                  ("regenerate_epics_csv_uuid", "Regenerate the epics CSV export uuid"),
                  ("delete_userstories_csv_uuid", "Delete the user stories CSV export uuid")):
    rec("POST", f"/api/v1/projects/{{id}}/{act}", summ, viewset=PVS, handler=[("meth", PAPI, "ProjectViewSet", act, 9)],
        perm=(PPERM, PP), action=act, dominant="group_role", checks=[admin_check(PPERM, PP, act)],
        auth_summary=f"ProjectPermission.{act}_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS_PKG, params=[ID])
for act, h, summ in (("like", [M_LIKE], "Like a project (requester becomes a fan)"), ("unlike", [M_UNLIKE], "Unlike a project"),
                     ("watch", [("meth", PAPI, "ProjectViewSet", "watch")], "Watch a project (requester)"),
                     ("unwatch", [("meth", PAPI, "ProjectViewSet", "unwatch")], "Unwatch a project (requester)"),
                     ("duplicate", [("meth", PAPI, "ProjectViewSet", "duplicate", 10)], "Duplicate a project into a new one owned by requester"),
                     ("transfer_validate_token", [("meth", PAPI, "ProjectViewSet", "transfer_validate_token")], "Validate a project transfer token"),
                     ("transfer_accept", [("meth", PAPI, "ProjectViewSet", "transfer_accept", 8)], "Accept a project ownership transfer (token)"),
                     ("transfer_reject", [("meth", PAPI, "ProjectViewSet", "transfer_reject", 8)], "Reject a project ownership transfer (token)")):
    rec("POST", f"/api/v1/projects/{{id}}/{act}", summ, viewset=PVS, handler=h, perm=(PPERM, PP), action=act,
        dominant="compound_and",
        checks=[chk("compound_and", "IsAuthenticated() & HasProjectPerm('view_project')", PPERM, PP, f"{act}_perms"),
                auth_check(PPERM, PP, act), hp_check(PPERM, PP, act, "view_project")],
        auth_summary=f"ProjectPermission.{act}_perms = IsAuthenticated() & HasProjectPerm('view_project'): any logged-in user who can view the project (public branch applies); acts on behalf of request.user",
        primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/projects/{id}/transfer_request", "Request ownership transfer of the project to the requester", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "transfer_request")], perm=(PPERM, PP), action="transfer_request",
    dominant="group_role", checks=[admin_check(PPERM, PP, "transfer_request")],
    auth_summary="ProjectPermission.transfer_request_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/projects/{id}/transfer_start", "Start transferring project ownership to a member", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "transfer_start", 17)], perm=(PPERM, PP), action="transfer_start",
    dominant="owner_field",
    checks=[chk("owner_field", "IsObjectOwner()", PPERM, PP, "transfer_start_perms",
                note="project.owner == request.user; inherited enough_perms IsSuperUser() is OR-ed"),
            chk_line("membership_row", "project.memberships.filter(user=user).exists()", PAPI,
                     r"if not project\.memberships\.filter\(user=user\)\.exists\(\):", note="target user must be a member")],
    auth_summary="ProjectPermission.transfer_start_perms = IsObjectOwner() (project owner only; superuser bypass via enough_perms)",
    primitives=["IsObjectOwner", "IsSuperUser"], params=[ID])
rec("POST", "/api/v1/projects/{id}/leave", "Leave a project (remove own membership)", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "leave")], perm=(PPERM, PP), action="leave", dominant="membership_row",
    checks=[chk("membership_row", "CanLeaveProject()", PPERM, PP, "leave_perms",
                note="requires an existing Membership row for request.user; owner / last admin cannot leave")],
    auth_summary="ProjectPermission.leave_perms = CanLeaveProject(): request.user must hold a membership row in the project and not be owner/last admin",
    primitives=[("cls", PPERM, "CanLeaveProject"), ("func", "taiga/projects/services/members.py", "can_user_leave_project")], params=[ID])
rec("POST", "/api/v1/projects/{id}/create_template", "Create a project template from a project", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "create_template", 18)], perm=(PPERM, PP), action="create_template",
    dominant="global_role", checks=[super_check(PPERM, PP, "create_template")],
    auth_summary="ProjectPermission.create_template_perms = IsSuperUser()", primitives=SUPER_PRIMS, params=[ID])
rec("POST", "/api/v1/projects/bulk_update_order", "Reorder the requester's project list", viewset=PVS,
    handler=[("meth", PAPI, "ProjectViewSet", "bulk_update_order")], perm=(PPERM, PP), action=None, dominant="self_target",
    checks=[chk_line("self_target", "request.user.is_anonymous -> Unauthorized; order stored per request.user", PAPI,
                     r"services\.update_projects_order_in_bulk\(data, \"user_order\", request\.user\)")],
    auth_summary="No permission class call; anonymous rejected inline, ordering applied to request.user's own memberships")
rec("GET", "/api/v1/projects", "List projects visible to the requester", viewset=PVS, handler=[("meth", MIX, "ListModelMixin", "list", 4)],
    perm=(PPERM, PP), action="list", dominant="visibility_branch",
    checks=[any_check(PPERM, PP, "list"),
            chk_line("visibility_branch", "project_filters.CanViewProjectObjFilterBackend", PAPI, r"project_filters\.CanViewProjectObjFilterBackend,",
                     note="queryset filtered to public projects + projects where the user is a member")],
    auth_summary="ProjectPermission.list_perms = AllowAny(); CanViewProjectObjFilterBackend restricts rows to viewable projects",
    primitives=["AllowAny"], security=False)
rec("POST", "/api/v1/delete-owned-projects", "Delete all private projects owned by the requester", viewset=(PAPI, "DeleteOwnProjectsViewSet"),
    handler=[("meth", PAPI, "DeleteOwnProjectsViewSet", "create", 6)], perm=(PPERM, PP), action=None, dominant="self_target",
    checks=[chk_line("self_target", "Project.objects.filter(owner=request.user, is_private=True)", PAPI,
                     r"projects = models\.Project\.objects\.filter\(owner=request\.user, is_private=True\)")],
    auth_summary="No permission class; queryset limited to projects owned by request.user")
for pfx, vs, pc, hl in (("fans", "ProjectFansViewSet", "ProjectFansPermission", M_FANS_LIST),
                        ("watchers", "ProjectWatchersViewSet", "ProjectWatchersPermission", M_WATCHERS_LIST)):
    rec("GET", f"/api/v1/projects/{{resource_id}}/{pfx}", f"List project {pfx}", viewset=(PAPI, vs), handler=[hl],
        perm=(PPERM, pc), action="list", dominant="visibility_branch", checks=[hp_check(PPERM, pc, "list", "view_project")],
        auth_summary=f"{pc}.list_perms = HasProjectPerm('view_project'); enough_perms = IsProjectAdmin() | IsSuperUser()",
        primitives=HP_PRIMS_PKG, params=[P("resource_id")])

# memberships / invitations / roles
MP = "MembershipPermission"
MVS = (PAPI, "MembershipViewSet")
rec("GET", "/api/v1/memberships/{id}", "Get a project membership", viewset=MVS, handler=[M_RETRIEVE], perm=(PPERM, MP),
    action="retrieve", dominant="visibility_branch", checks=[hp_check(PPERM, MP, "retrieve", "view_project")],
    auth_summary="MembershipPermission.retrieve_perms = HasProjectPerm('view_project') on membership.project", primitives=HP_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/memberships", "Invite / add a member to a project", viewset=MVS,
    handler=[M_CREATE, ("meth", PAPI, "MembershipViewSet", "pre_save", 6)], perm=(PPERM, MP), action="create",
    dominant="group_role", checks=[admin_check(PPERM, MP, "create")],
    auth_summary="MembershipPermission.create_perms = IsProjectAdmin() evaluated on validator.object.project", primitives=ADMIN_PRIMS_PKG,
    body={"content": {"application/json": {"schema": {"type": "object", "properties": {"project": {"type": "integer"}, "role": {"type": "integer"}, "username": {"type": "string"}}}}}})
for m, act in (("PATCH", "partial_update"), ("DELETE", "destroy")):
    rec(m, "/api/v1/memberships/{id}", f"{'Update' if m == 'PATCH' else 'Remove'} a project membership", viewset=MVS,
        handler=[M_UPDATE if m == "PATCH" else M_DESTROY] + ([("meth", PAPI, "MembershipViewSet", "pre_delete")] if m == "DELETE" else []),
        perm=(PPERM, MP), action=act, dominant="group_role", checks=[admin_check(PPERM, MP, act)],
        auth_summary=f"MembershipPermission.{act}_perms = IsProjectAdmin() on membership.project", primitives=ADMIN_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/memberships/bulk_create", "Invite several members to a project", viewset=MVS,
    handler=[("meth", PAPI, "MembershipViewSet", "bulk_create", 15)], perm=(PPERM, MP), action="bulk_create",
    dominant="group_role", checks=[admin_check(PPERM, MP, "bulk_create")],
    auth_summary="MembershipPermission.bulk_create_perms = IsProjectAdmin() on Project(project_id)", primitives=ADMIN_PRIMS_PKG)
rec("POST", "/api/v1/memberships/{id}/resend_invitation", "Resend a membership invitation mail", viewset=MVS,
    handler=[("meth", PAPI, "MembershipViewSet", "resend_invitation")], perm=(PPERM, MP), action="resend_invitation",
    dominant="group_role", checks=[admin_check(PPERM, MP, "resend_invitation")],
    auth_summary="MembershipPermission.resend_invitation_perms = IsProjectAdmin() on invitation.project", primitives=ADMIN_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/memberships/remove_user_from_all_my_projects", "Remove a user from every project owned by the requester", viewset=MVS,
    handler=[("meth", PAPI, "MembershipViewSet", "remove_user_from_all_my_projects", 18)], perm=(PPERM, MP), action=None,
    dominant="owner_field",
    checks=[chk_line("owner_field", "Membership.objects.filter(project__owner=request.user, user=user)", PAPI,
                     r"memberships = models\.Membership\.objects\.filter\(project__owner=request\.user, user=user\)",
                     note="no permission class call; affected rows limited to projects whose owner is request.user")],
    auth_summary="No check_permissions; queryset limited to memberships of projects owned by request.user")
rec("GET", "/api/v1/invitations/{token}", "Get a pending invitation by its token", viewset=(PAPI, "InvitationViewSet"),
    handler=[M_RETRIEVE], perm=(PERM_BASE, "AllowAnyPermission"), action=None, dominant="anonymous",
    checks=[chk_line("anonymous", "permission_classes = (AllowAnyPermission,)", PAPI, r"permission_classes = \(AllowAnyPermission,\)"),
            chk("anonymous", "AllowAny()", PERM_BASE, "AllowAnyPermission", "enough_perms")],
    auth_summary="AllowAnyPermission (enough_perms = AllowAny()); lookup by secret invitation token", primitives=["AllowAny"],
    params=[P("token", "path", "string")], security=False)
RVS = (UAPI, "RolesViewSet")
RP = "RolesPermission"
rec("GET", "/api/v1/roles/{id}", "Get a project role", viewset=RVS, handler=[M_RETRIEVE], perm=(UPERM, RP), action="retrieve",
    dominant="visibility_branch", checks=[hp_check(UPERM, RP, "retrieve", "view_project")],
    auth_summary="RolesPermission.retrieve_perms = HasProjectPerm('view_project') on role.project", primitives=HP_PRIMS, params=[ID])
for m, act, h in (("POST", "create", [M_CREATE]), ("PATCH", "partial_update", [M_UPDATE]), ("DELETE", "destroy", [M_DESTROY, ("meth", UAPI, "RolesViewSet", "pre_delete", 8)])):
    rec(m, "/api/v1/roles" + ("" if m == "POST" else "/{id}"), f"{act.replace('_', ' ').capitalize()} a project role", viewset=RVS,
        handler=h, perm=(UPERM, RP), action=act, dominant="group_role", checks=[admin_check(UPERM, RP, act)],
        auth_summary=f"RolesPermission.{act}_perms = IsProjectAdmin() on role.project", primitives=ADMIN_PRIMS,
        params=[] if m == "POST" else [ID])

# project values (statuses etc.) and templates
for pfx, vs, pc, acts in (("userstory-statuses", "UserStoryStatusViewSet", "UserStoryStatusPermission", ["retrieve", "create", "partial_update", "destroy", "bulk_update_order"]),
                          ("points", "PointsViewSet", "PointsPermission", ["create", "destroy"]),
                          ("swimlanes", "SwimlaneViewSet", "SwimlanePermission", ["create", "partial_update"]),
                          ("issue-types", "IssueTypeViewSet", "IssueTypePermission", ["create"]),
                          ("priorities", "PriorityViewSet", "PriorityPermission", ["partial_update"])):
    for act in acts:
        m = {"retrieve": "GET", "create": "POST", "partial_update": "PATCH", "destroy": "DELETE", "bulk_update_order": "POST"}[act]
        path = f"/api/v1/{pfx}" + ("" if act in ("create",) else "/bulk_update_order" if act == "bulk_update_order" else "/{id}")
        h = {"retrieve": [M_RETRIEVE], "create": [M_CREATE], "partial_update": [M_UPDATE], "destroy": [M_DESTROY], "bulk_update_order": [M_BULK_ORDER]}[act]
        if act == "retrieve":
            rec(m, path, f"Get a {pfx} value", viewset=(PAPI, vs), handler=h, perm=(PPERM, pc), action=act,
                dominant="visibility_branch", checks=[hp_check(PPERM, pc, act, "view_project")],
                auth_summary=f"{pc}.retrieve_perms = HasProjectPerm('view_project')", primitives=HP_PRIMS_PKG, params=[ID])
        else:
            rec(m, path, f"{act.replace('_', ' ').capitalize()} {pfx} value(s)", viewset=(PAPI, vs), handler=h, perm=(PPERM, pc), action=act,
                dominant="group_role", checks=[admin_check(PPERM, pc, act)],
                auth_summary=f"{pc}.{act}_perms = IsProjectAdmin() (project values are admin-managed)", primitives=ADMIN_PRIMS_PKG,
                params=[] if path.endswith(pfx) or path.endswith("bulk_update_order") else [ID])
TVS = (PAPI, "ProjectTemplateViewSet")
TP = "ProjectTemplatePermission"
rec("GET", "/api/v1/project-templates/{id}", "Get a project template", viewset=TVS, handler=[M_RETRIEVE], perm=(PPERM, TP),
    action="retrieve", dominant="anonymous", checks=[any_check(PPERM, TP, "retrieve")],
    auth_summary="ProjectTemplatePermission.retrieve_perms = AllowAny()", primitives=["AllowAny"], params=[ID], security=False)
for m, act, h in (("POST", "create", [M_CREATE]), ("PATCH", "partial_update", [M_UPDATE]), ("DELETE", "destroy", [M_DESTROY])):
    rec(m, "/api/v1/project-templates" + ("" if m == "POST" else "/{id}"), f"{act.replace('_', ' ').capitalize()} a project template",
        viewset=TVS, handler=h, perm=(PPERM, TP), action=act, dominant="global_role", checks=[super_check(PPERM, TP, act)],
        auth_summary=f"ProjectTemplatePermission.{act}_perms = IsSuperUser() (site-wide superuser only)", primitives=SUPER_PRIMS,
        params=[] if m == "POST" else [ID])

# ============================================================================
# 6. WORK ITEMS: userstories / tasks / issues / epics / wiki / milestones
# ============================================================================
ITEMS = {
    "userstories": dict(api="taiga/projects/userstories/api.py", perm="taiga/projects/userstories/permissions.py", vs="UserStoryViewSet", pc="UserStoryPermission",
                        view="view_us", add="add_us", mod="modify_us", com="comment_us", dele="delete_us", label="user story",
                        voters="UserStoryVotersViewSet", vpc="UserStoryVotersPermission", watchers="UserStoryWatchersViewSet", wpc="UserStoryWatchersPermission"),
    "tasks": dict(api="taiga/projects/tasks/api.py", perm="taiga/projects/tasks/permissions.py", vs="TaskViewSet", pc="TaskPermission",
                  view="view_tasks", add="add_task", mod="modify_task", com="comment_task", dele="delete_task", label="task",
                  voters="TaskVotersViewSet", vpc="TaskVotersPermission", watchers="TaskWatchersViewSet", wpc="TaskWatchersPermission"),
    "issues": dict(api="taiga/projects/issues/api.py", perm="taiga/projects/issues/permissions.py", vs="IssueViewSet", pc="IssuePermission",
                   view="view_issues", add="add_issue", mod="modify_issue", com="comment_issue", dele="delete_issue", label="issue",
                   voters="IssueVotersViewSet", vpc="IssueVotersPermission", watchers="IssueWatchersViewSet", wpc="IssueWatchersPermission"),
    "epics": dict(api="taiga/projects/epics/api.py", perm="taiga/projects/epics/permissions.py", vs="EpicViewSet", pc="EpicPermission",
                  view="view_epics", add="add_epic", mod="modify_epic", com="comment_epic", dele="delete_epic", label="epic",
                  voters="EpicVotersViewSet", vpc="EpicVotersPermission", watchers="EpicWatchersViewSet", wpc="EpicWatchersPermission"),
    "wiki": dict(api="taiga/projects/wiki/api.py", perm="taiga/projects/wiki/permissions.py", vs="WikiViewSet", pc="WikiPagePermission",
                 view="view_wiki_pages", add="add_wiki_page", mod="modify_wiki_page", com="comment_wiki_page", dele="delete_wiki_page", label="wiki page",
                 voters=None, vpc=None, watchers="WikiWatchersViewSet", wpc="WikiPageWatchersPermission"),
}
CU_PRIMS = ["CommentAndOrUpdatePerm", "user_has_perm", "calculate_permissions"]

for pfx, it in ITEMS.items():
    api, pm, vs, pc, lab = it["api"], it["perm"], it["vs"], it["pc"], it["label"]
    # retrieve
    rec("GET", f"/api/v1/{pfx}/{{id}}", f"Get a {lab}", viewset=(api, vs), handler=[M_RETRIEVE], perm=(pm, pc), action="retrieve",
        dominant="visibility_branch", checks=[hp_check(pm, pc, "retrieve", it["view"])],
        auth_summary=f"{pc}.retrieve_perms = HasProjectPerm('{it['view']}'): member with view perm, or anyone when the project is public; enough_perms = IsProjectAdmin() | IsSuperUser()",
        primitives=HP_PRIMS_PKG, params=[ID])
    # create
    if pfx == "userstories":
        cexpr_checks = [chk("group_role", "HasProjectPerm('add_us_to_project') | HasProjectPerm('add_us')", pm, pc, "create_perms"),
                        hp_check(pm, pc, "create", "add_us_to_project"), hp_check(pm, pc, "create", "add_us")]
        csum = "UserStoryPermission.create_perms = HasProjectPerm('add_us_to_project') | HasProjectPerm('add_us'): member whose role grants add_us (role-based)"
    else:
        cexpr_checks = [hp_check(pm, pc, "create", it["add"])]
        csum = f"{pc}.create_perms = HasProjectPerm('{it['add']}'): member whose role grants {it['add']} (role-based); IsProjectAdmin()/IsSuperUser() bypass"
    rec("POST", f"/api/v1/{pfx}", f"Create a {lab}", viewset=(api, vs), handler=[M_CREATE], perm=(pm, pc), action="create",
        dominant="group_role", checks=cexpr_checks, auth_summary=csum, primitives=HP_PRIMS_PKG,
        body={"content": {"application/json": {"schema": {"type": "object", "properties": {"project": {"type": "integer"}, "subject": {"type": "string"}}}}}})
    # update (PATCH) -> CommentAndOrUpdatePerm
    rec("PATCH", f"/api/v1/{pfx}/{{id}}", f"Update a {lab} (partial) or add a comment", viewset=(api, vs),
        handler=[("meth", api, vs, "update", 10)] if pfx != "wiki" else [M_UPDATE], perm=(pm, pc), action="partial_update",
        dominant="group_role",
        checks=[chk("group_role", f"CommentAndOrUpdatePerm('{it['mod']}', '{it['com']}')", pm, pc, "partial_update_perms",
                    note=f"payload with only 'comment' needs role perm {it['com']}; anything else needs {it['mod']} (both role-based, members only)"),
                chk_line("group_role", f"user_has_perm(request.user, self.update_perm, project)", PERM_PKG,
                         r"return services\.user_has_perm\(request\.user, self\.update_perm, project\)")],
        auth_summary=f"{pc}.partial_update_perms = CommentAndOrUpdatePerm('{it['mod']}', '{it['com']}'): role perm {it['mod']} (or {it['com']} for comment-only payloads); moving to another project re-checks destroy/create",
        primitives=CU_PRIMS, params=[ID])
    # destroy
    rec("DELETE", f"/api/v1/{pfx}/{{id}}", f"Delete a {lab}", viewset=(api, vs), handler=[M_DESTROY], perm=(pm, pc), action="destroy",
        dominant="group_role", checks=[hp_check(pm, pc, "destroy", it["dele"])],
        auth_summary=f"{pc}.destroy_perms = HasProjectPerm('{it['dele']}') (role-based)", primitives=HP_PRIMS_PKG, params=[ID])
    # watch (self in project)
    rec("POST", f"/api/v1/{pfx}/{{id}}/watch", f"Watch a {lab} (requester)", viewset=(api, vs), handler=[M_WATCH], perm=(pm, pc), action="watch",
        dominant="compound_and",
        checks=[chk("compound_and", f"IsAuthenticated() & HasProjectPerm('{it['view']}')", pm, pc, "watch_perms"),
                auth_check(pm, pc, "watch"), hp_check(pm, pc, "watch", it["view"])],
        auth_summary=f"{pc}.watch_perms = IsAuthenticated() & HasProjectPerm('{it['view']}'): logged-in user who can view the {lab}; adds request.user as watcher",
        primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
    if pfx != "wiki":
        rec("POST", f"/api/v1/{pfx}/{{id}}/upvote", f"Upvote a {lab} (requester)", viewset=(api, vs), handler=[M_UPVOTE], perm=(pm, pc), action="upvote",
            dominant="compound_and",
            checks=[chk("compound_and", f"IsAuthenticated() & HasProjectPerm('{it['view']}')", pm, pc, "upvote_perms"),
                    auth_check(pm, pc, "upvote"), hp_check(pm, pc, "upvote", it["view"])],
            auth_summary=f"{pc}.upvote_perms = IsAuthenticated() & HasProjectPerm('{it['view']}'); vote recorded for request.user",
            primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
        # bulk_create
        bc_checks = ([chk("compound_and", "IsAuthenticated() & (HasProjectPerm('add_us_to_project') | HasProjectPerm('add_us'))", pm, pc, "bulk_create_perms"),
                      auth_check(pm, pc, "bulk_create"), hp_check(pm, pc, "bulk_create", "add_us")]
                     if pfx == "userstories" else [hp_check(pm, pc, "bulk_create", it["add"])])
        rec("POST", f"/api/v1/{pfx}/bulk_create", f"Create several {lab}s in a project", viewset=(api, vs),
            handler=[("meth", api, vs, "bulk_create", 9)], perm=(pm, pc), action="bulk_create",
            dominant="compound_and" if pfx == "userstories" else "group_role", checks=bc_checks,
            auth_summary=f"{pc}.bulk_create_perms checked against Project(project_id) from the body: role perm {it['add']}",
            primitives=(["IsAuthenticated"] if pfx == "userstories" else []) + HP_PRIMS_PKG,
            body={"content": {"application/json": {"schema": {"type": "object", "properties": {"project_id": {"type": "integer"}, f"bulk_{pfx}": {"type": "string"}}}}}})
    # voters / watchers lists
    if it["voters"]:
        rec("GET", f"/api/v1/{pfx}/{{resource_id}}/voters", f"List voters of a {lab}", viewset=(api, it["voters"]), handler=[M_VOTERS_LIST],
            perm=(pm, it["vpc"]), action="list", dominant="visibility_branch", checks=[hp_check(pm, it["vpc"], "list", it["view"])],
            auth_summary=f"{it['vpc']}.list_perms = HasProjectPerm('{it['view']}') on the parent {lab}", primitives=HP_PRIMS_PKG, params=[P("resource_id")])
    if pfx in ("issues", "wiki", "milestones"):
        rec("GET", f"/api/v1/{pfx}/{{resource_id}}/watchers", f"List watchers of a {lab}", viewset=(api, it["watchers"]), handler=[M_WATCHERS_LIST],
            perm=(pm, it["wpc"]), action="list", dominant="visibility_branch", checks=[hp_check(pm, it["wpc"], "list", it["view"])],
            auth_summary=f"{it['wpc']}.list_perms = HasProjectPerm('{it['view']}') on the parent {lab}", primitives=HP_PRIMS_PKG, params=[P("resource_id")])

# userstories extras
US, USP = ITEMS["userstories"]["api"], ITEMS["userstories"]["perm"]
rec("GET", "/api/v1/userstories/by_ref", "Get a user story by project ref", viewset=(US, "UserStoryViewSet"), handler=[M_BYREF, M_RETRIEVE],
    perm=(USP, "UserStoryPermission"), action="by_ref", dominant="visibility_branch", checks=[hp_check(USP, "UserStoryPermission", "by_ref", "view_us")],
    auth_summary="UserStoryPermission.by_ref_perms = HasProjectPerm('view_us')", primitives=HP_PRIMS_PKG,
    params=[P("ref", "query", "integer"), PROJ_Q, P("project__slug", "query", "string", False)])
for act, h in (("bulk_update_backlog_order", ("meth", US, "UserStoryViewSet", "bulk_update_backlog_order", 11)),
               ("bulk_update_milestone", ("meth", US, "UserStoryViewSet", "bulk_update_milestone", 10))):
    pa = "bulk_update_order" if act == "bulk_update_backlog_order" else act
    rec("POST", f"/api/v1/userstories/{act}", f"User stories: {act.replace('_', ' ')}", viewset=(US, "UserStoryViewSet"), handler=[h],
        perm=(USP, "UserStoryPermission"), action=pa, dominant="group_role", checks=[hp_check(USP, "UserStoryPermission", pa, "modify_us")],
        auth_summary=f"UserStoryPermission.{pa}_perms = HasProjectPerm('modify_us') on Project(project_id) from body (role-based)", primitives=HP_PRIMS_PKG)
# tasks / issues extras
TK, TKP = ITEMS["tasks"]["api"], ITEMS["tasks"]["perm"]
rec("POST", "/api/v1/tasks/{id}/promote_to_user_story", "Promote a task to a user story", viewset=(TK, "TaskViewSet"), handler=[M_PROMOTE],
    perm=(TKP, "TaskPermission"), action="promote_to_us", dominant="compound_and",
    checks=[chk("compound_and", "IsAuthenticated() & HasProjectPerm('view_tasks')", TKP, "TaskPermission", "promote_to_us_perms"),
            auth_check(TKP, "TaskPermission", "promote_to_us"), hp_check(TKP, "TaskPermission", "promote_to_us", "view_tasks")],
    auth_summary="TaskPermission.promote_to_us_perms = IsAuthenticated() & HasProjectPerm('view_tasks') on Project(project_id); note: only a view perm is required to create a US and delete the task",
    primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
IS, ISP = ITEMS["issues"]["api"], ITEMS["issues"]["perm"]
rec("POST", "/api/v1/issues/{id}/promote_to_user_story", "Promote an issue to a user story", viewset=(IS, "IssueViewSet"), handler=[M_PROMOTE],
    perm=(ISP, "IssuePermission"), action="promote_to_us", dominant="compound_and",
    checks=[chk("compound_and", "IsAuthenticated() & HasProjectPerm('add_us')", ISP, "IssuePermission", "promote_to_us_perms"),
            auth_check(ISP, "IssuePermission", "promote_to_us"), hp_check(ISP, "IssuePermission", "promote_to_us", "add_us")],
    auth_summary="IssuePermission.promote_to_us_perms = IsAuthenticated() & HasProjectPerm('add_us') (role-based)",
    primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/issues/bulk_update_milestone", "Move several issues to a sprint", viewset=(IS, "IssueViewSet"),
    handler=[("meth", IS, "IssueViewSet", "bulk_update_milestone", 10)], perm=(ISP, "IssuePermission"), action="bulk_update_milestone",
    dominant="group_role", checks=[hp_check(ISP, "IssuePermission", "bulk_update_milestone", "modify_issue")],
    auth_summary="IssuePermission.bulk_update_milestone_perms = HasProjectPerm('modify_issue') on Project(project_id)", primitives=HP_PRIMS_PKG)
# epics related user stories
EP, EPP = ITEMS["epics"]["api"], ITEMS["epics"]["perm"]
ERVS = (EP, "EpicRelatedUserStoryViewSet")
ERP = "EpicRelatedUserStoryPermission"
rec("POST", "/api/v1/epics/{epic}/related_userstories", "Link a user story to an epic", viewset=ERVS, handler=[("meth", EP, "EpicRelatedUserStoryViewSet", "create"), M_CREATE],
    perm=(EPP, ERP), action="create", dominant="group_role", checks=[hp_check(EPP, ERP, "create", "modify_epic")],
    auth_summary="EpicRelatedUserStoryPermission.create_perms = HasProjectPerm('modify_epic') (role-based)", primitives=HP_PRIMS_PKG, params=[P("epic")])
rec("DELETE", "/api/v1/epics/{epic}/related_userstories/{user_story}", "Unlink a user story from an epic", viewset=ERVS, handler=[M_DESTROY],
    perm=(EPP, ERP), action="destroy", dominant="group_role", checks=[hp_check(EPP, ERP, "destroy", "modify_epic")],
    auth_summary="EpicRelatedUserStoryPermission.destroy_perms = HasProjectPerm('modify_epic')", primitives=HP_PRIMS_PKG, params=[P("epic"), P("user_story")])
rec("POST", "/api/v1/epics/{epic}/related_userstories/bulk_create", "Create and link several user stories to an epic", viewset=ERVS,
    handler=[("meth", EP, "EpicRelatedUserStoryViewSet", "bulk_create", 13)], perm=(EPP, ERP), action="bulk_create", dominant="group_role",
    checks=[hp_check(EPP, ERP, "bulk_create", "modify_epic")],
    auth_summary="EpicRelatedUserStoryPermission.bulk_create_perms = HasProjectPerm('modify_epic') on Project(project_id)", primitives=HP_PRIMS_PKG, params=[P("epic")])
# wiki extras
WK, WKP = ITEMS["wiki"]["api"], ITEMS["wiki"]["perm"]
rec("GET", "/api/v1/wiki/by_slug", "Get a wiki page by slug", viewset=(WK, "WikiViewSet"), handler=[("meth", WK, "WikiViewSet", "by_slug"), M_RETRIEVE],
    perm=(WKP, "WikiPagePermission"), action="by_slug", dominant="visibility_branch", checks=[hp_check(WKP, "WikiPagePermission", "by_slug", "view_wiki_pages")],
    auth_summary="WikiPagePermission.by_slug_perms = HasProjectPerm('view_wiki_pages')", primitives=HP_PRIMS_PKG,
    params=[P("slug", "query", "string"), PROJ_Q])
rec("POST", "/api/v1/wiki/render", "Render wiki markdown for a project", viewset=(WK, "WikiViewSet"), handler=[("meth", WK, "WikiViewSet", "render")],
    perm=(WKP, "WikiPagePermission"), action="render", dominant="anonymous", checks=[any_check(WKP, "WikiPagePermission", "render")],
    auth_summary="WikiPagePermission.render_perms = AllowAny() (project only used as render context)", primitives=["AllowAny"], security=False)
WLVS = (WK, "WikiLinkViewSet")
WLP = "WikiLinkPermission"
rec("GET", "/api/v1/wiki-links/{id}", "Get a wiki link", viewset=WLVS, handler=[M_RETRIEVE], perm=(WKP, WLP), action="retrieve",
    dominant="visibility_branch", checks=[hp_check(WKP, WLP, "retrieve", "view_wiki_links")],
    auth_summary="WikiLinkPermission.retrieve_perms = HasProjectPerm('view_wiki_links')", primitives=HP_PRIMS_PKG, params=[ID])
for m, act, perm_name, h in (("POST", "create", "add_wiki_link", [M_CREATE, ("meth", WK, "WikiLinkViewSet", "post_save")]),
                             ("PATCH", "partial_update", "modify_wiki_link", [M_UPDATE]), ("DELETE", "destroy", "delete_wiki_link", [M_DESTROY])):
    rec(m, "/api/v1/wiki-links" + ("" if m == "POST" else "/{id}"), f"{act.replace('_', ' ').capitalize()} a wiki link", viewset=WLVS, handler=h,
        perm=(WKP, WLP), action=act, dominant="group_role", checks=[hp_check(WKP, WLP, act, perm_name)] +
        ([chk("group_role", "HasProjectPerm('add_wiki_page')", WKP, WLP, "create_wiki_page_perms", note="post_save also creates the page only if this perm holds")] if m == "POST" else []),
        auth_summary=f"WikiLinkPermission.{act}_perms = HasProjectPerm('{perm_name}') (role-based)", primitives=HP_PRIMS_PKG, params=[] if m == "POST" else [ID])
# milestones
ML = "taiga/projects/milestones/api.py"
MLP = "taiga/projects/milestones/permissions.py"
MLVS = (ML, "MilestoneViewSet")
MLPC = "MilestonePermission"
rec("GET", "/api/v1/milestones/{id}", "Get a milestone (sprint)", viewset=MLVS, handler=[M_RETRIEVE], perm=(MLP, MLPC), action="retrieve",
    dominant="visibility_branch", checks=[hp_check(MLP, MLPC, "retrieve", "view_milestones")],
    auth_summary="MilestonePermission.retrieve_perms = HasProjectPerm('view_milestones')", primitives=HP_PRIMS_PKG, params=[ID])
rec("GET", "/api/v1/milestones/{id}/stats", "Get sprint stats", viewset=MLVS, handler=[("meth", ML, "MilestoneViewSet", "stats", 6)], perm=(MLP, MLPC), action="stats",
    dominant="visibility_branch", checks=[hp_check(MLP, MLPC, "stats", "view_milestones")],
    auth_summary="MilestonePermission.stats_perms = HasProjectPerm('view_milestones')", primitives=HP_PRIMS_PKG, params=[ID])
for m, act, perm_name, h in (("POST", "create", "add_milestone", [M_CREATE]), ("PATCH", "partial_update", "modify_milestone", [M_UPDATE]),
                             ("DELETE", "destroy", "delete_milestone", [M_DESTROY])):
    rec(m, "/api/v1/milestones" + ("" if m == "POST" else "/{id}"), f"{act.replace('_', ' ').capitalize()} a milestone", viewset=MLVS, handler=h,
        perm=(MLP, MLPC), action=act, dominant="group_role", checks=[hp_check(MLP, MLPC, act, perm_name)],
        auth_summary=f"MilestonePermission.{act}_perms = HasProjectPerm('{perm_name}') (role-based)", primitives=HP_PRIMS_PKG, params=[] if m == "POST" else [ID])
rec("POST", "/api/v1/milestones/{id}/watch", "Watch a milestone (requester)", viewset=MLVS, handler=[M_WATCH], perm=(MLP, MLPC), action="watch",
    dominant="compound_and", checks=[chk("compound_and", "IsAuthenticated() & HasProjectPerm('view_milestones')", MLP, MLPC, "watch_perms"),
                                     auth_check(MLP, MLPC, "watch"), hp_check(MLP, MLPC, "watch", "view_milestones")],
    auth_summary="MilestonePermission.watch_perms = IsAuthenticated() & HasProjectPerm('view_milestones')", primitives=["IsAuthenticated"] + HP_PRIMS_PKG, params=[ID])
rec("POST", "/api/v1/milestones/{id}/move_userstories_to_sprint", "Move user stories into a sprint", viewset=MLVS,
    handler=[("meth", ML, "MilestoneViewSet", "move_userstories_to_sprint", 18)], perm=(MLP, MLPC), action="move_related_items", dominant="group_role",
    checks=[hp_check(MLP, MLPC, "move_related_items", "modify_milestone"), hp_check(MLP, MLPC, "move_uss_to_sprint", "modify_us")],
    auth_summary="MilestonePermission.move_related_items_perms = HasProjectPerm('modify_milestone') on the milestone, then move_uss_to_sprint_perms = HasProjectPerm('modify_us') on the target project",
    primitives=HP_PRIMS_PKG, params=[ID])
rec("GET", "/api/v1/milestones/{resource_id}/watchers", "List watchers of a milestone", viewset=(ML, "MilestoneWatchersViewSet"), handler=[M_WATCHERS_LIST],
    perm=(MLP, "MilestoneWatchersPermission"), action="list", dominant="visibility_branch",
    checks=[hp_check(MLP, "MilestoneWatchersPermission", "list", "view_milestones")],
    auth_summary="MilestoneWatchersPermission.list_perms = HasProjectPerm('view_milestones')", primitives=HP_PRIMS_PKG, params=[P("resource_id")])
# custom attributes
CA = "taiga/projects/custom_attributes/api.py"
CAP = "taiga/projects/custom_attributes/permissions.py"
rec("POST", "/api/v1/userstory-custom-attributes", "Create a user story custom attribute", viewset=(CA, "UserStoryCustomAttributeViewSet"), handler=[M_CREATE],
    perm=(CAP, "UserStoryCustomAttributePermission"), action="create", dominant="group_role", checks=[admin_check(CAP, "UserStoryCustomAttributePermission", "create")],
    auth_summary="UserStoryCustomAttributePermission.create_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS)
rec("DELETE", "/api/v1/userstory-custom-attributes/{id}", "Delete a user story custom attribute", viewset=(CA, "UserStoryCustomAttributeViewSet"), handler=[M_DESTROY],
    perm=(CAP, "UserStoryCustomAttributePermission"), action="destroy", dominant="group_role", checks=[admin_check(CAP, "UserStoryCustomAttributePermission", "destroy")],
    auth_summary="UserStoryCustomAttributePermission.destroy_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS, params=[ID])
rec("GET", "/api/v1/userstories/custom-attributes-values/{id}", "Get custom attribute values of a user story", viewset=(CA, "UserStoryCustomAttributesValuesViewSet"),
    handler=[M_RETRIEVE], perm=(CAP, "UserStoryCustomAttributesValuesPermission"), action="retrieve", dominant="visibility_branch",
    checks=[hp_check(CAP, "UserStoryCustomAttributesValuesPermission", "retrieve", "view_us")],
    auth_summary="UserStoryCustomAttributesValuesPermission.retrieve_perms = HasProjectPerm('view_us')", primitives=HP_PRIMS, params=[P("id", desc="user story id")])
rec("PATCH", "/api/v1/userstories/custom-attributes-values/{id}", "Update custom attribute values of a user story", viewset=(CA, "UserStoryCustomAttributesValuesViewSet"),
    handler=[M_UPDATE], perm=(CAP, "UserStoryCustomAttributesValuesPermission"), action="partial_update", dominant="group_role",
    checks=[hp_check(CAP, "UserStoryCustomAttributesValuesPermission", "partial_update", "modify_us")],
    auth_summary="UserStoryCustomAttributesValuesPermission.partial_update_perms = HasProjectPerm('modify_us') (role-based)", primitives=HP_PRIMS, params=[P("id", desc="user story id")])

# ============================================================================
# 7. SELF-SCOPED RESOURCES and misc
# ============================================================================
ST = "taiga/userstorage/api.py"
STP = "taiga/userstorage/permissions.py"
SVS = (ST, "StorageEntriesViewSet")
SPC = "StorageEntriesPermission"
for m, path, act, summ, h in (("GET", "/api/v1/user-storage", "list", "List the requester's storage entries", [("meth", MIX, "ListModelMixin", "list", 4)]),
                              ("GET", "/api/v1/user-storage/{key}", "retrieve", "Get one of the requester's storage entries", [M_RETRIEVE]),
                              ("POST", "/api/v1/user-storage", "create", "Create a storage entry for the requester", [("meth", ST, "StorageEntriesViewSet", "create"), ("meth", ST, "StorageEntriesViewSet", "pre_save")]),
                              ("PUT", "/api/v1/user-storage/{key}", "update", "Update one of the requester's storage entries", [M_UPDATE]),
                              ("DELETE", "/api/v1/user-storage/{key}", "destroy", "Delete one of the requester's storage entries", [M_DESTROY])):
    rec(m, path, summ, viewset=SVS, handler=[("meth", ST, "StorageEntriesViewSet", "get_queryset")] + h, perm=(STP, SPC), action=None,
        dominant="self_target",
        checks=[chk("auth_only", "IsAuthenticated()", STP, SPC, "enough_perms",
                    note="no per-action *_perms; global_perms = DenyAll() makes the action permset False, so enough_perms IsAuthenticated() alone decides"),
                chk_line("self_target", "self.request.user.storage_entries.all()", ST, r"return self\.request\.user\.storage_entries\.all\(\)",
                         note="queryset limited to the requester's own rows; owner forced in pre_save")],
        auth_summary="StorageEntriesPermission: IsAuthenticated (enough_perms) only; get_queryset restricts to request.user.storage_entries and pre_save sets owner",
        primitives=["IsAuthenticated", "DenyAll", "ResourcePermission.check"], params=[P("key", "path", "string")] if "{key}" in path else [])
NP = "taiga/projects/notifications/api.py"
NPP = "taiga/projects/notifications/permissions.py"
for m, path, act, summ, h in (("GET", "/api/v1/notify-policies", "list", "List the requester's notify policies", [("meth", MIX, "ListModelMixin", "list", 4)]),
                              ("GET", "/api/v1/notify-policies/{id}", "retrieve", "Get one of the requester's notify policies", [M_RETRIEVE]),
                              ("PATCH", "/api/v1/notify-policies/{id}", "partial_update", "Update one of the requester's notify policies", [M_UPDATE])):
    rec(m, path, summ, viewset=(NP, "NotifyPolicyViewSet"), handler=[("meth", NP, "NotifyPolicyViewSet", "get_queryset")] + h, perm=(NPP, "NotifyPolicyPermission"),
        action=act, dominant="self_target",
        checks=[auth_check(NPP, "NotifyPolicyPermission", act),
                chk_line("self_target", "NotifyPolicy.objects.filter(user=self.request.user)", NP, r"return models\.NotifyPolicy\.objects\.filter\(user=self\.request\.user\)\.filter\(",
                         note="rows limited to the requester's own policies in projects they own or belong to")],
        auth_summary=f"NotifyPolicyPermission.{act}_perms = IsAuthenticated(); get_queryset filters user=request.user",
        primitives=["IsAuthenticated"], params=[ID] if "{id}" in path else [])
for m, path, summ, h in (("GET", "/api/v1/web-notifications", "List the requester's web notifications", [("meth", NP, "WebNotificationsViewSet", "list", 8)]),
                         ("POST", "/api/v1/web-notifications/set-as-read", "Mark all of the requester's web notifications as read", [("meth", NP, "WebNotificationsViewSet", "post")]),
                         ("PATCH", "/api/v1/web-notifications/{resource_id}/set-as-read", "Mark one web notification as read", [("meth", NP, "WebNotificationsViewSet", "patch")])):
    checks = [chk_line("self_target", "WebNotificationsViewSet.check_permissions (request.user.pk == obj.user_id)", NP,
                       r"def check_permissions\(self, request, obj=None\):", note="overridden check returns a boolean and is called without obj; it never raises")]
    if m == "PATCH":
        checks.append(chk_line("auth_only", "get_object_or_error(self.resource_model, request.user, pk=resource_id)", NP,
                               r"resource = get_object_or_error\(self\.resource_model, request\.user, pk=resource_id\)",
                               note="lookup by pk only; the notification's user_id is not compared with request.user in this handler"))
    else:
        checks.append(chk_line("self_target", "WebNotification.objects.filter(user=self.request.user)", NP,
                               r"models\.WebNotification\.objects\\?" if False else r"\.filter\(user=self\.request\.user\)"))
    rec(m, path, summ, viewset=(NP, "WebNotificationsViewSet"), handler=[("meth", NP, "WebNotificationsViewSet", "check_permissions")] + h,
        perm=(NPP, "NotifyPolicyPermission"), action=None, dominant="self_target" if m != "PATCH" else "auth_only", checks=checks,
        auth_summary=("No permission class; " + ("rows filtered by user=request.user" if m != "PATCH" else
                      "custom check_permissions is invoked with obj=None (boolean, not enforced); row fetched by pk via get_object_or_error (401 for anonymous, else any id)")),
        params=[P("resource_id")] if "{resource_id}" in path else [], extra={"unlocated": False})
PS = "taiga/projects/settings/api.py"
PSP = "taiga/projects/settings/permissions.py"
for m, path, act, summ, h in (("GET", "/api/v1/user-project-settings", "list", "List the requester's per-project settings", [("meth", PS, "UserProjectSettingsViewSet", "list")]),
                              ("PATCH", "/api/v1/user-project-settings/{id}", "partial_update", "Update one of the requester's per-project settings", [M_UPDATE])):
    rec(m, path, summ, viewset=(PS, "UserProjectSettingsViewSet"), handler=[("meth", PS, "UserProjectSettingsViewSet", "get_queryset")] + h,
        perm=(PSP, "UserProjectSettingsPermission"), action=act, dominant="self_target",
        checks=[auth_check(PSP, "UserProjectSettingsPermission", act),
                chk_line("self_target", "UserProjectSettings.objects.filter(user=self.request.user)", PS, r"return models\.UserProjectSettings\.objects\.filter\(user=self\.request\.user\)")],
        auth_summary=f"UserProjectSettingsPermission.{act}_perms = IsAuthenticated(); queryset filtered to user=request.user and projects they belong to",
        primitives=["IsAuthenticated"], params=[ID] if "{id}" in path else [])
# webhooks
WH = "taiga/webhooks/api.py"
WHP = "taiga/webhooks/permissions.py"
WHVS = (WH, "WebhookViewSet")
for m, path, act, summ, h in (("GET", "/api/v1/webhooks/{id}", "retrieve", "Get a project webhook", [M_RETRIEVE]),
                              ("POST", "/api/v1/webhooks", "create", "Create a project webhook", [M_CREATE]),
                              ("PATCH", "/api/v1/webhooks/{id}", "partial_update", "Update a project webhook", [M_UPDATE]),
                              ("DELETE", "/api/v1/webhooks/{id}", "destroy", "Delete a project webhook", [M_DESTROY]),
                              ("POST", "/api/v1/webhooks/{id}/test", "test", "Send a test payload for a webhook", [("meth", WH, "WebhookViewSet", "test")])):
    rec(m, path, summ, viewset=WHVS, handler=h, perm=(WHP, "WebhookPermission"), action=act, dominant="group_role",
        checks=[admin_check(WHP, "WebhookPermission", act)],
        auth_summary=f"WebhookPermission.{act}_perms = IsProjectAdmin() on webhook.project", primitives=ADMIN_PRIMS, params=[ID] if "{id}" in path else [])
for m, path, act, summ, h in (("GET", "/api/v1/webhooklogs/{id}", "retrieve", "Get a webhook delivery log", [M_RETRIEVE]),
                              ("POST", "/api/v1/webhooklogs/{id}/resend", "resend", "Resend a webhook delivery", [("meth", WH, "WebhookLogViewSet", "resend", 8)])):
    rec(m, path, summ, viewset=(WH, "WebhookLogViewSet"), handler=h, perm=(WHP, "WebhookLogPermission"), action=act, dominant="group_role",
        checks=[chk("group_role", "IsWebhookProjectAdmin()", WHP, "WebhookLogPermission", f"{act}_perms", note="is_project_admin(request.user, obj.webhook.project)")],
        auth_summary=f"WebhookLogPermission.{act}_perms = IsWebhookProjectAdmin(): admin of the webhook's project",
        primitives=[("cls", WHP, "IsWebhookProjectAdmin"), "is_project_admin", "_get_user_project_membership"], params=[ID])
# external apps / tokens
EA = "taiga/external_apps/api.py"
EAP = "taiga/external_apps/permissions.py"
rec("GET", "/api/v1/applications/{id}", "Get an external application", viewset=(EA, "Application"), handler=[M_RETRIEVE], perm=(EAP, "ApplicationPermission"),
    action="retrieve", dominant="auth_only", checks=[auth_check(EAP, "ApplicationPermission", "retrieve")],
    auth_summary="ApplicationPermission.retrieve_perms = IsAuthenticated() (no object condition)", primitives=["IsAuthenticated"], params=[P("id", "path", "string")])
rec("GET", "/api/v1/applications/{id}/token", "Get or create the requester's token for an application", viewset=(EA, "Application"),
    handler=[("meth", EA, "Application", "token")], perm=(EAP, "ApplicationPermission"), action="token", dominant="self_target",
    checks=[auth_check(EAP, "ApplicationPermission", "token"),
            chk_line("self_target", "ApplicationToken.objects.get(user=request.user, application=application)", EA, r"application_token = models\.ApplicationToken\.objects\.get\(user=request\.user, application=application\)")],
    auth_summary="ApplicationPermission.token_perms = IsAuthenticated(); token row is the requester's own", primitives=["IsAuthenticated"], params=[P("id", "path", "string")])
ATVS = (EA, "ApplicationToken")
ATP = "ApplicationTokenPermission"
rec("GET", "/api/v1/application-tokens", "List the requester's application tokens", viewset=ATVS, handler=[("meth", EA, "ApplicationToken", "get_queryset"), ("meth", MIX, "ListModelMixin", "list", 4)],
    perm=(EAP, ATP), action="list", dominant="self_target",
    checks=[auth_check(EAP, ATP, "list"), chk_line("self_target", "ApplicationToken.objects.filter(user=self.request.user)", EA, r"queryset = models\.ApplicationToken\.objects\.filter\(user=self\.request\.user\)")],
    auth_summary="ApplicationTokenPermission.list_perms = IsAuthenticated(); queryset filtered user=request.user", primitives=["IsAuthenticated"])
for m, act, summ, h in (("GET", "retrieve", "Get one of the requester's application tokens", [M_RETRIEVE]), ("DELETE", "destroy", "Revoke one of the requester's application tokens", [M_DESTROY])):
    rec(m, "/api/v1/application-tokens/{id}", summ, viewset=ATVS, handler=[("meth", EA, "ApplicationToken", "get_queryset")] + h, perm=(EAP, ATP), action=act,
        dominant="owner_field",
        checks=[chk("compound_and", "IsAuthenticated() & CanUseToken()", EAP, ATP, f"{act}_perms"), auth_check(EAP, ATP, act),
                chk("owner_field", "CanUseToken()", EAP, ATP, f"{act}_perms", note="request.user == obj.user; inherited IsSuperUser enough_perms bypass")],
        auth_summary=f"ApplicationTokenPermission.{act}_perms = IsAuthenticated() & CanUseToken() (token.user == request.user); queryset also filtered by user",
        primitives=[("cls", EAP, "CanUseToken"), "IsAuthenticated"], params=[ID])
rec("POST", "/api/v1/application-tokens/authorize", "Authorize an application for the requester (auth code)", viewset=ATVS, handler=[("meth", EA, "ApplicationToken", "authorize")],
    perm=(EAP, ATP), action=None, dominant="self_target",
    checks=[chk_line("self_target", "request.user.is_anonymous -> NotAuthenticated; authorize_token(application_id, request.user, state)", EA,
                     r"application_token = services\.authorize_token\(application_id, request\.user, state\)")],
    auth_summary="No permission class call; anonymous rejected inline; token created for request.user")
rec("POST", "/api/v1/application-tokens/validate", "Exchange an auth code for an access token", viewset=ATVS, handler=[("meth", EA, "ApplicationToken", "validate")],
    perm=(EAP, ATP), action=None, dominant="anonymous",
    checks=[chk_line("anonymous", "get_object_or_404(ApplicationToken, application__id=..., auth_code=..., state=...)", EA, r"application_token = get_object_or_404\(models\.ApplicationToken,",
                     note="no user check; possession of (application, auth_code, state) suffices")],
    auth_summary="No permission check; secret auth_code + state identify the token", security=False)
# feedback / contact / importer / exporter
FB = "taiga/feedback/api.py"
FBP = "taiga/feedback/permissions.py"
rec("POST", "/api/v1/feedback", "Send feedback as the requester", viewset=(FB, "FeedbackViewSet"), handler=[("meth", FB, "FeedbackViewSet", "create", 8)],
    perm=(FBP, "FeedbackPermission"), action="create", dominant="auth_only", checks=[auth_check(FBP, "FeedbackPermission", "create")],
    auth_summary="FeedbackPermission.create_perms = IsAuthenticated() (no object)", primitives=["IsAuthenticated"])
CT = "taiga/projects/contact/api.py"
CTP = "taiga/projects/contact/permissions.py"
rec("POST", "/api/v1/contact", "Send a contact message to a project's admins", viewset=(CT, "ContactViewSet"), handler=[M_CREATE, ("meth", CT, "ContactViewSet", "pre_save")],
    perm=(CTP, "ContactPermission"), action="create", dominant="setting_dependent",
    checks=[chk("setting_dependent", "IsContactActivated()", CTP, "ContactPermission", "create_perms",
                note="project.is_contact_activated must be on; private project additionally requires a membership row for request.user; public project any authenticated user"),
            chk_line("membership_row", "obj.project.cached_memberships_for_user(request.user)", CTP, r"return obj\.project\.cached_memberships_for_user\(request\.user\)")],
    auth_summary="ContactPermission.create_perms = IsContactActivated(): authenticated + project contact enabled; membership required only for private projects",
    primitives=[("cls", CTP, "IsContactActivated")])
EX = "taiga/export_import/api.py"
EXP = "taiga/export_import/permissions.py"
rec("GET", "/api/v1/exporter/{id}", "Export a project dump", viewset=(EX, "ProjectExporterViewSet"), handler=[("meth", EX, "ProjectExporterViewSet", "retrieve", 10)],
    perm=(EXP, "ImportExportPermission"), action="export_project", dominant="group_role", checks=[admin_check(EXP, "ImportExportPermission", "export_project")],
    auth_summary="ImportExportPermission.export_project_perms = IsProjectAdmin()", primitives=ADMIN_PRIMS, params=[ID])
rec("POST", "/api/v1/importer", "Import a project dump (new project owned by requester)", viewset=(EX, "ProjectImporterViewSet"), handler=[("meth", EX, "ProjectImporterViewSet", "create", 8)],
    perm=(EXP, "ImportExportPermission"), action="import_project", dominant="auth_only", checks=[auth_check(EXP, "ImportExportPermission", "import_project")],
    auth_summary="ImportExportPermission.import_project_perms = IsAuthenticated(); owner defaults to request.user", primitives=["IsAuthenticated"])
rec("POST", "/api/v1/importer/load_dump", "Load a full project dump file", viewset=(EX, "ProjectImporterViewSet"), handler=[("meth", EX, "ProjectImporterViewSet", "load_dump", 10)],
    perm=(EXP, "ImportExportPermission"), action="load_dump", dominant="auth_only", checks=[auth_check(EXP, "ImportExportPermission", "load_dump")],
    auth_summary="ImportExportPermission.load_dump_perms = IsAuthenticated()", primitives=["IsAuthenticated"])
for act, summ in (("us", "Import a user story into an existing project"), ("milestone", "Import a milestone into an existing project")):
    rec("POST", f"/api/v1/importer/{{id}}/{act}", summ, viewset=(EX, "ProjectImporterViewSet"), handler=[("meth", EX, "ProjectImporterViewSet", act, 6)],
        perm=(EXP, "ImportExportPermission"), action="import_item", dominant="group_role", checks=[admin_check(EXP, "ImportExportPermission", "import_item")],
        auth_summary="ImportExportPermission.import_item_perms = IsProjectAdmin() on the target project", primitives=ADMIN_PRIMS, params=[ID])
# search / resolver / timeline / stats / locales
SR = "taiga/searches/api.py"
rec("GET", "/api/v1/search", "Full-text search inside a project", viewset=(SR, "SearchViewSet"), handler=[("meth", SR, "SearchViewSet", "list", 12), ("meth", SR, "SearchViewSet", "_get_project")],
    perm=(PERM_BASE, "TaigaResourcePermission"), action=None, dominant="visibility_branch",
    checks=[chk_line("visibility_branch", "user_has_perm(request.user, \"view_epics\"|\"view_us\"|\"view_tasks\"|\"view_issues\"|\"view_wiki_pages\", project)", SR,
                     r"if user_has_perm\(request\.user, \"view_us\", project\):",
                     note="no permission_classes; each result section gated by the corresponding view_* perm (public branch applies); project fetched by pk via get_object_or_error")],
    auth_summary="No permission class; per-section user_has_perm(view_*) checks decide what is returned (public project branch via public/anon permissions)",
    primitives=["user_has_perm", "calculate_permissions"], params=[P("project", "query"), P("text", "query", "string", False)])
RS = "taiga/projects/references/api.py"
RSP = "taiga/projects/references/permissions.py"
rec("GET", "/api/v1/resolver", "Resolve project slug / refs to ids", viewset=(RS, "ResolverViewSet"), handler=[("meth", RS, "ResolverViewSet", "list", 11)],
    perm=(RSP, "ResolverPermission"), action="list", dominant="visibility_branch", checks=[hp_check(RSP, "ResolverPermission", "list", "view_project")],
    auth_summary="ResolverPermission.list_perms = HasProjectPerm('view_project') on Project(slug); each ref type further gated by view_* perms",
    primitives=HP_PRIMS, params=[P("project", "query", "string")])
TL = "taiga/timeline/api.py"
TLP = "taiga/timeline/permissions.py"
rec("GET", "/api/v1/timeline/profile/{id}", "Get a user's profile timeline", viewset=(TL, "ProfileTimeline"), handler=[("meth", TL, "TimelineViewSet", "retrieve", 5)],
    perm=(TLP, "UserTimelinePermission"), action="retrieve", dominant="anonymous", checks=[any_check(TLP, "UserTimelinePermission", "retrieve")],
    auth_summary="UserTimelinePermission.retrieve_perms = AllowAny(); service filters entries by the accessing user's project visibility", primitives=["AllowAny"], params=[ID], security=False)
rec("GET", "/api/v1/timeline/user/{id}", "Get a user's activity timeline", viewset=(TL, "UserTimeline"), handler=[("meth", TL, "TimelineViewSet", "retrieve", 5)],
    perm=(TLP, "UserTimelinePermission"), action="retrieve", dominant="anonymous", checks=[any_check(TLP, "UserTimelinePermission", "retrieve")],
    auth_summary="UserTimelinePermission.retrieve_perms = AllowAny()", primitives=["AllowAny"], params=[ID], security=False)
rec("GET", "/api/v1/timeline/project/{id}", "Get a project's timeline", viewset=(TL, "ProjectTimeline"), handler=[("meth", TL, "TimelineViewSet", "retrieve", 5)],
    perm=(TLP, "ProjectTimelinePermission"), action="retrieve", dominant="visibility_branch", checks=[hp_check(TLP, "ProjectTimelinePermission", "retrieve", "view_project")],
    auth_summary="ProjectTimelinePermission.retrieve_perms = HasProjectPerm('view_project'); enough_perms = IsProjectAdmin() | IsSuperUser()", primitives=HP_PRIMS_PKG, params=[ID])
STA = "taiga/stats/api.py"
STAP = "taiga/stats/permissions.py"
rec("GET", "/api/v1/stats/discover", "Public discover statistics", viewset=(STA, "DiscoverStatsViewSet"), handler=[("meth", STA, "DiscoverStatsViewSet", "list")],
    perm=(STAP, "DiscoverStatsPermission"), action=None, dominant="anonymous",
    checks=[chk("anonymous", "AllowAny()", STAP, "DiscoverStatsPermission", "global_perms", note="global_perms = AllowAny(); no action perms -> allowed")],
    auth_summary="DiscoverStatsPermission.global_perms = AllowAny()", primitives=["AllowAny"], security=False)
rec("GET", "/api/v1/stats/system", "Public system statistics", viewset=(STA, "SystemStatsViewSet"), handler=[("meth", STA, "SystemStatsViewSet", "list")],
    perm=(STAP, "SystemStatsPermission"), action=None, dominant="anonymous",
    checks=[chk("anonymous", "AllowAny()", STAP, "SystemStatsPermission", "global_perms", note="registered only if settings.STATS_ENABLED")],
    auth_summary="SystemStatsPermission.global_perms = AllowAny() (route exists only when STATS_ENABLED)", primitives=["AllowAny"], security=False)
LC = "taiga/locale/api.py"
LCP = "taiga/locale/permissions.py"
rec("GET", "/api/v1/locales", "List available locales", viewset=(LC, "LocalesViewSet"), handler=[("meth", LC, "LocalesViewSet", "list")],
    perm=(LCP, "LocalesPermission"), action=None, dominant="anonymous",
    checks=[chk("anonymous", "AllowAny()", LCP, "LocalesPermission", "global_perms")],
    auth_summary="LocalesPermission.global_perms = AllowAny()", primitives=["AllowAny"], security=False)

# ----------------------------------------------------------------------------
# write + validate
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# trim to <= 150: drop near-duplicate variants (same permission class/kind as a
# kept record). Every owner_or_privileged record is kept.
# ----------------------------------------------------------------------------
DROP = {
    # history retrieve (visibility) - keep none, covered by items/projects retrieve
    ("GET", "/api/v1/history/epic/{id}"), ("GET", "/api/v1/history/userstory/{id}"), ("GET", "/api/v1/history/task/{id}"),
    ("GET", "/api/v1/history/issue/{id}"), ("GET", "/api/v1/history/wiki/{id}"),
    ("POST", "/api/v1/wiki/attachments"),
    # users
    ("GET", "/api/v1/users/{id}/contacts"), ("GET", "/api/v1/users/{id}/watched"), ("GET", "/api/v1/users/{id}/liked"),
    ("GET", "/api/v1/users/{id}/stats"), ("GET", "/api/v1/users/{id}/voted"), ("GET", "/api/v1/users/by_username"),
    ("POST", "/api/v1/users/change_password_from_recovery"), ("POST", "/api/v1/users/password_recovery"),
    ("POST", "/api/v1/users/remove_avatar"), ("POST", "/api/v1/users/send_verification_email"),
    # projects
    ("GET", "/api/v1/projects/{id}/member_stats"), ("GET", "/api/v1/projects/{id}/issues_stats"), ("GET", "/api/v1/projects/{id}/tags_colors"),
    ("POST", "/api/v1/projects/{id}/mix_tags"), ("POST", "/api/v1/projects/{id}/delete_tag"), ("POST", "/api/v1/projects/{id}/create_tag"),
    ("POST", "/api/v1/projects/{id}/remove_logo"), ("POST", "/api/v1/projects/{id}/delete_userstories_csv_uuid"),
    ("POST", "/api/v1/projects/{id}/regenerate_epics_csv_uuid"), ("PUT", "/api/v1/projects/{id}"), ("GET", "/api/v1/projects/{id}/modules"),
    ("POST", "/api/v1/projects/{id}/unlike"), ("POST", "/api/v1/projects/{id}/unwatch"), ("POST", "/api/v1/projects/{id}/transfer_validate_token"),
    ("POST", "/api/v1/projects/{id}/transfer_reject"), ("POST", "/api/v1/projects/{id}/transfer_accept"), ("POST", "/api/v1/projects/{id}/duplicate"),
    ("GET", "/api/v1/projects/by_slug"), ("GET", "/api/v1/projects/{resource_id}/watchers"), ("GET", "/api/v1/projects"),
    # memberships / roles / values / templates
    ("PATCH", "/api/v1/memberships/{id}"), ("PATCH", "/api/v1/roles/{id}"),
    ("PATCH", "/api/v1/userstory-statuses/{id}"), ("DELETE", "/api/v1/points/{id}"), ("POST", "/api/v1/swimlanes"),
    ("POST", "/api/v1/issue-types"), ("PATCH", "/api/v1/priorities/{id}"), ("PATCH", "/api/v1/project-templates/{id}"),
    # work items
    ("GET", "/api/v1/userstories/{resource_id}/voters"), ("GET", "/api/v1/tasks/{resource_id}/voters"), ("GET", "/api/v1/issues/{resource_id}/voters"),
    ("GET", "/api/v1/epics/{resource_id}/voters"), ("GET", "/api/v1/issues/{resource_id}/watchers"), ("GET", "/api/v1/wiki/{resource_id}/watchers"),
    ("GET", "/api/v1/milestones/{resource_id}/watchers"), ("POST", "/api/v1/tasks/{id}/upvote"), ("POST", "/api/v1/epics/{id}/upvote"),
    ("POST", "/api/v1/issues/{id}/upvote"), ("POST", "/api/v1/tasks/{id}/watch"), ("POST", "/api/v1/issues/{id}/watch"), ("POST", "/api/v1/epics/{id}/watch"),
    ("POST", "/api/v1/wiki/{id}/watch"), ("POST", "/api/v1/tasks/bulk_create"), ("POST", "/api/v1/epics/bulk_create"),
    ("GET", "/api/v1/userstories/by_ref"), ("GET", "/api/v1/wiki/by_slug"), ("POST", "/api/v1/wiki/render"),
    ("GET", "/api/v1/wiki-links/{id}"), ("PATCH", "/api/v1/wiki-links/{id}"), ("DELETE", "/api/v1/wiki-links/{id}"),
    ("DELETE", "/api/v1/epics/{epic}/related_userstories/{user_story}"), ("POST", "/api/v1/epics/{epic}/related_userstories/bulk_create"),
    ("GET", "/api/v1/milestones/{id}/stats"), ("POST", "/api/v1/milestones/{id}/watch"),
    ("GET", "/api/v1/userstories/custom-attributes-values/{id}"), ("POST", "/api/v1/issues/bulk_update_milestone"),
    ("POST", "/api/v1/userstories/bulk_update_milestone"), ("POST", "/api/v1/userstories/bulk_update_backlog_order"), ("DELETE", "/api/v1/tasks/{id}"),
    # self-scoped / misc
    ("PUT", "/api/v1/user-storage/{key}"), ("GET", "/api/v1/user-storage"), ("GET", "/api/v1/notify-policies/{id}"), ("GET", "/api/v1/web-notifications"),
    ("PATCH", "/api/v1/webhooks/{id}"), ("POST", "/api/v1/importer/{id}/milestone"), ("GET", "/api/v1/timeline/user/{id}"), ("GET", "/api/v1/stats/system"),
}
missing = [k for k in DROP if k not in SEEN]
assert not missing, missing
RECORDS = [r for r in RECORDS if (r["method"], r["path"]) not in DROP]
print("dropped:", len(DROP))
assert len(RECORDS) <= 150, len(RECORDS)
OUT_DIR.mkdir(parents=True, exist_ok=True)
with OUT.open("w", encoding="utf-8", newline="\n") as fh:
    for r in RECORDS:
        fh.write(json.dumps(r, ensure_ascii=False) + "\n")

from collections import Counter
cnt = Counter(r["dominant_kind"] for r in RECORDS)
print("records:", len(RECORDS))
for k, v in sorted(cnt.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")
print("omitted blocks:", sum(1 for r in RECORDS if r["omitted_blocks"]))
print("text len min/max:", min(len(r["controller_text"]) for r in RECORDS), max(len(r["controller_text"]) for r in RECORDS))
short = [(r["method"], r["path"], len(r["controller_text"])) for r in RECORDS if len(r["controller_text"]) < 500]
print("under 500 chars:", len(short), short[:10])
