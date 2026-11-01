"""Static extraction of Zulip REST endpoint candidates for BLADE data-v4 (training).

Reads only the local clone; writes data/raw_v4/zulip/candidates.jsonl.
No code from the clone is imported or executed (ast + yaml.safe_load only).
"""
import ast
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(r"C:\BLADE\datasets\blade\raw\opensource\zulip_zulip")
OUT = Path(r"C:\BLADE\data\raw_v4\zulip\candidates.jsonl")
COMMIT = sys.argv[1]
TAG = sys.argv[2]
MAX_CHARS = 3000
VIEW_BUDGET = 1700

BASE = {
    "project": "zulip",
    "service": "Zulip",
    "repository": "https://github.com/zulip/zulip",
    "commit": COMMIT,
    "tag": TAG,
    "license": "Apache-2.0",
}

# Doc-only pseudo operations in zulip.yaml (no server endpoint behind them).
EXCLUDE_OPS = {
    ("POST", "/real-time"): "documentation-only pseudo path for the real-time events API overview (no operationId, no route)",
    ("POST", "/rest-error-handling"): "documentation-only pseudo path describing common error responses (no route)",
    ("POST", "/zulip-outgoing-webhook"): "describes the payload Zulip sends to outgoing webhook bots; not an endpoint served by Zulip",
}

# ---------------------------------------------------------------- source index
_src_cache = {}


def src_lines(rel):
    if rel not in _src_cache:
        _src_cache[rel] = (REPO / rel).read_text(encoding="utf-8").splitlines()
    return _src_cache[rel]


def rel(p):
    return p.relative_to(REPO).as_posix()


FUNC_INDEX = {}  # name -> list of dict(file,start,end,node,cls)
INDEX_DIRS = [
    "zerver/lib", "zerver/models", "zerver/actions", "zerver/tornado", "zilencer",
]
INDEX_FILES = ["zerver/decorator.py"]
PRIORITY = {"zerver/decorator.py": 0, "zerver/lib": 1, "zerver/models": 2, "zerver/tornado": 3,
            "zerver/actions": 4, "zilencer": 5}
SKIP_FILES = {"zerver/lib/event_schema.py", "zerver/lib/validator.py", "zerver/lib/typed_endpoint.py",
              "zerver/lib/typed_endpoint_validators.py", "zerver/lib/response.py"}


def prio(f):
    for k, v in PRIORITY.items():
        if f.startswith(k):
            return v
    return 9


def def_start(node):
    return min([d.lineno for d in node.decorator_list] + [node.lineno])


def index_file(path):
    r = rel(path)
    if r in SKIP_FILES or "/test_" in r or "/migrations/" in r or "/management/" in r or "/tests/" in r:
        return
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            FUNC_INDEX.setdefault(node.name, []).append(
                dict(file=r, start=def_start(node), end=node.end_lineno, node=node, cls=None))
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    FUNC_INDEX.setdefault(sub.name, []).append(
                        dict(file=r, start=def_start(sub), end=sub.end_lineno, node=sub, cls=node.name))


for d in INDEX_DIRS:
    for p in sorted((REPO / d).rglob("*.py")):
        index_file(p)
for f in INDEX_FILES:
    index_file(REPO / f)
for v in FUNC_INDEX.values():
    v.sort(key=lambda e: (prio(e["file"]), e["file"]))


def module_file(mod):
    p = REPO / (mod.replace(".", "/") + ".py")
    return p if p.exists() else None


def find_def_in_file(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return dict(file=rel(path), start=def_start(node), end=node.end_lineno, node=node, cls=None)
    return None


# ---------------------------------------------------------------- url parsing
def parse_imports(tree):
    m = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                m[a.asname or a.name] = node.module
    return m


ROUTES = []  # dict(route_full, method|None, func, module, flags, file, start, end)


def collect_routes(relfile, prefix_for_list, default_prefix):
    path = REPO / relfile
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = parse_imports(tree)

    def handle_list(node, prefix, include_plain_path):
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            fname = call.func.id
            if fname not in ("rest_path", "path", "remote_server_path") or not call.args:
                continue
            if not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
                continue
            route = call.args[0].value
            if fname in ("rest_path", "remote_server_path"):
                for kw in call.keywords:
                    v = kw.value
                    flags = []
                    if isinstance(v, ast.Tuple):
                        fn = v.elts[0]
                        if isinstance(v.elts[1], ast.Set):
                            flags = [e.value for e in v.elts[1].elts if isinstance(e, ast.Constant)]
                    else:
                        fn = v
                    if not isinstance(fn, ast.Name):
                        continue
                    ROUTES.append(dict(route=prefix + route, method=kw.arg, func=fn.id,
                                       module=imports.get(fn.id), flags=flags, file=relfile,
                                       start=call.lineno, end=call.end_lineno, kind=fname))
            elif include_plain_path and len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
                if call.args[1].id in ("include",):
                    continue
                fn = call.args[1].id
                ROUTES.append(dict(route=prefix + route, method=None, func=fn, module=imports.get(fn),
                                   flags=[], file=relfile, start=call.lineno, end=call.end_lineno,
                                   kind="path"))

    for node in tree.body:
        target = None
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            t = node.targets[0] if isinstance(node, ast.Assign) else node.target
            target = t.id if isinstance(t, ast.Name) else None
            val = node.value
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
            val = node.value
        elif isinstance(node, ast.If):
            # e.g. "if settings.X: urls += [...]" -- only plain lists matter here
            continue
        else:
            continue
        if target is None or val is None:
            continue
        if target in prefix_for_list:
            handle_list(val, prefix_for_list[target], True)
        elif target == "urls" and default_prefix is not None:
            handle_list(val, default_prefix, True)


collect_routes("zproject/urls.py",
               {"v1_api_and_json_patterns": "/api/v1/", "v1_api_mobile_patterns": "/api/v1/"}, "/")
collect_routes("zproject/tornado_urls.py", {"api_and_json_patterns": "/api/v1/"}, None)
collect_routes("zproject/dev_urls.py", {"v1_api_mobile_patterns": "/api/v1/"}, None)
collect_routes("zilencer/urls.py", {"push_bouncer_patterns": "/api/v1/", "billing_patterns": "/api/v1/"}, None)


def norm_route(r):
    r = re.sub(r"<(?:[a-z_]+:)?([A-Za-z_]+)>", r"{\1}", r)
    if not r.startswith("/"):
        r = "/" + r
    return r.rstrip("/") or "/"


for r in ROUTES:
    r["oas_path"] = norm_route(r["route"])


def match_route(method, oas_path):
    cands = [r for r in ROUTES if r["oas_path"] == oas_path]
    exact = [r for r in cands if r["method"] == method]
    if exact:
        return exact[0]
    loose = [r for r in cands if r["method"] is None]
    if loose:
        return loose[0]
    shape = re.sub(r"\{[^}]+\}", "{}", oas_path)
    cands = [r for r in ROUTES if re.sub(r"\{[^}]+\}", "{}", r["oas_path"]) == shape and r["method"] == method]
    return cands[0] if cands else None


# ---------------------------------------------------------------- trimming
AUTH_LINE = re.compile(
    r"(raise |access_|check_|validate_|require|can_|has_|permission|is_realm_admin|is_realm_owner|"
    r"is_moderator|is_guest|is_bot|bot_owner|realm_id|\.realm\b|realm=|subscri|owner|admin|"
    r"Insufficient|[Nn]ot allowed|Unauthorized|PermissionDenied|Error\(|Error$|Error\b|role|"
    r"user_profile\.id|sender|acting_user|is_authenticated|is_staff|spectator|web_public|"
    r"recipient|member|is_active|"
    r"is_public|invite_only|group)")
STRICT_LINE = re.compile(
    r"(raise |access_|check_|validate_|require|can_|has_|permission|is_realm_admin|is_realm_owner|"
    r"is_moderator|is_guest|bot_owner|realm_id|realm=|owner|admin|Insufficient|[Nn]ot allowed|"
    r"Unauthorized|Error\(|Error$|is_authenticated|is_staff|spectator|"
    r"member|subscri)")


VSTRICT_LINE = re.compile(
    r"(raise |access_|check_\w*(can|permission|access|admin|owner)|validate_|can_|has_\w*(permission|access)|"
    r"permission|is_realm_admin|is_realm_owner|is_moderator|is_guest|bot_owner|Insufficient|[Nn]ot allowed|"
    r"Unauthorized|is_authenticated|is_staff|\.realm\b|realm_id|realm=|Subscription|is_subscribed|member)")


def func_text(entry):
    lines = src_lines(entry["file"])
    return lines[entry["start"] - 1: entry["end"]]


def _units(stmts, lines_of, ancestors, out):
    """Collect (start, end, ancestor_header_list) units for statements."""
    for st in stmts:
        if isinstance(st, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try,
                           ast.FunctionDef, ast.AsyncFunctionDef)) or type(st).__name__ in ("TryStar", "Match"):
            hstart = min([d.lineno for d in getattr(st, "decorator_list", [])] + [st.lineno])
            hend = max(st.lineno, (st.body[0].lineno - 1) if st.body else st.lineno)
            header = (hstart, hend)
            out.append((hstart, hend, list(ancestors), "header"))
            anc = ancestors + [header]
            _units(st.body, lines_of, anc, out)
            if isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
                for h in st.handlers:
                    hh = (h.lineno, max(h.lineno, h.body[0].lineno - 1))
                    out.append((hh[0], hh[1], list(anc), "header"))
                    _units(h.body, lines_of, ancestors + [header, hh], out)
                if st.orelse:
                    _units(st.orelse, lines_of, anc, out)
                if st.finalbody:
                    _units(st.finalbody, lines_of, anc, out)
            elif getattr(st, "orelse", None):
                first = st.orelse[0]
                if isinstance(st, ast.If) and len(st.orelse) == 1 and isinstance(first, ast.If)                         and lines_of(first.lineno).lstrip().startswith("elif"):
                    _units(st.orelse, lines_of, ancestors, out)  # elif chain at same level
                else:
                    eln = first.lineno - 1
                    while eln > st.lineno and lines_of(eln).strip() != "else:":
                        eln -= 1
                    eh = (eln, eln)
                    out.append((eln, eln, list(ancestors), "header"))
                    _units(st.orelse, lines_of, ancestors + [eh], out)
        else:
            out.append((st.lineno, st.end_lineno, list(ancestors), type(st).__name__))


ULTRA_LINE = re.compile(
    r"(raise |access_|can_|permission|is_realm_admin|is_realm_owner|is_moderator|is_guest|Insufficient|"
    r"[Nn]ot allowed|Unauthorized|is_authenticated)")


def trim_lines(lines, start_line, node, regex, max_unit=8):
    """Keep auth-relevant statements (whole statement + enclosing block headers);
    collapse other runs to '...' at their indentation."""
    lines_of = lambda ln: lines[ln - start_line] if 0 <= ln - start_line < len(lines) else ""
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant)             and isinstance(body[0].value.value, str):
        body = body[1:]
    body_start = node.body[0].lineno if node.body else node.lineno
    keep = [False] * len(lines)

    def mark(a, b):
        for ln in range(a, b + 1):
            i = ln - start_line
            if 0 <= i < len(keep):
                keep[i] = True

    # decorators, def line, signature lines with user_profile/return annotation
    for ln in range(start_line, body_start):
        sline = lines_of(ln).strip()
        if ln <= node.lineno or re.search(r"user_profile|^\) -> |request: HttpRequest|^self\b", sline):
            mark(ln, ln)
    units = []
    _units(body, lines_of, [], units)
    for (a, b, anc, kind) in units:
        text = "\n".join(lines_of(ln) for ln in range(a, b + 1))
        if regex.search(text):
            if b - a + 1 <= max_unit:
                mark(a, b)
            else:
                mark(a, a)
                for ln in range(a + 1, b + 1):
                    if regex.search(lines_of(ln)) and not lines_of(ln).strip().startswith("#"):
                        mark(ln, ln)
                mark(b, b) if lines_of(b).strip() in (")", "]", "}", "),") else None
            for (ha, hb) in anc:
                mark(ha, hb)
    # keep short return/raise/continue statements directly inside kept auth blocks
    for (a, b, anc, kind) in units:
        if kind in ("Return", "Raise", "Continue", "Break") and anc and b - a <= 2:
            ha, hb = anc[-1]
            if keep[ha - start_line]:
                mark(a, b)
    out = []
    i = 0
    while i < len(lines):
        if keep[i]:
            out.append(lines[i])
            i += 1
        else:
            j = i
            while j < len(lines) and not keep[j]:
                j += 1
            seg = [l for l in lines[i:j] if l.strip()]
            if seg:
                ind = re.match(r"\s*", seg[0]).group(0)
                if not (out and out[-1].strip() == "..."):
                    out.append(ind + "...")
            i = j
    return out


def render(entry, budget):
    lines = func_text(entry)
    full = "\n".join(lines)
    if len(full) <= budget:
        return full
    t = "\n".join(trim_lines(lines, entry["start"], entry["node"], AUTH_LINE))
    if len(t) <= budget:
        return t
    for rx in (STRICT_LINE, VSTRICT_LINE):
        t = "\n".join(trim_lines(lines, entry["start"], entry["node"], rx))
        if len(t) <= budget:
            return t
    return None


AUTH_CALL = re.compile(
    r"^(access_\w+|check_\w*(can|permission|access|admin|owner|basic|stream|sender|user_group|group|"
    r"channel|edit|send|delete|direct|message)\w*|validate_\w*(can|permission|access|attachment|user)\w*|"
    r"require_\w+|can_\w+|has_\w*(permission|access)\w*|user_has_permission_for_group_setting|"
    r"is_user_in_group|get_recursive_membership_groups|bulk_access_\w+|filter_stream_authorization\w*|"
    r"get_user_by_id_in_realm_including_cross_realm|get_user_profile_by_id_in_realm|"
    r"validate_message_edit_payload|human_users_only|authenticated_\w+|internal_api_view|"
    r"web_public_view|zulip_login_required|check_if_user_can_manage_default_streams|"
    r"get_stream_by_id_in_realm|get_user_in_realm|validate_\w+_access\w*)$")
SKIP_CALLS = {"check_string", "check_int", "check_bool", "check_dict", "check_list", "check_url",
              "check_capped_string"}

_imp_cache = {}
_def_cache = {}


def file_imports(relfile):
    if relfile not in _imp_cache:
        _imp_cache[relfile] = parse_imports(ast.parse((REPO / relfile).read_text(encoding="utf-8")))
    return _imp_cache[relfile]


def resolve_name(name, from_file):
    key = (name, from_file)
    if key in _def_cache:
        return _def_cache[key]
    res = None
    mod = file_imports(from_file).get(name)
    if mod:
        mf = module_file(mod)
        if mf:
            res = find_def_in_file(mf, name)
    if res is None:
        res = find_def_in_file(REPO / from_file, name)
    if res is None and name in FUNC_INDEX:
        res = FUNC_INDEX[name][0]
    if res is not None and rel(REPO / res["file"]) in SKIP_FILES:
        res = None
    _def_cache[key] = res
    return res


def called_names(node):
    names = []
    calls = sorted((n for n in ast.walk(node) if isinstance(n, ast.Call)), key=lambda c: (c.lineno, c.col_offset))
    for n in calls:
        f = n.func
        if isinstance(f, ast.Name):
            names.append(f.id)
        elif isinstance(f, ast.Attribute):
            names.append(f.attr)
    for d in getattr(node, "decorator_list", []):
        if isinstance(d, ast.Name):
            names.append(d.id)
        elif isinstance(d, ast.Call) and isinstance(d.func, ast.Name):
            names.append(d.func.id)
    seen = []
    for x in names:
        if x not in seen:
            seen.append(x)
    return seen


def auth_helpers(node, from_file):
    out, local = [], []
    for n in called_names(node):
        if n in SKIP_CALLS:
            continue
        if AUTH_CALL.match(n) and (n.startswith("access_") or not NON_AUTH_NAME.search(n)):
            e = resolve_name(n, from_file)
            if e is not None:
                out.append((n, e))
        elif from_file.startswith("zerver/views/") and n != getattr(node, "name", None):
            e = None if n.startswith(("notify_", "send_", "do_", "compose_", "json_", "get_")) else find_def_in_file(REPO / from_file, n)
            if e is not None:
                local.append((n, e))
    return out + local


NON_AUTH_NAME = re.compile(r"(_name$|_name_|available|_valid|_limit|in_use|_format|_length|_type$|_size|pygments|_schedule_|_settings_values)")


def secondary_calls(node, from_file):
    out = []
    for c in ast.walk(node):
        if not isinstance(c, ast.Call):
            continue
        args = list(c.args) + [k.value for k in c.keywords]
        if not any(isinstance(a, ast.Name) and a.id == "user_profile" for a in args):
            continue
        f = c.func
        n = f.id if isinstance(f, ast.Name) else None
        if not n or n in SKIP_CALLS or AUTH_CALL.match(n) or n.startswith(("notify_", "send_event", "json_")):
            continue
        e = resolve_name(n, from_file)
        if e is None or not e["file"].startswith(("zerver/lib/", "zerver/actions/", "zerver/views/")):
            continue
        if any(x[0] == n for x in out):
            continue
        out.append((n, e))
    return out[:4]


def name_prio(n):
    if n.startswith(("access_", "require_", "authenticated_")):
        return 0
    if n.startswith(("check_", "validate_", "can_", "has_", "user_has_", "is_user_in_group", "filter_stream_authorization", "bulk_access_")):
        return 1
    return 3 if n.startswith("get_") else 2


def meaningful(t):
    body = [l for l in t.splitlines()[1:] if l.strip() and l.strip() != "..." and not l.strip().startswith(("@", ")", "def "))]
    return len(body) >= 1


def is_trivial_wrapper(entry):
    return False


DISPATCH_ANON = None


def dispatch_anon_excerpt():
    lines = src_lines("zerver/lib/rest.py")
    for i, l in enumerate(lines):
        if '"allow_anonymous_user_web" in view_flags' in l and "elif" not in l:
            # the condition line; find enclosing elif start
            s = i
            while "elif (" not in lines[s]:
                s -= 1
            e = i
            while "raise MissingAuthenticationError" not in lines[e]:
                e += 1
            return s + 1, e + 1, "\n".join(lines[s:e + 1])
    return None


DISPATCH_ANON = dispatch_anon_excerpt()


HARD_CUT = []


def build_code(route, view):
    parts, locs = [], []
    rlines = src_lines(route["file"])[route["start"] - 1: route["end"]]
    rtxt = "\n".join(l for l in rlines)
    # dedent route block
    ind = min(len(re.match(r"\s*", l).group(0)) for l in rlines if l.strip())
    rtxt = "\n".join(l[ind:] for l in rlines)
    parts.append(rtxt)
    locs.append(dict(file=route["file"], start_line=route["start"], end_line=route["end"]))
    if "allow_anonymous_user_web" in route["flags"] and DISPATCH_ANON:
        s, e, t = DISPATCH_ANON
        lines = t.splitlines()
        ind = min(len(re.match(r"\s*", l).group(0)) for l in lines if l.strip())
        parts.append("\n".join(l[ind:] for l in lines))
        locs.append(dict(file="zerver/lib/rest.py", start_line=s, end_line=e))
    used = sum(len(p) + 2 for p in parts)

    # candidate helpers: BFS (depth <= 3) in priority order
    level1 = auth_helpers(view["node"], view["file"])
    if route["kind"] == "remote_server_path":
        level1 = [("authenticated_remote_server_view", resolve_name("authenticated_remote_server_view", "zilencer/auth.py"))] + level1
    queue = [(n, e, 1, i) for i, (n, e) in enumerate(level1)]
    auth_names = {n for n, e in level1}
    for i, (n, e) in enumerate(secondary_calls(view["node"], view["file"])):
        if n not in auth_names:
            queue.append((n, e, 2.5, 100 + i))
    level1 = [n for n, e in level1]
    seen = {view["node"].name}
    cands = []
    order = 1000
    while queue and len(cands) < 16:
        queue.sort(key=lambda q: (q[2], name_prio(q[0]), q[3]))
        name, entry, lvl, _ = queue.pop(0)
        if name in seen or entry is None:
            continue
        seen.add(name)
        cands.append((name, entry))
        if lvl < 3:
            for n, e in auth_helpers(entry["node"], entry["file"]):
                if n not in seen:
                    order += 1
                    queue.append((n, e, lvl + 1, order))

    def levels(entry):
        lines = func_text(entry)
        outs = ["\n".join(lines)]
        for rx, mu in ((AUTH_LINE, 8), (STRICT_LINE, 8), (VSTRICT_LINE, 8), (ULTRA_LINE, 1)):
            t = "\n".join(trim_lines(lines, entry["start"], entry["node"], rx, mu))
            if len(t) < len(outs[-1]):
                outs.append(t)
        return outs  # longest first

    view_lv = levels(view)
    budget = MAX_CHARS - used
    if len(view_lv[-1]) > budget:
        cut = view_lv[-1][: budget - 4]
        cut = cut[: cut.rfind("\n")] if "\n" in cut else cut
        vt = cut + "\n..."
        HARD_CUT.append(view["node"].name)
        view_lv = [vt]
    chosen = [["view", view, view_lv, len(view_lv) - 1]]
    slack = budget - len(view_lv[-1])
    skipped = []
    for name, entry in cands:
        lv = levels(entry)
        if not meaningful(lv[-1]):
            skipped.append(name)
            continue
        need = len(lv[-1]) + 2
        if need <= slack:
            chosen.append([name, entry, lv, len(lv) - 1])
            slack -= need
        else:
            skipped.append(name)
    # upgrade: view first, then helpers in order, to the longest level that still fits
    for c in chosen:
        cur = len(c[2][c[3]])
        for k in range(c[3]):
            if len(c[2][k]) - cur <= slack:
                slack -= len(c[2][k]) - cur
                c[3] = k
                break
    parts.append(chosen[0][2][chosen[0][3]])
    locs.append(dict(file=view["file"], start_line=view["start"], end_line=view["end"]))
    helper_names = []
    for name, entry, lv, k in chosen[1:]:
        parts.append(lv[k])
        locs.append(dict(file=entry["file"], start_line=entry["start"], end_line=entry["end"]))
        helper_names.append(name if entry["cls"] is None else f"{entry['cls']}.{name}")
    text = "\n\n".join(parts)
    assert len(text) <= MAX_CHARS, (route, len(text))
    return text, locs, level1, helper_names, skipped


# ---------------------------------------------------------------- auth summary
DECOR_AUTH = {"require_realm_admin", "require_realm_owner", "require_non_guest_user",
              "require_human_non_guest_user", "require_user_group_create_permission",
              "check_if_user_can_manage_default_streams", "require_billing_access",
              "require_bot_user", "human_users_only", "require_server_admin_api",
              "require_post", "authenticated_json_view", "web_public_view", "internal_api_view",
              "zulip_login_required"}
INLINE_CHECKS = [
    (r"\.is_realm_owner\b", "is_realm_owner"),
    (r"\.is_realm_admin\b", "is_realm_admin"),
    (r"\.is_moderator\b", "is_moderator"),
    (r"\.is_guest\b", "is_guest"),
    (r"bot_owner", "bot_owner"),
    (r"\.can_admin_user\(", "can_admin_user"),
    (r"user_profile\.id\s*!=|!=\s*user_profile\.id|user_profile_id\s*!=|\.sender_id\s*!=|\.sender\s*!=|sender_id ==|== user_profile\.id", "requester==target/sender"),
    (r"is_web_public|web_public", "web_public"),
    (r"invite_only", "invite_only"),
    (r"is_authenticated", "is_authenticated"),
    (r"realm_id\s*=|realm=user_profile\.realm|\.realm_id\s*!=|realm_id ==", "realm scoping"),
    (r"user_profile=user_profile|user_profile_id=user_profile\.id|owner=user_profile|owner_id=user_profile\.id|sender=user_profile|sender_id=user_profile\.id", "query scoped to requester"),
]


def summarize(route, view, level1, code_text=""):
    deco = []
    for d in view["node"].decorator_list:
        nm = d.id if isinstance(d, ast.Name) else (d.func.id if isinstance(d, ast.Call) and isinstance(d.func, ast.Name) else None)
        if nm and nm in DECOR_AUTH:
            deco.append(nm)
    body = "\n".join(func_text(view)) + "\n" + (code_text or "")
    inl = []
    for rx, lab in INLINE_CHECKS:
        if re.search(rx, body):
            inl.append(lab)
    helpers = [h for h in level1 if h not in deco and (AUTH_CALL.match(h) or h.endswith("_backend"))]
    parts = []
    if "allow_anonymous_user_web" in route["flags"]:
        parts.append("rest_dispatch allow_anonymous_user_web (spectator allowed)")
    if route["kind"] == "path":
        parts.append("plain Django path (no rest_dispatch auth)")
    if deco:
        parts.append("@" + ", @".join(deco))
    if helpers:
        parts.append("calls " + ", ".join(helpers[:6]))
    if inl:
        parts.append("inline: " + ", ".join(inl))
    if not parts:
        parts.append("authenticated user only (rest_dispatch); no explicit authorization check found in view")
    elif route["kind"] != "path" and "allow_anonymous_user_web" not in route["flags"]:
        parts.insert(0, "authenticated")
    return "; ".join(parts)


def category(summary, path, method, xreq):
    s = summary
    if "plain Django path" in s and ("fetch_api_key" in path or "server_settings" in path or "dev_" in path):
        return "anonymous/public"
    if "allow_anonymous_user_web" in s:
        return "anonymous/public"
    if xreq or re.search(r"require_realm_admin|require_realm_owner|require_server_admin|check_if_user_can_manage_default_streams|require_billing", s):
        return "admin-only"
    if re.search(r"bot_owner|access_bot_by_id|can_admin_user", s):
        return "owner-or-admin (bot owner / can_admin_user)"
    if re.search(r"access_message|sender|can_delete|validate_user_can_edit_message|edit", s):
        return "sender-or-admin / message access"
    if re.search(r"access_stream|subscri|access_user_group|check_basic_stream_access|is_user_in_group|access_default_stream_group|stream", s):
        return "subscription/membership"
    if re.search(r"/users/me|/drafts|/saved_snippets|/navigation_views|/reminders|/scheduled_messages|/attachments|/alert_words|/settings|/user_topics|/mark_|/typing|bot_storage|muted_users|apns|android_gcm|client_device|mobile_push|/user_uploads$", path):
        return "self"
    if re.search(r"is_realm_admin|is_realm_owner|is_moderator|user_has_permission_for_group_setting|can_\w+|has_\w*permission|require_", s):
        return "role/org-setting"
    return "other"


# ---------------------------------------------------------------- OAS helpers
spec = yaml.safe_load((REPO / "zerver/openapi/zulip.yaml").read_text(encoding="utf-8"))
COMP = spec.get("components", {})


def resolve(o, depth=0):
    if isinstance(o, dict) and "$ref" in o and depth < 20:
        ref = o["$ref"]
        assert ref.startswith("#/components/")
        _, _, kind, name = ref.split("/", 3)
        return resolve(COMP[kind][name], depth + 1)
    return o


def schema_type(s):
    s = resolve(s or {})
    if "type" in s:
        t = {"type": s["type"]}
        if s["type"] == "array" and "items" in s:
            it = resolve(s["items"])
            if "type" in it:
                t["items"] = {"type": it["type"]}
        if "enum" in s:
            t["enum"] = s["enum"]
        return t
    for k in ("oneOf", "anyOf", "allOf"):
        if k in s:
            return {k: [schema_type(x) for x in s[k]]}
    if "content" in s:
        return {"content": list(s["content"].keys())}
    return {}


def param_min(p):
    p = resolve(p)
    out = {"name": p.get("name"), "in": p.get("in"), "required": bool(p.get("required", False))}
    if "schema" in p:
        out["schema"] = schema_type(p["schema"])
    elif "content" in p:
        ct = list(p["content"].keys())
        sch = p["content"][ct[0]].get("schema") if ct else None
        out["schema"] = schema_type(sch) if sch else {}
        out["content_type"] = ct[0] if ct else None
    return out


def merged_props(s, depth=0):
    s = resolve(s or {})
    props, req = {}, []
    if depth > 10:
        return props, req
    if "allOf" in s:
        for x in s["allOf"]:
            p, r = merged_props(x, depth + 1)
            props.update(p)
            req += r
    for k in ("oneOf", "anyOf"):
        if k in s:
            for x in s[k]:
                p, r = merged_props(x, depth + 1)
                for kk, vv in p.items():
                    props.setdefault(kk, vv)
    if "properties" in s:
        props.update(s["properties"])
    req += s.get("required", [])
    return props, req


def request_body_min(rb):
    if not rb:
        return None
    rb = resolve(rb)
    out = {"required": bool(rb.get("required", False)), "content": {}}
    for ct, c in rb.get("content", {}).items():
        props, req = merged_props(c.get("schema"))
        out["content"][ct] = {
            "properties": {k: schema_type(v) for k, v in props.items()},
            "required": sorted(set(req)),
        }
    return out


def responses_min(rs):
    out = {}
    fields = []
    for code, r in (rs or {}).items():
        r = resolve(r)
        out[str(code)] = {"description": (r.get("description") or "").strip()[:300]}
        if str(code).startswith("2"):
            for ct, c in (r.get("content") or {}).items():
                props, _ = merged_props(c.get("schema"))
                for k in props:
                    if k not in fields:
                        fields.append(k)
    return out, fields


PERM_RX = re.compile(
    r"(administrator|admin\b|admins\b|owner|moderator|permission|allowed|only|guest|member|subscribed|"
    r"subscriber|organization setting|can_[a-z_]+|role|bot's owner|policy|unauthenticated|authenticated|"
    r"requires|require|access|spectator|not available|restricted|must be|cannot|can only|private|"
    r"public|anonymous|logged-in|login)", re.I)


def permission_doc(desc):
    if not desc:
        return ""
    keep = []
    for para in re.split(r"\n\s*\n", desc):
        p = para.strip()
        if not p or p.startswith("**Changes**") or p.startswith("[") and "]:" in p.split("\n")[0][:80]:
            continue
        if re.match(r"^(\*\*)?(Changes|Note)\b", p) and p.startswith("**Changes"):
            continue
        # sentence split (keep markdown verbatim)
        flat = re.sub(r"\s*\n\s*", " ", p)
        for sent in re.split(r"(?<=[.!?])\s+(?=[A-Z`\[*])", flat):
            if PERM_RX.search(sent):
                keep.append(sent.strip())
    return " ".join(keep)


def doc_first(node):
    d = ast.get_docstring(node)
    return d or ""


# ---------------------------------------------------------------- main
records, excluded, unmatched = [], [], []
documented_keys = set()
glob_sec = spec.get("security", [])
schemes = COMP.get("securitySchemes", {})

for p, item in spec["paths"].items():
    common_params = item.get("parameters", [])
    for m, op in item.items():
        if m not in ("get", "post", "put", "patch", "delete"):
            continue
        M = m.upper()
        if (M, p) in EXCLUDE_OPS:
            excluded.append((M, p, EXCLUDE_OPS[(M, p)]))
            continue
        real = "/api/v1" + p
        route = match_route(M, real)
        if route is None:
            unmatched.append((M, p))
            continue
        documented_keys.add((route["func"], route["oas_path"], M))
        mod = route["module"]
        mf = module_file(mod) if mod else None
        view = find_def_in_file(mf, route["func"]) if mf else None
        if view is None:
            unmatched.append((M, p, "view not found", route["func"], mod))
            continue
        params = [param_min(x) for x in common_params + op.get("parameters", [])]
        resp, fields = responses_min(op.get("responses"))
        oas_op = {
            "operationId": op.get("operationId"),
            "summary": op.get("summary"),
            "description": op.get("description", ""),
            "tags": op.get("tags", []),
            "parameters": params,
        }
        rb = request_body_min(op.get("requestBody"))
        if rb:
            oas_op["requestBody"] = rb
        oas_op["responses"] = resp
        if "security" in op:
            oas_op["security"] = op["security"]
        xreq = {k: v for k, v in op.items() if k in ("x-requires-administrator", "x-requires-owner")}
        oas_op.update(xreq)
        text, locs, level1, helpers, skipped = build_code(route, view)
        summ = summarize(route, view, level1, text)
        if xreq:
            summ += "; OAS " + ",".join(xreq)
        rec = dict(BASE)
        rec.update(method=M, path=real, oas_status="repository_spec", oas_operation=oas_op,
                   oas_global_security=glob_sec, oas_security_schemes=schemes,
                   response_schema_fields=fields, controller_text=text, source_locations=locs,
                   auth_summary=summ, permission_doc=permission_doc(op.get("description", "")))
        rec["_view"] = f"{mod}.{route['func']}"
        rec["_route_flags"] = route["flags"]
        rec["_helpers_included"] = helpers
        rec["_helpers_omitted_for_length"] = skipped
        rec["_category"] = category(summ, real, M, xreq)
        records.append(rec)

# ---- undocumented rest_path routes (oas_status=generated)
gen_skipped = []
for route in ROUTES:
    if route["kind"] not in ("rest_path",) or route["method"] is None:
        continue
    if route["file"] == "zilencer/urls.py":
        continue
    key = (route["func"], route["oas_path"], route["method"])
    if key in documented_keys:
        continue
    if not route["oas_path"].startswith(("/api/v1/",)) and not route["oas_path"].startswith(
            ("/user_uploads", "/thumbnail", "/avatar", "/json/fetch_api_key")):
        gen_skipped.append((route["method"], route["oas_path"], "outside API prefix (billing/other)"))
        continue
    if "intentionally_undocumented" in route["flags"] and route["oas_path"].startswith("/api/v1/settings/"):
        gen_skipped.append((route["method"], route["oas_path"], "intentionally_undocumented alias of a documented endpoint"))
        continue
    mod = route["module"]
    mf = module_file(mod) if mod else None
    view = find_def_in_file(mf, route["func"]) if mf else None
    if view is None:
        gen_skipped.append((route["method"], route["oas_path"], f"view {route['func']} not found"))
        continue
    params = [{"name": n, "in": "path", "required": True, "schema": {"type": "integer" if f"<int:{n}>" in route["route"] else "string"}}
              for n in re.findall(r"\{([^}]+)\}", route["oas_path"])]
    doc = doc_first(view["node"])
    oas_op = {"operationId": route["func"], "summary": doc.split("\n")[0] if doc else "",
              "description": doc, "parameters": params, "responses": {}}
    text, locs, level1, helpers, skipped = build_code(route, view)
    summ = summarize(route, view, level1, text)
    rec = dict(BASE)
    rec.update(method=route["method"], path=route["oas_path"], oas_status="generated",
               oas_operation=oas_op, oas_global_security=glob_sec, oas_security_schemes=schemes,
               response_schema_fields=[], controller_text=text, source_locations=locs,
               auth_summary=summ, permission_doc="")
    rec["_view"] = f"{mod}.{route['func']}"
    rec["_route_flags"] = route["flags"]
    rec["_helpers_included"] = helpers
    rec["_helpers_omitted_for_length"] = skipped
    rec["_category"] = category(summ, route["oas_path"], route["method"], {})
    records.append(rec)
    documented_keys.add(key)

with OUT.open("w", encoding="utf-8", newline="\n") as f, \
        OUT.with_name("_candidates_debug.jsonl").open("w", encoding="utf-8", newline="\n") as g:
    for r in records:
        f.write(json.dumps({k: v for k, v in r.items() if not k.startswith("_")}, ensure_ascii=False) + "\n")
        g.write(json.dumps({"method": r["method"], "path": r["path"],
                            **{k: v for k, v in r.items() if k.startswith("_")}}, ensure_ascii=False) + "\n")

json.dump(dict(hard_cut_views=sorted(set(HARD_CUT)), excluded=excluded, unmatched=unmatched, gen_skipped=gen_skipped,
               n=len(records),
               n_spec=sum(r["oas_status"] == "repository_spec" for r in records),
               n_gen=sum(r["oas_status"] == "generated" for r in records)),
          open(OUT.with_name("_extract_log.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
print(len(records), "records;", "unmatched", unmatched, "excluded", len(excluded))
