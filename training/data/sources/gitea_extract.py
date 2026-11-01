"""Gitea (go-gitea/gitea, MIT) endpoint extraction for data-v2 (static analysis only; the clone is never modified or executed).

Extraction rules (reports/eval/data_v2/gitea_extraction_rules.md):
 R1 Routes come from routers/api/v1/api.go: m.Group / m.Get|Post|Put|Patch|Delete / m.Combo chains, with group middleware taken from the
    trailing arguments after the group closure. Middleware accumulates from outer to inner group, then route-level middleware, in order.
 R2 Each route is matched to templates/swagger/v1-openapi3.generated.json by METHOD + path with every {param} and * normalised to {}.
 R3 Code excerpt = (a) definitions of every authentication/authorization middleware in the chain (from api.go, deduplicated, each capped
    at 30 lines; context.* helpers summarised by a fixed note), (b) the handler function: signature, the first 20 non-comment body lines,
    plus every line matching the authorization idiom regex with 2 lines of context (merged ranges), capped at 60 lines.
    Swagger comment blocks are dropped. Nothing outside the handler file and api.go is read except the fixed context-helper appendix.
 R4 bind(...) option binders and non-authorization middleware (mustEnable*, context.ReferencesGitRepo) are listed by name only.
 R5 Unresolved handlers (helper-registered routes such as addActionsRoutes) are recorded with handler_resolved=false and no excerpt.
"""
from __future__ import annotations
import argparse, hashlib, json, random, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
GITEA = ROOT / 'datasets/blade/raw/opensource/gitea'
API = GITEA / 'routers/api/v1/api.go'; OAS = GITEA / 'templates/swagger/v1-openapi3.generated.json'
OUT_DIR = ROOT / 'datasets/blade/processed/opensource'; REPORT_DIR = ROOT / 'reports/eval/data_v2'
TAG = 'v28.2.0'; COMMIT = '829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1'; LICENSE = 'MIT'
METHODS = ('Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options', 'Any')
AUTHZ = re.compile(r'ctx\.Doer|ctx\.IsSigned|IsAdmin|IsOwner|IsPoster|PosterID|Forbidden|Permission|\.Can[A-Z]\w*\(|access_model\.|perm\.Access|IsOrgMember|IsUserOrgOwner|HasOrgOrUserVisible|unit\.Type|Collaborator|CheckPrivate|IsPrivate|Visibility|\.IsOwnedBy|ctx\.ContextUser\.ID|OwnerID|RepoAssignment|IsUserSiteAdmin|IsUserRepo')
CONTEXT_NOTE = {
    'context.UserAssignmentAPI': '// context.UserAssignmentAPI(): resolves {username} into ctx.ContextUser (404 if missing); no authorization.',
    'context.ReferencesGitRepo': '// context.ReferencesGitRepo(): opens the git repository for ctx.Repo; no authorization.',
    'context.RepoAssignment': '// context.RepoAssignment(): resolves {username}/{reponame} and computes ctx.Repo.Permission; 404 when the doer has no access to a private repo.',
    'repoAssignment': '// repoAssignment() (api.go): resolves {username}/{reponame}; computes ctx.Repo.Permission = access_model.GetUserRepoPermission(doer, repo); anonymous or unauthorized doer on a private repo -> 404; public repo readable by anyone.',
    'orgAssignment': '// orgAssignment() (api.go): resolves {org} (and optional team) into ctx.Org; no authorization by itself.',
    'sudo': '// sudo(): site admins may impersonate another user via ?sudo=; non-admins get 403 only when they try to sudo. Not an authorization rule for the endpoint.',
    'tokenRequiresScopes': '// tokenRequiresScopes(category): OAuth2/access-token scope check (read for GET, write for mutations). Not a user-object relationship check.',
    'checkTokenPublicOnly': '// checkTokenPublicOnly(): tokens restricted to public-only may not access private resources.',
    'rejectPublicOnly': '// rejectPublicOnly(): public-only tokens are rejected (403).',
    'individualPermsChecker': '// individualPermsChecker: a user with restricted visibility is only visible to admins/self; otherwise no effect.',
    'contextAuthenticatedUser': '// contextAuthenticatedUser(): sets ctx.ContextUser = ctx.Doer (the authenticated user itself).',
    'reqToken': '// reqToken(): authentication only — the request must be signed in with a token (401 otherwise). No authorization.',
    'reqBasicOrRevProxyAuth': '// reqBasicOrRevProxyAuth(): authentication method restriction (basic auth or reverse proxy). No authorization.',
    'mustNotBeArchived': '// mustNotBeArchived: 403 when the repository is archived (feature state, not a caller check).',
}
HELPER_FILES = ['services/context/api.go', 'services/context/permission.go', 'services/context/context.go', 'models/perm/access/repo_permission.go']
HELPER_FUNCS = ['IsUserSiteAdmin', 'IsUserRepoAdmin', 'IsUserRepoWriter', 'IsUserRepoReaderSpecific', 'IsUserRepoReaderAny', 'CanRead', 'CanWrite', 'CanAccess', 'CanReadIssuesOrPulls', 'CanWriteIssuesOrPulls', 'HasAnyUnitAccess', 'IsOwner', 'IsAdmin']

def read(p): return p.read_text(encoding='utf-8', errors='replace')

def split_args(s):
    """Split a Go argument list at top-level commas."""
    out, depth, cur = [], 0, ''
    for ch in s:
        if ch in '([{': depth += 1
        elif ch in ')]}': depth -= 1
        if ch == ',' and depth == 0: out.append(cur.strip()); cur = ''
        else: cur += ch
    if cur.strip(): out.append(cur.strip())
    return out

def match_paren(text, i):
    """i points at '(' ; return index of matching ')'."""
    depth = 0
    for j in range(i, len(text)):
        if text[j] == '(': depth += 1
        elif text[j] == ')':
            depth -= 1
            if depth == 0: return j
        elif text[j] == '"':
            k = text.find('"', j + 1)
            while k != -1 and text[k - 1] == '\\': k = text.find('"', k + 1)
            j = k
    raise ValueError('unbalanced')

def match_brace(text, i):
    depth = 0
    for j in range(i, len(text)):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: return j
    raise ValueError('unbalanced brace')

CALL = re.compile(r'\bm\.(Group|Combo|' + '|'.join(METHODS) + r')\(')

def parse_routes(body, prefix, mws, routes, lines_offset):
    pos = 0
    while True:
        mo = CALL.search(body, pos)
        if not mo: return
        kind = mo.group(1); open_i = mo.end() - 1; close_i = match_paren(body, open_i)
        args_text = body[open_i + 1:close_i]
        if kind == 'Group':
            # m.Group("path", func() { ... }, mw...)
            first_comma = args_text.index(',')
            path = args_text[:first_comma].strip().strip('"')
            fn_start = args_text.index('{', first_comma); fn_end = match_brace(args_text, fn_start)
            inner = args_text[fn_start + 1:fn_end]; trailing = args_text[fn_end + 1:].lstrip(', ').strip()
            group_mws = split_args(trailing) if trailing else []
            parse_routes(inner, prefix + path, mws + group_mws, routes, lines_offset + body[:mo.start()].count('\n') + 1)
            pos = close_i + 1
        elif kind == 'Combo':
            args = split_args(args_text); path = args[0].strip('"'); combo_mws = args[1:]
            # chained .Get(...) etc. until the statement ends
            j = close_i + 1
            while True:
                mm = re.match(r'\s*\.\s*(' + '|'.join(METHODS) + r')\(', body[j:])
                if not mm: break
                oi = j + mm.end() - 1; ci = match_paren(body, oi); cargs = split_args(body[oi + 1:ci])
                add_route(routes, mm.group(1), prefix + path, mws + combo_mws, cargs, lines_offset + body[:oi].count('\n') + 1)
                j = ci + 1
            pos = j
        else:
            args = split_args(args_text); path = args[0].strip('"')
            add_route(routes, kind, prefix + path, mws, args[1:], lines_offset + body[:mo.start()].count('\n') + 1)
            pos = close_i + 1

def add_route(routes, method, path, mws, args, line):
    handler = args[-1] if args else None; route_mws = [a for a in args[:-1]]
    routes.append(dict(method=method.upper(), path=path or '/', middleware=[m for m in mws + route_mws if not m.startswith('bind(')], binders=[m for m in mws + route_mws if m.startswith('bind(')], handler=handler, api_go_line=line))

def go_func(text, name):
    """Return (source, start_line, end_line) of `func name(` or `func (recv) name(` at column 0."""
    mo = re.search(r'^func (?:\([^)]*\) )?' + re.escape(name) + r'\(', text, re.M)
    if not mo: return None
    brace = text.index('{', mo.start()); end = match_brace(text, brace)
    return text[mo.start():end + 1], text[:mo.start()].count('\n') + 1, text[:end].count('\n') + 1

def mw_name(mw):
    return re.sub(r'\(.*$', '', mw).strip()

def middleware_defs(api_text, chain):
    out, seen = [], set()
    for mw in chain:
        name = mw_name(mw)
        if name in seen: continue
        seen.add(name)
        if name in CONTEXT_NOTE:
            note = CONTEXT_NOTE[name]
            if note: out.append(note)
            continue
        if name.startswith('context.'): out.append(f'// {mw}: services/context helper (request context setup).'); continue
        if name.startswith('mustEnable') or name.startswith('mustAllow'): out.append(f'// {mw}: feature/unit enabled check (404 when the unit is disabled); not a caller check.'); continue
        fn = go_func(api_text, name)
        if fn:
            src = fn[0].splitlines()
            out.append('\n'.join(src[:30]) + ('\n// ... (truncated)' if len(src) > 30 else ''))
        else:
            out.append(f'// {mw}: middleware defined outside api.go or as a local variable (not resolved).')
    return out

def handler_excerpt(src):
    lines = src.splitlines(); sig = lines[0]
    body = [(i, l) for i, l in enumerate(lines[1:], 1) if not l.strip().startswith('//')]
    keep = set(i for i, _ in body[:20])
    for i, l in body:
        if AUTHZ.search(l):
            for k in range(max(1, i - 2), min(len(lines), i + 3)): keep.add(k)
    ordered = sorted(keep); out = [sig]; last = 0
    for i in ordered:
        if lines[i].strip().startswith('//'): continue
        if i > last + 1 and last: out.append('\t// ...')
        out.append(lines[i]); last = i
        if len(out) >= 60: out.append('\t// ... (truncated)'); break
    if last < len(lines) - 1 and len(out) < 60: out.append('\t// ...\n}')
    return '\n'.join(out), sum(1 for _, l in body if AUTHZ.search(l))

def resolve_handler(handler):
    if not handler or '.' not in handler: return None
    pkg, name = handler.rsplit('.', 1)
    pkg = pkg.strip()
    if pkg not in ('repo', 'user', 'org', 'admin', 'misc', 'notify', 'packages', 'activitypub', 'settings', 'shared', 'token'): return None
    for f in sorted((GITEA / 'routers/api/v1' / pkg).glob('*.go')):
        if f.name.endswith('_test.go'): continue
        fn = go_func(read(f), name)
        if fn: return dict(file=str(f.relative_to(GITEA)).replace('\\', '/'), start_line=fn[1], end_line=fn[2], source=fn[0])
    return None

def norm(path):
    return re.sub(r'\{[^}]*\}|\*', '{}', path).rstrip('/') or '/'

def helper_appendix():
    out = []
    for rel in HELPER_FILES:
        p = GITEA / rel
        if not p.exists(): continue
        text = read(p)
        for name in HELPER_FUNCS:
            fn = go_func(text, name)
            if fn and len(fn[0].splitlines()) <= 25: out.append(f'// {rel}:{fn[1]}\n' + fn[0])
    return '\n\n'.join(out)

def main(sample_only=False):
    api_text = read(API); oas = json.loads(read(OAS))
    routes_fn = go_func(api_text, 'Routes'); body = routes_fn[0]
    routes = []; parse_routes(body, '', [], routes, routes_fn[1])
    # Routes registered inside helper functions (e.g. addActionsRoutes) are not expanded (R5).
    ops = {}
    for p, item in oas['paths'].items():
        for m, op in item.items():
            if m in ('get', 'post', 'put', 'patch', 'delete', 'head', 'options'): ops[(m.upper(), norm(p))] = (p, op)
    records = []; unmatched = []; seen = set()
    for r in routes:
        key = (r['method'], norm('/api/v1' + r['path'] if not r['path'].startswith('/api/v1') else r['path']))
        key = (r['method'], norm(r['path']))
        hit = ops.get(key)
        if not hit: unmatched.append(dict(method=r['method'], path=r['path'], handler=r['handler'])); continue
        oas_path, op = hit
        if (r['method'], oas_path) in seen: continue
        seen.add((r['method'], oas_path))
        h = resolve_handler(r['handler']); excerpt, nauth = (handler_excerpt(h['source']) if h else ('', 0))
        mw_text = middleware_defs(api_text, r['middleware'])
        code = '\n\n'.join(['// ---- route middleware chain (api.go): ' + ', '.join(r['middleware'] or ['(none)'])] + mw_text + [f'// ---- handler {r["handler"]} ({h["file"]}:{h["start_line"]}-{h["end_line"]})\n' + excerpt if h else f'// handler {r["handler"]} not resolved'])
        snippet = dict(openapi=oas['openapi'], security=oas.get('security'), paths={oas_path: {r['method'].lower(): op}}, components={'securitySchemes': oas['components']['securitySchemes']})
        records.append(dict(id=f'gitea:{r["method"].lower()}:{oas_path}', source='opensource', service='gitea', method=r['method'], path=oas_path, label=None,
                            oas_snippet=json.dumps(snippet, ensure_ascii=False), erd_snippet='', controller_text=code,
                            controller_signals=dict(middleware=r['middleware'], binders=r['binders'], handler=r['handler'], handler_resolved=bool(h), authz_lines_in_handler=nauth,
                                                    route_authentication=any(mw_name(m) in ('reqToken', 'reqBasicOrRevProxyAuth', 'reqExploreSignIn') for m in r['middleware']),
                                                    route_authorization=[m for m in r['middleware'] if mw_name(m) in ('reqAdmin', 'reqOwner', 'reqSiteAdmin', 'reqSelfOrAdmin', 'reqRepoWriter', 'reqRepoReader', 'reqAnyRepoReader', 'reqOrgOwnership', 'reqOrgMembership', 'reqTeamMembership', 'reqTeamReadAccess', 'reqRepoDangerZone', 'reqPackageAccess', 'reqProjectsUnitAccess', 'reqOrgVisible')]),
                            meta=dict(source='opensource', project='gitea', repository='https://github.com/go-gitea/gitea', tag=TAG, commit=COMMIT, license=LICENSE, oas_status='repo_generated_openapi3',
                                      oas_file='templates/swagger/v1-openapi3.generated.json', api_go_line=r['api_go_line'], erd_status='unknown', controller_status='available' if h else 'unresolved',
                                      source_locations=([dict(file=h['file'], start_line=h['start_line'], end_line=h['end_line'])] if h else []) + [dict(file='routers/api/v1/api.go', start_line=r['api_go_line'], end_line=r['api_go_line'])],
                                      extraction_rules='R1-R5 gitea_extract.py', data_version='data-v2-candidate', partition='undecided_until_heldout_policy')))
    OUT_DIR.mkdir(parents=True, exist_ok=True); REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / 'gitea_context_helpers.txt').write_text(helper_appendix(), encoding='utf-8')
    out = OUT_DIR / f'gitea_{TAG}_endpoints.jsonl'
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        for rec in records: f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    stats = dict(routes_parsed=len(routes), oas_operations=len(ops), records=len(records), unmatched_routes=len(unmatched), handler_unresolved=sum(not r['controller_signals']['handler_resolved'] for r in records),
                 by_package={}, route_authentication=sum(r['controller_signals']['route_authentication'] for r in records), with_route_authorization=sum(bool(r['controller_signals']['route_authorization']) for r in records),
                 handler_authz_lines_gt0=sum(r['controller_signals']['authz_lines_in_handler'] > 0 for r in records), oas_unmatched_ops=len(ops) - len(records))
    for r in records:
        pkg = (r['controller_signals']['handler'] or '?').split('.')[0]; stats['by_package'][pkg] = stats['by_package'].get(pkg, 0) + 1
    manifest = dict(**stats, tag=TAG, commit=COMMIT, license=LICENSE, output_sha256=hashlib.sha256(out.read_bytes()).hexdigest(), api_go_sha256=hashlib.sha256(API.read_bytes()).hexdigest(), oas_sha256=hashlib.sha256(OAS.read_bytes()).hexdigest(), unmatched=unmatched[:80])
    with open(OUT_DIR / f'gitea_{TAG}_manifest.json', 'w', encoding='utf-8', newline='\n') as f: json.dump(manifest, f, ensure_ascii=False, indent=2)
    # 10-sample report, stratified by package, seed 42
    rng = random.Random(42); pkgs = sorted(stats['by_package'], key=lambda k: -stats['by_package'][k]); sample = []
    pools = {p: [r for r in records if (r['controller_signals']['handler'] or '?').split('.')[0] == p and r['controller_signals']['handler_resolved']] for p in pkgs}
    quota = {'repo': 4, 'user': 2, 'org': 2, 'admin': 1, 'misc': 1}
    for p, n in quota.items():
        if pools.get(p): sample += rng.sample(pools[p], min(n, len(pools[p])))
    t = f'# Gitea {TAG} 발췌 표본 10건 (seed 42, 패키지별 층화) — 라벨 전 검토용\n\n커밋 {COMMIT}, MIT. 추출 규칙 R1~R5는 gitea_extraction_rules.md. 통계: 라우트 {stats["routes_parsed"]}, OAS operation {stats["oas_operations"]}, 매칭 레코드 {stats["records"]}, 미매칭 라우트 {stats["unmatched_routes"]}, 핸들러 미해결 {stats["handler_unresolved"]}, 라우트 미들웨어에 인증 {stats["route_authentication"]}, 라우트 인가 미들웨어 보유 {stats["with_route_authorization"]}, 핸들러 내부 인가 idiom 1줄 이상 {stats["handler_authz_lines_gt0"]}.\n\n'
    for r in sample:
        cs = r['controller_signals']
        t += f"## {r['id']}\n\n- 미들웨어: `{', '.join(cs['middleware']) or '(none)'}` | 핸들러: `{cs['handler']}` | 인가 idiom 줄 수: {cs['authz_lines_in_handler']}\n- OAS summary: {json.loads(r['oas_snippet'])['paths'][r['path']][r['method'].lower()].get('summary','')}\n\n```go\n{r['controller_text']}\n```\n\n"
    (REPORT_DIR / 'gitea_sample10.md').write_text(t, encoding='utf-8')
    print(json.dumps({k: v for k, v in manifest.items() if k != 'unmatched'}, ensure_ascii=False, indent=1)); print('unmatched sample', json.dumps(unmatched[:12], ensure_ascii=False))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--run', action='store_true'); a = ap.parse_args()
    if a.run: main()
