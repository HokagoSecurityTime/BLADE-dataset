"""NetBox (netbox-community/netbox, Apache-2.0) endpoint extraction for the data-v2 held-out test project. Static analysis only.

DRF-adapted rules (reports/eval/data_v2/netbox_extraction_rules.md):
 R1' Operations come from the repository-generated OpenAPI (contrib/openapi.json, drf-spectacular). operationId = <app>_<basename>_<action>.
     <app>/api/urls.py router.register(prefix, ViewSet) maps the path prefix to the ViewSet class; the action is the operationId suffix.
 R2' Code excerpt = (a) fixed framework note: DEFAULT_PERMISSION_CLASSES=TokenPermissions (Django model permission per HTTP method; token write
     flag) and BaseViewSet.initial() which restricts the queryset with RestrictedQuerySet.restrict(user, action) (object-level constraints
     configured by administrators; superusers bypass; anonymous read only when LOGIN_REQUIRED is false); (b) the ViewSet class header and
     class-level attributes (queryset, serializer_class, permission_classes, authentication_classes); (c) for a custom action, that method's
     source; for get_queryset / get_object overrides, their source. Cap 60 lines.
 R3' OAS snippet = the operation + securitySchemes (no global security in this spec; each operation lists cookieAuth/tokenAuth).
 R4' meta records app, viewset, action, permission_override, custom_action, base classes.
 R5' Held-out subset proposal: every non-standard operation (custom @action / special views), every ViewSet with an explicit permission_classes
     override, the whole users app, plus one representative model per app for the standard CRUD actions. Marked meta.heldout_subset_proposed.
"""
from __future__ import annotations
import ast, hashlib, json, re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]; NB = ROOT / 'datasets/blade/raw/opensource/netbox'; SRC = NB / 'netbox'
OAS = NB / 'contrib/openapi.json'; OUT_DIR = ROOT / 'datasets/blade/processed/opensource'
TAG = 'v4.7.3'; COMMIT = '3cd2c1d6469caed6c50e80eddd4cde863e0e2cf5'; LICENSE = 'Apache-2.0'
FRAMEWORK_NOTE = ('# NetBox DRF framework (netbox/netbox/api): settings.REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES = TokenPermissions (DjangoObjectPermissions):\n'
                  '#   GET/HEAD -> <app>.view_<model>, POST -> add_, PUT/PATCH -> change_, DELETE -> delete_ ; a Token must be write_enabled for unsafe methods.\n'
                  '#   authenticated_users_only = settings.LOGIN_REQUIRED (anonymous read allowed only when LOGIN_REQUIRED is False).\n'
                  '# BaseViewSet.initial(): for authenticated users self.queryset = self.queryset.restrict(request.user, action) -> RestrictedQuerySet.restrict():\n'
                  '#   superusers bypass; users without the model permission get queryset.none(); otherwise objects are filtered by the ObjectPermission constraints\n'
                  '#   assigned to the user/group (administrator-configured, may reference the requesting user via $user). Object-level checks also run on save().\n'
                  '# NetBoxModelViewSet adds bulk update/delete and change logging on top of BaseViewSet; NetBoxReadOnlyModelViewSet is list/retrieve only.')
STANDARD = {'list', 'create', 'retrieve', 'update', 'partial_update', 'destroy', 'bulk_update', 'bulk_partial_update', 'bulk_destroy'}
REP_MODELS = {'dcim': 'devices', 'ipam': 'prefixes', 'circuits': 'circuits', 'virtualization': 'virtual-machines', 'vpn': 'tunnels', 'wireless': 'wireless-lans', 'tenancy': 'tenants', 'extras': 'journal-entries', 'core': 'data-sources', 'users': 'users'}

def read(p): return p.read_text(encoding='utf-8', errors='replace')

def registrations():
    """prefix -> (app, ViewSet name, file) from each app's api/urls.py router.register calls."""
    out = {}
    for urls in SRC.glob('*/api/urls.py'):
        app = urls.parts[-3]; text = read(urls)
        for mo in re.finditer(r'router\.register\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(?:views\.)?(\w+)', text): out[(app, mo.group(1))] = mo.group(2)
        for mo in re.finditer(r'path\(\s*[\'"]([^\'"]+)[\'"]\s*,\s*(?:views\.)?(\w+)\.as_view\(\)', text): out[(app, mo.group(1).strip('/'))] = mo.group(2)
    return out

def class_source(app, name):
    f = SRC / app / 'api/views.py'
    if not f.exists(): return None
    text = read(f)
    try: tree = ast.parse(text)
    except SyntaxError: return None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == name: return f, text, node
    # try other view modules in the app api package
    for g in sorted((SRC / app / 'api').glob('views*.py')):
        t = read(g)
        try: tr = ast.parse(t)
        except SyntaxError: continue
        for node in tr.body:
            if isinstance(node, ast.ClassDef) and node.name == name: return g, t, node
    return None

def excerpt(f, text, node, action, http_method=''):
    lines = text.splitlines(); bases = [ast.unparse(b) for b in node.bases]
    head = [f'# {f.relative_to(NB).as_posix()}:{node.lineno}', f'class {node.name}({", ".join(bases)}):']
    attrs, methods = [], {}
    for item in node.body:
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            seg = ast.get_source_segment(text, item) or ''
            if any(k in seg for k in ('queryset', 'permission_classes', 'authentication_classes', 'serializer_class', 'filterset_class')): attrs.append('    ' + seg.replace('\n', '\n    ')[:400])
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)): methods[item.name] = item
    wanted = [m for m in ('get_queryset', 'get_object', 'initial', action, http_method, 'perform_create', 'perform_update', 'perform_destroy') if m in methods]
    body = head + attrs
    for m in wanted:
        seg = ast.get_source_segment(text, methods[m]) or ''
        seg_lines = seg.splitlines(); body.append(''); body += ['    ' + l for l in seg_lines[:25]] + (['    # ... (truncated)'] if len(seg_lines) > 25 else [])
    perm = next((a.strip() for a in attrs if 'permission_classes' in a), None)
    return '\n'.join(body[:60]), bases, perm, (action in methods)

def main():
    oas = json.loads(read(OAS)); regs = registrations(); records = []; unresolved = Counter(); seen_vs = Counter()
    for path, item in oas['paths'].items():
        for method, op in item.items():
            if method not in ('get', 'post', 'put', 'patch', 'delete'): continue
            opid = op.get('operationId', ''); parts = path.strip('/').split('/')
            if len(parts) < 2 or parts[0] != 'api': continue
            app = parts[1]; prefix = parts[2] if len(parts) > 2 else ''
            action = opid.split('_')[-1] if opid else ''
            if opid.endswith('bulk_update'): action = 'bulk_update'
            elif opid.endswith('bulk_partial_update'): action = 'bulk_partial_update'
            elif opid.endswith('bulk_destroy'): action = 'bulk_destroy'
            elif opid.endswith('partial_update'): action = 'partial_update'
            rest = [p for p in parts[2:] if not p.startswith('{')]
            vs = regs.get((app, '/'.join(rest))) or regs.get((app, prefix))
            nonstd_tail = [p for p in parts[3:] if not p.startswith('{')]
            if nonstd_tail and not re.fullmatch(r'/api/[\w-]+/[\w-]+/(\{id\}/)?', path): action = nonstd_tail[-1].replace('-', '_')
            if not vs:
                unresolved[(app, prefix)] += 1
                code = FRAMEWORK_NOTE + f'\n# viewset for {path} not resolved from {app}/api/urls.py'; bases = []; perm = None; custom = False; loc = []
            else:
                cs = class_source(app, vs)
                if not cs:
                    unresolved[(app, vs)] += 1; code = FRAMEWORK_NOTE + f'\n# class {vs} not found in {app}/api/views*.py'; bases = []; perm = None; custom = False; loc = []
                else:
                    f, text, node = cs; ex, bases, perm, custom = excerpt(f, text, node, action, method); code = FRAMEWORK_NOTE + '\n\n' + ex
                    loc = [dict(file=f.relative_to(NB).as_posix(), start_line=node.lineno, end_line=node.end_lineno)]
            seen_vs[vs or '?'] += 1
            nonstd = not re.fullmatch(r'/api/[\w-]+/[\w-]+/(\{id\}/)?', path)
            proposed = nonstd or bool(perm) or app == 'users' or REP_MODELS.get(app) == prefix
            snippet = dict(openapi=oas['openapi'], paths={path: {method: op}}, components={'securitySchemes': oas['components']['securitySchemes']})
            records.append(dict(id=f'netbox:{method}:{path}', source='opensource', service='netbox', method=method.upper(), path=path, label=None, llm_reference_label=None,
                                oas_snippet=json.dumps(snippet, ensure_ascii=False), erd_snippet='', controller_text=code,
                                controller_signals=dict(app=app, viewset=vs, action=action, bases=bases, permission_override=perm, custom_action=custom, standard_action=action in STANDARD, nonstandard_path=nonstd),
                                meta=dict(source='opensource', project='netbox', repository='https://github.com/netbox-community/netbox', tag=TAG, commit=COMMIT, license=LICENSE, license_notice_required=False,
                                          oas_status='repo_generated_openapi3', oas_file='contrib/openapi.json', erd_status='unknown', controller_status='available' if vs else 'unresolved', partition='heldout_test_only',
                                          heldout_subset_proposed=proposed, data_version='data-v2', source_locations=loc, extraction_rules="R1'-R5' netbox_extract.py")))
    OUT_DIR.mkdir(parents=True, exist_ok=True); out = OUT_DIR / f'netbox_{TAG}_endpoints.jsonl'
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        for r in records: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    prop = [r for r in records if r['meta']['heldout_subset_proposed']]
    man = dict(records=len(records), viewsets=len([k for k in seen_vs if k != '?']), unresolved=sum(unresolved.values()), unresolved_keys=[f'{a}:{b}' for (a, b) in unresolved][:40],
               proposed_subset=len(prop), proposed_by_reason=dict(nonstandard=sum(r['controller_signals']['nonstandard_path'] for r in prop), permission_override=sum(bool(r['controller_signals']['permission_override']) for r in prop),
                                                                     users_app=sum(r['controller_signals']['app'] == 'users' for r in prop), representative_model=sum(REP_MODELS.get(r['controller_signals']['app']) == r['path'].strip('/').split('/')[2] if len(r['path'].strip('/').split('/')) > 2 else False for r in prop)),
               by_app=dict(Counter(r['controller_signals']['app'] for r in records)), tag=TAG, commit=COMMIT, license=LICENSE, output_sha256=hashlib.sha256(out.read_bytes()).hexdigest(), oas_sha256=hashlib.sha256(OAS.read_bytes()).hexdigest())
    with open(OUT_DIR / f'netbox_{TAG}_manifest.json', 'w', encoding='utf-8', newline='\n') as f: json.dump(man, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in man.items() if k != 'unresolved_keys'}, ensure_ascii=False, indent=1)); print('unresolved', man['unresolved_keys'][:20])

if __name__ == '__main__': main()
