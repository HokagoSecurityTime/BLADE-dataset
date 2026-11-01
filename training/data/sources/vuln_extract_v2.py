"""Extract endpoints + authorization code from the two approved vulnerable API projects (test-only, data-v2):
  vAPI (roottusk/vapi, GPL-3.0, Laravel)  and  Damn Vulnerable RESTaurant (theowni, GPL-3.0, FastAPI).
Static analysis only. Labels are left empty (human ground truth); an LLM reference label may be added later as a separate field.
Output: datasets/blade/processed/test_v2_extra_candidates.jsonl (+ manifest). Never touches test.jsonl / test_v30.jsonl."""
from __future__ import annotations
import ast, hashlib, json, re, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]; RAW = ROOT / 'datasets/blade/raw/vuln_apis'
OUT = ROOT / 'datasets/blade/processed/test_v2_extra_candidates.jsonl'

def head(repo): return subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

# ---------------- vAPI (Laravel) ----------------
def php_method(text, name):
    mo = re.search(r'public function ' + re.escape(name) + r'\s*\(', text)
    if not mo: return None
    i = text.index('{', mo.end()); depth = 0
    for j in range(i, len(text)):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: return text[mo.start():j + 1], text[:mo.start()].count('\n') + 1, text[:j].count('\n') + 1
    return None

def vapi():
    repo = RAW / 'vAPI'; app = repo / 'vapi'; routes = (app / 'routes/api.php').read_text(encoding='utf-8', errors='replace'); commit = head(repo)
    auth_note = (app / 'app/CustomClasses/CustomHeaderAuth.php')
    auth_text = auth_note.read_text(encoding='utf-8', errors='replace') if auth_note.exists() else ''
    auth_summary = '// app/CustomClasses/CustomHeaderAuth.php: decodes the Authorization-Token header into username/password (used by controllers for authentication).'
    recs = []
    for mo in re.finditer(r"Route::(get|post|put|patch|delete)\('([^']+)'\s*,\s*'([^']+)'\)((?:->[^;]*)?);", routes):
        method, path, target, chain = mo.group(1).upper(), '/' + mo.group(2), mo.group(3), mo.group(4)
        ctrl, action = target.rsplit('@', 1); ctrl_file = app / 'app/Http/Controllers' / (ctrl.split('\\')[-1] + '.php')
        mws = re.findall(r"middleware\('([^']+)'\)", chain)
        fn = php_method(ctrl_file.read_text(encoding='utf-8', errors='replace'), action) if ctrl_file.exists() else None
        code = f'// routes/api.php: Route::{method.lower()}(\'{path}\') -> {target}' + (f'  middleware: {mws}' if mws else '') + '\n' + auth_summary + '\n\n' + (fn[0] if fn else '// controller method not found')
        oas = {'openapi': '3.0.0', 'paths': {path: {method.lower(): {'parameters': [{'name': p, 'in': 'path', 'required': True, 'schema': {'type': 'string'}} for p in re.findall(r'\{([^}]+)\}', path)], 'responses': {}}}}}
        recs.append(dict(id=f'vapi:{method.lower()}:{path}', source='vuln', service='vAPI', method=method, path=path, label=None, llm_reference_label=None,
                         oas_snippet=json.dumps(oas, ensure_ascii=False), erd_snippet='', controller_text=code,
                         controller_signals=dict(middleware=mws, handler=target, handler_resolved=bool(fn), auth_inline=bool(fn and 'CustomHeaderAuth' in fn[0]), auth_middleware=any('auth' in m for m in mws)),
                         meta=dict(source='vuln', project='vAPI', repository='https://github.com/roottusk/vapi', author='roottusk', commit=commit, license='GPL-3.0', license_notice_required=True,
                                   oas_status='route_only', erd_status='unknown', controller_status='available' if fn else 'unavailable', partition='test_only', data_version='data-v2',
                                   source_locations=[dict(file=str(ctrl_file.relative_to(repo)).replace('\\', '/'), start_line=fn[1], end_line=fn[2])] if fn else [])))
    return recs

# ---------------- Damn Vulnerable RESTaurant (FastAPI) ----------------
def dvr():
    repo = RAW / 'DVRestaurant'; app = repo / 'app'; commit = head(repo); recs = []
    prefixes = {}
    for py in app.rglob('*.py'):
        for mo in re.finditer(r'include_router\(\s*([\w\.]+)\s*,\s*prefix\s*=\s*["\']([^"\']*)["\']', py.read_text(encoding='utf-8', errors='replace')): prefixes[mo.group(1)] = mo.group(2)
    checker = (app / 'apis/auth/utils/roles_based_auth_checker.py').read_text(encoding='utf-8', errors='replace')
    auth_note = ('// apis/auth/utils/jwt_auth.py get_current_user: decodes the Bearer JWT (signature verification disabled in this fixture) and loads the user; 401 when invalid. Authentication only.\n'
                 '// apis/auth/utils/roles_based_auth_checker.py:\n' + checker.strip())
    for py in sorted(app.glob('apis/*/services/*.py')) + sorted(app.glob('apis/*/service.py')):
        text = py.read_text(encoding='utf-8', errors='replace')
        try: tree = ast.parse(text)
        except SyntaxError: continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
            for dec in node.decorator_list:
                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in ('get', 'post', 'put', 'patch', 'delete') and dec.args and isinstance(dec.args[0], ast.Constant):
                    method = dec.func.attr.upper(); path = dec.args[0].value; src = ast.get_source_segment(text, node)
                    deps = re.findall(r'Depends\(([^)]*\)?)', src); roles = re.findall(r'RolesBasedAuthChecker\(\[([^\]]*)\]\)', src)
                    include_in_schema = 'include_in_schema=False' in text
                    code = f'# {py.relative_to(repo).as_posix()}: @router.{method.lower()}("{path}")\n' + auth_note + '\n\n' + src
                    oas = {'openapi': '3.1.0', 'paths': {path: {method.lower(): {'summary': node.name.replace('_', ' '), 'parameters': [{'name': p, 'in': 'path', 'required': True, 'schema': {'type': 'string'}} for p in re.findall(r'\{([^}]+)\}', path)], 'responses': {}}}}}
                    if 'get_current_user' in src or 'RolesBasedAuthChecker' in src: oas['paths'][path][method.lower()]['security'] = [{'OAuth2PasswordBearer': []}]
                    recs.append(dict(id=f'dvrestaurant:{method.lower()}:{path}', source='vuln', service='DVRestaurant', method=method, path=path, label=None, llm_reference_label=None,
                                     oas_snippet=json.dumps(oas, ensure_ascii=False), erd_snippet='', controller_text=code,
                                     controller_signals=dict(dependencies=deps, required_roles=roles, auth_dependency=('get_current_user' in src) or bool(roles), handler=node.name, handler_resolved=True, hidden_from_schema=include_in_schema),
                                     meta=dict(source='vuln', project='DVRestaurant', repository='https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game', author='theowni', commit=commit, license='GPL-3.0', license_notice_required=True,
                                               oas_status='decorator_projection', erd_status='unknown', controller_status='available', partition='test_only', data_version='data-v2',
                                               source_locations=[dict(file=py.relative_to(repo).as_posix(), start_line=node.lineno, end_line=node.end_lineno)])))
    return recs

def main():
    recs = vapi() + dvr()
    if OUT.exists(): raise FileExistsError(OUT)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        for r in recs: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    man = dict(records=len(recs), by_project={p: sum(r['service'] == p for r in recs) for p in ('vAPI', 'DVRestaurant')}, output_sha256=sha(OUT),
               commits={'vAPI': head(RAW / 'vAPI'), 'DVRestaurant': head(RAW / 'DVRestaurant')}, licenses={'vAPI': 'GPL-3.0', 'DVRestaurant': 'GPL-3.0'}, labels='empty (human ground truth pending); llm_reference_label pending approval')
    with open(OUT.with_suffix('.manifest.json'), 'w', encoding='utf-8', newline='\n') as f: json.dump(man, f, ensure_ascii=False, indent=2)
    print(json.dumps(man, ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
