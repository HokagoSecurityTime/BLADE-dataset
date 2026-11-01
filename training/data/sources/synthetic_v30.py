"""v3.0 group-membership synthetic fixtures (2026-10-21 user decision 3).

summit_club  : test-only  (FastAPI, expeditions; group = club)   — membership_required x4, compound tenant AND membership -> manual x2
relay_forum  : train-only (FastAPI, threads;     group = circle) — membership_required x4, owner_or_admin x4
membership_required here means the caller is a member of the target object's group ((user_id, group_id) in memberships), the v3.0 meaning.
Never touches the six original fixtures, test.jsonl, train.jsonl or val.jsonl. Framework-exported OpenAPI (fastapi app.openapi()).
"""
from __future__ import annotations
import argparse, ast, hashlib, importlib.util, json, re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / 'datasets/blade/raw/synthetic'
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user'},
              'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user'},
              'carol': {'id': 'carol', 'tenant_id': 'north', 'role': 'user'},
              'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin'}}
MEMBERSHIPS = [('alice', 'g_north_hikers'), ('bob', 'g_south_riders'), ('carol', 'g_south_riders')]
OBJECTS = {'1': {'id': '1', 'owner_id': 'alice', 'tenant_id': 'north', 'group_id': 'g_north_hikers', 'value': 'fixture secret'},
           '2': {'id': '2', 'owner_id': 'bob', 'tenant_id': 'south', 'group_id': 'g_south_riders', 'value': 'other secret'},
           '3': {'id': '3', 'owner_id': 'carol', 'tenant_id': 'north', 'group_id': 'g_south_riders', 'value': 'cross-tenant group secret'}}
CHECK = {'owner_match': 'principal["id"] != obj["owner_id"]',
         'owner_or_admin': 'principal["id"] != obj["owner_id"] and principal["role"] != "admin"',
         'tenant_match': 'principal["tenant_id"] != obj["tenant_id"]',
         'role_required': 'principal["role"] != "admin"',
         'membership_required': '(principal["id"], obj["group_id"]) not in MEMBERSHIPS',
         'manual_review_required': 'principal["tenant_id"] != obj["tenant_id"] or (principal["id"], obj["group_id"]) not in MEMBERSHIPS'}
REASON = {'public': 'Intentionally anonymous reference catalogue.',
          'owner_match': 'Only the record owner may read it.',
          'owner_or_admin': 'The record owner or an administrator may read it.',
          'tenant_match': 'Caller and record must share a tenant.',
          'role_required': 'Only administrators may read this operational resource.',
          'membership_required': 'Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.',
          'manual_review_required': 'Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.'}
# (section, label, vulnerable variant exists)
SERVICES = {
    'summit_club': dict(noun='expeditions', group='club', sections=[('catalogue', 'public'), ('drafts', 'owner_match'), ('shared', 'owner_or_admin'), ('workspace', 'tenant_match'), ('audit', 'role_required'), ('roster', 'membership_required'), ('gear', 'membership_required'), ('council', 'manual_review_required')], partition='test'),
    'relay_forum': dict(noun='threads', group='circle', sections=[('catalogue', 'public'), ('drafts', 'owner_match'), ('shared', 'owner_or_admin'), ('moderation', 'owner_or_admin'), ('workspace', 'tenant_match'), ('audit', 'role_required'), ('roster', 'membership_required'), ('pins', 'membership_required'), ('council', 'manual_review_required')], partition='train'),
}

def endpoints(name):
    rows = []
    for section, label in SERVICES[name]['sections']:
        for i in range(2):
            rows.append(dict(id=f'{name}_{section}_{i}', method='GET', path=f'/fixtures/{name}/{SERVICES[name]["noun"]}/{section}/{"current" if i == 0 else "archive"}/{{item_id}}',
                             label=label, vulnerable=(i == 1 and label not in {'public', 'manual_review_required'}), reason=REASON[label]))
    return rows

def app_source(name, rows):
    code = 'from fastapi import FastAPI, Header, HTTPException\napp = FastAPI(title=' + repr(name) + ')\n'
    code += 'PRINCIPALS = ' + repr(PRINCIPALS) + '\n'
    code += 'MEMBERSHIPS = {' + ', '.join(repr(m) for m in MEMBERSHIPS) + '}  # (user_id, group_id): group membership, independent of tenant\n'
    code += 'OBJECTS = ' + json.dumps(OBJECTS) + '\n'
    code += 'def principal_for(token):\n    return PRINCIPALS.get(token.removeprefix("Bearer "))\n\n'
    for row in rows:
        code += f'@app.get({row["path"]!r}, description={row["reason"]!r})\ndef {row["id"]}(item_id: str, authorization: str = Header(default="")):\n'
        code += '    obj = OBJECTS.get(item_id)\n    if obj is None: raise HTTPException(404)\n'
        if row['label'] != 'public':
            code += '    principal = principal_for(authorization)\n    if principal is None: raise HTTPException(401)\n'
            if row['vulnerable']: code += '    # Deliberate fixture: object authorization check omitted.\n'
            else: code += '    if ' + CHECK[row['label']] + ': raise HTTPException(403)\n'
        code += '    return obj\n\n'
    return code

def model_source(name):
    noun = SERVICES[name]['noun']
    return ('from dataclasses import dataclass, fields\n@dataclass\nclass Record:\n    id: str\n    owner_id: str\n    tenant_id: str\n    group_id: str\n    value: str\n\n'
            '@dataclass\nclass Membership:\n    user_id: str\n    group_id: str\n\n'
            'def ddl():\n    rec = "CREATE TABLE ' + name + '_' + noun + ' (" + ", ".join(f.name + " TEXT" + (" PRIMARY KEY" if f.name == "id" else " NOT NULL") for f in fields(Record)) + ");"\n'
            '    mem = "CREATE TABLE ' + name + '_memberships (" + ", ".join(f.name + " TEXT NOT NULL" for f in fields(Membership)) + ", PRIMARY KEY (user_id, group_id));"\n    return rec + "\\n" + mem\n\n'
            'if __name__ == "__main__":\n    from pathlib import Path\n    Path(__file__).with_name("schema.sql").write_text(ddl())\n')

def write(base, rel, text):
    p = base / rel; p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8', newline='\n') as f: f.write(text)

def export_openapi(base):
    spec = importlib.util.spec_from_file_location('fixture_app_' + base.name, base / 'app.py'); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    write(base, 'openapi.json', json.dumps(mod.app.openapi(), indent=2))

def generate(name):
    base = RAW / name; rows = endpoints(name)
    if base.exists(): raise FileExistsError(f'{base} exists; fixtures are generated once and then frozen')
    write(base, 'app.py', app_source(name, rows))
    write(base, 'model.py', model_source(name)); ns = {}; exec(compile(model_source(name), 'model.py', 'exec'), ns); write(base, 'schema.sql', ns['ddl']() + '\n')
    write(base, 'intended_labels.yaml', yaml.safe_dump({'service': name, 'group_semantics': 'membership_required = (caller_id, record.group_id) in memberships (v3.0 meaning)', 'partition': SERVICES[name]['partition'] + '_only', 'endpoints': rows}, sort_keys=False))
    write(base, 'requirements.txt', 'fastapi>=0.115,<1\nuvicorn>=0.30,<1\n')
    write(base, 'export_openapi.py', 'import json\nfrom app import app\nfrom pathlib import Path\nPath("openapi.json").write_text(json.dumps(app.openapi(),indent=2))\n')
    write(base, 'Dockerfile', 'FROM python:3.11-slim\nWORKDIR /fixture\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\nRUN python export_openapi.py\nEXPOSE 8080\nCMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080"]\n')
    write(base, 'README.md', f'# {name}\n\nv3.0 group-membership synthetic fixture ({SERVICES[name]["partition"]}-only). Bearer tokens: alice (north, member of g_north_hikers), bob (south, member of g_south_riders), carol (north, member of g_south_riders), admin (north, admin, no memberships). Objects 1/alice/north/g_north_hikers, 2/bob/south/g_south_riders, 3/carol/north/g_south_riders (cross-tenant group). membership_required routes check (caller_id, record.group_id) in MEMBERSHIPS — not a plan, tier or tenant. council routes require tenant match AND group membership (two independent conditions → manual_review_required). archive variants omit the indicated authorization check. OpenAPI is exported by FastAPI (app.openapi()), not hand-written.\n')
    export_openapi(base)
    return rows

def handler_blocks(base):
    text = (base / 'app.py').read_text(encoding='utf-8'); tree = ast.parse(text); lines = text.splitlines()
    return {n.name: (ast.get_source_segment(text, n), n.lineno, n.end_lineno) for n in tree.body if isinstance(n, ast.FunctionDef)}, lines

def signals(row):
    return {'has_auth_check': row['label'] != 'public', 'admin_bypass': row['label'] == 'owner_or_admin' and not row['vulnerable'],
            'tenant_check': row['label'] in {'tenant_match', 'manual_review_required'} and not row['vulnerable'],
            'owner_filter': row['label'] in {'owner_match', 'owner_or_admin'} and not row['vulnerable'],
            'membership_check': row['label'] in {'membership_required', 'manual_review_required'} and not row['vulnerable']}

def test_records(name='summit_club'):
    """Frozen-test record shape (same keys as test.jsonl synthetic rows)."""
    base = RAW / name; oas = json.loads((base / 'openapi.json').read_text(encoding='utf-8')); ddl = (base / 'schema.sql').read_text(encoding='utf-8').strip()
    blocks, lines = handler_blocks(base); out = []
    for row in endpoints(name):
        src, start, end = blocks[row['id']]; block = src.splitlines()
        k = next((i for i, l in enumerate(block) if '403' in l or 'Deliberate fixture' in l), max(0, len(block) - 2))
        excerpt = '\n'.join(block[k:k + 3]).strip()
        op = oas['paths'][row['path']]['get']
        out.append(dict(id=row['id'], source='synthetic', service=name, method='GET', path=row['path'], label=row['label'],
                        oas_snippet=json.dumps({'openapi': oas['openapi'], 'paths': {row['path']: {'get': op}}}, ensure_ascii=False), erd_snippet=ddl,
                        controller_text=excerpt, controller_signals=signals(row),
                        meta={'label_source': 'intended_labels_v30_design', 'known_vulnerable': row['vulnerable'], 'oas_status': 'original_export', 'erd_status': 'available', 'controller_status': 'available',
                              'source_locations': [{'file': f'datasets/blade/raw/synthetic/{name}/app.py', 'start_line': start, 'end_line': end}], 'group_membership_semantics': 'v3.0', 'added': 'test_v30 2026-10-21'}))
    return out

def train_records(name='relay_forum'):
    """train.jsonl synthetic row shape (as build_train.synthetic_rows), plus membership_check signal."""
    base = RAW / name; oas = json.loads((base / 'openapi.json').read_text(encoding='utf-8')); ddl = (base / 'schema.sql').read_text(encoding='utf-8')
    blocks, _ = handler_blocks(base); out = []
    for row in endpoints(name):
        op = oas['paths'][row['path']]['get']; src = blocks[row['id']][0]
        out.append(dict(id=row['id'], service=name, method='GET', path=row['path'], oas_snippet=json.dumps({'paths': {row['path']: {'get': op}}}, ensure_ascii=False), erd_snippet=ddl,
                        controller_signals={**signals(row), 'raw_snippet': src}, label=row['label'], rationale=row['reason'], confidence=1.0, description=op.get('description', row['reason']), security_state='unknown',
                        meta=dict(source='synthetic', label_source='intended_labels', human_confirmed=False, evidence_invalid=False, flag_review=False, known_vulnerable=row['vulnerable'],
                                  confidence_provenance='design_intent_not_model_probability', source_file=f'datasets/blade/raw/synthetic/{name}/app.py', group_membership_semantics='v3.0'),
                        training_target_fields=['label', 'rationale']))
    return out

def file_hashes(name):
    base = RAW / name
    return {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(base.rglob('*')) if p.is_file()}

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--generate', action='store_true'); a = ap.parse_args()
    if a.generate:
        for name in SERVICES: print(name, len(generate(name)), 'endpoints')
        part = json.loads((ROOT / 'training/data/synthetic_partition.json').read_text(encoding='utf-8'))
        part_v30 = {**part, 'v30_added': {'train_services': ['relay_forum'], 'test_services': ['summit_club'], 'date': '2026-10-21', 'reason': 'group-membership (v3.0 meaning) and owner_or_admin coverage'},
                    'train_services': part['train_services'] + ['relay_forum'], 'test_services': part['test_services'] + ['summit_club']}
        with open(ROOT / 'training/data/synthetic_partition_v30.json', 'w', encoding='utf-8', newline='\n') as f: json.dump(part_v30, f, indent=2)
        print(json.dumps({n: len(file_hashes(n)) for n in SERVICES}))
