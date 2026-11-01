"""Import human test decisions; refuse overwrite of a frozen test artifact."""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from functools import lru_cache
import yaml
from training.data.xlsx_review import sheets

ROOT = Path(__file__).resolve().parents[2]
LABELS = {'public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required'}

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]

@lru_cache(maxsize=20)
def read_spec(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding='utf-8'))

def oas_for(row: dict) -> tuple[str, str]:
    if row.get('oas_snippet'):
        return row['oas_snippet'], 'original_export'
    method, path = row['method'].lower(), row['path']
    origin = row.get('oas_source', {})
    if origin.get('oas_file'):
        spec = read_spec(ROOT / 'datasets/blade/raw/vuln_apis' / row['service'] / origin['oas_file'])
        item = deepcopy(spec.get('paths', {}).get(origin['oas_path'], {}))
        if method in item:
            selected = {method: item[method]}
            if 'parameters' in item:
                selected['parameters'] = item['parameters']
            result = {k: deepcopy(spec[k]) for k in ('openapi', 'swagger', 'info', 'security', 'securityDefinitions', 'servers', 'basePath') if k in spec}
            result['paths'] = {path: selected}
            # Include only transitively referenced schemas, avoiding unrelated endpoint data.
            pending = re.findall(r'"\$ref"\s*:\s*"(#[^"]+)"', json.dumps(selected))
            seen = set()
            while pending:
                ref = pending.pop()
                if ref in seen:
                    continue
                seen.add(ref)
                keys = [s.replace('~1', '/').replace('~0', '~') for s in ref[2:].split('/')]
                value = spec
                try:
                    for key in keys:
                        value = value[key]
                except (KeyError, TypeError):
                    continue
                target = result
                for key in keys[:-1]:
                    target = target.setdefault(key, {})
                target[keys[-1]] = deepcopy(value)
                pending.extend(re.findall(r'"\$ref"\s*:\s*"(#[^"]+)"', json.dumps(value)))
            if 'securitySchemes' in spec.get('components', {}):
                result.setdefault('components', {})['securitySchemes'] = spec['components']['securitySchemes']
            return json.dumps(result, ensure_ascii=False), 'repository_spec'
    params = row.get('parameters') or [{'name': p, 'in': 'path', 'required': True, 'schema': {'type': 'string'}} for p in re.findall(r'\{([^}]+)\}', path)]
    return json.dumps({'openapi': '3.0.0', 'paths': {path: {method: {'parameters': params, 'responses': {}}}}}, ensure_ascii=False), 'route_only'

def prepare(workbook: Path, approve_synthetic: bool = False) -> tuple[list[dict], dict]:
    sources = [ROOT / 'datasets/blade/processed/vuln_review_candidates.jsonl', ROOT / 'verification/synthetic_review_records.jsonl']
    records = {r['id']: r for p in sources for r in read_rows(p)}
    partition = json.loads((ROOT / 'training/data/synthetic_partition.json').read_text())
    result, excluded, pending = [], [], []
    seen = set()
    for sheet in sheets(workbook).values():
        for cell in sheet:
            ident = cell.get('A', '').strip()
            if ident not in records:
                if cell.get('B') in ('vuln', 'synthetic'):
                    raise ValueError(f'Unknown workbook ID: {ident}')
                continue
            if ident in seen:
                raise ValueError(f'Duplicate workbook ID: {ident}')
            seen.add(ident)
            row = deepcopy(records[ident])
            label = cell.get('J', '').strip()
            if label == '제외':
                excluded.append(ident)
                continue
            confirmation = 'workbook_confirmed'
            if not label and row['source'] == 'synthetic':
                if not approve_synthetic:
                    pending.append(ident)
                    continue
                label = row['proposed_label']
                confirmation = 'user_approved_intended_labels'
            if label not in LABELS:
                raise ValueError(f'Unconfirmed/invalid label for {ident}: {label!r}')
            if row['service'] in partition['train_services']:
                raise ValueError(f'Train-only synthetic service: {row["service"]}')
            row['path'] = cell.get('E', '').strip() or row.get('effective_path') or row['path']
            oas, oas_status = oas_for(row)
            excerpts = row.get('handler_excerpts_50') or row.get('source_locations') or []
            controller = '\n\n'.join(x.get('excerpt', '') for x in excerpts)
            if not controller:
                controller = row.get('code_excerpt', '')
            result.append({k: row[k] for k in ('id', 'source', 'service', 'method', 'path')} | {
                'label': label, 'oas_snippet': oas, 'erd_snippet': row.get('erd_snippet', ''),
                'controller_text': controller, 'controller_signals': row.get('controller_signals', {}),
                'meta': {'label_source': confirmation, 'known_vulnerable': row.get('meta', {}).get('known_vulnerable', False),
                         'oas_status': oas_status, 'erd_status': 'available' if row.get('erd_snippet') else 'unknown',
                         'controller_status': 'available' if controller else 'unavailable',
                         'source_locations': [{k: x[k] for k in ('file', 'start_line', 'end_line', 'file_sha256') if k in x} for x in excerpts]}})
    assert len(seen) == 317, len(seen)
    assert len(excluded) == 64, len(excluded)
    assert len(result) + len(pending) == 253
    assert len({r['id'] for r in result}) == len(result)
    counts = Counter((r['label'], r['source']) for r in result)
    manifest = {'created_at': datetime.now(timezone.utc).isoformat(), 'workbook': str(workbook), 'workbook_sha256': digest(workbook),
                'source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in sources}, 'count': len(result),
                'excluded_count': len(excluded), 'excluded_ids': excluded, 'pending_confirmation_ids': pending,
                'label_by_source': {label: {src: counts[label, src] for src in ('vuln', 'synthetic')} for label in sorted(LABELS)},
                'inference_input_policy': 'Original specification, route parameters, raw source excerpts, and available original ERD only; human labels/review reasons are never inserted into inputs.'}
    return result, manifest

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--workbook', type=Path, default=Path('<USERPROFILE>/Downloads/review/review_test.xlsx'))
    parser.add_argument('--approve-synthetic-intended', action='store_true')
    parser.add_argument('--freeze', action='store_true')
    args = parser.parse_args()
    rows, manifest = prepare(args.workbook, args.approve_synthetic_intended)
    if args.freeze and manifest['pending_confirmation_ids']:
        raise ValueError('Synthetic confirmed labels are blank; explicit user confirmation required.')
    destination = ROOT / ('datasets/blade/processed/test.jsonl' if args.freeze else 'verification/test_confirmed_draft.jsonl')
    if args.freeze and destination.exists():
        raise FileExistsError('Frozen test file already exists; overwrite forbidden.')
    data = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows).encode('utf-8')
    destination.write_bytes(data)
    manifest['test_sha256'] = hashlib.sha256(data).hexdigest()
    manifest['frozen'] = args.freeze
    out = ROOT / ('verification/test_frozen_manifest.json' if args.freeze else 'verification/test_draft_manifest.json')
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    if args.freeze:
        with (ROOT / 'AGENTS.md').open('a', encoding='utf-8') as handle:
            handle.write('\n## Frozen human-reviewed test set (2026-10-20)\n\n- `datasets/blade/processed/test.jsonl`: 253 records (vuln 211 + synthetic 42).\n- SHA-256: `' + manifest['test_sha256'] + '`.\n- Human-confirmed test set is frozen. Do not modify or regenerate it.\n- Provenance: `verification/test_frozen_manifest.json`.\n')
    print(json.dumps({'count': len(rows), 'pending': len(manifest['pending_confirmation_ids']), 'sha256': manifest['test_sha256'], 'frozen': args.freeze}))

if __name__ == '__main__':
    main()
