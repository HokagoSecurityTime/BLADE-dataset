"""Offline evidence recovery and fixed pilot selection; never overwrite inputs/outputs."""
from __future__ import annotations

import copy
import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'datasets/blade/raw/openapi-directory/APIs'
PROCESSED = ROOT / 'datasets/blade/processed'


class OpenAPILoader(getattr(yaml, 'CSafeLoader', yaml.SafeLoader)):
    def construct_mapping(self, node, deep=False):
        self.flatten_mapping(node)
        result = {}
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                raise ValueError('Non-scalar OpenAPI object key')
            result[key.value] = self.construct_object(value, deep=deep)
        return result


OpenAPILoader.add_constructor('tag:yaml.org,2002:timestamp', lambda loader, node: loader.construct_scalar(node))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pointer(parent, key):
    return parent + '/' + str(key).replace('~', '~0').replace('/', '~1')


def resolve_pointer(document, ref):
    if not isinstance(ref, str) or not ref.startswith('#/'):
        raise ValueError('External or unsupported reference')
    node = document
    for token in unquote(ref[2:]).split('/'):
        token = token.replace('~1', '/').replace('~0', '~')
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def recover(spec, row, source_file, source_sha256):
    path_ptr = pointer('#/paths', row['path'])
    method = row['method'].lower()
    paths = spec.get('paths') or {}
    path_item = paths.get(row['path'])
    base = dict(status='operation_not_found', source_file=source_file,
                source_sha256=source_sha256, spec_version=spec.get('openapi', spec.get('swagger')),
                info_version=(spec.get('info') or {}).get('version'),
                revision_verification='original_extraction_hash_unavailable_current_local_snapshot_only',
                schema_provenance='api_response_inferred', verified_erd=None)
    # Referenced path items must be followed without silently treating missing data as absent.
    if isinstance(path_item, dict) and '$ref' in path_item:
        try:
            path_ptr = path_item['$ref']
            path_item = resolve_pointer(spec, path_ptr)
        except (ValueError, KeyError, IndexError, TypeError):
            return dict(base, status='path_reference_unresolved')
    if not isinstance(path_item, dict) or not isinstance(path_item.get(method), dict):
        return base
    op = path_item[method]
    op_ptr = pointer(path_ptr, method)
    facts, refs, unresolved, visited = [], {}, [], set()

    def walk(node, location, kind, active=()):
        if isinstance(node, dict):
            ref = node.get('$ref')
            if ref is not None:
                if ref in active:
                    unresolved.append(dict(json_pointer=pointer(location, '$ref'), ref=ref, reason='cycle'))
                elif ref not in visited:
                    visited.add(ref)
                    try:
                        target = resolve_pointer(spec, ref)
                    except (KeyError, TypeError, ValueError, IndexError):
                        unresolved.append(dict(json_pointer=pointer(location, '$ref'), ref=ref, reason='external_or_missing'))
                    else:
                        refs[ref] = copy.deepcopy(target)
                        walk(target, ref, kind, (*active, ref))
            for key, value in node.items():
                child = pointer(location, key)
                if key in ('description', 'summary') and isinstance(value, str) and value.strip():
                    facts.append(dict(json_pointer=child, text=value, kind=kind))
                walk(value, child, kind, active)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, pointer(location, index), kind, active)

    trees = {}
    for field in ('summary', 'description', 'parameters'):
        if field in path_item:
            trees['path_' + field] = path_item[field]
            walk({field: path_item[field]}, path_ptr, 'path_' + field)
    for field in ('summary', 'description', 'parameters', 'requestBody', 'responses'):
        if field in op:
            trees[field] = op[field]
            if field == 'responses':
                for code, response in op[field].items():
                    kind = 'response_success' if str(code).startswith('2') else 'response_error_or_default'
                    walk(response, pointer(pointer(op_ptr, field), code), kind)
            else:
                walk({field: op[field]}, op_ptr, 'operation_' + field)
    if 'security' in op:
        origin, effective = 'operation', op['security']
    elif 'security' in spec:
        origin, effective = 'global', spec['security']
    else:
        origin, effective = 'unspecified', None
    all_schemes = (spec.get('components') or {}).get('securitySchemes', spec.get('securityDefinitions', {})) or {}
    scheme_ptr = '#/components/securitySchemes' if 'openapi' in spec else '#/securityDefinitions'
    names = {name for item in effective or [] if isinstance(item, dict) for name in item}
    schemes = {name: all_schemes[name] for name in sorted(names) if name in all_schemes}
    for name, scheme in schemes.items():
        walk(scheme, pointer(scheme_ptr, name), 'security_scheme')
        # Scope descriptions use arbitrary scope names as keys, not a description property.
        scopes = scheme.get('scopes', {})
        scope_sets = [(pointer(pointer(scheme_ptr, name), 'scopes'), scopes)]
        for flow, data in (scheme.get('flows') or {}).items():
            scope_sets.append((pointer(pointer(pointer(pointer(scheme_ptr, name), 'flows'), flow), 'scopes'), data.get('scopes', {})))
        for location, mapping in scope_sets:
            for name_, description in mapping.items():
                if isinstance(description, str):
                    facts.append(dict(json_pointer=pointer(location, name_), text=description, kind='security_scope'))
    unique = {(f['json_pointer'], f['kind']): f for f in facts}
    old_snippet = json.loads(row.get('oas_snippet', '{}'))
    comparison = {
        'summary_matches_extractor_projection': old_snippet.get('summary') == (op.get('summary') or op.get('description', '')[:300]),
        'security_matches_extractor_projection': old_snippet.get('security') == effective,
    }
    return dict(base, status='recovered', operation_pointer=op_ptr,
                original_projection_comparison=comparison,
                operation={k: op.get(k) for k in ('operationId', 'summary', 'description')},
                trees=trees, references=refs, unresolved_references=unresolved,
                security=dict(origin=origin, effective=effective, schemes=schemes,
                              missing_schemes=sorted(names - schemes.keys()),
                              anonymous_alternative=(effective == [] or any(x == {} for x in effective or [])) if effective is not None else None),
                facts=list(unique.values()))


def select_pilot(enriched, old):
    rng = random.Random(42)
    old_by_id = {row['id']: row for row in old}
    positives = [row for row in enriched if old_by_id[row['id']]['label'] != 'manual_review_required']
    if len(positives) != 21:
        raise ValueError('Expected exactly 21 existing non-manual decisions')
    selections = [(row, 'existing_direct_decision') for row in positives]
    allocation = {}
    for group, quota in zip(('owner', 'tenant', 'both', 'path_only', 'none'), (16,16,16,16,15)):
        pool = [row for row in enriched if old_by_id[row['id']]['label'] == 'manual_review_required' and row['meta']['signal_class'] == group]
        mandatory = [row for row in pool if 'bigoven' in row['service'].lower() and any(any(phrase in fact['text'].lower() for phrase in ('original one that posted', 'owned by someone else')) for fact in row['enrichment'].get('facts', []))]
        if len(mandatory) > quota:
            raise ValueError('Mandatory BigOven cases exceed group quota')
        others = [row for row in pool if row not in mandatory]
        chosen = mandatory + rng.sample(others, min(quota-len(mandatory), len(others)))
        selections.extend((row, 'mandatory_explicit_owner_bigoven' if row in mandatory else 'stratified_manual') for row in chosen)
        allocation[group] = len(chosen)
    if len(selections) < 100:
        used = {row['id'] for row, _ in selections}
        pool = [row for row in enriched if row['id'] not in used]
        for row in rng.sample(pool, 100-len(selections)):
            selections.append((row, 'quota_shortfall_reallocation'))
            allocation[row['meta']['signal_class']] += 1
    records = [dict(id=row['id'], source_sha256=row['enrichment'].get('source_sha256'), signal_class=row['meta']['signal_class'], selection_reason=reason) for row, reason in selections]
    return dict(seed=42, design='purposive_stratified_pilot_not_population_random_sample',
                manual_allocation=allocation, ids=[row['id'] for row in records], records=records)


def main():
    outputs = [PROCESSED/'apisguru_enriched_v2.jsonl', ROOT/'training/data/pilot_v2_ids.json', ROOT/'training/data/enrichment_report_v2.md']
    if any(path.exists() for path in outputs):
        raise FileExistsError('Refusing to overwrite an existing v2 artifact')
    source = PROCESSED/'apisguru_filtered.jsonl'
    old_file = PROCESSED/'apisguru_agent_labeled.jsonl'
    source_bytes, old_bytes = source.read_bytes(), old_file.read_bytes()
    rows = [json.loads(line) for line in source_bytes.decode('utf8').splitlines()]
    old = [json.loads(line) for line in old_bytes.decode('utf8').splitlines()]
    cache = {}
    for row in rows:
        relative = row['meta']['source_file'].replace('\\', '/')
        local = (SOURCE/relative).resolve()
        if not local.is_relative_to(SOURCE.resolve()):
            raise ValueError('Source path escapes source root')
        if relative not in cache:
            if not local.is_file():
                cache[relative] = (None, None)
            else:
                data = local.read_bytes()
                cache[relative] = (yaml.load(data.decode('utf8'), Loader=OpenAPILoader), digest(data))
        spec, sha = cache[relative]
        row['enrichment'] = recover(spec, row, relative, sha) if spec else dict(status='source_unavailable', source_file=relative, source_sha256=sha, verified_erd=None)
    pilot = select_pilot(rows, old)
    pilot['input_sha256'] = digest(source_bytes)
    pilot['previous_labels_sha256'] = digest(old_bytes)
    outputs[0].write_text(''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in rows), encoding='utf8')
    pilot['enriched_sha256'] = digest(outputs[0].read_bytes())
    outputs[1].write_text(json.dumps(pilot, indent=2, ensure_ascii=False)+'\n', encoding='utf8')
    counts = Counter(row['enrichment']['status'] for row in rows)
    unresolved = sum(bool(row['enrichment'].get('unresolved_references')) for row in rows)
    report = f'''# Evidence recovery v2\n\nRecords: {len(rows)}. Status counts: {dict(counts)}.\n\nRecords with cyclic/external/missing references: {unresolved}. References retain raw structure and per-reference unresolved reasons; no network requests.\n\nCurrent source snapshot hashes are recorded, but original extraction hashes were not recorded, so identity with the original source revision cannot be proven. No newer source was downloaded.\n\nOriginal fields are preserved. Inferred ERD is not a verified database schema.\n\nPilot: {len(pilot['ids'])}; original direct decisions 21; manual allocation {pilot['manual_allocation']}; seed 42. Deliberately constructed, not a population-random evaluation.\n\nInput SHA-256: {digest(source_bytes)}\n\nEnriched SHA-256: {pilot['enriched_sha256']}\n'''
    outputs[2].write_text(report, encoding='utf8')
    assert source.read_bytes() == source_bytes and old_file.read_bytes() == old_bytes
    print(report)


if __name__ == '__main__':
    main()
