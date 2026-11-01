"""Dataset inspection, conversion and service splitting only; no model training.

Run: python -m training.data.convert
Missing raw data is an error and never produces empty 'successful' splits.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import random
import re
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
LABELS = ('public', 'role_required', 'membership_required', 'tenant_match',
          'owner_match', 'owner_or_admin', 'manual_review_required')
FIELDS = ('id', 'service', 'method', 'path', 'oas_snippet', 'erd_snippet',
          'controller_signals', 'label', 'rationale')
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE'}


def encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def sha(value: Any) -> str:
    return hashlib.sha256(encoded(value).encode('utf-8')).hexdigest()


def empty(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip()) or value == [] or value == {}


def field(row: dict[str, Any], location: str) -> Any:
    value: Any = row
    for part in location.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def snippet(value: Any) -> str:
    if empty(value):
        return ''
    return value.strip() if isinstance(value, str) else encoded(value)


def path_signature(path: str) -> str:
    return re.sub(r'\{[^/{}]+\}', '{}', path.rstrip('/') or '/')


def demo_endpoints(source: Path = ROOT / 'demo_backend/main.py') -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(source.read_text(encoding='utf-8-sig'))):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name) and decorator.func.value.id == 'app'
                    and decorator.func.attr.upper() in METHODS and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                    and isinstance(decorator.args[0].value, str)):
                routes.add((decorator.func.attr.upper(), path_signature(decorator.args[0].value)))
    return routes


def load_raw(directory: Path) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    supported = {'.jsonl', '.json', '.csv', '.yaml', '.yml'}
    files = sorted(p for p in directory.rglob('*') if p.is_file() and p.suffix.lower() in supported)
    if not files:
        raise ValueError(f'No supported source records in {directory}; no splits written')
    records: list[tuple[str, dict[str, Any]]] = []
    manifest = []
    for path in files:
        relative = path.relative_to(directory).as_posix()
        contents = path.read_text(encoding='utf-8-sig')
        if path.suffix.lower() == '.jsonl':
            rows = [(line_no, json.loads(line)) for line_no, line in enumerate(contents.splitlines(), 1)
                    if line.strip()]
        elif path.suffix.lower() == '.csv':
            with path.open(encoding='utf-8-sig', newline='') as stream:
                rows = list(enumerate(csv.DictReader(stream), 2))
        else:
            data = json.loads(contents) if path.suffix.lower() == '.json' else yaml.safe_load(contents)
            if isinstance(data, dict):
                containers = [data[key] for key in ('records', 'data', 'items')
                              if isinstance(data.get(key), list)]
                if len(containers) > 1:
                    raise ValueError(f'Ambiguous record container: {relative}')
                data = containers[0] if containers else [data]
            if not isinstance(data, list):
                raise ValueError(f'Expected record list: {relative}')
            rows = list(enumerate(data, 1))
        for index, row in rows:
            if not isinstance(row, dict):
                raise ValueError(f'Expected object: {relative}:{index}')
            records.append((f'{relative}:{index}', row))
        manifest.append(dict(path=relative, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), records=len(rows)))
    if not records:
        raise ValueError('Source contains zero records; no splits written')
    return records, manifest


def prepare(raw: list[tuple[str, dict[str, Any]]], config: dict[str, Any],
            demo: set[tuple[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    mapping = config['mapping']
    for source, target in mapping.items():
        options = target if isinstance(target, list) else [target]
        if any(option not in LABELS for option in options):
            raise ValueError(f'Invalid target label in mapping for {source}')
    fields = config.get('fields', {})
    missing: Counter[str] = Counter()
    original_labels: Counter[str] = Counter()
    frameworks: Counter[str] = Counter()
    services: set[str] = set()
    unique: dict[str, dict[str, Any]] = {}
    duplicate_count = 0
    for reference, original in raw:
        values = {name: field(original, fields.get(name, name)) for name in (*FIELDS, 'framework')}
        for name in FIELDS:
            missing[name] += int(empty(values[name]))
        source_label = snippet(values['label']) or '<missing>'
        original_labels[source_label] += 1
        frameworks[snippet(values['framework']) or '<unknown>'] += 1
        service = snippet(values['service'])
        if service:
            services.add(service)
        fingerprint = sha(original)
        if fingerprint in unique:
            unique[fingerprint]['source_refs'].append(reference)
            duplicate_count += 1
            continue
        target = mapping.get(source_label)
        needs_decision = not isinstance(target, str)
        row = {name: values[name] for name in FIELDS}
        row.update(id=snippet(values['id']) or 'generated-' + fingerprint[:20], service=service,
                   method=snippet(values['method']).upper(), path=snippet(values['path']),
                   oas_snippet=snippet(values['oas_snippet']), erd_snippet=snippet(values['erd_snippet']),
                   controller_signals=values['controller_signals'] if values['controller_signals'] is not None else [],
                   label=None if needs_decision else target, rationale=snippet(values['rationale']),
                   source_label=source_label, candidates=target if isinstance(target, list) else [],
                   source_refs=[reference], needs_decision=needs_decision, conflict=False)
        row['incomplete'] = not row['oas_snippet'] or not row['erd_snippet']
        row['demo_match'] = (row['method'], path_signature(row['path'])) in demo
        row['invalid_identity'] = not service or row['method'] not in METHODS or not row['path'].startswith('/')
        unique[fingerprint] = row
    id_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in unique.values():
        groups[(row['service'], row['method'], row['path'])].append(row)
        id_groups[row['id']].append(row)
    duplicate_ids = {identifier for identifier, rows in id_groups.items()
                     if len({(r['service'], r['method'], r['path']) for r in rows}) > 1}
    kept, excluded, conflicts, decisions = [], [], [], []
    endpoint_duplicates = 0
    for identity, rows in sorted(groups.items()):
        conflict = len({r['label'] for r in rows if r['label'] is not None}) > 1
        undecided = any(r['needs_decision'] for r in rows)
        invalid = any(r['invalid_identity'] or r['id'] in duplicate_ids for r in rows)
        if conflict or undecided or invalid:
            for row in rows:
                row['conflict'] = conflict
                row['needs_decision'] |= undecided or invalid
                row['exclusion_reasons'] = [name for name, condition in (
                    ('conflict', conflict), ('needs_decision', undecided), ('invalid_identity_or_id', invalid)) if condition]
                excluded.append(row)
            item = dict(service=identity[0], method=identity[1], path=identity[2],
                        ids=[r['id'] for r in rows], source_labels=sorted({r['source_label'] for r in rows}),
                        targets=sorted({r['label'] for r in rows if r['label']}))
            (conflicts if conflict else decisions).append(item)
            continue
        # Prefer an existing complete record; never synthesize or merge evidence.
        rows.sort(key=lambda r: (r['incomplete'], not r['rationale'], r['id'], r['source_refs'][0]))
        representative = dict(rows[0])
        representative['source_refs'] = sorted(ref for row in rows for ref in row['source_refs'])
        kept.append(representative)
        endpoint_duplicates += len(rows) - 1
    report = dict(raw_records=len(raw), raw_label_distribution=dict(original_labels),
                  missing_fields=dict(missing), raw_service_count=len(services), frameworks=dict(frameworks),
                  exact_duplicates_removed=duplicate_count, endpoint_duplicates_removed=endpoint_duplicates,
                  endpoint_duplicate_groups=sum(len(rows) > 1 for rows in groups.values()),
                  excluded_records=len(excluded), exclusion_reasons=dict(Counter(
                      reason for row in excluded for reason in row['exclusion_reasons'])),
                  incomplete_unique_records=sum(r['incomplete'] for r in unique.values()),
                  eligible_records=len(kept), eligible_incomplete=sum(r['incomplete'] for r in kept),
                  duplicate_ids=sorted(duplicate_ids), conflicts=conflicts, decisions=decisions,
                  label_decisions=[dict(source_label=label, count=count,
                                       candidates=mapping.get(label, []))
                                   for label, count in sorted(original_labels.items())
                                   if not isinstance(mapping.get(label), str)],
                  demo_matches=[dict(id=r['id'], service=r['service'], method=r['method'], path=r['path'])
                                for r in unique.values() if r['demo_match']])
    assert len(raw) == duplicate_count + endpoint_duplicates + len(kept) + len(excluded)
    return kept, excluded, report


def split_services(rows: list[dict[str, Any]], seed: int = 42) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    services = sorted({r['service'] for r in rows})
    forced = {r['service'] for r in rows if r['incomplete'] or r['demo_match']}
    remaining = [service for service in services if service not in forced]
    random.Random(seed).shuffle(remaining)
    # Largest-remainder allocation approximates 8:1:1 by number of services.
    exact = [len(services) * ratio for ratio in (.8, .1, .1)]
    sizes = [int(n) for n in exact]
    order = sorted(range(3), key=lambda i: (-(exact[i] - sizes[i]), i))
    for index in order[:len(services) - sum(sizes)]:
        sizes[index] += 1
    targets = list(sizes)
    sizes[0] = max(sizes[0], len(forced))
    while sum(sizes) > len(services):
        index = max((1, 2), key=lambda i: (sizes[i], -i))
        sizes[index] -= 1
    selected = dict(train=sorted(forced) + remaining[:sizes[0] - len(forced)])
    offset = sizes[0] - len(forced)
    selected['val'] = remaining[offset:offset + sizes[1]]
    selected['test'] = remaining[offset + sizes[1]:]
    assignments = {service: name for name, values in selected.items() for service in values}
    splits: dict[str, list[dict[str, Any]]] = {name: [] for name in selected}
    for row in sorted(rows, key=lambda r: (r['service'], r['method'], r['path'], r['id'])):
        record = {name: row[name] for name in FIELDS}
        record.update(incomplete=row['incomplete'], conflict=False, needs_decision=False)
        splits[assignments[row['service']]].append(record)
    distributions = {name: {label: sum(r['label'] == label for r in records) for label in LABELS}
                     for name, records in splits.items()}
    warnings = [f'test {label}: {count} records (<5)' for label, count in distributions['test'].items() if count < 5]
    if sizes != targets:
        warnings.append('8:1:1 service target adjusted: incomplete/demo services must stay in train')
    if any(not records for records in splits.values()):
        warnings.append('At least one split is empty; not ready for baseline evaluation')
    return splits, dict(seed=seed, target_service_counts=dict(zip(selected, targets)),
                        actual_service_counts={name: len(values) for name, values in selected.items()},
                        forced_train_services=sorted(forced), services=selected,
                        label_distributions=distributions, warnings=warnings)


def cell(value: Any) -> str:
    return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')


def table(headers: list[str], rows: list[list[Any]]) -> str:
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |']
                     + ['| ' + ' | '.join(cell(v) for v in row) + ' |' for row in rows])


def review(rows: list[dict[str, Any]], seed: int) -> str:
    lines = ['# Label review sample', '', f'Seed: {seed}. Up to 30 per label; no replacement. Excluded records are in audit/.', '']
    for label in LABELS:
        candidates = sorted((r for r in rows if r['label'] == label), key=lambda r: (r['id'], r['service']))
        sample = random.Random(f'{seed}:{label}').sample(candidates, min(30, len(candidates)))
        lines += [f'## {label} ({len(sample)} / {len(candidates)})', '',
                  table(['id', 'service', 'method/path', 'label', 'source rationale', 'corrected label / reviewer note'],
                        [[r['id'], r['service'], r['method'] + ' ' + r['path'], label,
                          r['rationale'] or '[source rationale missing]', ''] for r in sample]), '']
    return '\n'.join(lines)


def data_card(report: dict[str, Any], config: dict[str, Any]) -> str:
    split = report['split']
    lines = ['# BLADE DATA CARD', '', 'Status: converted; human label/sample review is still required.', '',
             '## Source', '', encoded(config.get('source', {})), '',
             'Raw files are not redistributed. Paths/hashes: audit/report.json.', '',
             '## Raw audit', '', table(['metric', 'count'], [[key, report[key]] for key in (
                 'raw_records', 'raw_service_count', 'exact_duplicates_removed', 'endpoint_duplicates_removed',
                 'excluded_records', 'eligible_records', 'eligible_incomplete')]), '',
             table(['source label', 'count'], list(map(list, sorted(report['raw_label_distribution'].items())))), '',
             table(['missing field', 'count'], list(map(list, report['missing_fields'].items()))), '',
             '## Labels after splitting', '', table(['label', 'train', 'val', 'test'],
                 [[label] + [split['label_distributions'][name][label] for name in ('train', 'val', 'test')] for label in LABELS]), '',
             '## Split and exclusions', '',
             f'Seed {split["seed"]}; service-level 8:1:1 target, largest-remainder rounding. Actual service counts: {encoded(split["actual_service_counts"])}.', '',
             'Any service with retained incomplete records or possible demo endpoint matches is assigned wholly to train. '
             'No endpoint is moved between sets independently. Constraints can make the target ratio impossible; warnings report this.', '',
             'Unknown/ambiguous labels, conflicting endpoint labels, missing identity, and reused IDs across endpoints are quarantined. '
             'An unresolved member excludes its entire endpoint group. Incomplete means empty OAS or ERD; complete duplicates are preferred without inventing evidence.', '',
             'Exclusion reasons (overlapping counts): ' + encoded(report['exclusion_reasons']), '',
             f'Possible demo matches: {len(report["demo_matches"])}. Match uses method and parameter-name-normalized path across all services conservatively; audit/report.json lists every match.', '',
             '## Decisions required', '', table(['source label', 'raw count', 'candidate targets'],
                 [[r['source_label'], r['count'], r['candidates'] or 'Unmapped: user decision required'] for r in report['label_decisions']]), '',
             'Endpoint conflicts and identity decisions: audit/decisions.md; excluded records: audit/excluded.jsonl.', '',
             '## Known bias and limits', '',
             'Framework counts (explicit source metadata only): ' + encoded(report['frameworks']), '',
             'Unknown framework metadata is not inferred. Service counts, not endpoint counts, determine the ratio; large services can skew label counts. '
             'Forcing incomplete/demo services into train changes its domain mix. Human review is pending; source labels and rationales are not independent ground truth. '
             'Exact/endpoint deduplication does not establish absence of semantic duplicates or related-service forks.', '',
             '## Warnings', '']
    lines += ['- ' + warning for warning in split['warnings']] or ['None.']
    lines += ['', '## Test integrity', '',
              'Existing differing test.jsonl is never overwritten by this tool. Freeze its hash for the baseline; reruns with identical content are allowed. '
              'Do not delete or replace the test set after baseline evaluation.', '']
    return '\n'.join(lines)


def build(raw_dir: Path, output: Path, mapping_path: Path, review_path: Path, seed: int = 42) -> dict[str, Any]:
    config = yaml.safe_load(mapping_path.read_text(encoding='utf-8-sig'))
    raw, manifest = load_raw(raw_dir)
    rows, excluded, report = prepare(raw, config, demo_endpoints())
    splits, split_report = split_services(rows, seed)
    report.update(source_files=manifest, split=split_report, mapping_sha256=hashlib.sha256(mapping_path.read_bytes()).hexdigest())
    contents = {name: ''.join(encoded(r) + '\n' for r in values) for name, values in splits.items()}
    test = output / 'processed/test.jsonl'
    if test.exists() and test.read_bytes() != contents['test'].encode('utf-8'):
        raise ValueError('Existing test.jsonl differs; stopped before writing. Review baseline freeze status with the user.')
    processed, audit = output / 'processed', output / 'audit'
    processed.mkdir(parents=True, exist_ok=True)
    audit.mkdir(parents=True, exist_ok=True)
    for name, text in contents.items():
        (processed / f'{name}.jsonl').write_bytes(text.encode('utf-8'))
    (audit / 'excluded.jsonl').write_text(''.join(encoded(r) + '\n' for r in excluded), encoding='utf-8')
    (audit / 'lineage.jsonl').write_text(''.join(encoded(dict(id=r['id'], source_refs=r['source_refs'])) + '\n' for r in rows), encoding='utf-8')
    report['processed_sha256'] = {name: hashlib.sha256(text.encode('utf-8')).hexdigest() for name, text in contents.items()}
    (audit / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    (audit / 'decisions.md').write_text('# Endpoint decisions\n\n' + table(
        ['service', 'method/path', 'ids', 'source labels', 'targets', 'kind'],
        [[r['service'], r['method'] + ' ' + r['path'], r['ids'], r['source_labels'], r['targets'], kind]
         for kind in ('conflicts', 'decisions') for r in report[kind]]) + '\n', encoding='utf-8')
    (output / 'DATA_CARD.md').write_text(data_card(report, config), encoding='utf-8')
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(review(rows, seed), encoding='utf-8')
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, default=ROOT / 'datasets/blade/raw')
    parser.add_argument('--output', type=Path, default=ROOT / 'datasets/blade')
    parser.add_argument('--label-map', type=Path, default=Path(__file__).with_name('label_map.yaml'))
    parser.add_argument('--review', type=Path, default=Path(__file__).with_name('review_sample.md'))
    args = parser.parse_args()
    try:
        report = build(args.raw, args.output, args.label_map, args.review)
    except (ValueError, OSError) as exc:
        parser.exit(2, f'{exc}\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
