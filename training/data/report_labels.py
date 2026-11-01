"""Validate completed Stage D output and create a reproducible human review sheet."""
import json
import random
from collections import Counter
from pathlib import Path

from common.labels import Label

ROOT = Path(__file__).resolve().parents[2]


def main():
    folder = ROOT / 'datasets/blade/processed'
    source = [json.loads(line) for line in (folder / 'apisguru_filtered.jsonl').read_text(encoding='utf-8').splitlines()]
    rows = [json.loads(line) for line in (folder / 'apisguru_labeled.partial.jsonl').read_text(encoding='utf-8').splitlines()]
    assert len(rows) == len(source)
    assert len({row['id'] for row in rows}) == len(rows)
    originals = {row['id']: row for row in source}
    for row in rows:
        original = originals[row['id']]
        assert all(row[key] == value for key, value in original.items() if key != 'meta')
        assert all(row['meta'][key] == value for key, value in original['meta'].items())
        assert row['model_id'] == 'gpt-4o-mini' and row['prompt_version'] == 'v2.1'
        assert row['meta']['label_error'] or row['label'] in {item.value for item in Label}
    successes = [row for row in rows if not row['meta']['label_error']]
    distribution = Counter(row['label'] for row in successes)
    low = sum(row['meta']['low_conf'] for row in successes)
    report = dict(records=len(rows), successful=len(successes), label_error=len(rows)-len(successes),
                  low_conf=low, low_conf_fraction_successful=low/len(successes) if successes else None,
                  labels={item.value: distribution[item.value] for item in Label}, seed=42)
    rng = random.Random(42)
    def cell(value):
        return str(value).replace('|', '\\|').replace('\r', ' ').replace('\n', ' ')
    lines = ['# Stage D label review', '', 'LLM-generated labels; not ground truth. Enter corrected label in the final column. Seed 42.', '',
             '| id | service | method | path | label | confidence | rationale | ERD owner/tenant columns | 검수 |',
             '|---|---|---|---|---|---:|---|---|---|']
    samples = []
    for item in Label:
        group = [row for row in successes if row['label'] == item.value]
        for row in rng.sample(group, min(20, len(group))):
            samples.append(row['id'])
            values = [row[key] for key in ('id','service','method','path','label','confidence','rationale')]
            values.append('owner=' + ', '.join(row['meta']['owner_cols']) + '; tenant=' + ', '.join(row['meta']['tenant_cols']))
            lines.append('| ' + ' | '.join(map(cell, values)) + ' |  |')
    report['review_records'] = len(samples)
    report['labels_below_20'] = [item.value for item in Label if distribution[item.value] < 20]
    (folder / 'apisguru_labeled.jsonl').write_bytes((folder / 'apisguru_labeled.partial.jsonl').read_bytes())
    (ROOT / 'training/data/review_sample.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    (ROOT / 'training/data/label_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
