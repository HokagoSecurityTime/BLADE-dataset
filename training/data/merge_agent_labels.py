"""Merge explicitly authored agent decisions; never infer or default a label.

This records an interactive agent review, not a replay of an API model run.
It has no network or model invocation code.
"""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import re

from common.labels import Label
from training.data.label import ModelOutput
from training.data.resignal import erd_columns

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'datasets/blade/processed'
SHARDS = ROOT / 'training/data/agent_labels'


def read(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def validate_decision(source, decision):
    if source['id'] != decision['id']:
        raise ValueError('Decision ID mismatch')
    fields = {key: decision[key] for key in ('label', 'confidence', 'object_param', 'owner_lookup', 'roles', 'allowed_membership')}
    checked = ModelOutput.model_validate(dict(fields, evidence=decision['rationale']))
    label = checked.label.value
    object_labels = {'owner_match', 'owner_or_admin', 'tenant_match'}
    if label in object_labels:
        oas = json.loads(source['oas_snippet'])
        parameters = set(oas.get('path_params') or []) | set(oas.get('query_params') or [])
        parameters.update(re.findall(r'\{([^{}]+)\}', source['path']))
        lookup = checked.owner_lookup
        columns = erd_columns(source['erd_snippet'])
        table = re.match(r'CREATE TABLE (.*?) \(', source['erd_snippet']).group(1)
        if checked.object_param not in parameters or lookup is None:
            raise ValueError(f'Missing object parameter/lookup: {source["id"]}')
        if lookup.table != table or lookup.id_col not in columns:
            raise ValueError(f'Invented lookup table/key: {source["id"]}')
        for name in (lookup.owner_col, lookup.tenant_col):
            if name is not None and name not in columns:
                raise ValueError(f'Invented ownership column: {source["id"]}')
        if label == 'tenant_match' and not lookup.tenant_col:
            raise ValueError('Missing tenant column')
        if label != 'tenant_match' and not lookup.owner_col:
            raise ValueError('Missing owner column')
    elif checked.object_param is not None or checked.owner_lookup is not None:
        raise ValueError('Non-object label has lookup')
    if label in {'role_required', 'owner_or_admin'} and not checked.roles:
        raise ValueError('Role policy without roles')
    if label == 'membership_required' and not checked.allowed_membership:
        raise ValueError('Membership policy without membership')
    return checked


def main():
    source_path = DATA / 'apisguru_filtered.jsonl'
    source = read(source_path)
    originals = {row['id']: row for row in source}
    if len(originals) != len(source):
        raise ValueError('Duplicate input ID')
    decisions = {}
    hashes = {}
    for shard in range(3):
        path = SHARDS / f'shard{shard}.jsonl'
        hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        assigned = {row['id'] for index, row in enumerate(source) if index % 3 == shard}
        items = read(path)
        if len(items) != len(assigned) or {item['id'] for item in items} != assigned:
            raise ValueError(f'Incomplete, duplicate, or misplaced decisions: {path.name}')
        for item in items:
            validate_decision(originals[item['id']], item)
            if item['id'] in decisions:
                raise ValueError('Duplicate decision')
            decisions[item['id']] = (shard, item)
    timestamp = datetime.now(timezone.utc).isoformat()
    output = []
    for row in source:
        shard, decision = decisions[row['id']]
        record = dict(row)
        record.update({key: decision[key] for key in ('label','confidence','rationale','object_param','owner_lookup','roles','allowed_membership')})
        record.update(model_id='codex-agent-unreported', prompt_version='v2.1', labeled_at=timestamp)
        record['meta'] = dict(row['meta'], low_conf=decision['confidence'] < .6, label_error=False,
            erd_truncated=False, label_source='interactive_codex_agent', labeling_method='direct_agent_review',
            reviewer_shard=shard, confidence_calibrated=False, human_reviewed=False,
            exact_api_prompt_replay=False, labeled_at_semantics='merge_timestamp')
        output.append(record)
    payload = ''.join(json.dumps(row, ensure_ascii=False)+'\n' for row in output)
    destination = DATA / 'apisguru_agent_labeled.jsonl'
    destination.write_text(payload, encoding='utf-8', newline='\n')
    counts = Counter(row['label'] for row in output)
    low = sum(row['meta']['low_conf'] for row in output)
    report = dict(records=len(output), successful=len(output), label_error=0, low_conf=low,
        low_conf_fraction=low/len(output), labels={item.value: counts[item.value] for item in Label},
        provider='interactive_codex_agent', model_id='codex-agent-unreported', prompt_version='v2.1',
        api_calls_this_run=0, source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),
        prompt_sha256=hashlib.sha256((ROOT/'prompts/v2.1.md').read_bytes()).hexdigest(), shard_sha256=hashes,
        output_sha256=hashlib.sha256(destination.read_bytes()).hexdigest(),
        limitations=['Exact underlying agent model/configuration not exposed; not gpt-4o-mini.',
          'v2.1 used as review instructions, not an exact isolated API prompt per record.',
          'Confidence is an uncalibrated agent judgment, not measured probability.',
          'API response pseudo-DDL is not verified database schema; controllers absent.',
          'No human review or training split has occurred.'])
    rng = random.Random(42)
    lines = ['# Agent-generated label review', '',
        'Source: interactive Codex agents; exact model unavailable. Not human-verified ground truth.',
        'Write a corrected seven-class label in 검수; leave unchanged decisions blank. Seed 42. Up to 20 per observed label.', '',
        '| id | service | method | path | label | confidence | rationale | ERD owner/tenant columns | 검수 |',
        '|---|---|---|---|---|---:|---|---|---|']
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    sample_ids = []
    for item in Label:
        group = [row for row in output if row['label'] == item.value]
        for row in rng.sample(group, min(20, len(group))):
            sample_ids.append(row['id'])
            values = [row[key] for key in ('id','service','method','path','label','confidence','rationale')]
            values.append('owner='+','.join(row['meta']['owner_cols'])+'; tenant='+','.join(row['meta']['tenant_cols']))
            lines.append('| '+' | '.join(map(cell,values))+' |  |')
    review = ROOT / 'training/data/review_sample.md'
    if review.exists():
        raise ValueError('Review sheet already exists: preserve possible human edits before replacing')
    review.write_text('\n'.join(lines)+'\n', encoding='utf-8')
    report.update(review_count=len(sample_ids), review_ids=sample_ids,
        labels_below_20=[item.value for item in Label if counts[item.value]<20])
    (ROOT/'training/data/agent_label_report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    details = ['# D — Agent labeling report', '',
        f'Records: {len(output):,}; API calls in this agent run: 0; label_error: 0.', '',
        '| label | count |', '|---|---:|']
    details.extend(f'| {item.value} | {counts[item.value]} |' for item in Label)
    details.extend(['', f'low_conf (<0.6): {low:,} ({100*low/len(output):.2f}%).',
        f'Review sample: {len(sample_ids)}; labels below 20: '+', '.join(report['labels_below_20'])+'.', '',
        '## Provenance and limitations', '',
        'The user authorized interactive agent labeling instead of the blocked paid API run. Three agents read disjoint record sets and authored decisions. The merger validates IDs, fields and lookup names; it never assigns a missing label.', '',
        *['- '+value for value in report['limitations']], '',
        'manual_review_required is a completed uncertainty decision, not a failed request. label_error=0 does not mean correct labels or verified policies. A heavily concentrated distribution is unsuitable for balanced seven-class training without additional evidence and human review.', '',
        'Source and prompt hashes plus individual shard hashes are in agent_label_report.json. Per-record authorship files are in agent_labels/. The API checkpoint remains separate. No train/val/test split or training was performed.', '',
        'Input limitations: 136 records lack summary; 754 have unknown security; 14 explicitly specify empty security; none retains operation.description; all 2,027 lack controller signals.', '',
        'Next: human review_sample.md review. Add full OAS authorization descriptions and verified schema/controller evidence before promoting uncertain records to concrete policies. Do not manufacture missing labels to balance the classes.', ''])
    (ROOT/'training/data/AGENT_LABEL_REPORT.md').write_text('\n'.join(details),encoding='utf-8')
    print(json.dumps({key:value for key,value in report.items() if key not in {'review_ids','shard_sha256'}},ensure_ascii=False,indent=2))


if __name__ == '__main__':
    main()
