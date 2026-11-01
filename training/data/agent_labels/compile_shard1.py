"""Serialize explicitly authored, individually inspected decisions; no classifier."""
import json
from pathlib import Path
from collections import Counter

root = Path(__file__).resolve().parents[3]
folder = Path(__file__).resolve().parent
rows = [json.loads(x) for x in (root/'datasets/blade/processed/apisguru_filtered.jsonl').read_text(encoding='utf-8').splitlines()]
decisions = {}
for path in [folder/'shard1_decisions.tsv', *sorted(folder.glob('shard1_batch*.tsv'))]:
    for line in path.read_text(encoding='utf-8').splitlines():
        index, label, confidence, rationale = line.split('\t', 3)
        index = int(index)
        assert index not in decisions and index % 3 == 1
        decisions[index] = dict(id=rows[index]['id'], label=label, confidence=float(confidence), rationale=rationale,
            object_param=None, owner_lookup=None, roles=['admin'] if index == 1699 else [], allowed_membership=[])
assert set(decisions) == set(range(1, len(rows), 3))
with (folder/'shard1.jsonl').open('w', encoding='utf-8', newline='\n') as stream:
    for index in sorted(decisions):
        stream.write(json.dumps(decisions[index], ensure_ascii=False)+'\n')
print(len(decisions), dict(Counter(x['label'] for x in decisions.values())))
