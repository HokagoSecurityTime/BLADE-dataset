"""Serialize manually authored, individually inspected shard2 decisions; no classifier."""
import json
from pathlib import Path
from collections import Counter

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
source = ROOT / 'datasets/blade/processed/apisguru_filtered.jsonl'
rows = [json.loads(line) for line in source.read_text(encoding='utf-8').splitlines()]
notes = {}
for line in (HERE / 'shard2_notes.tsv').read_text(encoding='utf-8').splitlines():
    if not line.strip():
        continue
    index, rationale = line.split('\t', 1)
    index = int(index)
    assert index not in notes
    notes[index] = rationale
assert set(notes) == set(range(2, len(rows), 3)), 'Never serialize uninspected records'

# These seven decisions were explicitly reconsidered from their supplied OAS/ERD.
# All other individually authored notes explicitly describe unresolved policy evidence.
positive = {
    146: ('membership_required', .58, [], ['Developer Plan Or Greater'],
          'Valuation is tagged Premium and Developer Plan Or Greater, indicating tier gating; the exact canonical tier names and hierarchy need review.'),
    404: ('role_required', .58, ['admin'], [],
          'Admin path and Admin tag plus user anonymization support an inferred admin-only operation, although no explicit caller role check is supplied.'),
    407: ('role_required', .58, ['admin'], [],
          'Admin path and Admin tag plus user suspension support an inferred admin-only operation, although no explicit caller role check is supplied.'),
    488: ('public', .65, [], [],
          'The supplied Public tag affirmatively describes reply-metadata retrieval; author and edit-capability metadata do not impose an owner-only read rule.'),
    494: ('public', .65, [], [],
          'The supplied Public tag affirmatively describes adjacent-photo metadata retrieval without an owner-only read restriction.'),
    521: ('role_required', .58, ['admin'], [],
          'Admin path, admin tag and adminEditHook operation support an inferred admin-only hook update, although an exact caller-role check is absent.'),
    1709: ('membership_required', .58, [], ['donor'],
           'Summary explicitly excludes the free plan and requires donation; donor is a descriptive tier inferred from that text and needs canonical-name review.'),
}
out = []
for index, rationale in sorted(notes.items()):
    if index in positive:
        label, confidence, roles, membership, rationale = positive[index]
    else:
        # This is serialization of authored abstention decisions, not a fallback classifier:
        # every index above has a unique, previously inspected rationale in the TSV.
        label, confidence, roles, membership = 'manual_review_required', .55, [], []
    out.append(dict(id=rows[index]['id'], label=label, confidence=confidence,
                    rationale=rationale, object_param=None, owner_lookup=None,
                    roles=roles, allowed_membership=membership))
(HERE / 'shard2.jsonl').write_text(''.join(json.dumps(x, ensure_ascii=False)+'\n' for x in out), encoding='utf-8')
print(json.dumps(dict(count=len(out), distribution=Counter(x['label'] for x in out))))
