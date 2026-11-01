"""Create datasets/blade/processed/test_v30.jsonl (user decision 2026-10-21, decision 3).
= frozen test.jsonl (byte-identical lines) with the 6 subscription-membership records relabelled to manual_review_required
+ 16 summit_club records (test-only v3.0 group-membership fixture). test.jsonl itself is never modified. Refuses to overwrite."""
import hashlib, json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from training.data.sources import synthetic_v30 as s

ROOT = Path(__file__).resolve().parents[2]; DATA = ROOT / 'datasets/blade/processed'
TEST = DATA / 'test.jsonl'; OUT = DATA / 'test_v30.jsonl'; FROZEN = 'bd22c2580c2ddc2154974f76aa9e7aa2ca30bc6f8434e4960f3d3966093977fa'
RELABEL = {f'{svc}_subscription_{i}' for svc in ('quill_blog', 'folio_wiki', 'beacon_iot') for i in (0, 1)}
REASON = 'intended membership_required means premium plan (subscription tier); v3.0 defines membership_required as target group/team membership, so the record is manual_review_required (user decision 2026-10-21)'

def main():
    data = TEST.read_bytes(); assert hashlib.sha256(data).hexdigest() == FROZEN, 'test.jsonl hash mismatch'
    if OUT.exists(): raise FileExistsError('test_v30.jsonl exists; regenerate forbidden')
    lines = data.split(b'\n'); out = []; relabelled = []
    for line in lines:
        if not line.strip(): continue
        rec = json.loads(line)
        if rec['id'] in RELABEL:
            assert rec['label'] == 'membership_required'
            rec['meta'] = {**rec['meta'], 'label_before_v30': 'membership_required', 'v30_relabel_reason': REASON}; rec['label'] = 'manual_review_required'
            out.append(json.dumps(rec, ensure_ascii=False).encode('utf-8')); relabelled.append(rec['id'])
        else: out.append(line)
    assert sorted(relabelled) == sorted(RELABEL)
    added = s.test_records('summit_club'); assert len(added) == 16
    out.extend(json.dumps(r, ensure_ascii=False).encode('utf-8') for r in added)
    payload = b'\n'.join(out) + b'\n'; OUT.write_bytes(payload); sha = hashlib.sha256(payload).hexdigest()
    rows = [json.loads(l) for l in payload.decode('utf-8').splitlines() if l.strip()]
    assert len(rows) == 253 + 16 and len({r['id'] for r in rows}) == len(rows)
    counts = Counter((r['label'], r['source']) for r in rows)
    manifest = dict(created_at=datetime.now(timezone.utc).isoformat(), base_test_sha256=FROZEN, test_v30_sha256=sha, records=len(rows), base_records=253, added_records=16,
                    relabelled_ids=sorted(relabelled), relabel_reason=REASON, added_service='summit_club', added_service_files_sha256=s.file_hashes('summit_club'),
                    label_by_source={label: {src: counts[label, src] for src in ('vuln', 'synthetic')} for label in sorted({l for l, _ in counts})},
                    byte_identical_policy='all lines except the 6 relabelled records are the original test.jsonl bytes; summit_club records appended at the end',
                    group_membership_semantics='v3.0: (caller_id, record.group_id) in memberships', human_confirmed=False, frozen=True)
    (ROOT / 'verification/test_v30_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    assert hashlib.sha256(TEST.read_bytes()).hexdigest() == FROZEN
    print(json.dumps(dict(records=len(rows), sha256=sha, labels={l: sum(v.values()) for l, v in manifest['label_by_source'].items()}), ensure_ascii=False))

if __name__ == '__main__': main()
