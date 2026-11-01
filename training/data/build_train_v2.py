"""data-v2 train draft (user decision ④ 2026-10-21, plan A' variant):
  train_v2_draft = train_v30 (data-v1, unchanged) + data_v2_synthetic_additions (129) + Gitea labelled records with
    - visibility_dependent -> manual_review_required override (meta.v30_override_reason="visibility_dependent", meta.label_before_override)
    - owner_or_admin (85) excluded to gitea_train_pool_v2.jsonl pending human review
  Originals are never modified. val stays val_v30. Gitea share is recomputed; the 40% cap applies only if exceeded."""
import json, hashlib
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]; P = ROOT / 'datasets/blade/processed'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    train_v30 = rd(P / 'train_v30.jsonl'); syn = rd(P / 'data_v2_synthetic_additions.jsonl'); gitea = rd(P / 'opensource/gitea_v28.2.0_labeled_v301.jsonl')
    assert sha(P / 'train_v30.jsonl') == 'a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2', 'data-v1 train_v30 changed'
    keep, pool, over = [], [], 0
    for r in gitea:
        rec = json.loads(json.dumps(r)); rec['meta']['data_version'] = 'data-v2'; rec['meta']['partition'] = 'train'
        if rec['meta'].get('visibility_dependent'):
            rec['meta'].update(v30_override_reason='visibility_dependent', label_before_override=rec['label']); rec['label'] = MANUAL; over += 1
        if r['label'] == 'owner_or_admin' and not rec['meta'].get('v30_override_reason'):
            rec['meta']['pool_reason'] = 'gitea_owner_or_admin_pending_review (reqAdmin = repository-level admin ACL, may differ from BLADE owner_or_admin)'; pool.append(rec); continue
        if r['label'] == 'owner_or_admin' and rec['meta'].get('v30_override_reason'):
            # overridden to manual; keep (decision: override applies regardless of model label)
            pass
        keep.append(rec)
    for r in syn: r['meta']['data_version'] = 'data-v2'
    train = train_v30 + syn + keep
    share = len(keep) / len(train)
    cap_applied = share > .40
    assert not ({r['service'] for r in train} & {'quill_blog', 'folio_wiki', 'beacon_iot', 'summit_club', 'netbox', 'VAmPI', 'crAPI', 'juice-shop', 'Pixi', 'DVWS-node', 'vAPI', 'DVRestaurant'})
    assert len({r['id'] for r in train}) == len(train)
    out = P / 'train_v2_draft.jsonl'; poolp = P / 'opensource/gitea_train_pool_v2.jsonl'
    for p, rows in ((out, train), (poolp, pool)):
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    dist = lambda rows: {l: sum(r['label'] == l for r in rows) for l in L}
    rep = dict(records=len(train), sources=dict(train_v30=len(train_v30), synthetic_v2=len(syn), gitea=len(keep)), gitea_share=round(share, 4), cap_40_applied=cap_applied,
               gitea_visibility_override=over, gitea_owner_or_admin_pooled=len(pool), gitea_label_dist=dist(keep), train_label_dist=dist(train), manual_share=round(dist(train)[MANUAL] / len(train), 4),
               val='val_v30.jsonl (unchanged, 52)', outputs_sha256={out.name: sha(out), poolp.name: sha(poolp)}, inputs_sha256={'train_v30.jsonl': sha(P / 'train_v30.jsonl'), 'data_v2_synthetic_additions.jsonl': sha(P / 'data_v2_synthetic_additions.jsonl'), 'gitea_v28.2.0_labeled_v301.jsonl': sha(P / 'opensource/gitea_v28.2.0_labeled_v301.jsonl')},
               services=len({r['service'] for r in train}), status='draft until data-v2 freeze (human review of review_sample_gitea / public_candidate pending)')
    with open(ROOT / 'training/data/build_train_v2_report.json', 'w', encoding='utf-8', newline='\n') as f: json.dump(rep, f, ensure_ascii=False, indent=2)
    print(json.dumps(rep, ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
