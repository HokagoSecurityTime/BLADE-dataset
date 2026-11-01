"""Apply human review results to build the data-v2 artifacts (user decisions 2026-10-21):
  review_overlap20.md            -> kappa gate (< 0.6 stops unless --ignore-kappa)
  review_summit_club.md          -> test_v30_corrections.json (test_v30.jsonl itself is never modified)
  review_sample_test_v2_extra.md -> datasets/blade/processed/test_v2_extra.jsonl (only rows with a confirmed label)
  review_sample_netbox.md        -> datasets/blade/processed/opensource/netbox_heldout.jsonl (confirmed rows; priority, per-label support)
  review_gitea_ownadmin10.md     -> reported; Gitea owner_or_admin pool inclusion is a user flag (--include-gitea-ownadmin)
  review_sample_gitea.md / review_sample_v30.md -> override tables applied while building train_v2.jsonl
  train_v2.jsonl = train_v30 (+v30 overrides) + data_v2_synthetic_additions + Gitea (visibility_dependent -> manual, overrides, owner_or_admin pooled)
                   with the manual 25% quota: keep all data-v1 manual and all synthetic manual; remaining slots from Gitea visibility_dependent manual,
                   stratified by label_before_override (seed 42); everything else manual -> pool. Synthetic manual is never reduced (reported instead).
--dry-run computes everything and writes only reports/eval/data_v2/apply_reviews_dryrun.{json,md}."""
import argparse, hashlib, json, random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]; P = ROOT / 'datasets/blade/processed'; T = ROOT / 'training/data'; R = ROOT / 'reports/eval/data_v2'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
DATA_V1 = {'train_v30.jsonl': 'a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2', 'val_v30.jsonl': '62bdadb29cae7aaf814007ad8adec40115e8612d70f2911693219399c82b595c', 'test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2'}
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if Path(p).exists() else []
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

def parse_md(path):
    rows, header = [], None
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.startswith('|'): continue
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if header is None:
            if 'id' in cells: header = cells
            continue
        if set(''.join(cells)) <= set('-: '): continue
        if len(cells) != len(header): continue
        rows.append(dict(zip(header, cells)))
    return rows

def decision(cell):
    v = (cell or '').strip()
    if not v: return None
    if v in ('제외', 'exclude', 'EXCLUDE'): return '제외'
    if v in L: return v
    low = v.lower().replace(' ', '_')
    return low if low in L else 'INVALID:' + v

def truth_map(path, col):
    out, invalid = {}, []
    for r in parse_md(path):
        d = decision(r.get(col))
        if d is None: continue
        if d.startswith('INVALID'): invalid.append((r['id'], r.get(col))); continue
        out[r['id']] = d
    return out, invalid

def kappa_gate(args):
    try: from training.data.review_kappa import parse, kappa, LABELS
    except ImportError: return dict(pairs=0, note='review_kappa import failed')
    rows = parse(T / 'review_overlap20.md'); a, b = '검수자A label', '검수자B label'
    pairs = [(r[a], r[b]) for r in rows if r.get(a) in LABELS and r.get(b) in LABELS]
    if len(pairs) < 10: return dict(pairs=len(pairs), status='not_enough_filled_pairs (need >=10); gate skipped')
    po, k = kappa(pairs); status = 'pass' if k >= .6 else 'FAIL_below_0.6'
    return dict(pairs=len(pairs), agreement=round(po, 4), kappa=round(k, 4), status=status, disagreements=[dict(id=r['id'], A=r[a], B=r[b]) for r in rows if r.get(a) in LABELS and r.get(b) in LABELS and r[a] != r[b]])

def build_test(name, cand_path, truth, invalid):
    rows = rd(cand_path); out, excluded, unconfirmed = [], [], []
    for r in rows:
        d = truth.get(r['id'])
        if d is None: unconfirmed.append(r['id']); continue
        if d == '제외': excluded.append(r['id']); continue
        rec = dict(r); rec['label'] = d; rec['meta'] = {**rec['meta'], 'label_source': 'human_confirmed', 'llm_reference_label': r.get('llm_reference_label')}; out.append(rec)
    sup = {l: sum(r['label'] == l for r in out) for l in L}
    rep = dict(candidates=len(rows), confirmed=len(out), excluded=len(excluded), unconfirmed=len(unconfirmed), invalid_cells=invalid, support=sup,
               manual_share=round(sup[MANUAL] / len(out), 4) if out else None, llm_agreement=round(sum(r['label'] == r.get('llm_reference_label') for r in out) / len(out), 4) if out else None)
    if name == 'netbox':
        rep['by_priority'] = {str(p): dict(confirmed=sum(r['meta'].get('heldout_priority') == p for r in out), candidates=sum(r['meta'].get('heldout_priority') == p for r in rows)) for p in (1, 2, 3)}
        rep['concrete_support'] = {l: sup[l] for l in L if l != MANUAL}
        rep['note'] = '보류 판단 검증 성격(manual 비중이 높음)' if out and sup[MANUAL] / len(out) > .5 else ''
    return out, rep

def build_train(args, overrides_gitea, overrides_v30, ownadmin_report):
    for n, h in DATA_V1.items(): assert sha(P / n) == h, f'data-v1 {n} changed'
    tv30 = rd(P / 'train_v30.jsonl'); syn = rd(P / 'data_v2_synthetic_additions.jsonl'); gitea = rd(P / 'opensource/gitea_v28.2.0_labeled_v301.jsonl')
    stats = Counter(); base = []
    for r in tv30:
        rec = json.loads(json.dumps(r)); d = overrides_v30.get(r['id'])
        if d == '제외': stats['v30_excluded'] += 1; continue
        if d and d != r['label']: rec['meta'].update(human_override_label=d, label_before_human=r['label']); rec['label'] = d; stats['v30_corrected'] += 1
        rec['meta']['data_version'] = 'data-v2'; rec['meta']['origin'] = 'data-v1'; base.append(rec)
    for r in syn:
        rec = json.loads(json.dumps(r)); rec['meta']['origin'] = 'synthetic_v2'; base.append(rec)
    gkeep, pool = [], []
    for r in gitea:
        rec = json.loads(json.dumps(r)); rec['meta'].update(data_version='data-v2', origin='gitea'); d = overrides_gitea.get(r['id'])
        if d == '제외': pool.append(dict(rec, pool_reason='human_excluded')); stats['gitea_excluded'] += 1; continue
        if d and d != r['label']: rec['meta'].update(human_override_label=d, label_before_human=r['label']); rec['label'] = d; stats['gitea_corrected'] += 1
        if rec['meta'].get('visibility_dependent'):
            if rec['label'] != MANUAL: rec['meta'].update(v30_override_reason='visibility_dependent', label_before_override=rec['label']); rec['label'] = MANUAL; stats['gitea_visibility_override'] += 1
            else: rec['meta'].setdefault('label_before_override', rec['label']); rec['meta']['v30_override_reason'] = 'visibility_dependent'
        if rec['label'] == 'owner_or_admin' and not args.include_gitea_ownadmin:
            pool.append(dict(rec, pool_reason='gitea_owner_or_admin_pending_review')); stats['gitea_ownadmin_pooled'] += 1; continue
        gkeep.append(rec)
    # manual quota (data-v1 rule): total manual = round_half_up(C/3); fixed = data-v1 manual + synthetic manual
    concrete = [r for r in base + gkeep if r['label'] != MANUAL]
    fixed = [r for r in base if r['label'] == MANUAL]
    target = int(len(concrete) / 3 + .5); remaining = target - len(fixed)
    vis_manual = sorted([r for r in gkeep if r['label'] == MANUAL and r['meta'].get('v30_override_reason') == 'visibility_dependent'], key=lambda r: r['id'])
    other_manual = [r for r in gkeep if r['label'] == MANUAL and r not in vis_manual]
    chosen, quota_note = [], ''
    if remaining < 0:
        quota_note = f'fixed manual {len(fixed)} exceeds quota {target}; synthetic/data-v1 manual NOT reduced (reported)'
    else:
        rng = random.Random(42); groups = Counter(r['meta'].get('label_before_override') for r in vis_manual); n = min(remaining, len(vis_manual))
        alloc = {g: int(c * n / len(vis_manual)) for g, c in groups.items()} if vis_manual else {}
        for g in sorted(groups, key=lambda g: -groups[g]):
            if sum(alloc.values()) >= n: break
            alloc[g] += 1
        for g, k in alloc.items():
            pool_g = [r for r in vis_manual if r['meta'].get('label_before_override') == g]; rng.shuffle(pool_g); chosen += pool_g[:k]
        quota_note = f'remaining {remaining} slots filled with {len(chosen)} Gitea visibility_dependent manual (stratified by label_before_override)'
    chosen_ids = {r['id'] for r in chosen}
    for r in vis_manual:
        if r['id'] not in chosen_ids: pool.append(dict(r, pool_reason='manual_quota_visibility'))
    for r in other_manual: pool.append(dict(r, pool_reason='manual_quota_gitea_model_manual'))
    train = base + [r for r in gkeep if r['label'] != MANUAL] + chosen
    assert not ({r['service'] for r in train} & {'quill_blog', 'folio_wiki', 'beacon_iot', 'summit_club', 'netbox', 'VAmPI', 'crAPI', 'juice-shop', 'Pixi', 'DVWS-node', 'vAPI', 'DVRestaurant'})
    assert len({r['id'] for r in train}) == len(train)
    dist = lambda rows: {l: sum(r['label'] == l for r in rows) for l in L}
    by_origin = {o: dict(records=sum(r['meta'].get('origin') == o for r in train), labels=dist([r for r in train if r['meta'].get('origin') == o])) for o in ('data-v1', 'synthetic_v2', 'gitea')}
    rep = dict(records=len(train), label_dist=dist(train), by_origin=by_origin, manual_share=round(dist(train)[MANUAL] / len(train), 4), concrete=len(concrete), manual_target=target, fixed_manual=len(fixed),
               fixed_manual_breakdown=dict(data_v1=sum(r['meta'].get('origin') == 'data-v1' for r in fixed), synthetic_v2=sum(r['meta'].get('origin') == 'synthetic_v2' for r in fixed)),
               gitea_visibility_manual_selected=len(chosen), gitea_visibility_selected_by_label_before=dict(Counter(r['meta'].get('label_before_override') for r in chosen)), quota_note=quota_note,
               pool=len(pool), pool_reasons=dict(Counter(r['pool_reason'] for r in pool)), gitea_share=round(sum(r['meta'].get('origin') == 'gitea' for r in train) / len(train), 4),
               stats=dict(stats), ownadmin_review=ownadmin_report, include_gitea_ownadmin=args.include_gitea_ownadmin, val='val_v30.jsonl unchanged (52)', services=len({r['service'] for r in train}))
    return train, pool, rep

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--dry-run', action='store_true'); ap.add_argument('--ignore-kappa', action='store_true'); ap.add_argument('--include-gitea-ownadmin', action='store_true'); args = ap.parse_args()
    gate = kappa_gate(args)
    if gate.get('status', '').startswith('FAIL') and not args.ignore_kappa: raise SystemExit('kappa gate failed: ' + json.dumps(gate, ensure_ascii=False))
    summit, inv_s = truth_map(T / 'review_summit_club.md', '정답'); extra, inv_e = truth_map(T / 'review_sample_test_v2_extra.md', '정답'); nb, inv_n = truth_map(T / 'review_sample_netbox.md', '정答') if False else truth_map(T / 'review_sample_netbox.md', '정답')
    g_over, inv_g = truth_map(T / 'review_sample_gitea.md', '검수'); own, inv_o = truth_map(T / 'review_gitea_ownadmin10.md', '검수'); v_over, inv_v = truth_map(T / 'review_sample_v30.md', '검수')
    g_over.update(own)
    design = {r['id']: r['label'] for r in rd(P / 'test_v30.jsonl') if r['service'] == 'summit_club'}
    summit_corr = {i: dict(design=design[i], confirmed=d) for i, d in summit.items() if i in design and d != design[i]}
    test_extra, rep_extra = build_test('test_v2_extra', P / 'test_v2_extra_candidates_llmref.jsonl', extra, inv_e)
    nb_rows, rep_nb = build_test('netbox', P / 'opensource/netbox_v4.7.3_heldout185_llmref.jsonl', nb, inv_n)
    own_rep = dict(reviewed=len(own), decisions=dict(Counter(own.values())), invalid=inv_o)
    train, pool, rep_train = build_train(args, g_over, v_over, own_rep)
    report = dict(mode='dry-run' if args.dry_run else 'apply', kappa_gate=gate, summit_club=dict(confirmed=len(summit), corrections_vs_design=summit_corr, invalid=inv_s),
                  test_v2_extra=rep_extra, netbox_heldout=rep_nb, train_v2=rep_train, gitea_overrides=len(g_over), v30_overrides=len(v_over), invalid_cells=dict(gitea=inv_g, v30=inv_v))
    R.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        (R / 'apply_reviews_dryrun.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        md = '# apply_reviews_v2 dry-run\n\n```json\n' + json.dumps({k: v for k, v in report.items()}, ensure_ascii=False, indent=2)[:12000] + '\n```\n'
        (R / 'apply_reviews_dryrun.md').write_text(md, encoding='utf-8'); print(json.dumps(report, ensure_ascii=False, indent=1)); return
    def w(path, rows):
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
        return sha(path)
    hashes = {}
    if test_extra: hashes['test_v2_extra.jsonl'] = w(P / 'test_v2_extra.jsonl', test_extra)
    if nb_rows: hashes['netbox_heldout.jsonl'] = w(P / 'opensource/netbox_heldout.jsonl', nb_rows)
    hashes['train_v2.jsonl'] = w(P / 'train_v2.jsonl', train); hashes['train_v2_manual_pool.jsonl'] = w(P / 'opensource/train_v2_manual_pool.jsonl', pool)
    (T / 'test_v30_corrections.json').write_text(json.dumps(dict(note='test_v30.jsonl is frozen; these confirmed differences apply to data-v2 evaluation only', corrections=summit_corr), ensure_ascii=False, indent=2), encoding='utf-8')
    report['outputs_sha256'] = hashes
    (R / 'apply_reviews_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8'); print(json.dumps(report, ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
