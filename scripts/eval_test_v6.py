"""test_v6 scoring (S9 hold-out; separate evaluation condition next to eval-def v2; the test_v30 main metric is unchanged).
Inputs: v6test_predictions_{oas|oas_code}_<tag>.jsonl (training/lora/runpod/run_train_v7.py --jobs v6test) + datasets/blade/processed/test_v6.jsonl, whose SHA-256 must equal the one in
data_v6/test_v6_manifest.json. Runs only under scripts/testv6_guard.assert_allowed('scoring') (frozen manifest + BLADE_TESTV6_STAGE=S9). Derived from scripts/eval_test_v5.py.
Per model: label P/R/F1, macro-F1 over labels with support, confusion, per-project accuracy (seahub/redash/glitchtip/penpot), manual ratio, output errors, review-meta phrases,
plus test_v6-specific cuts pre-registered in AGENTS.md "test_v6 동결": accuracy by meta.label_status (human_confirmed / ai_double_confirmed / ai_single), Redash G1-b boundary ids,
public misjudge (security_state declared ∧ truth ≠ public ∧ prediction public; denominator declared ∧ truth ≠ public). Groups seeds (tag ..._s<seed>_...) into mean ± std."""
from __future__ import annotations
import argparse, json, re, statistics as st, sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
from scripts.testv6_guard import assert_allowed
TEST = ROOT / 'datasets/blade/processed/test_v6.jsonl'; G1B = ROOT / 'datasets/blade/processed/data_v6/redash_g1b_boundary_ids.json'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
PROJECTS = ['seahub', 'redash', 'glitchtip', 'penpot']; STATUSES = ['human_confirmed', 'ai_double_confirmed', 'ai_single']
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+')
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]


def g1b_ids():
    g = json.load(open(G1B, encoding='utf-8')); out = []
    def flat(x):
        if isinstance(x, str): yield x
        elif isinstance(x, dict):
            for v in x.values(): yield from flat(v)
        elif isinstance(x, list):
            for v in x: yield from flat(v)
    for s in flat(g):
        if s.startswith('v6t-') and s not in out: out.append(s)
    return out


def score(rows, truth, g1b):
    pairs = [(truth[r['id']]['label'], r['prediction']['label'] if r.get('prediction') else 'output_error', truth[r['id']], r.get('raw') or '') for r in rows if r['id'] in truth]
    assert len(pairs) == len(truth), (len(pairs), len(truth))
    per = {}
    for l in L:
        tp = sum(t == l and p == l for t, p, *_ in pairs); fp = sum(t != l and p == l for t, p, *_ in pairs); fn = sum(t == l and p != l for t, p, *_ in pairs)
        P = tp / (tp + fp) if tp + fp else 0.; R = tp / (tp + fn) if tp + fn else 0.
        per[l] = dict(support=sum(t == l for t, *_ in pairs), precision=round(P, 4), recall=round(R, 4), f1=round(2 * P * R / (P + R), 4) if P + R else 0.)
    sup = [l for l in L if per[l]['support']]
    acc = lambda sel: round(sum(t == p for t, p, *_ in sel) / len(sel), 4) if sel else None
    proj = {pj: dict(n=sum(x[2]['meta']['project'] == pj for x in pairs), accuracy=acc([x for x in pairs if x[2]['meta']['project'] == pj])) for pj in PROJECTS}
    stat = {s: dict(n=sum(x[2]['meta']['label_status'] == s for x in pairs), accuracy=acc([x for x in pairs if x[2]['meta']['label_status'] == s])) for s in STATUSES}
    gsel = [x for x in pairs if x[2]['id'] in g1b]; g1 = dict(n=len(gsel), accuracy=acc(gsel), predicted=dict(sorted(((k, sum(p == k for _, p, *_ in gsel)) for k in set(p for _, p, *_ in gsel)))))
    den = [x for x in pairs if x[2]['security_state'] == 'declared' and x[0] != 'public']; pub = [x for x in den if x[1] == 'public']
    conc = [x for x in pairs if x[0] != MANUAL]; ans = [x for x in conc if x[1] not in (MANUAL, 'output_error')]
    return dict(records=len(pairs), macro_f1=round(sum(per[l]['f1'] for l in sup) / len(sup), 4), accuracy=acc(pairs), manual_ratio=round(sum(p == MANUAL for _, p, *_ in pairs) / len(pairs), 4),
                output_errors=sum(p == 'output_error' for _, p, *_ in pairs), meta_phrase_outputs=sum(bool(META.search(raw)) for *_, raw in pairs),
                concrete=dict(n=len(conc), answer_rate=round(len(ans) / len(conc), 4), precision=round(sum(t == p for t, p, *_ in ans) / len(ans), 4) if ans else 0., recall=round(sum(t == p for t, p, *_ in conc) / len(conc), 4)),
                public_misjudge=dict(count=len(pub), denominator=len(den), ids=[x[2]['id'] for x in pub]), per_label=per, per_project=proj, per_label_status=stat, g1b=g1,
                confusion={a: {b: sum(t == a and p == b for t, p, *_ in pairs) for b in L + ['output_error']} for a in L})


def group(tag):
    m = re.match(r'(.+?)_s(\d+)(_.*)?$', tag)
    return (m.group(1) + (m.group(3) or '').replace('_final', '')) if m else tag


def ms(xs, nd=3): return f'{st.mean(xs):.{nd}f} ± {st.stdev(xs):.{nd}f}' if len(xs) > 1 else f'{xs[0]:.{nd}f}'


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--pred', nargs='+', required=True); ap.add_argument('--out', required=True); ap.add_argument('--md'); a = ap.parse_args()
    man = assert_allowed('scoring'); truth = {r['id']: r for r in rd(TEST)}; assert len(truth) == man['records'] == 289; g1b = g1b_ids(); assert len(g1b) == 18
    res = []
    for p in a.pred:
        m = re.match(r'^v6test_predictions_(oas_code|oas)_(.+)$', Path(p).stem); assert m, p
        res.append(dict(condition=m.group(1), model=m.group(2), group=group(m.group(2)), file=Path(p).name, **score(rd(p), truth, g1b)))
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding='utf-8')
    if not a.md: return
    t = f'# test_v6 채점 (S9 hold-out, 별도 조건, {len(truth)}건; 동결 {man.get("frozen")}, manifest `{man["sha256"]["datasets/blade/processed/test_v6.jsonl"][:12]}…`)\n\neval-def v2 주지표(test_v30)와 별개. 판정 지표는 oas_code macro-F1(support>0 label 평균, 3 seed 평균 ± 표준편차; AGENTS.md 작업 data-v7 채택 기준 (1)). label이 프로젝트에 몰려 있어(tenant→Redash, membership→GlitchTip) label별·프로젝트별 표를 함께 본다. 정답 출처(label_status)별 정확도와 Redash G1-b 경계 18건은 사전 기록 항목.\n\n'
    for cond in ('oas_code', 'oas'):
        rs = [r for r in res if r['condition'] == cond]
        if not rs: continue
        g = defaultdict(list)
        for r in rs: g[r['group']].append(r)
        t += f'## {cond}\n\n| 모델 | n | macro-F1 | 정확도 | 구체 정밀도 | 구체 재현율 | manual 비율 | public 오판(/{rs[0]["public_misjudge"]["denominator"]}, seed별) | 출력 오류(합) |\n|---|---:|---:|---:|---:|---:|---:|---|---:|\n'
        for k, v in sorted(g.items()):
            t += f"| {k} | {v[0]['records']} | {ms([r['macro_f1'] for r in v])} | {ms([r['accuracy'] for r in v])} | {ms([r['concrete']['precision'] for r in v])} | {ms([r['concrete']['recall'] for r in v])} | {ms([r['manual_ratio'] * 100 for r in v], 1)}% | {' / '.join(str(r['public_misjudge']['count']) for r in v)} | {sum(r['output_errors'] for r in v)} |\n"
        t += '\n### label별 F1 (support)\n\n| 모델 | ' + ' | '.join(f"{l} ({rs[0]['per_label'][l]['support']})" for l in L) + ' |\n|---|' + '---:|' * len(L) + '\n'
        for k, v in sorted(g.items()): t += f'| {k} | ' + ' | '.join(ms([r['per_label'][l]['f1'] for r in v]) for l in L) + ' |\n'
        t += '\n### 프로젝트별 정확도\n\n| 모델 | ' + ' | '.join(f"{p} ({rs[0]['per_project'][p]['n']})" for p in PROJECTS) + ' |\n|---|' + '---:|' * len(PROJECTS) + '\n'
        for k, v in sorted(g.items()): t += f'| {k} | ' + ' | '.join(ms([r['per_project'][p]['accuracy'] for r in v]) for p in PROJECTS) + ' |\n'
        t += '\n### 정답 출처(label_status)별 정확도 · Redash G1-b 경계 18건\n\n| 모델 | ' + ' | '.join(f"{s} ({rs[0]['per_label_status'][s]['n']})" for s in STATUSES) + ' | G1-b 18 정확도 |\n|---|' + '---:|' * (len(STATUSES) + 1) + '\n'
        for k, v in sorted(g.items()): t += f'| {k} | ' + ' | '.join(ms([r['per_label_status'][s]['accuracy'] for r in v]) for s in STATUSES) + f" | {ms([r['g1b']['accuracy'] for r in v])} |\n"
        t += '\n'
    t += '원자료: --out json. 채점 scripts/eval_test_v6.py(testv6_guard: manifest 해시 + BLADE_TESTV6_STAGE=S9).\n'
    Path(a.md).write_text(t, encoding='utf-8', newline='\r\n')


if __name__ == '__main__': main()
