"""test_v5 scoring (hold-out, task C; separate evaluation condition next to eval-def v2 and test_v31_supp; the test_v30 main metric is unchanged).
Inputs: v5test_predictions_{oas|oas_code}_<tag>.jsonl (training/lora/runpod/run_train.py) + datasets/blade/processed/test_v5.jsonl, whose SHA-256 must equal the one in
data_v5/test_v5_manifest.json (written by scripts/build_test_v5.py freeze; the scorer refuses to run before the freeze). Derived from scripts/eval_v31_supp.py.
Per model: label P/R/F1, macro-F1 over labels with support, confusion, per-project accuracy (labels are concentrated in single projects, so both tables are reported),
manual ratio, output errors, review-meta phrases in the raw output. Groups seeds (tag ..._s<seed>_...) into mean ± std. Writes --out json and --md report."""
from __future__ import annotations
import argparse, hashlib, json, re, statistics as st
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / 'datasets/blade/processed/test_v5.jsonl'; MANIFEST = ROOT / 'datasets/blade/processed/data_v5/test_v5_manifest.json'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
PROJECTS = ['rocketchat', 'ghost', 'umami']
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+')
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]


def score(rows, truth):
    pairs = [(truth[r['id']]['label'], r['prediction']['label'] if r.get('prediction') else 'output_error', truth[r['id']]['meta']['project'], r.get('raw') or '') for r in rows if r['id'] in truth]
    per = {}
    for l in L:
        tp = sum(t == l and p == l for t, p, *_ in pairs); fp = sum(t != l and p == l for t, p, *_ in pairs); fn = sum(t == l and p != l for t, p, *_ in pairs)
        P = tp / (tp + fp) if tp + fp else 0.; R = tp / (tp + fn) if tp + fn else 0.
        per[l] = dict(support=sum(t == l for t, *_ in pairs), precision=round(P, 4), recall=round(R, 4), f1=round(2 * P * R / (P + R), 4) if P + R else 0.)
    sup = [l for l in L if per[l]['support']]
    proj = {p: dict(n=sum(x[2] == p for x in pairs), accuracy=round(sum(t == q for t, q, pp, _ in pairs if pp == p) / max(1, sum(x[2] == p for x in pairs)), 4)) for p in PROJECTS}
    return dict(records=len(pairs), macro_f1=round(sum(per[l]['f1'] for l in sup) / len(sup), 4), accuracy=round(sum(t == p for t, p, *_ in pairs) / len(pairs), 4),
                manual_ratio=round(sum(p == MANUAL for _, p, *_ in pairs) / len(pairs), 4), output_errors=sum(p == 'output_error' for _, p, *_ in pairs),
                meta_phrase_outputs=sum(bool(META.search(raw)) for *_, raw in pairs), per_label=per, per_project=proj,
                confusion={a: {b: sum(t == a and p == b for t, p, *_ in pairs) for b in L + ['output_error']} for a in L})


def group(tag):
    m = re.match(r'(.+?)_s(\d+)(_.*)?$', tag)
    return (m.group(1) + (m.group(3) or '').replace('_final', '')) if m else tag


def ms(xs): return f'{st.mean(xs):.3f} ± {st.stdev(xs):.3f}' if len(xs) > 1 else f'{xs[0]:.3f}'


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--pred', nargs='+', required=True); ap.add_argument('--out', required=True); ap.add_argument('--md'); a = ap.parse_args()
    assert MANIFEST.exists(), 'test_v5 is not frozen yet (data_v5/test_v5_manifest.json missing): no test_v5 scoring before the freeze'
    man = json.loads(MANIFEST.read_text(encoding='utf-8')); TEST_SHA = man['sha256']['datasets/blade/processed/test_v5.jsonl']
    assert hashlib.sha256(TEST.read_bytes()).hexdigest() == TEST_SHA, 'test_v5.jsonl differs from the frozen manifest hash'
    truth = {r['id']: r for r in rd(TEST)}; res = []
    for p in a.pred:
        m = re.match(r'^v5test_predictions_(oas_code|oas)_(.+)$', Path(p).stem); assert m, p
        res.append(dict(condition=m.group(1), model=m.group(2), group=group(m.group(2)), file=Path(p).name, **score(rd(p), truth)))
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding='utf-8')
    if not a.md: return
    t = f'# test_v5 채점 (hold-out, 별도 조건, {len(truth)}건; 동결 {man.get("frozen")})\n\neval-def v2 주지표(test_v30)·test_v31_supp와 별개. 판정 지표는 owner_or_admin·membership_required F1(seed 평균 ± 표준편차, AGENTS.md 작업 C 사전 고정 기준). label이 프로젝트에 몰려 있으면(membership→Rocket.Chat) label별 표와 프로젝트별 표를 함께 본다.\n\n'
    for cond in ('oas_code', 'oas'):
        rs = [r for r in res if r['condition'] == cond]
        if not rs: continue
        g = defaultdict(list)
        for r in rs: g[r['group']].append(r)
        t += f'## {cond}\n\n| 모델 | n | macro-F1 | 정확도 | manual 비율 | 출력 오류(합) | 메타 문구 출력(합) |\n|---|---:|---:|---:|---:|---:|---:|\n'
        for k, v in sorted(g.items()):
            t += f"| {k} | {len(v)} | {ms([x['macro_f1'] for x in v])} | {ms([x['accuracy'] for x in v])} | {ms([x['manual_ratio'] for x in v])} | {sum(x['output_errors'] for x in v)} | {sum(x['meta_phrase_outputs'] for x in v)} |\n"
        t += '\n### label별 F1 (support)\n\n| 모델 | ' + ' | '.join(f"{l} ({rs[0]['per_label'][l]['support']})" for l in L) + ' |\n|---|' + '---:|' * len(L) + '\n'
        for k, v in sorted(g.items()): t += f'| {k} | ' + ' | '.join(ms([x['per_label'][l]['f1'] for x in v]) for l in L) + ' |\n'
        t += '\n### 프로젝트별 정확도 (n)\n\n| 모델 | ' + ' | '.join(f"{p} ({rs[0]['per_project'][p]['n']})" for p in PROJECTS) + ' |\n|---|' + '---:|' * len(PROJECTS) + '\n'
        for k, v in sorted(g.items()): t += f'| {k} | ' + ' | '.join(ms([x['per_project'][p]['accuracy'] for x in v]) for p in PROJECTS) + ' |\n'
        t += '\n'
    Path(a.md).write_text(t, encoding='utf-8')


if __name__ == '__main__': main()
