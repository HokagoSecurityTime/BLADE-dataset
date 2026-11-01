"""Task 2: test_v30 scoring with versioned evaluation definitions. Inputs: predictions jsonl (id,label,source,security_state,prediction) + test_v30.jsonl.
eval-def v1 (구): all records; public misjudge = declared ∧ pred==public.
eval-def v2 (신): oas main metric excludes route_only (109) -> 160 records; aux metric on route_only with manual accepted as correct;
                 public misjudge = declared ∧ pred==public ∧ truth!=public (denominator declared ∧ truth!=public); synthetic 58 reported separately,
                 macro-F1 with and without synthetic; oas_code truth unchanged (only the public and synthetic rules apply).
test_v30.jsonl is never modified; segment id lists are written to reports/eval_v30_redef/segments.json."""
from __future__ import annotations
import argparse, json, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
TEST = ROOT / 'datasets/blade/processed/test_v30.jsonl'; SEG_DIR = ROOT / 'reports/eval_v30_redef'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]

def security_state(r):
    spec = json.loads(r['oas_snippet']); op = spec['paths'][r['path']][r['method'].lower()]
    if op.get('security') == [] and 'security' in spec: return 'explicitly_anonymous'
    return 'declared' if ('security' in op or 'security' in spec) else 'unknown'

def segments():
    test = rd(TEST); meta = {}
    for r in test: meta[r['id']] = dict(label=r['label'], source=r.get('source'), oas_status=r['meta'].get('oas_status', 'original_export'), security_state=security_state(r), has_code=bool((r.get('controller_text') or '').strip()))
    seg = dict(all=[r['id'] for r in test], synthetic=[i for i, m in meta.items() if m['source'] == 'synthetic'], vuln_route_only=[i for i, m in meta.items() if m['source'] == 'vuln' and m['oas_status'] == 'route_only'],
               vuln_repository_spec=[i for i, m in meta.items() if m['source'] == 'vuln' and m['oas_status'] == 'repository_spec'], declared=[i for i, m in meta.items() if m['security_state'] == 'declared'])
    seg['oas_main_v2'] = [i for i in seg['all'] if i not in set(seg['vuln_route_only'])]
    return meta, seg

def prf(pairs):
    out = {}
    for l in L:
        tp = sum(t == l and p == l for t, p in pairs); fp = sum(t != l and p == l for t, p in pairs); fn = sum(t == l and p != l for t, p in pairs)
        P = tp / (tp + fp) if tp + fp else 0.; R = tp / (tp + fn) if tp + fn else 0.; F = 2 * P * R / (P + R) if P + R else 0.
        out[l] = dict(support=sum(t == l for t, _ in pairs), precision=round(P, 4), recall=round(R, 4), f1=round(F, 4))
    sup = [l for l in L if out[l]['support']]
    return out, (round(sum(out[l]['f1'] for l in sup) / len(sup), 4) if sup else None), len(sup)

def concrete(pairs):
    truth_conc = [(t, p) for t, p in pairs if t != MANUAL]; answered = [(t, p) for t, p in truth_conc if p not in (MANUAL, 'output_error')]
    return dict(n_truth_concrete=len(truth_conc), answered=len(answered), answer_rate=round(len(answered) / len(truth_conc), 4) if truth_conc else None,
                precision=round(sum(t == p for t, p in answered) / len(answered), 4) if answered else None, recall=round(sum(t == p for t, p in truth_conc) / len(truth_conc), 4) if truth_conc else None)

def score(pred_rows, meta, seg, condition, version):
    preds = {r['id']: (r['prediction']['label'] if r.get('prediction') else 'output_error') for r in pred_rows}
    ids = [i for i in seg['all'] if i in preds]
    def block(subset, accept_manual=False):
        pairs = [((preds[i] if (accept_manual and preds[i] == MANUAL) else meta[i]['label']), preds[i]) for i in subset]
        per, mf, n = prf(pairs)
        return dict(records=len(subset), macro_f1=mf, supported_labels=n, per_label=per, manual_ratio=round(sum(preds[i] == MANUAL for i in subset) / len(subset), 4) if subset else None,
                    accuracy=round(sum(t == p for t, p in pairs) / len(pairs), 4) if pairs else None, output_errors=sum(preds[i] == 'output_error' for i in subset), concrete=concrete(pairs),
                    confusion={a: {b: sum(t == a and p == b for t, p in pairs) for b in L + ['output_error']} for a in L})
    declared = [i for i in ids if meta[i]['security_state'] == 'declared']
    pub_old = [i for i in declared if preds[i] == 'public']; pub_new = [i for i in declared if preds[i] == 'public' and meta[i]['label'] != 'public']
    denom_new = [i for i in declared if meta[i]['label'] != 'public']
    res = dict(condition=condition, eval_def=version, records_scored=len(ids),
               public_misjudge_old=dict(count=len(pub_old), denominator=len(declared), ids=pub_old, truth_public_among=len([i for i in pub_old if meta[i]['label'] == 'public']), truth_public_ids=[i for i in pub_old if meta[i]['label'] == 'public']),
               public_misjudge_new=dict(count=len(pub_new), denominator=len(denom_new), ids=pub_new))
    syn = [i for i in ids if i in set(seg['synthetic'])]
    if version == 'v1':
        res['main'] = block(ids); res['synthetic'] = block(syn)
    else:
        main_ids = [i for i in ids if i in set(seg['oas_main_v2'])] if condition == 'oas' else ids
        res['main'] = block(main_ids); res['main_excl_synthetic'] = block([i for i in main_ids if i not in set(seg['synthetic'])]); res['synthetic'] = block(syn)
        if condition == 'oas':
            ro = [i for i in ids if i in set(seg['vuln_route_only'])]; res['aux_route_only_manual_accepted'] = block(ro, accept_manual=True); res['aux_route_only_strict'] = block(ro)
    return res

def table(rows, header, right_from=1):
    return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c) for c in r) + ' |\n' for r in rows)

def pm(b): return f"{b['count']}/{b['denominator']}"
def cp(b): c = b['concrete']; return f"{c['precision']} / {c['recall']} (응답률 {c['answer_rate']})"

def report(results, seg, path):
    v1 = {(r['condition'], r['model']): r for r in results if r['eval_def'] == 'v1'}; v2 = {(r['condition'], r['model']): r for r in results if r['eval_def'] == 'v2'}
    keys = sorted(v2, key=lambda k: (k[0], k[1]))
    t = '# eval-def v2 재계산 — LoRA v1 4개 조합 (test_v30, 예측 파일 재사용, 추론 없음)\n\n'
    t += f"구간(reports/eval_v30_redef/segments.json): 전체 269 · 합성 58 · 취약 route_only 109 · 취약 repository_spec 102 · security declared 64 · oas 주지표(route_only 제외) 160. test_v30.jsonl은 불변. 정의 변경 내용은 AGENTS.md '평가 정의 eval-def v2'.\n\n"
    t += '## 1. 구 정의(v1) vs 신 정의(v2) 비교\n\n주지표 macro-F1은 support 있는 label 평균. 신 정의 oas 주지표는 route_only 109건 제외(160건), oas_code는 전체 265건(정답 변경 없음). "합성 제외"는 주지표에서 합성 58건을 뺀 값(oas 102건 = repository_spec, oas_code 207건). public 오판 신 정의 = declared ∧ 예측 public ∧ 정답≠public, 분모 declared ∧ 정답≠public(47건). 구체 응답 정밀도/재현율 = 정답이 구체 label인 건 중 구체로 답한 비율의 정확도 / 전체 대비 정답률.\n\n'
    rows = []
    for k in keys:
        a, b = v1[k], v2[k]
        rows.append([k[0], k[1], a['main']['macro_f1'], b['main']['macro_f1'], b['main_excl_synthetic']['macro_f1'], b['synthetic']['macro_f1'], f"{a['main']['manual_ratio']:.1%}", f"{b['main']['manual_ratio']:.1%}", pm(a['public_misjudge_old']), pm(b['public_misjudge_new']), cp(a['main']), cp(b['main'])])
    t += table(rows, ['조건', '모델', 'macro-F1 구(전체)', 'macro-F1 신(주지표)', '신·합성 제외', '합성 58만', 'manual 구', 'manual 신(주지표)', 'public 오판 구', 'public 오판 신', '구체 P/R 구', '구체 P/R 신'], 2)
    t += '\n합성 58건 주석: test 합성 58건 중 56건이 train 합성과 같은 경로 템플릿, 43건은 정규화한 인가 검사 줄까지 동일(reports/data_v1_audit.md 4절). 합성 구간 수치는 일반화 근거로 쓰지 않는다.\n\n'
    t += '## 2. oas 보조지표 — route_only 109건(명세 없음), manual 예측을 정답으로 인정\n\n'
    rows = []
    for k in keys:
        b = v2[k]
        if k[0] != 'oas': continue
        ax = b['aux_route_only_manual_accepted']; st = b['aux_route_only_strict']
        rows.append([k[1], ax['records'], f"{ax['accuracy']:.1%}", ax['macro_f1'], f"{ax['manual_ratio']:.1%}", f"{st['accuracy']:.1%}", st['macro_f1']])
    t += table(rows, ['모델', 'N', '정확도(manual 인정)', 'macro-F1(manual 인정)', 'manual 예측 비율', '정확도(엄격, 구 정의)', 'macro-F1(엄격)'], 1)
    t += '\n## 3. public 오판 재정의 효과 — 구 정의로 잡힌 건 중 정답이 실제 public인 건\n\n'
    rows = []
    for k in keys:
        a = v1[k]; o = a['public_misjudge_old']
        rows.append([k[0], k[1], o['count'], o['truth_public_among'], pm(v2[k]['public_misjudge_new']), ', '.join(o['truth_public_ids'])])
    t += table(rows, ['조건', '모델', '구 정의 건수', '그중 정답이 public(오판 아님)', '신 정의 건수/분모', '정답 public인 id'], 2)
    t += '\n신 정의 오판 id:\n\n'
    for k in keys: t += f"- {k[0]} / {k[1]}: {', '.join(v2[k]['public_misjudge_new']['ids']) or '없음'}\n"
    t += '\n## 4. 신 정의 주지표 label별 P/R/F1 (support 포함)\n\n'
    for k in keys:
        b = v2[k]; per = b['main']['per_label']
        t += f"### {k[0]} / {k[1]} — 주지표 {b['main']['records']}건, macro-F1 {b['main']['macro_f1']} ({b['main']['supported_labels']}종)\n\n" + table([[l, d['support'], d['precision'], d['recall'], d['f1']] for l, d in per.items()], ['label', 'support', 'P', 'R', 'F1']) + '\n'
    models = sorted({k[1] for k in keys})
    if models != ['base_v301', 'lora_v1']:
        t += '\n원자료: scores.json. (모델 집합이 base_v301/lora_v1이 아니므로 5절 결론 생략)\n'; Path(path).write_text(t, encoding='utf-8'); return
    t += '## 5. 결론이 바뀌는 항목 (사실만)\n\n'
    o_b, o_l = v1[('oas', keys[0][1])], v1[('oas', keys[1][1])]; n_b, n_l = v2[('oas', keys[0][1])], v2[('oas', keys[1][1])]
    t += f"- oas 주지표 macro-F1: 구 {o_b['main']['macro_f1']} vs {o_l['main']['macro_f1']} → 신 {n_b['main']['macro_f1']} vs {n_l['main']['macro_f1']}. 순위(베이스 > LoRA)는 유지되나 차이가 줄고, 합성을 제외하면 {n_b['main_excl_synthetic']['macro_f1']} vs {n_l['main_excl_synthetic']['macro_f1']}로 역전된다.\n"
    t += f"- oas manual 비율: LoRA 구 {o_l['main']['manual_ratio']:.1%} → 신(주지표) {n_l['main']['manual_ratio']:.1%}. route_only 109건에서 LoRA는 전부 manual을 예측했고 보조지표(manual 인정) 정확도 {n_l['aux_route_only_manual_accepted']['accuracy']:.1%}, 베이스 {n_b['aux_route_only_manual_accepted']['accuracy']:.1%}.\n"
    t += f"- public 오판: 구 정의 베이스 {o_b['public_misjudge_old']['count']}·LoRA {o_l['public_misjudge_old']['count']}(oas) 가운데 각각 {o_b['public_misjudge_old']['truth_public_among']}·{o_l['public_misjudge_old']['truth_public_among']}건은 정답이 public이라 오판이 아니었다. 신 정의로는 oas 베이스 {pm(n_b['public_misjudge_new'])}, LoRA {pm(n_l['public_misjudge_new'])}; oas_code 베이스 {pm(v2[('oas_code', keys[2][1])]['public_misjudge_new'])}, LoRA {pm(v2[('oas_code', keys[3][1])]['public_misjudge_new'])}.\n"
    t += f"- oas_code macro-F1은 정의 변경으로 바뀌지 않는다({v2[('oas_code', keys[2][1])]['main']['macro_f1']} vs {v2[('oas_code', keys[3][1])]['main']['macro_f1']}); 합성 제외 시 {v2[('oas_code', keys[2][1])]['main_excl_synthetic']['macro_f1']} vs {v2[('oas_code', keys[3][1])]['main_excl_synthetic']['macro_f1']}.\n"
    t += '\n원자료: reports/eval_v30_redef/scores.json, segments.json. 채점 스크립트 scripts/eval_v30.py (`--eval-def both --md`).\n'
    Path(path).write_text(t, encoding='utf-8')

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--pred', nargs='+', required=True, help='predictions jsonl paths; condition inferred from name (oas / oas_code)')
    ap.add_argument('--eval-def', choices=['v1', 'v2', 'both'], default='both'); ap.add_argument('--out', default=str(SEG_DIR / 'scores.json')); ap.add_argument('--md', help='write comparison report markdown'); a = ap.parse_args()
    assert_data_v1('start'); meta, seg = segments(); SEG_DIR.mkdir(parents=True, exist_ok=True)
    (SEG_DIR / 'segments.json').write_text(json.dumps(dict(definition='eval-def v2 segments over test_v30 (frozen, unmodified)', counts={k: len(v) for k, v in seg.items()}, ids=seg), ensure_ascii=False, indent=1), encoding='utf-8')
    results = []
    for p in a.pred:
        name = Path(p).stem; m0 = re.match(r'^predictions_(oas_code|oas)_(.+)$', name); assert m0, f'unexpected prediction file name: {name}'
        cond, model = m0.group(1), m0.group(2)
        rows = rd(p)
        for v in (['v1', 'v2'] if a.eval_def == 'both' else [a.eval_def]):
            r = score(rows, meta, seg, cond, v); r['model'] = model; r['file'] = str(Path(p).resolve().relative_to(ROOT.resolve())).replace('\\', '/'); results.append(r)
    Path(a.out).write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding='utf-8')
    if a.md: report(results, seg, a.md)
    assert_data_v1('end')
    for r in results: print(r['condition'], r['model'], r['eval_def'], 'macroF1', r['main']['macro_f1'], 'manual', r['main']['manual_ratio'], 'pub_old', r['public_misjudge_old']['count'], 'pub_new', r['public_misjudge_new']['count'])

if __name__ == '__main__': main()
