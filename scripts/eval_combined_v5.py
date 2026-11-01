"""보조 지표: 세 test 셋 합산 채점 (test_v30 oas_code 합성 제외 207 + test_v31_supp oas_code 222 + test_v5 oas_code 283 = 712건).
사용자 결정 2026-10-31 (C-5 수용·마무리 3항). 주지표(test_v30 207)는 바꾸지 않으며 이 합산은 보조 지표로만 표기한다.

정의
- 7-class 채점(manual_review_required도 class). macro-F1은 합산 셋에서 정답 support > 0인 label의 F1 평균(712건에는 7 label 모두 support가 있다).
- 정확도 = 예측 label == 정답 label 비율(출력 오류는 오답).
- 구체 정밀도·재현율(eval_v30.py concrete()와 같은 정의): 정답이 구체 label인 건만 대상. 응답 = 예측이 manual도 출력 오류도 아닌 건.
  정밀도 = 응답 중 정답 일치 / 응답 수, 재현율 = 정답 일치 / 정답 구체 건수, 응답률 = 응답 수 / 정답 구체 건수.
- 모델: base 1회, LoRA v4·v5 각 seed 42·43·44 (평균 ± 표본 표준편차). 기존 예측 파일을 다시 읽어 채점하며 재추론은 없다.
- 동결 파일 해시 검증: test_v30(data_v1_guard), test_v31_supp(803d9149…), test_v5(test_v5_manifest.json 57fd384f… → 7b8e4a94…).
"""
from __future__ import annotations
import hashlib, json, statistics as st, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1

L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
TEST30 = ROOT / 'datasets/blade/processed/test_v30.jsonl'
SUPP = ROOT / 'datasets/blade/processed/data_v4/test_v31_supp.jsonl'; SUPP_SHA = '803d914902c7ca2042fd15d4a7852d42e71828e58d4ae4d3ac791fb868e63395'
TEST5 = ROOT / 'datasets/blade/processed/test_v5.jsonl'; MANIFEST5 = ROOT / 'datasets/blade/processed/data_v5/test_v5_manifest.json'; MANIFEST5_SHA = '57fd384f46e89e905209e627a7ff7fb9f312e22a7bed222639e91a80bd05fccd'
SEG = ROOT / 'reports/eval_v30_redef/segments.json'
OUT_JSON = ROOT / 'reports/eval/lora_v5/scores_combined_712.json'; OUT_MD = ROOT / 'reports/eval/lora_v5/eval_combined_712.md'
V4 = ROOT / 'reports/eval/lora_v4'; V5 = ROOT / 'reports/eval/lora_v5'
MODELS = [('base', 'base_qwen_runpod', 'base_qwen_runpod', V4), ('v4', 'lora_v4_s42', 'lora_v4_s42_final', V4), ('v4', 'lora_v4_s43', 'lora_v4_s43_final', V4), ('v4', 'lora_v4_s44', 'lora_v4_s44_final', V4),
          ('v5', 'lora_v5_s42', 'lora_v5_s42_final', V5), ('v5', 'lora_v5_s43', 'lora_v5_s43_final', V5), ('v5', 'lora_v5_s44', 'lora_v5_s44_final', V5)]
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def verify():
    assert_data_v1('start')
    assert sha(SUPP) == SUPP_SHA, 'test_v31_supp.jsonl hash mismatch'
    assert sha(MANIFEST5) == MANIFEST5_SHA, 'test_v5_manifest.json hash mismatch'
    man = json.load(open(MANIFEST5, encoding='utf-8')); rel = 'datasets/blade/processed/test_v5.jsonl'
    assert sha(TEST5) == man['sha256'][rel], 'test_v5.jsonl hash mismatch with manifest'


def truth_sets():
    seg = json.load(open(SEG, encoding='utf-8'))['ids']; synthetic = set(seg['synthetic'])
    # oas_code 조건은 코드(controller_text)가 있는 265건만 추론했다(eval_v30.py main 265 = 269 − 코드 없는 vuln repository_spec 4건). 합성 58건을 빼면 207.
    t30 = {r['id']: r['label'] for r in rd(TEST30) if r['id'] not in synthetic and (r.get('controller_text') or '').strip()}
    tsupp = {r['id']: r['label'] for r in rd(SUPP)}
    t5 = {r['id']: r['label'] for r in rd(TEST5)}
    assert len(t30) == 207 and len(tsupp) == 222 and len(t5) == 283, (len(t30), len(tsupp), len(t5))
    assert not (set(t30) & set(tsupp)) and not (set(t30) & set(t5)) and not (set(tsupp) & set(t5))
    return dict(test_v30_207=t30, test_v31_supp=tsupp, test_v5=t5)


def preds(run_dir, model, kind):
    name = {'test_v30_207': 'predictions_oas_code_', 'test_v31_supp': 'supp_predictions_oas_code_', 'test_v5': 'v5test_predictions_oas_code_'}[kind]
    p = run_dir / 'eval' / f'{name}{model}.jsonl'
    if kind == 'test_v5': p = V5 / run_dir.name / 'eval' / f'{name}{model}.jsonl'
    return p, {r['id']: (r['prediction']['label'] if r.get('prediction') else 'output_error') for r in rd(p)}


def metrics(pairs):
    per = {}
    for l in L:
        tp = sum(t == l and p == l for t, p in pairs); fp = sum(t != l and p == l for t, p in pairs); fn = sum(t == l and p != l for t, p in pairs)
        P = tp / (tp + fp) if tp + fp else 0.; R = tp / (tp + fn) if tp + fn else 0.; F = 2 * P * R / (P + R) if P + R else 0.
        per[l] = dict(support=sum(t == l for t, _ in pairs), precision=round(P, 4), recall=round(R, 4), f1=round(F, 4))
    sup = [l for l in L if per[l]['support']]
    conc = [(t, p) for t, p in pairs if t != MANUAL]; ans = [(t, p) for t, p in conc if p not in (MANUAL, 'output_error')]
    return dict(records=len(pairs), macro_f1=round(sum(per[l]['f1'] for l in sup) / len(sup), 4), supported_labels=len(sup), accuracy=round(sum(t == p for t, p in pairs) / len(pairs), 4),
                manual_ratio=round(sum(p == MANUAL for _, p in pairs) / len(pairs), 4), output_errors=sum(p == 'output_error' for _, p in pairs),
                concrete=dict(n_truth_concrete=len(conc), answered=len(ans), answer_rate=round(len(ans) / len(conc), 4), precision=round(sum(t == p for t, p in ans) / len(ans), 4) if ans else None, recall=round(sum(t == p for t, p in conc) / len(conc), 4)),
                per_label=per)


def main():
    verify(); T = truth_sets(); results = []
    for group, run, model, base_dir in MODELS:
        pairs_all = []; files = {}; per_set = {}
        for kind, truth in T.items():
            path, pr = preds(base_dir / run, model, kind); files[kind] = str(path.relative_to(ROOT)).replace('\\', '/')
            missing = [i for i in truth if i not in pr]; assert not missing, (model, kind, len(missing))
            if kind == 'test_v30_207': assert len(pr) == 265 and len(set(pr) - set(truth)) == 58, (model, len(pr))
            pairs = [(truth[i], pr[i]) for i in truth]; per_set[kind] = metrics(pairs); pairs_all += pairs
        m = metrics(pairs_all); assert m['records'] == 712 and m['supported_labels'] == 7
        results.append(dict(group=group, model=model, files=files, combined=m, per_set={k: {kk: v[kk] for kk in ('records', 'macro_f1', 'accuracy', 'manual_ratio', 'output_errors', 'concrete')} for k, v in per_set.items()}))
    assert_data_v1('end')
    json.dump(dict(definition=__doc__, truth_hashes=dict(test_v30=sha(TEST30), test_v31_supp=SUPP_SHA, test_v5=sha(TEST5), test_v5_manifest=MANIFEST5_SHA), results=results), open(OUT_JSON, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    def ms(vals, pct=False):
        if len(vals) == 1: return f'{vals[0]*100:.1f}%' if pct else f'{vals[0]:.3f}'
        mu, sd = st.mean(vals), st.stdev(vals)
        return f'{mu*100:.1f} ± {sd*100:.1f}%' if pct else f'{mu:.3f} ± {sd:.3f}'
    G = {}
    for r in results: G.setdefault(r['group'], []).append(r)
    t = '# 보조 지표 — 세 test 셋 합산 712건 (test_v30 oas_code 합성 제외 207 + test_v31_supp oas_code 222 + test_v5 oas_code 283)\n\n'
    t += '사용자 결정 2026-10-31(C-5 수용·마무리 3항). 주지표(test_v30 207건)는 그대로이고 이 표는 보조 지표다. 정의는 scripts/eval_combined_v5.py 머리말(7-class macro-F1은 support>0 label 평균 — 712건에는 7 label 모두 support 있음; 구체 정밀도·재현율은 eval_v30.py concrete()와 동일). 기존 예측 파일 재채점, 재추론 없음. base 1회, v4·v5는 3 seed 평균 ± 표본 표준편차.\n\n'
    t += '정답 support(712): ' + ', '.join(f"{l} {results[0]['combined']['per_label'][l]['support']}" for l in L) + '\n\n'
    t += '## 합산 712건\n\n| 모델 | macro-F1(7종) | 정확도 | 구체 정밀도 | 구체 재현율 | 구체 응답률 | manual 비율 | 출력 오류(seed별) |\n|---|---:|---:|---:|---:|---:|---:|---|\n'
    for g in ('base', 'v4', 'v5'):
        rs = [r['combined'] for r in G[g]]
        t += f"| {g} | {ms([r['macro_f1'] for r in rs])} | {ms([r['accuracy'] for r in rs])} | {ms([r['concrete']['precision'] for r in rs])} | {ms([r['concrete']['recall'] for r in rs])} | {ms([r['concrete']['answer_rate'] for r in rs])} | {ms([r['manual_ratio'] for r in rs], pct=True)} | {' / '.join(str(r['output_errors']) for r in rs)} |\n"
    t += '\n## label별 F1 (합산 712)\n\n| 모델 | ' + ' | '.join(f"{l} ({results[0]['combined']['per_label'][l]['support']})" for l in L) + ' |\n|---|' + '---:|' * len(L) + '\n'
    for g in ('base', 'v4', 'v5'):
        rs = [r['combined'] for r in G[g]]; t += f'| {g} | ' + ' | '.join(ms([r['per_label'][l]['f1'] for r in rs]) for l in L) + ' |\n'
    t += '\n## 셋별 기여 (같은 정의로 셋 안에서 계산)\n\n| 모델 | 셋 | n | macro-F1 | 정확도 | 구체 정밀도 | 구체 재현율 | manual 비율 |\n|---|---|---:|---:|---:|---:|---:|---:|\n'
    for g in ('base', 'v4', 'v5'):
        for k in T:
            rs = [r['per_set'][k] for r in G[g]]
            t += f"| {g} | {k} | {rs[0]['records']} | {ms([r['macro_f1'] for r in rs])} | {ms([r['accuracy'] for r in rs])} | {ms([r['concrete']['precision'] for r in rs])} | {ms([r['concrete']['recall'] for r in rs])} | {ms([r['manual_ratio'] for r in rs], pct=True)} |\n"
    t += '\n- 주의: 셋별 macro-F1은 그 셋에 support가 있는 label만 평균하므로(test_v30 207은 5종, supp 6종, test_v5 6종) 합산 7종 macro-F1과 직접 비교하지 않는다. test_v30 207의 값은 scores_test_v30.json main_excl_synthetic과 같고, supp·test_v5 값은 scores_supp.json·scores_test_v5.json과 같다.\n'
    t += '- 예측 파일: ' + '; '.join(f"{r['model']}: " + ', '.join(r['files'].values()) for r in results) + '\n'
    t += f"- 정답 해시: test_v30 {sha(TEST30)[:16]}…, test_v31_supp {SUPP_SHA[:16]}…, test_v5 {sha(TEST5)[:16]}… (manifest {MANIFEST5_SHA[:16]}…). supp 정답·예측 파일은 코드 본문 비공개로 .gitignore.\n"
    OUT_MD.write_text(t, encoding='utf-8', newline='\n'); print(t)


if __name__ == '__main__':
    main()
