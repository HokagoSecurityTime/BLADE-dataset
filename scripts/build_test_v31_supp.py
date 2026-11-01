"""test_v31_supp: evaluation additions (Chatwoot, Chamilo, Flowise, multitenant lab, Generic University) confirmed from
review/test_v31_supp_review_reviewed.xlsx (reviewer: Claude, AI-assisted review on the evidence columns; human spot-check sheet is generated, non-blocking).
비고=EXCLUDE rows (review convention G8) go to test_v31_supp_excluded.jsonl with the reason; the rest become test_v31_supp.jsonl with '확정 label'.
Input strings are the candidate records unchanged (only label and review meta are added). Separate evaluation condition next to eval-def v2 (test_v30 unchanged).
Outputs: datasets/blade/processed/data_v4/{test_v31_supp,test_v31_supp_excluded}.jsonl, test_v31_supp_manifest.json (id, project, repository, commit, permalink, label,
no code), review/test_v31_supp_spotcheck.xlsx, training/lora/data_v4/test_v31_supp_inputs.jsonl. Refuses to overwrite existing outputs."""
from __future__ import annotations
import hashlib, json, random, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from data_v1_guard import assert_data_v1
from data_v2_guard import assert_data_v2
from build_data_v4 import LABELS, TEST_PROJECTS, permalink, write_sheet, rd, dump, sha, guard
OUT = ROOT / 'datasets/blade/processed/data_v4'; SFT = ROOT / 'training/lora/data_v4'; REVIEW = ROOT / 'review'
SRC = OUT / 'test_v31_supp_candidates.jsonl'; SHEET = REVIEW / 'test_v31_supp_review_reviewed.xlsx'
FILES = dict(test=OUT / 'test_v31_supp.jsonl', excluded=OUT / 'test_v31_supp_excluded.jsonl', manifest=OUT / 'test_v31_supp_manifest.json', spot=REVIEW / 'test_v31_supp_spotcheck.xlsx', inputs=SFT / 'test_v31_supp_inputs.jsonl')
SEED, PER_LABEL = 42, 4
REVIEWER = 'Claude (AI-assisted review on evidence columns; human spot-check pending)'


def read_review():
    from openpyxl import load_workbook
    ws = load_workbook(SHEET, data_only=True)['test_v31_supp_review']; rows = list(ws.iter_rows(values_only=True)); H = rows[0]
    return {d['id']: d for d in (dict(zip(H, r)) for r in rows[1:]) if d['id']}


def main():
    guard('start')
    for p in FILES.values(): assert not p.exists(), f'refusing to overwrite {p}'
    cands = rd(SRC); rev = read_review(); assert set(rev) == {c['id'] for c in cands}, 'review sheet ids differ from candidates'
    test, excluded = [], []
    for c in cands:
        v = rev[c['id']]; note = (v['비고'] or '').strip()
        if note == 'EXCLUDE':
            excluded.append(dict(id=c['id'], project=c['meta']['project'], method=c['method'], path=c['path'], draft_label=c['meta']['draft_label'], reason=v['확정 근거'])); continue
        lab = v['확정 label']; assert lab in LABELS, (c['id'], lab)
        assert note in ('', 'CHANGED'), (c['id'], note); assert (note == 'CHANGED') == (lab != c['meta']['draft_label']), (c['id'], note, lab)
        r = dict(c); r['label'] = lab
        r['meta'] = {**c['meta'], 'label_status': 'confirmed_ai_review', 'reviewer': REVIEWER, 'review_reason': v['확정 근거'], 'review_changed': note == 'CHANGED'}
        test.append(r)
    dump(FILES['test'], test); dump(FILES['excluded'], excluded)
    # inputs in the test_v30 format (oas_user and oas_code_user)
    from training.lora.prepare_lora_inputs import test_record
    SFT.mkdir(parents=True, exist_ok=True); inputs = [dict(test_record(r), project=r['meta']['project']) for r in test]; assert all('oas_code_user' in x for x in inputs)
    dump(FILES['inputs'], inputs)
    dist = {l: {p: sum(r['label'] == l and r['meta']['project'] == p for r in test) for p in TEST_PROJECTS} for l in LABELS}
    manifest = dict(name='test_v31_supp', records=len(test), excluded=len(excluded), reviewer=REVIEWER, review_sheet=SHEET.name, review_sheet_sha256=sha(SHEET),
                    source_candidates_sha256=sha(SRC), sha256={k: sha(FILES[k]) for k in ('test', 'excluded', 'inputs')}, label_by_project=dist,
                    note='Public release: code excerpts are not distributed (Flowise enterprise/ commercial license, two sources without a license); links and commits only.',
                    records_index=[dict(id=r['id'], project=r['meta']['project'], repository=r['meta']['repository'], commit=r['meta']['commit'], method=r['method'], path=r['path'],
                                        label=r['label'], known_vulnerable=r['meta'].get('known_vulnerable'), advisory=r['meta'].get('advisory'), permalink=permalink(r['meta'])) for r in test])
    FILES['manifest'].write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    # human spot-check: every CHANGED row + PER_LABEL per label (stratified random, seed 42) from the unchanged rows
    rng = random.Random(SEED); spot = [('CHANGED', r) for r in test if r['meta']['review_changed']]
    for l in LABELS:
        pool = sorted([r for r in test if r['label'] == l and not r['meta']['review_changed']], key=lambda r: r['id'])
        spot += [(f'{l} 무작위', r) for r in rng.sample(pool, min(PER_LABEL, len(pool)))]
    ev = lambda m: '\n'.join(f"[{e.get('type')}] {e.get('location', '')}\n{e.get('text', '')}" for e in m.get('evidence') or [])
    rows = [[g, r['id'], r['meta']['project'], r['method'], r['path'], r['meta']['draft_label'], r['label'], r['meta']['review_reason'], ev(r['meta']), r['controller_text'], permalink(r['meta']), '', '', ''] for g, r in spot]
    system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    defs = '프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip() + '\n\n검수 규약 G1~G8: AGENTS.md data-v4 검수 규약 절.'
    write_sheet(FILES['spot'], 'spotcheck', ['그룹', 'id', 'project', 'method', 'path', '초안 label', 'AI 확정 label', 'AI 확정 근거', '근거(문서·코드 줄·advisory·커밋)', 'controller_text', 'source permalink',
                '사람 확인 label', '사람 의견', '확인자'], rows, [14, 26, 12, 8, 40, 18, 18, 50, 60, 70, 40, 18, 40, 10], 12, defs)
    guard('end')
    print(json.dumps(dict(test=len(test), excluded=len(excluded), by_project=Counter(r['meta']['project'] for r in test), spot=len(spot), sha=manifest['sha256']), ensure_ascii=False, default=str))
    for l in LABELS: print(f"{l:24s} {sum(dist[l].values()):3d} " + ' '.join(f'{p}={dist[l][p]}' for p in TEST_PROJECTS))


if __name__ == '__main__': main()
