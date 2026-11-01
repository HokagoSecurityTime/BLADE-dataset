"""test_v5 hold-out evaluation set (task C-1/C-2): Rocket.Chat, Ghost, Umami extraction candidates -> records -> review sheet -> (after human review) frozen test_v5.
Reads data/raw_v5/<project>/candidates.jsonl (format: data/raw_v4/EXTRACTION_SPEC.md, test fields required).
Steps (new files only; frozen data-v1..v4, test_v30, test_v31_supp are hash-asserted and read only):
  assemble  candidates -> records (oas_code input format), de-duplication against APIs.guru candidates, data-v1..v4 train/val/pools, test_v30, test_v31_supp on (service, method, normalized path)
  sheets    review/test_v5_review.xlsx: every record, evidence columns, 담당자 column split over 3 reviewers (project x draft_label stratified, round-robin), 검수 규약 sheet (G1-G8)
  freeze    review/test_v5_review_reviewed.xlsx ('확정 label', '비고' = EXCLUDE) -> datasets/blade/processed/test_v5.jsonl, data_v5/test_v5_excluded.jsonl, test_v5_manifest.json, training/lora/data_v5/test_v5_inputs.jsonl
No LLM labeling, no training."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
import build_data_v4 as v4
from build_data_v4 import LABELS, key, oas_snippet, permalink, rd, dump, security_state, sha, write_sheet
RAW = ROOT / 'data/raw_v5'; P = ROOT / 'datasets/blade/processed'; OUT = P / 'data_v5'; REVIEW = ROOT / 'review'
TEST_PROJECTS = ['rocketchat', 'ghost', 'umami']; REVIEWERS = ['검수자A', '검수자B', '검수자C']
FROZEN_V4 = {P / 'train_v4.jsonl': '1729f79dd1c06408846e4083b2e82fdace113166c0f92fea32e293441791966c', P / 'val_v4.jsonl': '2b3362b6adcc6da13b0d1c71fcf671b9700f54fedcd57bb6f55010f3c63c9105',
             P / 'data_v4/test_v31_supp.jsonl': '803d914902c7ca2042fd15d4a7852d42e71828e58d4ae4d3ac791fb868e63395', P / 'data_v4/train_v4_rule_labeled.jsonl': '3ce32a737c71d9433b1c7ddf31a93a04328d783d3a4db8e92fff0d092e16ae2d',
             P / 'train_v31b.jsonl': '8ca09e29ec00d7816e933f5b6e6bf92a36743d4c41ac2c72a1f66e8639d26543', P / 'val_v31.jsonl': '5b359e736f34edc176de62f4fea1f985aa7e09652bb3151b78a35e0c94f9d024'}
DEDUP_EXTRA = {'data-v4 train/val/rule_labeled': [P / 'train_v4.jsonl', P / 'val_v4.jsonl', P / 'data_v4/train_v4_rule_labeled.jsonl'],
               'test_v31_supp': [P / 'data_v4/test_v31_supp.jsonl', P / 'data_v4/test_v31_supp_excluded.jsonl'],
               'data-v3 pools': [P / 'train_v3b_manual_pool.jsonl', P / 'train_v3a_manual_pool.jsonl']}


def guard(stage):
    v4.guard(stage)
    for p, h in FROZEN_V4.items(): assert sha(p) == h, f'frozen file changed: {p}'


def existing_keys():
    keys = v4.existing_keys()
    for name, src in DEDUP_EXTRA.items():
        for p in src:
            if not p.exists(): continue
            for r in rd(p): keys.setdefault(key(r.get('service') or r.get('meta', {}).get('project'), r.get('method'), r.get('path')), name)
    return keys


def to_record(c):
    ident = f"v5t-{c['project']}-{hashlib.sha1((c['method'].upper() + ' ' + c['path']).encode()).hexdigest()[:10]}"
    spec = json.loads(oas_snippet(c)); op = spec['paths'][c['path']][c['method'].lower()]
    meta = dict(data_version='test_v5', project=c['project'], repository=c['repository'], commit=c['commit'], tag=c.get('tag'), license=c.get('license'), oas_status=c.get('oas_status'),
                source_locations=c.get('source_locations') or [], auth_summary=c.get('auth_summary', ''), permission_doc=c.get('permission_doc', ''), draft_label=c.get('draft_label'),
                draft_confidence=c.get('draft_confidence'), evidence=c.get('evidence') or [], draft_reason=c.get('draft_reason', ''), known_vulnerable=bool(c.get('known_vulnerable')),
                advisory=c.get('advisory'), fix_commit=c.get('fix_commit'), label_status='draft_pending_human_confirmation')
    return dict(id=ident, source='test_v5', service=c['service'], method=c['method'].upper(), path=c['path'], label=None, oas_snippet=oas_snippet(c), erd_snippet='',
                security_state=security_state(spec, op), controller_text=(c.get('controller_text') or '').strip(), meta=meta)


def assemble(args):
    guard('start'); OUT.mkdir(parents=True, exist_ok=True); seen = existing_keys()
    rep = dict(projects={}, duplicates=[], internal_duplicates=[], missing=[], invalid=[]); recs, keys_here = [], {}
    for proj in TEST_PROJECTS:
        f = RAW / proj / 'candidates.jsonl'
        if not f.exists(): rep['missing'].append(proj); continue
        cands = rd(f); kept = 0
        for c in cands:
            assert c['project'] == proj, (proj, c.get('project'))
            if c.get('draft_label') not in LABELS or not (c.get('controller_text') or '').strip() or len(c['controller_text']) > 3000:
                rep['invalid'].append(dict(project=proj, method=c['method'], path=c['path'], draft_label=c.get('draft_label'), text_len=len(c.get('controller_text') or ''))); continue
            k = key(c['service'], c['method'], c['path'])
            if k in seen: rep['duplicates'].append(dict(project=proj, method=c['method'], path=c['path'], matched=seen[k])); continue
            if k in keys_here: rep['internal_duplicates'].append(dict(project=proj, method=c['method'], path=c['path'])); continue
            r = to_record(c); keys_here[k] = r['id']; recs.append(r); kept += 1
        rep['projects'][proj] = dict(candidates=len(cands), kept=kept, draft_labels=dict(Counter(c.get('draft_label') for c in cands)))
    assert len({r['id'] for r in recs}) == len(recs)
    dump(OUT / 'test_v5_candidates.jsonl', recs); rep['total'] = len(recs)
    rep['draft_label_x_project'] = {p: dict(Counter(r['meta']['draft_label'] for r in recs if r['meta']['project'] == p)) for p in TEST_PROJECTS}
    (OUT / 'assemble_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end')
    print(json.dumps({k: v for k, v in rep.items() if k != 'duplicates'} | dict(duplicates=len(rep['duplicates'])), ensure_ascii=False))


def rules_text():
    a = (ROOT / 'AGENTS.md').read_text(encoding='utf-8').replace('\r\n', '\n')
    return a.split('## data-v4 검수 규약')[1].split('\n## ')[0].strip()


def sheets(args):
    guard('start'); system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    defs = ('프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
            + '\n\nBLADE 규약: 인가 검사가 빠졌어도 경로·스키마·수정 커밋으로 의도된 정책이 드러나면 그 정책을 label로 한다. membership_required = 요청 대상 그룹·팀의 구성원 관계(구독·등급 아님). 구성원 OR 관리자 우회도 membership_required. 소유자 OR 관리자 우회는 owner_or_admin. 경계·근거 부족 건은 manual로 넣지 말고 비고에 EXCLUDE와 사유를 적는다(G8).')
    test = rd(OUT / 'test_v5_candidates.jsonl')
    # reviewer split: stratified by (project, draft_label), round-robin so each reviewer gets a comparable mix
    order = sorted(test, key=lambda r: (r['meta']['project'], r['meta']['draft_label'], r['id'])); assign = {r['id']: REVIEWERS[i % 3] for i, r in enumerate(order)}
    ev = lambda m: '\n'.join(f"[{e.get('type')}] {e.get('location', '')}\n{e.get('text', '')}" for e in m.get('evidence') or [])
    rows = [[r['id'], assign[r['id']], r['meta']['project'], r['service'], r['method'], r['path'], r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['meta'].get('draft_label'),
             r['meta'].get('draft_confidence'), r['meta'].get('draft_reason', ''), ev(r['meta']), r['controller_text'], permalink(r['meta']), '', '', ''] for r in order]
    header = ['id', '담당자', 'project', 'service', 'method', 'path', 'auth_summary', 'permission_doc', '초안 label', '초안 confidence', '초안 근거 설명', '근거(코드 줄·문서)', 'controller_text(입력 코드)', 'source permalink', '확정 label', '확정 근거', '비고(EXCLUDE + 사유)']
    write_sheet(REVIEW / 'test_v5_review.xlsx', 'test_v5_review', header, rows, [26, 9, 11, 12, 8, 40, 40, 30, 18, 9, 50, 60, 70, 40, 18, 40, 24], 15, defs)
    from openpyxl import load_workbook
    wb = load_workbook(REVIEW / 'test_v5_review.xlsx'); ws = wb.create_sheet('검수 규약'); ws.column_dimensions['A'].width = 160
    for line in rules_text().splitlines(): ws.append([line])
    wb.save(REVIEW / 'test_v5_review.xlsx')
    rep = dict(rows=len(rows), per_reviewer={rv: dict(Counter(r['meta']['draft_label'] for r in order if assign[r['id']] == rv)) for rv in REVIEWERS},
               per_reviewer_project={rv: dict(Counter(r['meta']['project'] for r in order if assign[r['id']] == rv)) for rv in REVIEWERS})
    (OUT / 'sheets_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(rep, ensure_ascii=False))


def freeze(args):
    from openpyxl import load_workbook
    guard('start'); src = REVIEW / 'test_v5_review_reviewed.xlsx'; assert src.exists(), src
    ws = load_workbook(src, read_only=True)['test_v5_review']; rows = list(ws.iter_rows(values_only=True)); h = {n: i for i, n in enumerate(rows[0])}
    by_id = {r['id']: r for r in rd(OUT / 'test_v5_candidates.jsonl')}; kept, excl = [], []
    for row in rows[1:]:
        if not row or not row[h['id']]: continue
        r = by_id[row[h['id']]]; final = (row[h['확정 label']] or '').strip(); note = (row[h['비고(EXCLUDE + 사유)']] or '').strip(); reason = (row[h['확정 근거']] or '').strip()
        if note.upper().startswith('EXCLUDE') or not final:
            excl.append(dict(id=r['id'], project=r['meta']['project'], method=r['method'], path=r['path'], draft_label=r['meta']['draft_label'], reason=note or 'no final label')); continue
        assert final in LABELS, (r['id'], final)
        m = {**r['meta'], 'label_status': 'human_confirmed', 'final_reason': reason, 'review_note': note, 'reviewer': row[h['담당자']], 'changed_from_draft': final != r['meta']['draft_label']}
        kept.append({**r, 'label': final, 'meta': m})
    dump(P / 'test_v5.jsonl', kept); dump(OUT / 'test_v5_excluded.jsonl', excl)
    from training.lora.prepare_lora_inputs import test_record
    inputs = [test_record(r) for r in kept]; (ROOT / 'training/lora/data_v5').mkdir(parents=True, exist_ok=True); dump(ROOT / 'training/lora/data_v5/test_v5_inputs.jsonl', inputs)
    dist = {p: dict(Counter(r['label'] for r in kept if r['meta']['project'] == p)) for p in TEST_PROJECTS}
    first = lambda p, k: next((r['meta'][k] for r in kept if r['meta']['project'] == p), None)
    man = dict(name='test_v5', frozen=args.date, records=len(kept), excluded=len(excl),
               sha256={str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in [P / 'test_v5.jsonl', OUT / 'test_v5_excluded.jsonl', ROOT / 'training/lora/data_v5/test_v5_inputs.jsonl']},
               label_x_project=dist, label_total=dict(Counter(r['label'] for r in kept)), changed_from_draft=sum(r['meta']['changed_from_draft'] for r in kept),
               sources={p: dict(repository=first(p, 'repository'), commit=first(p, 'commit'), tag=first(p, 'tag'), license=first(p, 'license')) for p in TEST_PROJECTS if first(p, 'repository')},
               review_sheet=str(src.relative_to(ROOT)).replace('\\', '/'), rules='AGENTS.md data-v4 검수 규약 G1~G8 + 작업 C 절', eval='eval-def v2 별도 조건(보조 구간); 주지표 불변')
    (OUT / 'test_v5_manifest.json').write_text(json.dumps(man, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(man, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('step', choices=['assemble', 'sheets', 'freeze']); ap.add_argument('--date', default='2026-10-31'); a = ap.parse_args()
    dict(assemble=assemble, sheets=sheets, freeze=freeze)[a.step](a)
