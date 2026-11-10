"""test_v6 hold-out evaluation set (task S0): seahub, Redash, GlitchTip, Penpot extraction candidates -> records -> review sheet -> (after human review) frozen test_v6.
Reads data/raw_v6/<project>/candidates.jsonl (format: data/raw_v4/EXTRACTION_SPEC.md + data/raw_v6/EXTRACTION_SPEC_v6.md, test fields required).
Steps (new files only; frozen data-v1..v5, test_v30, test_v31_supp, test_v5 are hash-asserted and read only):
  assemble  candidates -> records (oas_code input format), de-duplication against APIs.guru candidates, data-v1..v5 train/val/pools/rule_labeled, test_v30, test_v31_supp, test_v5 (incl. excluded) on (service, method, normalized path)
  sheets    review/test_v6_review.xlsx: every record, evidence columns, 담당자 split over 3 reviewers (project x draft_label stratified, round-robin), '라벨 정의' + '검수 규약' (G1-G8 + test_v6 보충) sheets. No model prediction column.
  freeze    review/test_v6_review_reviewed.xlsx ('확정 label', '비고' = EXCLUDE) -> datasets/blade/processed/test_v6.jsonl, data_v6/test_v6_excluded.jsonl, test_v6_manifest.json, training/lora/data_v6/test_v6_inputs.jsonl
No LLM labeling, no training, no inference. test_v6 must not be inferred by any model before S9 (see scripts/testv6_guard.py)."""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
import build_test_v5 as v5
from build_data_v4 import LABELS, key, oas_snippet, rd, dump, security_state, sha, write_sheet
RAW = ROOT / 'data/raw_v6'; P = ROOT / 'datasets/blade/processed'; OUT = P / 'data_v6'; REVIEW = ROOT / 'review'
TEST_PROJECTS = ['seahub', 'redash', 'glitchtip', 'penpot']; REVIEWERS = ['검수자A', '검수자B', '검수자C']
TARGET = {'seahub': 90, 'redash': 70, 'glitchtip': 70, 'penpot': 60}; MAX_SHARE = 0.5
FROZEN_V5 = {P / 'train_v5.jsonl': '528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344', P / 'val_v5.jsonl': '43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9',
             P / 'test_v5.jsonl': '7b8e4a940967ec474e0d5dbf6dcdbd6b7e04be439599c2a684664d6b9393fd9c', P / 'data_v5/test_v5_excluded.jsonl': '56161a35cda3c7d487eecc16266a185a6f0cf9c09ac4c62e6542ca29488a839f',
             P / 'data_v5/test_v5_manifest.json': '57fd384f46e89e905209e627a7ff7fb9f312e22a7bed222639e91a80bd05fccd',
             P / 'data_v5/train_v5_rule_labeled.jsonl': '6f2e02f933a88cbb84a6d8c7ea57f42a81b2c3d8db62d4559c20217209876988', P / 'data_v5/train_v5_pool.jsonl': 'd5916fb43ea34c81b69aca2f3d252c175cada01156aa8ec59d99c2631acc0ebf'}
DEDUP_EXTRA = {'data-v5 train/val/rule_labeled/pool': [P / 'train_v5.jsonl', P / 'val_v5.jsonl', P / 'data_v5/train_v5_rule_labeled.jsonl', P / 'data_v5/train_v5_pool.jsonl'],
               'test_v5': [P / 'test_v5.jsonl', P / 'data_v5/test_v5_excluded.jsonl', P / 'data_v5/test_v5_candidates.jsonl']}
EXCL_PREFIX = re.compile(r'^\s*EXCLUDE\s*후보')


def guard(stage):
    v5.guard(stage)
    for p, h in FROZEN_V5.items(): assert sha(p) == h, f'frozen file changed: {p}'


def existing_keys():
    keys = v5.existing_keys()
    for name, src in DEDUP_EXTRA.items():
        for p in src:
            if not p.exists(): continue
            for r in rd(p): keys.setdefault(key(r.get('service') or r.get('meta', {}).get('project'), r.get('method'), r.get('path')), name)
    return keys


def permalink(m):
    """GitHub: /blob/<sha>/<file>#La-Lb ; GitLab: /-/blob/<sha>/<file>#La-b."""
    locs = m.get('source_locations') or []; repo = m['repository'].rstrip('/')
    if 'gitlab.com' in repo:
        return '\n'.join(f"{repo}/-/blob/{m['commit']}/{x['file']}#L{x.get('start_line', 1)}-{x.get('end_line', x.get('start_line', 1))}" for x in locs)
    return '\n'.join(f"{repo}/blob/{m['commit']}/{x['file']}#L{x.get('start_line', 1)}-L{x.get('end_line', x.get('start_line', 1))}" for x in locs)


def default_scheme(cands):
    """Project default security scheme = the first record's non-empty oas_security_schemes (name, schemes)."""
    for c in cands:
        s = c.get('oas_security_schemes') or {}
        if s: return next(iter(s)), s
    return None


def anonymous_fix(c, scheme):
    """Operation security [] with no spec-level security is read as 'declared' by security_state()/prepare_lora_inputs (needs a top-level
    `security` to compare against). Add the project default scheme as spec-level security so an anonymous operation becomes
    'explicitly_anonymous' uniformly across projects (GlitchTip extractor already did this; seahub/Redash/Penpot did not)."""
    op = c['oas_operation']
    if op.get('security') == [] and not c.get('oas_global_security') and scheme:
        return dict(c, oas_global_security=[{scheme[0]: []}], oas_security_schemes=c.get('oas_security_schemes') or scheme[1], _anon_fixed=True)
    return c


def to_record(c):
    ident = f"v6t-{c['project']}-{hashlib.sha1((c['method'].upper() + ' ' + c['path']).encode()).hexdigest()[:10]}"
    spec = json.loads(oas_snippet(c)); op = spec['paths'][c['path']][c['method'].lower()]
    meta = dict(data_version='test_v6', project=c['project'], repository=c['repository'], commit=c['commit'], tag=c.get('tag'), license=c.get('license'), oas_status=c.get('oas_status'),
                source_locations=c.get('source_locations') or [], auth_summary=c.get('auth_summary', ''), permission_doc=c.get('permission_doc', ''), draft_label=c.get('draft_label'),
                draft_confidence=c.get('draft_confidence'), evidence=c.get('evidence') or [], draft_reason=c.get('draft_reason', ''), known_vulnerable=bool(c.get('known_vulnerable')),
                advisory=c.get('advisory'), fix_commit=c.get('fix_commit'), draft_exclude_candidate=bool(EXCL_PREFIX.match(c.get('draft_reason', '') or '')),
                anonymous_global_security_added=bool(c.get('_anon_fixed')), label_status='draft_pending_human_confirmation')
    return dict(id=ident, source='test_v6', service=c['service'], method=c['method'].upper(), path=c['path'], label=None, oas_snippet=oas_snippet(c), erd_snippet='',
                security_state=security_state(spec, op), controller_text=(c.get('controller_text') or '').strip(), meta=meta)


def assemble(args):
    guard('start'); OUT.mkdir(parents=True, exist_ok=True); seen = existing_keys()
    rep = dict(projects={}, duplicates=[], internal_duplicates=[], missing=[], invalid=[], share_violations=[]); recs, keys_here = [], {}
    for proj in TEST_PROJECTS:
        f = RAW / proj / 'candidates.jsonl'
        if not f.exists(): rep['missing'].append(proj); continue
        cands = rd(f); kept = 0; scheme = default_scheme(cands)
        for c in cands:
            assert c['project'] == proj, (proj, c.get('project')); c = anonymous_fix(c, scheme)
            if c.get('draft_label') not in LABELS or not (c.get('controller_text') or '').strip() or len(c['controller_text']) > 3000:
                rep['invalid'].append(dict(project=proj, method=c['method'], path=c['path'], draft_label=c.get('draft_label'), text_len=len(c.get('controller_text') or ''))); continue
            k = key(c['service'], c['method'], c['path'])
            if k in seen: rep['duplicates'].append(dict(project=proj, method=c['method'], path=c['path'], matched=seen[k])); continue
            if k in keys_here: rep['internal_duplicates'].append(dict(project=proj, method=c['method'], path=c['path'])); continue
            r = to_record(c); keys_here[k] = r['id']; recs.append(r); kept += 1
        labels = Counter(c.get('draft_label') for c in cands)
        for lb, n in labels.items():
            if n > MAX_SHARE * len(cands): rep['share_violations'].append(dict(project=proj, label=lb, count=n, total=len(cands)))
        rep['projects'][proj] = dict(candidates=len(cands), kept=kept, target=TARGET[proj], draft_labels=dict(labels),
                                     exclude_candidates=sum(bool(EXCL_PREFIX.match(c.get('draft_reason', '') or '')) for c in cands),
                                     text_len_min=min(len(c.get('controller_text') or '') for c in cands), text_len_max=max(len(c.get('controller_text') or '') for c in cands))
    assert len({r['id'] for r in recs}) == len(recs)
    dump(OUT / 'test_v6_candidates.jsonl', recs); rep['total'] = len(recs)
    rep['draft_label_x_project'] = {p: dict(Counter(r['meta']['draft_label'] for r in recs if r['meta']['project'] == p)) for p in TEST_PROJECTS}
    rep['draft_label_total'] = dict(Counter(r['meta']['draft_label'] for r in recs)); rep['exclude_candidates_total'] = sum(r['meta']['draft_exclude_candidate'] for r in recs)
    rep['security_state'] = dict(Counter(r['security_state'] for r in recs)); rep['anonymous_global_security_added'] = dict(Counter(r['meta']['project'] for r in recs if r['meta']['anonymous_global_security_added']))
    for r in recs:  # an anonymous operation must read as explicitly_anonymous in the model input (prompt v3.0.1 public rule)
        op = json.loads(r['oas_snippet'])['paths'][r['path']][r['method'].lower()]
        assert not (op.get('security') == [] and r['security_state'] != 'explicitly_anonymous'), ('anonymous op without explicitly_anonymous state', r['id'])
    (OUT / 'assemble_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end')
    print(json.dumps({k: v for k, v in rep.items() if k != 'duplicates'} | dict(duplicates=len(rep['duplicates'])), ensure_ascii=False))


def rules_text():
    a = (ROOT / 'AGENTS.md').read_text(encoding='utf-8').replace('\r\n', '\n')
    g = a.split('## data-v4 검수 규약')[1].split('\n## ')[0].strip()
    s0 = a.split('## 작업 S0: hold-out test_v6 구축')[1].split('\n## ')[0].strip()
    return g + '\n\n---- test_v6 보충 규약 (AGENTS.md 작업 S0 절) ----\n' + s0


def sheets(args):
    guard('start'); system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    defs = ('프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
            + '\n\nBLADE 규약: 인가 검사가 빠졌어도 경로·스키마·수정 커밋으로 의도된 정책이 드러나면 그 정책을 label로 한다. membership_required = 요청 대상 그룹·팀의 구성원 관계(구독·등급 아님). 구성원 OR 관리자 우회도 membership_required. 소유자 OR 관리자 우회는 owner_or_admin. 요청자의 현재 테넌트(org)로 자원을 필터·고정하면 tenant_match(RBAC 동반해도). 경계·근거 부족 건은 manual로 넣지 말고 비고에 EXCLUDE와 사유를 적는다(G8). 초안 EXCLUDE 후보 열은 추출기의 제안이며 검수자가 판단한다.')
    test = rd(OUT / 'test_v6_candidates.jsonl')
    order = sorted(test, key=lambda r: (r['meta']['project'], r['meta']['draft_label'], r['id'])); assign = {r['id']: REVIEWERS[i % 3] for i, r in enumerate(order)}
    ev = lambda m: '\n'.join(f"[{e.get('type')}] {e.get('location', '')}\n{e.get('text', '')}" for e in m.get('evidence') or [])
    rows = [[r['id'], assign[r['id']], r['meta']['project'], r['service'], r['method'], r['path'], r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['meta'].get('draft_label'),
             r['meta'].get('draft_confidence'), 'Y' if r['meta'].get('draft_exclude_candidate') else '', r['meta'].get('draft_reason', ''), ev(r['meta']), r['controller_text'], permalink(r['meta']), '', '', ''] for r in order]
    header = ['id', '담당자', 'project', 'service', 'method', 'path', 'auth_summary', 'permission_doc', '초안 label', '초안 confidence', '초안 EXCLUDE 후보', '초안 근거 설명', '근거(코드 줄·문서)', 'controller_text(입력 코드)', 'source permalink', '확정 label', '확정 근거', '비고(EXCLUDE + 사유)']
    assert not any('v5' in h.lower() and '예측' in h for h in header)
    out = REVIEW / 'test_v6_review.xlsx'
    write_sheet(out, 'test_v6_review', header, rows, [26, 9, 11, 14, 8, 44, 40, 30, 18, 9, 9, 50, 60, 70, 40, 18, 40, 24], 16, defs)
    from openpyxl import load_workbook
    wb = load_workbook(out); ws = wb.create_sheet('검수 규약'); ws.column_dimensions['A'].width = 160
    for line in rules_text().splitlines(): ws.append([line])
    wb.save(out)
    rep = dict(rows=len(rows), sheet=str(out.relative_to(ROOT)).replace('\\', '/'), sha256=sha(out), columns=header,
               per_reviewer={rv: dict(Counter(r['meta']['draft_label'] for r in order if assign[r['id']] == rv)) for rv in REVIEWERS},
               per_reviewer_project={rv: dict(Counter(r['meta']['project'] for r in order if assign[r['id']] == rv)) for rv in REVIEWERS})
    (OUT / 'sheets_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(rep, ensure_ascii=False))


def freeze(args):
    from openpyxl import load_workbook
    guard('start'); src = Path(args.sheet).resolve() if args.sheet else REVIEW / 'test_v6_review_reviewed.xlsx'; assert src.exists(), src
    ws = load_workbook(src, read_only=True)['test_v6_review']; rows = list(ws.iter_rows(values_only=True)); h = {n: i for i, n in enumerate(rows[0])}
    # A안 (AGENTS.md 2026-11-08): '정답 출처' column = human_confirmed | ai_double_confirmed | ai_single -> meta.label_status; absent column -> 'human_confirmed' (original protocol)
    status_col = h.get('정답 출처'); STATUSES = {'human_confirmed', 'ai_double_confirmed', 'ai_single'}
    by_id = {r['id']: r for r in rd(OUT / 'test_v6_candidates.jsonl')}; kept, excl = [], []
    for row in rows[1:]:
        if not row or not row[h['id']]: continue
        r = by_id[row[h['id']]]; final = (row[h['확정 label']] or '').strip(); note = (row[h['비고(EXCLUDE + 사유)']] or '').strip(); reason = (row[h['확정 근거']] or '').strip()
        if note.upper().startswith('EXCLUDE') or not final:
            excl.append(dict(id=r['id'], project=r['meta']['project'], method=r['method'], path=r['path'], draft_label=r['meta']['draft_label'], reason=note or 'no final label')); continue
        assert final in LABELS, (r['id'], final)
        status = (row[status_col] or '').strip() if status_col is not None else 'human_confirmed'; assert status in STATUSES, (r['id'], status)
        m = {**r['meta'], 'label_status': status, 'final_reason': reason, 'review_note': note, 'reviewer': row[h['담당자']], 'changed_from_draft': final != r['meta']['draft_label']}
        kept.append({**r, 'label': final, 'meta': m})
    total = len(kept) + len(excl); rate = len(excl) / total if total else 0.0
    if rate > 0.10 and not args.allow_exclusion_rate: raise SystemExit(f'exclusion rate {rate:.1%} > 10% ({len(excl)}/{total}); stop and report (AGENTS.md 작업 S0 보충 8)')
    status_counts = dict(Counter(r['meta']['label_status'] for r in kept))
    if args.dry_run:
        print(json.dumps(dict(dry_run=True, sheet=str(src), records=len(kept), excluded=len(excl), exclusion_rate=round(rate, 4), label_status=status_counts, label_total=dict(Counter(r['label'] for r in kept)),
                              excluded_reasons=dict(Counter(e['reason'][:60] for e in excl))), ensure_ascii=False, indent=1)); guard('end'); return
    dump(P / 'test_v6.jsonl', kept); dump(OUT / 'test_v6_excluded.jsonl', excl)
    from training.lora.prepare_lora_inputs import test_record
    inputs = [test_record(r) for r in kept]; (ROOT / 'training/lora/data_v6').mkdir(parents=True, exist_ok=True); dump(ROOT / 'training/lora/data_v6/test_v6_inputs.jsonl', inputs)
    dist = {p: dict(Counter(r['label'] for r in kept if r['meta']['project'] == p)) for p in TEST_PROJECTS}
    first = lambda p, k: next((r['meta'][k] for r in kept if r['meta']['project'] == p), None)
    excl_reasons = Counter((e['reason'].split(':')[0].split('—')[0].strip()[:60]) for e in excl)
    man = dict(name='test_v6', frozen=args.date, records=len(kept), excluded=len(excl), exclusion_rate=round(rate, 4), excluded_reasons=dict(excl_reasons),
               sha256={str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in [P / 'test_v6.jsonl', OUT / 'test_v6_excluded.jsonl', ROOT / 'training/lora/data_v6/test_v6_inputs.jsonl', src]},
               label_x_project=dist, label_total=dict(Counter(r['label'] for r in kept)), changed_from_draft=sum(r['meta']['changed_from_draft'] for r in kept),
               sources={p: dict(repository=first(p, 'repository'), commit=first(p, 'commit'), tag=first(p, 'tag'), license=first(p, 'license')) for p in TEST_PROJECTS if first(p, 'repository')},
               review_sheet=str(src.relative_to(ROOT)).replace('\\', '/'), review_sheet_sha256=sha(src), label_status=status_counts,
               labeling=('A안(AGENTS.md 2026-11-08): AI 1차 확정 + 독립 AI 2차 검수(Claude) + 불일치·저확신 건 사람 확정; 건수는 label_status' if status_col is not None else '사람 확정'), rules='AGENTS.md data-v4 검수 규약 G1~G8 + 작업 S0 test_v6 보충 1~8',
               eval='eval-def v2 별도 조건(보조 구간); 주지표 불변. S9 전 추론 금지(scripts/testv6_guard.py)', inference_allowed_before='S9')
    (OUT / 'test_v6_manifest.json').write_text(json.dumps(man, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(man, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('step', choices=['assemble', 'sheets', 'freeze']); ap.add_argument('--date', default='2026-11-03')
    ap.add_argument('--allow-exclusion-rate', action='store_true', help='freeze despite >10% exclusions (only after the user approved)')
    ap.add_argument('--sheet', help="freeze: review sheet path (default review/test_v6_review_reviewed.xlsx; A안 uses review/test_v6_review_final.xlsx with a '정답 출처' column)")
    ap.add_argument('--dry-run', action='store_true', help='freeze: compute and print counts only, write nothing'); a = ap.parse_args()
    dict(assemble=assemble, sheets=sheets, freeze=freeze)[a.step](a)
