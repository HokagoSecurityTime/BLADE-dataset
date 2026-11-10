"""test_v6 A안 (AGENTS.md "test_v6 동결 방식 변경 — A안", 2026-11-08): AI double review + human confirmation of boundary cases only.
  audit  --claude <xlsx>            blind-audit 41: Claude (2nd AI) judgement vs human_check_audit_key.json (AI 1st final) -> agreement + mismatch list
                                    -> reports/data_v6/audit41_compare.json / .md ; mismatch sheet review/test_v6_audit41_mismatch.xlsx for the user's judgement
  apply  --priority <xlsx> [--audit <xlsx>] [--audit-human <xlsx>]
                                    review/test_v6_review_reviewed.xlsx (AI final) + priority-44 sheet (Claude opinion + human label) [+ audit mismatch human labels]
                                    -> review/test_v6_review_final.xlsx with '확정 label'/'비고' updated and a '정답 출처' column
                                    (human_confirmed | ai_double_confirmed | ai_single) -> reports/data_v6/human_check_apply.json
No model inference, no test_v6 prediction reading. The frozen AI-only sheet test_v6_review_reviewed.xlsx is never modified."""
from __future__ import annotations
import argparse, hashlib, json, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from build_data_v4 import LABELS
REVIEW = ROOT / 'review'; RA = ROOT / 'datasets/blade/processed/data_v6/review_ai'; REP = ROOT / 'reports/data_v6'
AI_SHEET = REVIEW / 'test_v6_review_reviewed.xlsx'; FINAL = REVIEW / 'test_v6_review_final.xlsx'; KEY = RA / 'human_check_audit_key.json'
BOUNDARY_IDS = ['v6t-penpot-0366cd50c0', 'v6t-redash-e8133c143b', 'v6t-seahub-5569330cd5', 'v6t-redash-c89e256edf']  # 3 disagreements + 1 low-confidence (user instruction 2026-11-08)
EXC = 'EXCLUDE'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_sheet(path, name=None):
    from openpyxl import load_workbook
    wb = load_workbook(path, read_only=True, data_only=True); ws = wb[name] if name else wb.worksheets[0]
    rows = [r for r in ws.iter_rows(values_only=True)]; h = [str(x).strip() if x is not None else '' for x in rows[0]]
    recs = [dict(zip(h, r)) for r in rows[1:] if r and r[h.index('id')]]
    return h, recs


def norm(x):
    s = (str(x).strip() if x is not None else '')
    return EXC if s.upper().startswith(EXC) else s


def find_col(h, *must, prefer=None):
    if prefer and prefer in h: return prefer
    c = [x for x in h if all(m.lower() in x.lower() for m in must)]
    assert len(c) == 1, f'column for {must} not unique in {h}: {c}'
    return c[0]


def audit(a):
    key = json.load(open(KEY, encoding='utf-8')); K = {r['id']: r for r in key['audit']}; assert len(K) == 41
    h, recs = load_sheet(a.claude); lab_col = find_col(h, 'claude', 'label', prefer='Claude 판정 label'); conf_col = next((x for x in h if 'claude' in x.lower() and '확신' in x), None)
    note_col = next((x for x in h if 'claude' in x.lower() and ('비고' in x or 'EXCLUDE' in x)), None); why_col = next((x for x in h if 'claude' in x.lower() and '근거' in x), None)
    R = {r['id']: r for r in recs}; miss = sorted(set(K) - set(R)); extra = sorted(set(R) - set(K)); assert not miss, f'audit ids missing in Claude sheet: {miss}'
    rows = []
    for i, k in K.items():
        r = R[i]; cl = norm(r.get(lab_col)) or (EXC if note_col and norm(r.get(note_col)) == EXC else '')
        assert cl in LABELS or cl == EXC, (i, cl)
        rows.append(dict(id=i, project=k['project'], method=k['method'], path=k['path'], reviewer=k['reviewer'], ai_final_label=k['ai_final_label'], ai_confidence=k['ai_confidence'], claude_label=cl,
                         claude_confidence=r.get(conf_col) if conf_col else None, claude_reason=(str(r.get(why_col))[:400] if why_col and r.get(why_col) is not None else None), agree=cl == k['ai_final_label']))
    n = len(rows); agree = sum(r['agree'] for r in rows); mis = [r for r in rows if not r['agree']]
    out = dict(name='test_v6 blind audit 41 — Claude(2nd AI) vs AI 1st final', date=a.date, claude_sheet=str(Path(a.claude)), claude_sheet_sha256=sha(a.claude), key_sha256=sha(KEY), n=n, agree=agree, agreement_rate=round(agree / n, 4),
               mismatch_rate=round(1 - agree / n, 4), mismatches=mis, pairs=dict(Counter(f"{r['ai_final_label']}->{r['claude_label']}" for r in mis)), per_project={p: dict(n=sum(r['project'] == p for r in rows), agree=sum(r['project'] == p and r['agree'] for r in rows)) for p in sorted({r['project'] for r in rows})},
               per_ai_label={l: dict(n=sum(r['ai_final_label'] == l for r in rows), agree=sum(r['ai_final_label'] == l and r['agree'] for r in rows)) for l in sorted({r['ai_final_label'] for r in rows})}, extra_ids_in_sheet=extra,
               note='일치율은 AI 1차 확정 vs 독립 AI 2차(Claude) 판정의 일치율이며 사람 대비 정확도가 아니다(A안). 불일치 건은 사용자가 사람 판정으로 확정한다.', rows=rows)
    REP.mkdir(parents=True, exist_ok=True); (REP / 'audit41_compare.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf-8')
    md = [f'# test_v6 블라인드 감사 41건 — Claude 2차 판정 vs AI 1차 확정 ({a.date})\n', f"일치 {agree}/{n} = {agree / n:.1%}, 불일치 {len(mis)}건({1 - agree / n:.1%}). 입력 `{Path(a.claude).name}`(SHA-256 `{out['claude_sheet_sha256'][:16]}…`), 정답키 human_check_audit_key.json(`{out['key_sha256'][:16]}…`). {out['note']}\n",
          '| project | n | 일치 |\n|---|---:|---:|'] + [f"| {p} | {d['n']} | {d['agree']} |" for p, d in out['per_project'].items()] + ['\n| AI 1차 label | n | 일치 |\n|---|---:|---:|'] + [f"| {l} | {d['n']} | {d['agree']} |" for l, d in out['per_ai_label'].items()]
    md += ['\n## 불일치 건(사용자 판정 대상)\n', '| id | project | method path | AI 1차 (conf) | Claude 2차 (확신) | Claude 근거 |\n|---|---|---|---|---|---|'] + [f"| {r['id']} | {r['project']} | {r['method']} {r['path']} | {r['ai_final_label']} ({r['ai_confidence']}) | {r['claude_label']} ({r['claude_confidence']}) | {(r['claude_reason'] or '').replace('|', '/').replace(chr(10), ' ')[:200]} |" for r in mis]
    (REP / 'audit41_compare.md').write_text('\n'.join(md) + '\n', encoding='utf-8', newline='\r\n')
    if mis:
        from openpyxl import Workbook
        wb = Workbook(); ws = wb.active; ws.title = '감사_불일치'
        hdr = ['id', 'project', 'method', 'path', 'AI 1차 label', 'AI 1차 confidence', 'Claude 2차 label', 'Claude 확신도', 'Claude 근거', '사람 판정 label', '사람 근거', '사람 비고(EXCLUDE + 사유)']; ws.append(hdr)
        for r in mis: ws.append([r['id'], r['project'], r['method'], r['path'], r['ai_final_label'], r['ai_confidence'], r['claude_label'], r['claude_confidence'], r['claude_reason'], None, None, None])
        wb.save(REVIEW / 'test_v6_audit41_mismatch.xlsx')
    print(json.dumps({k: v for k, v in out.items() if k not in ('rows', 'mismatches')}, ensure_ascii=False)); print('mismatch ids:', [r['id'] for r in mis])


def apply(a):
    from openpyxl import load_workbook
    key = json.load(open(KEY, encoding='utf-8')); audit_ids = {r['id'] for r in key['audit']}
    # --- priority 44 ---
    h, pr = load_sheet(a.priority, '공개_우선확인'); assert len(pr) == 44, len(pr); P = {r['id']: r for r in pr}
    ai_lab = lambda r: norm(r.get('AI 확정 label')) or (EXC if norm(r.get('AI 비고(EXCLUDE + 사유)')) == EXC else '')
    upd = {}  # id -> dict(label, source, reason, note)
    for i, r in P.items():
        ai = ai_lab(r); cl = norm(r.get('Claude 의견 label')); hum = norm(r.get('사람 판정 label')) or (EXC if norm(r.get('사람 비고(EXCLUDE + 사유)')) == EXC else '')
        if i in BOUNDARY_IDS:
            assert hum, f'boundary id without human label: {i}'; upd[i] = dict(label=hum, source='human_confirmed', reason=r.get('사람 근거'), note=r.get('사람 비고(EXCLUDE + 사유)'), ai=ai, claude=cl)
        else:
            assert ai == cl and not hum, (i, ai, cl, hum); upd[i] = dict(label=ai, source='ai_double_confirmed', reason=None, note=None, ai=ai, claude=cl)
    # --- audit 41 ---
    audit_cmp = None
    if a.audit:
        h2, au = load_sheet(a.audit); lab_col = find_col(h2, 'claude', 'label', prefer='Claude 판정 label'); A = {r['id']: r for r in au}; K = {r['id']: r for r in key['audit']}
        hum_map = {}
        if a.audit_human:
            h3, hm = load_sheet(a.audit_human); H = {r['id']: r for r in hm}
            for i, r in H.items(): hum_map[i] = (norm(r.get('사람 판정 label')) or (EXC if norm(r.get('사람 비고(EXCLUDE + 사유)')) == EXC else ''), r.get('사람 근거'), r.get('사람 비고(EXCLUDE + 사유)'))
        audit_cmp = dict(n=0, agree=0, human=0)
        for i, k in K.items():
            cl = norm(A[i].get(lab_col)); audit_cmp['n'] += 1
            if cl == k['ai_final_label']:
                audit_cmp['agree'] += 1; upd.setdefault(i, dict(label=cl, source='ai_double_confirmed', reason=None, note=None, ai=k['ai_final_label'], claude=cl))
            else:
                assert i in hum_map and hum_map[i][0], f'audit mismatch without human judgement: {i} (AI {k["ai_final_label"]} / Claude {cl})'
                audit_cmp['human'] += 1; lab, rs, nt = hum_map[i]; upd[i] = dict(label=lab, source='human_confirmed', reason=rs, note=nt, ai=k['ai_final_label'], claude=cl)
    elif a.allow_no_audit: pass
    else: raise SystemExit('audit sheet required (or --allow-no-audit for a dry run)')
    # --- build final sheet from the AI-only sheet ---
    wb = load_workbook(AI_SHEET); ws = wb['test_v6_review']; hdr = [c.value for c in ws[1]]; ix = {n: i + 1 for i, n in enumerate(hdr)}
    for col in ('정답 출처', '사람 판정 label', 'Claude 2차 label'):
        if col not in ix: ws.cell(row=1, column=ws.max_column + 1, value=col); ix[col] = ws.max_column
    changes = []; src_cnt = Counter(); labels = Counter(); n = 0
    for row in range(2, ws.max_row + 1):
        i = ws.cell(row=row, column=ix['id']).value
        if not i: continue
        n += 1; cur = norm(ws.cell(row=row, column=ix['확정 label']).value) or (EXC if norm(ws.cell(row=row, column=ix['비고(EXCLUDE + 사유)']).value) == EXC else '')
        u = upd.get(i); src = u['source'] if u else 'ai_single'
        if u:
            assert u['ai'] == cur, (i, u['ai'], cur)
            ws.cell(row=row, column=ix['Claude 2차 label'], value=u['claude'])
            if u['source'] == 'human_confirmed':
                ws.cell(row=row, column=ix['사람 판정 label'], value=u['label'])
                if u['label'] != cur:
                    changes.append(dict(id=i, from_=cur, to=u['label'], claude=u['claude'], reason=u['reason'], note=u['note']))
                    if u['label'] == EXC: ws.cell(row=row, column=ix['확정 label']).value = None; ws.cell(row=row, column=ix['비고(EXCLUDE + 사유)'], value=f"EXCLUDE: {(u['note'] or '').replace('EXCLUDE:', '').strip() or '사람 판정'}")
                    else:
                        ws.cell(row=row, column=ix['확정 label'], value=u['label']); nt = ws.cell(row=row, column=ix['비고(EXCLUDE + 사유)']).value or ''
                        if norm(nt) == EXC: ws.cell(row=row, column=ix['비고(EXCLUDE + 사유)'], value=f"(사람 판정으로 EXCLUDE 해제) 원 AI 비고: {nt}")
                        if u['reason']: ws.cell(row=row, column=ix['확정 근거'], value=f"[사람 판정] {u['reason']}\n[AI 1차] {ws.cell(row=row, column=ix['확정 근거']).value or ''}")
                ws.cell(row=row, column=ix['담당자'], value='사람(사용자) + Claude(AI)')
        ws.cell(row=row, column=ix['정답 출처'], value=src); src_cnt[src] += 1
        fin = norm(ws.cell(row=row, column=ix['확정 label']).value) or (EXC if norm(ws.cell(row=row, column=ix['비고(EXCLUDE + 사유)']).value) == EXC else ''); labels[fin] += 1
    assert n == 302 and len(upd) == (44 if not a.audit else 44 + 41 - len(audit_ids & set(P))), (n, len(upd))
    wb.save(FINAL)
    rep = dict(date=a.date, ai_sheet=str(AI_SHEET.relative_to(ROOT)), ai_sheet_sha256=sha(AI_SHEET), priority_sheet=str(Path(a.priority)), priority_sheet_sha256=sha(a.priority), audit_sheet=str(a.audit) if a.audit else None, audit_sheet_sha256=sha(a.audit) if a.audit else None,
               audit_human_sheet=str(a.audit_human) if a.audit_human else None, final_sheet=str(FINAL.relative_to(ROOT)), final_sheet_sha256=sha(FINAL), boundary_ids=BOUNDARY_IDS, rows=n, source_counts=dict(src_cnt), audit=audit_cmp, label_changes=changes,
               final_label_counts=dict(labels), excluded=labels[EXC], exclusion_rate=round(labels[EXC] / n, 4), priority_overlap_with_audit=sorted(audit_ids & set(P)))
    REP.mkdir(parents=True, exist_ok=True); (REP / 'human_check_apply.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); print(json.dumps(rep, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest='cmd', required=True)
    a1 = sp.add_parser('audit'); a1.add_argument('--claude', required=True); a1.add_argument('--date', default='2026-11-08')
    a2 = sp.add_parser('apply'); a2.add_argument('--priority', required=True); a2.add_argument('--audit'); a2.add_argument('--audit-human'); a2.add_argument('--allow-no-audit', action='store_true'); a2.add_argument('--date', default='2026-11-08')
    a = ap.parse_args(); dict(audit=audit, apply=apply)[a.cmd](a)
