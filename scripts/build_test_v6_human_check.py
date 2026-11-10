"""Human-check workbook for the AI-reviewed test_v6 (AGENTS.md 작업 S0, 사람 확인 프로토콜 2026-11-04).
Inputs : datasets/blade/processed/data_v6/test_v6_candidates.jsonl, data_v6/review_ai/<project>_review.jsonl, data_v6/redash_g1b_boundary_ids.json
Output : review/test_v6_human_check.xlsx
  sheet '공개_우선확인'  priority set (AI label/reason visible): EXCLUDE 13 ∪ AI confidence < 0.7 ∪ changed-from-draft ∪ seahub owner_or_admin→manual 4 ∪ Redash G1-b boundary ids, de-duplicated
  sheet '블라인드_감사'  stratified random audit of the remaining records, 15% per (AI final label × project) stratum, seed 42; AI/draft label, reason and evidence hidden
  sheets '라벨 정의', '검수 규약'
  key   : data_v6/review_ai/human_check_audit_key.json (audit ids → AI final label; kept out of the workbook; used to score agreement)
Reviewers A/B/C balanced per sheet. Pre-registered rule: audit disagreement ≤ 5% → accept remaining AI confirmations; > 5% → full human review; human judgement wins on every disagreement.
Usage: .python/python.exe -I scripts/build_test_v6_human_check.py"""
from __future__ import annotations
import argparse, hashlib, json, math, random, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from build_data_v4 import LABELS
from build_test_v6 import permalink, rules_text
P = ROOT / 'datasets/blade/processed'; RA = P / 'data_v6/review_ai'; OUT = ROOT / 'review/test_v6_human_check.xlsx'
PROJECTS = ['seahub', 'redash', 'glitchtip', 'penpot']; REVIEWERS = ['검수자A', '검수자B', '검수자C']; SEED, RATE, CONF = 42, 0.15, 0.7
SEAHUB_Q = ('확인 질문: repo_owner == username 비교와 is_repo_admin(share/utils.py:39-73) 내부의 소유자 검사가 같은 소유자 개념인가(그룹 소유 라이브러리의 repo_owner 포함)? '
            '같다면 허용 집합 = is_repo_admin 단독과 동일 → manual(보충 규약 2). 다르다면(명시적 소유자 비교가 독립 조건) → owner_or_admin(정지 지점 2 결정 3.2 문구).')
SEAHUB_4 = {('seahub', 'DELETE', '/api/v2.1/groups/{group_id}/libraries/{repo_id}/'), ('seahub', 'DELETE', '/api2/groups/{group_id}/repos/{repo_id}/'),
            ('seahub', 'POST', '/api2/repos/{repo_id}/dir/shared_items/'), ('seahub', 'POST', '/api/v2.1/wikis/')}
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
rd = lambda p: [json.loads(l) for l in Path(p).read_text(encoding='utf-8').splitlines() if l.strip()]


def main(date):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    recs = {r['id']: r for r in rd(P / 'data_v6/test_v6_candidates.jsonl')}
    rev = {}
    for p in PROJECTS:
        for x in rd(RA / f'{p}_review.jsonl'): assert x['id'] in recs and x['id'] not in rev; rev[x['id']] = x
    assert set(rev) == set(recs), 'review coverage'
    g1b = json.loads((P / 'data_v6/redash_g1b_boundary_ids.json').read_text(encoding='utf-8'))
    g1b_ids = {x['id'] for x in g1b['g1b_require_admin']} | {x['id'] for x in g1b['g1b_consistency_functional_permission']}
    key4 = lambda r: (r['meta']['project'], r['method'], r['path'])
    reasons = defaultdict(list)
    for i, x in rev.items():
        r = recs[i]; excl = (x.get('note') or '').upper().startswith('EXCLUDE')
        if excl: reasons[i].append('EXCLUDE')
        if (x.get('confidence') or 1) < CONF and not excl: reasons[i].append(f'confidence<{CONF}')
        if x.get('changed'): reasons[i].append('초안 대비 변경')
        if key4(r) in SEAHUB_4: reasons[i].append('seahub owner_or_admin→manual')
        if i in g1b_ids: reasons[i].append('Redash G1-b 경계')
    priority = sorted(reasons, key=lambda i: (recs[i]['meta']['project'], rev[i].get('final_label') or 'EXCLUDE', i))
    assert all(key4(recs[i]) in SEAHUB_4 for i in reasons if 'seahub owner_or_admin→manual' in reasons[i]) and sum('seahub owner_or_admin→manual' in v for v in reasons.values()) == 4
    # audit: stratified 15% of the remainder by (AI final label, project), seed 42
    rest = [i for i in recs if i not in reasons]; strata = defaultdict(list)
    for i in rest: strata[(rev[i]['final_label'], recs[i]['meta']['project'])].append(i)
    rng = random.Random(SEED); audit = []
    for k in sorted(strata):
        ids = sorted(strata[k]); n = round(RATE * len(ids)) if len(ids) >= 3 else (1 if len(ids) == 2 else 0)
        n = max(n, 1) if len(ids) >= 3 else n; audit += rng.sample(ids, n)
    audit = sorted(audit, key=lambda i: (recs[i]['meta']['project'], rev[i]['final_label'], i))
    assign = lambda ids: {i: REVIEWERS[n % 3] for n, i in enumerate(ids)}
    a_pri, a_aud = assign(priority), assign(audit)
    ev = lambda m: '\n'.join(f"[{e.get('type')}] {e.get('location', '')}\n{e.get('text', '')}" for e in m.get('evidence') or [])
    wb = Workbook(); ws = wb.active; ws.title = '공개_우선확인'
    hdr = ['id', '담당자', '확인 사유', 'project', 'service', 'method', 'path', 'auth_summary', 'permission_doc', '초안 label', '초안 confidence', '초안 근거 설명', '근거(코드 줄·문서)',
           'AI 확정 label', 'AI 확정 confidence', 'AI 확정 근거', 'AI 비고(EXCLUDE + 사유)', '확인 질문', 'controller_text(입력 코드)', 'source permalink', '사람 판정 label', '사람 근거', '사람 비고(EXCLUDE + 사유)']
    ws.append(hdr)
    for i in priority:
        r, x, m = recs[i], rev[i], recs[i]['meta']
        ws.append([i, a_pri[i], '; '.join(reasons[i]), m['project'], r['service'], r['method'], r['path'], m.get('auth_summary', ''), m.get('permission_doc', ''), m.get('draft_label'), m.get('draft_confidence'),
                   m.get('draft_reason', ''), ev(m), x.get('final_label') or '', x.get('confidence'), x.get('final_reason', ''), x.get('note', ''), SEAHUB_Q if key4(r) in SEAHUB_4 else '', r['controller_text'], permalink(m), '', '', ''])
    style(ws, [26, 9, 28, 10, 14, 8, 44, 36, 24, 18, 9, 44, 50, 18, 9, 50, 36, 50, 70, 40, 18, 40, 24], hdr.index('사람 판정 label') + 1, len(priority), DataValidation, Alignment, Font, PatternFill)
    wb_blind = wb.create_sheet('블라인드_감사')
    hdr_b = ['id', '담당자', 'project', 'service', 'method', 'path', 'auth_summary', 'permission_doc', 'controller_text(입력 코드)', 'source permalink', '사람 판정 label', '사람 근거', '사람 비고(EXCLUDE + 사유)']
    wb_blind.append(hdr_b)
    for i in audit:
        r, m = recs[i], recs[i]['meta']
        wb_blind.append([i, a_aud[i], m['project'], r['service'], r['method'], r['path'], m.get('auth_summary', ''), m.get('permission_doc', ''), r['controller_text'], permalink(m), '', '', ''])
    style(wb_blind, [26, 9, 10, 14, 8, 44, 36, 24, 80, 40, 18, 40, 24], hdr_b.index('사람 판정 label') + 1, len(audit), DataValidation, Alignment, Font, PatternFill)
    system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    d = wb.create_sheet('라벨 정의'); d.column_dimensions['A'].width = 140
    defs = ('프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
            + '\n\nBLADE 규약: 인가 검사가 빠졌어도 경로·스키마·수정 커밋으로 의도된 정책이 드러나면 그 정책을 label로 한다. membership_required = 요청 대상 그룹·팀의 구성원 관계(구독·등급 아님). 구성원 OR 관리자 우회도 membership_required. 소유자 OR 관리자 우회는 owner_or_admin. 요청자의 현재 테넌트(org)로 자원을 필터·고정하면 tenant_match(RBAC 동반해도). 경계·근거 부족 건은 manual로 넣지 말고 비고에 EXCLUDE와 사유를 적는다(G8).'
            + '\n\n사람 확인 프로토콜: 공개_우선확인 시트는 AI 확정을 보고 확인·수정한다(사람 판정 label을 반드시 채움). 블라인드_감사 시트는 AI 판정을 보지 않고 독립 판정한다. 감사 불일치 ≤ 5%면 나머지 AI 확정을 수용하고, 초과면 전수 사람 검수. 불일치 건은 사람 판정 우선.')
    for line in defs.splitlines(): d.append([line])
    g = wb.create_sheet('검수 규약'); g.column_dimensions['A'].width = 160
    for line in rules_text().splitlines(): g.append([line])
    OUT.parent.mkdir(parents=True, exist_ok=True); wb.save(OUT)
    key = dict(name='test_v6_human_check_audit_key', date=date, seed=SEED, rate=RATE, note='블라인드 감사 정답키(AI 확정). 시트에는 넣지 않는다. 불일치율 = (사람 판정 ≠ AI 확정) / 감사 건수.',
               audit=[dict(id=i, project=recs[i]['meta']['project'], method=recs[i]['method'], path=recs[i]['path'], ai_final_label=rev[i]['final_label'], ai_confidence=rev[i].get('confidence'), reviewer=a_aud[i]) for i in audit],
               strata={f'{k[0]}|{k[1]}': dict(size=len(v), sampled=sum(1 for i in audit if (rev[i]['final_label'], recs[i]['meta']['project']) == k)) for k, v in sorted(strata.items())})
    (RA / 'human_check_audit_key.json').write_text(json.dumps(key, ensure_ascii=False, indent=1), encoding='utf-8')
    rep = dict(sheet=str(OUT.relative_to(ROOT)).replace('\\', '/'), sha256=sha(OUT), date=date, priority=len(priority), priority_reasons=dict(Counter(x for v in reasons.values() for x in v)),
               priority_per_project=dict(Counter(recs[i]['meta']['project'] for i in priority)), priority_per_reviewer=dict(Counter(a_pri.values())),
               audit=len(audit), audit_universe=len(rest), audit_per_project=dict(Counter(recs[i]['meta']['project'] for i in audit)), audit_per_label=dict(Counter(rev[i]['final_label'] for i in audit)),
               audit_per_reviewer=dict(Counter(a_aud.values())), covered=len(priority) + len(audit), total=len(recs), audit_key='datasets/blade/processed/data_v6/review_ai/human_check_audit_key.json',
               rule='감사 불일치 ≤ 5% → 나머지 AI 확정 수용; > 5% → 전수 사람 검수; 불일치 건은 사람 판정 우선')
    (RA / 'human_check_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); print(json.dumps(rep, ensure_ascii=False))


def style(ws, widths, label_col, nrows, DataValidation, Alignment, Font, PatternFill):
    for c in ws[1]: c.font = Font(bold=True); c.fill = PatternFill('solid', fgColor='DDEBF7'); c.alignment = Alignment(wrap_text=True, vertical='top')
    for i, w in enumerate(widths, 1): ws.column_dimensions[ws.cell(1, i).column_letter].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    dv = DataValidation(type='list', formula1='"' + ','.join(LABELS) + '"', allow_blank=True); ws.add_data_validation(dv)
    col = ws.cell(1, label_col).column_letter; dv.add(f'{col}2:{col}{nrows + 1}'); ws.freeze_panes = 'C2'; ws.auto_filter.ref = ws.dimensions


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--date', default='2026-11-04'); main(ap.parse_args().date)
