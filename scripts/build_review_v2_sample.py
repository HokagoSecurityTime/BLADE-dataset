"""Task 3: data-v2 review sample sheets (sheet generation only; no label changes).
A: Gitea with code ∧ manual ∧ info-gap reason (가), 30 records stratified by sub-reason (seed 42, min 3 per stratum).
B: visibility_dependent override 96 -> 10 records (seed 42) + test_v30 records whose handler code has a visibility/private/public branch.
C: Gitea declared ∧ public (12 in train_v2_draft), all.
Outputs reports/review_v2_sample/{review_sheet.xlsx, sheet_A.csv, sheet_B.csv, sheet_C.csv, test_visibility_refs.csv, README.md}."""
from __future__ import annotations
import csv, json, random, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from data_v1_guard import assert_data_v1
import importlib.util
spec = importlib.util.spec_from_file_location('audit', ROOT / 'scripts/audit_data_v1.py'); audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
P = ROOT / 'datasets/blade/processed'; OUT = ROOT / 'reports/review_v2_sample'; MANUAL = 'manual_review_required'
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
COLS = ['id', 'source', 'method', 'path', 'security_state', '핸들러 코드(전체)', 'OAS operation 발췌', '현재 label', 'label_before_override', '사유 분류', '모델 rationale 원문', 'reviewer_label', 'reviewer_confidence', 'reviewer_note']
VIS_PATTERN = r'visib|private|is_public|public\b|hidden|publish|restricted|anonymous'

def oas_excerpt(r):
    spec = json.loads(r['oas_snippet']); op = spec['paths'][r['path']][r['method'].lower()]
    keep = {k: op.get(k) for k in ('summary', 'description', 'operationId', 'security', 'parameters') if op.get(k) is not None}
    if 'parameters' in keep: keep['parameters'] = [{k: p.get(k) for k in ('name', 'in', 'required')} for p in keep['parameters'] if isinstance(p, dict)]
    return json.dumps(keep, ensure_ascii=False, indent=1)

def row(r, reason):
    m = r.get('meta', {})
    return [r['id'], m.get('origin') or m.get('source') or 'gitea', r['method'], r['path'], r.get('security_state', ''), r.get('controller_text') or (r.get('controller_signals') or {}).get('raw_snippet', ''), oas_excerpt(r),
            r['label'], m.get('label_before_override', ''), reason, r.get('rationale', ''), '', '', '']

def main():
    verified = assert_data_v1('start'); OUT.mkdir(parents=True, exist_ok=True); rng = random.Random(42)
    v2 = rd(P / 'train_v2_draft.jsonl'); gitea = [r for r in v2 if r['id'].startswith('gitea:')]
    test = rd(P / 'test_v30.jsonl')
    # ---- Sheet A ----
    pool_a = []
    for r in gitea:
        if r['label'] != MANUAL or not (r.get('controller_text') or '').strip(): continue
        if r['meta'].get('v30_override_reason'): continue  # overrides are not model info-gap reasons
        c, st, ev = audit.manual_reason(r)
        if c == '가': pool_a.append((r, st))
    strata = Counter(st for _, st in pool_a)
    groups = {'관계 미확인': [x for x in pool_a if x[1] == '요청자-객체 관계 미확인'], '인증만 확인': [x for x in pool_a if x[1] == '인증만 확인·인가 조건 없음'], '접근 조건 미명시': [x for x in pool_a if x[1] == '접근 조건 미명시(일반)']}
    groups['기타'] = [x for x in pool_a if x[1] not in ('요청자-객체 관계 미확인', '인증만 확인·인가 조건 없음', '접근 조건 미명시(일반)')]
    total = len(pool_a); alloc = {g: max(3, round(30 * len(v) / total)) if v else 0 for g, v in groups.items()}
    while sum(alloc.values()) > 30:
        g = max((g for g in alloc if alloc[g] > 3), key=lambda g: alloc[g]); alloc[g] -= 1
    while sum(alloc.values()) < 30:
        g = max(groups, key=lambda g: len(groups[g]) - alloc[g]); alloc[g] += 1
    sheet_a = []
    for g, v in groups.items():
        picks = rng.sample(sorted(v, key=lambda x: x[0]['id']), min(alloc[g], len(v)))
        for r, st in picks: sheet_a.append(row(r, f'(가) {st}'))
    # ---- Sheet B ----
    vis = sorted([r for r in gitea if r['meta'].get('v30_override_reason') == 'visibility_dependent'], key=lambda r: r['id'])
    sheet_b = [row(r, 'visibility_dependent override') for r in rng.sample(vis, 10)]
    test_vis = []
    for r in test:
        code = r.get('controller_text') or ''
        hits = sorted({m.group(0).lower() for m in re.finditer(VIS_PATTERN, code, re.I)})
        if hits: test_vis.append([r['id'], r.get('source'), r['service'], r['method'], r['path'], r['label'], ', '.join(hits), code.replace('\n', ' ⏎ ')[:300]])
    # ---- Sheet C ----
    test_inputs = {r['id']: r for r in rd(ROOT / 'training/lora/data_v1/test_v30_inputs.jsonl')}
    sheet_c = [row(r, 'declared ∧ public (override 없음)') for r in sorted(gitea, key=lambda r: r['id']) if r.get('security_state') == 'declared' and r['label'] == 'public']
    # ---- CSV ----
    for name, rows in (('sheet_A.csv', sheet_a), ('sheet_B.csv', sheet_b), ('sheet_C.csv', sheet_c)):
        with open(OUT / name, 'w', encoding='utf-8-sig', newline='') as f: w = csv.writer(f); w.writerow(COLS); w.writerows(rows)
    with open(OUT / 'test_visibility_refs.csv', 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f); w.writerow(['id', 'source', 'service', 'method', 'path', '정답 label', '매칭 패턴', '코드(300자)']); w.writerows(test_vis)
    # ---- XLSX ----
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    wb = Workbook(); wb.remove(wb.active)
    widths = {'id': 46, 'source': 10, 'method': 8, 'path': 40, 'security_state': 12, '핸들러 코드(전체)': 110, 'OAS operation 발췌': 60, '현재 label': 22, 'label_before_override': 20, '사유 분류': 34, '모델 rationale 원문': 60, 'reviewer_label': 24, 'reviewer_confidence': 18, 'reviewer_note': 40}
    fill = PatternFill('solid', fgColor='FFF2CC'); head_fill = PatternFill('solid', fgColor='DDEBF7')
    def sheet(title, rows, note):
        ws = wb.create_sheet(title); ws.append([note]); ws.append(COLS)
        for i, c in enumerate(COLS, 1):
            cell = ws.cell(row=2, column=i); cell.font = Font(bold=True); cell.fill = fill if c.startswith('reviewer_') else head_fill; ws.column_dimensions[get_column_letter(i)].width = widths[c]
        for r in rows: ws.append(r)
        for rr in ws.iter_rows(min_row=3, max_row=ws.max_row):
            for cell in rr: cell.alignment = Alignment(wrap_text=True, vertical='top')
            for i, c in enumerate(COLS, 1):
                if c.startswith('reviewer_'): rr[i - 1].fill = fill
        ws.freeze_panes = 'B3'
    sheet('A_gitea_info_gap_30', sheet_a, '시트 A: Gitea 코드 있음 ∧ manual ∧ (가) 정보 부족 사유 30건(seed 42 층화). 코드를 보면 구체 label이 정해지는지 확인. reviewer_label은 7종 label 중 하나, reviewer_confidence는 high/mid/low.')
    sheet('B_visibility_10', sheet_b, '시트 B: visibility_dependent override 96건 중 10건(seed 42). 조건부 접근을 manual로 둘지 확인. test 대조 목록은 test_visibility_refs 시트.')
    sheet('C_declared_public_12', sheet_c, '시트 C: Gitea security declared ∧ label public 12건 전체. 코드 기준 public이 맞는지 확인(맞으면 override 없이 유지 예정).')
    ws = wb.create_sheet('test_visibility_refs'); ws.append(['test_v30에서 핸들러 코드에 공개/비공개 분기 패턴(' + VIS_PATTERN + ')이 있는 건 — 같은 유형을 test가 어떻게 채점하는지 대조용']); ws.append(['id', 'source', 'service', 'method', 'path', '정답 label', '매칭 패턴', '코드(300자)'])
    for r in test_vis: ws.append(r)
    for i, w in enumerate([24, 10, 14, 8, 50, 22, 24, 110], 1): ws.column_dimensions[get_column_letter(i)].width = w
    wb.save(OUT / 'review_sheet.xlsx')
    # ---- README ----
    labels_vis = Counter(r[5] for r in test_vis)
    readme = f"""# data-v2 검수 샘플 (시트 생성만, 라벨 변경 없음) — 2026-10-23

data-v1 해시 assert 통과(시작·종료): {', '.join(k.split('/')[-1] + ' ' + v for k, v in verified.items())}. 입력: datasets/blade/processed/train_v2_draft.jsonl(Gitea 371건), test_v30.jsonl(읽기 전용). seed 42.

## 시트 A — Gitea 코드 있음 ∧ manual ∧ (가) 정보 부족 사유: 30건
- 모집단 {total}건(Gitea manual 중 override 아님 ∧ 사유 분류 (가)). 사유 분류는 scripts/audit_data_v1.py의 manual_reason(모델 rationale 정규식) 기준.
- 층별 모집단 / 추출: {', '.join(f'{g} {len(v)} / {alloc[g]}' for g, v in groups.items())}. 층당 최소 3건, 비율 배분 후 30건으로 조정.
- 목적: 코드를 보면 구체 label이 정해지는데 보수적으로 manual이 붙었는지 확인.

## 시트 B — visibility_dependent override 96건 중 10건
- 모집단 96건(모델 label과 무관하게 manual override). 추출 10건.
- 대조: test_v30에서 핸들러 코드에 패턴 `{VIS_PATTERN}`이 있는 건 {len(test_vis)}건(test_visibility_refs 시트/CSV). 정답 분포: {dict(labels_vis)}. 같은 유형을 test가 어떻게 채점하는지 참고.

## 시트 C — Gitea declared ∧ public 12건 전체
- 모집단 = 추출 {len(sheet_c)}건. 코드 기준 public이 맞는지 확인(맞으면 override 없이 public 유지 예정).

## 공통 열
id, source, method, path, security_state, 핸들러 코드(전체), OAS operation 발췌, 현재 label, label_before_override, 사유 분류, 모델 rationale 원문, reviewer_label(빈칸, 7종 label), reviewer_confidence(high/mid/low), reviewer_note. reviewer_* 열은 노란색.

## 검수 후 집계 지표
- 시트 A: reviewer_label이 구체 label(6종)인 비율 = 과보류율 추정치. 이 비율로 manual 쿼터·재라벨 방침(A/B)을 결정한다. 층별로도 산출.
- 시트 B: reviewer_label이 manual인 비율(override 유지 타당성)과 구체 label로 바뀐 건의 label 분포; test_visibility_refs의 정답 분포와 대조.
- 시트 C: reviewer_label == public 비율. 전부 public이면 Gitea에 security_declared_public override를 적용하지 않는다.
- 세 시트 모두 reviewer_confidence=low 건은 2차 검수 대상으로 분리.

파일: review_sheet.xlsx(시트 4개), sheet_A.csv, sheet_B.csv, sheet_C.csv, test_visibility_refs.csv. 스크립트 scripts/build_review_v2_sample.py.
"""
    (OUT / 'README.md').write_text(readme, encoding='utf-8'); assert_data_v1('end')
    print(json.dumps(dict(pool_a=total, strata={g: len(v) for g, v in groups.items()}, alloc=alloc, sheet_a=len(sheet_a), sheet_b=len(sheet_b), sheet_c=len(sheet_c), test_vis=len(test_vis), test_vis_labels=dict(labels_vis)), ensure_ascii=False))

if __name__ == '__main__': main()
