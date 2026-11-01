"""data-v4 train additions (Zulip, Label Studio) and test_v31_supp evaluation additions (Chatwoot, Chamilo, Flowise, multitenant lab, Generic University).
Reads extraction candidates data/raw_v4/<project>/candidates.jsonl (format: data/raw_v4/EXTRACTION_SPEC.md) and builds records in the oas_code input format.
Steps (each writes new files only; frozen data-v1..v3 and test_v30 are hash-asserted and read only):
  assemble  candidates -> records, de-duplication against APIs.guru candidates, data-v1..v3 and test_v30 on (service, method, normalized path)
  label     train records only: gpt-4o-mini + prompt v3.0.1, oas_code input exactly as the SFT input (--execute required)
  select    per project <= 150 records, no label above 50% within a project, target labels first (seed 42)
  sheets    review/v4_train_review.xlsx (label-stratified 20% of the selection), review/test_v31_supp_review.xlsx (every test record, evidence columns)
  report    reports/data_v4_build.md
Test drafts come from the extraction (evidence-based) and are all subject to human confirmation; the train labeler is never run on test records.
No training, no freeze."""
from __future__ import annotations
import argparse, asyncio, hashlib, json, math, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from data_v1_guard import assert_data_v1
from data_v2_guard import assert_data_v2
RAW = ROOT / 'data/raw_v4'; P = ROOT / 'datasets/blade/processed'; OUT = P / 'data_v4'; REVIEW = ROOT / 'review'; LOG = ROOT / 'reports/eval/data_v4/label'
TRAIN_PROJECTS = ['zulip', 'label_studio']; TEST_PROJECTS = ['chatwoot', 'chamilo', 'flowise', 'multitenant_lab', 'generic_university']
LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']
TARGET = ['membership_required', 'tenant_match', 'owner_or_admin']
CAP, MAX_SHARE, SEED, REVIEW_SHARE = 150, 0.5, 42, 0.2
# Excerpts cut at a line boundary by the extractor with permission-check lines missing (data/raw_v4/zulip/SOURCE.md): input would not show the real check.
EXCLUDE = {('zulip', 'PATCH', '/api/v1/realm'): 'excerpt truncated, later permission checks missing',
           ('zulip', 'PATCH', '/api/v1/streams/{stream_id}'): 'excerpt truncated, later permission checks missing'}
FROZEN = {P / 'test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2',
          P / 'train_v3a.jsonl': '1f5d1055ac3d8d407e555c774183acf4c52ceb03ea508391ee5d508484446e66', P / 'train_v3b.jsonl': '723e3b3a784e624033379dce5e46b243c2c3444c34db7efb5032ea2436a696dd',
          P / 'val_v3.jsonl': '69536f8b10e99538673a1beaf96411aba2b18f341e04f9429f717d9d84cbc109', P / 'train_v2.jsonl': 'f26c368d051e1ec2683a1f70ed52162808740d9b06540bbad1fe94988ed47ada',
          P / 'val_v2.jsonl': 'd0e216dd1267ba7f46eb08e5db955473b11bbd049d875e33eb8032504c0f3ac0', P / 'train_v30.jsonl': 'a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2',
          P / 'val_v30.jsonl': '62bdadb29cae7aaf814007ad8adec40115e8612d70f2911693219399c82b595c'}
DEDUP_SOURCES = {'apisguru_candidates': ROOT / 'datasets/blade/raw/apisguru_candidates.jsonl', 'data-v1 train/val': [P / 'train_v30.jsonl', P / 'val_v30.jsonl'],
                 'data-v2 train/val/pool': [P / 'train_v2.jsonl', P / 'val_v2.jsonl', P / 'train_v2_manual_pool.jsonl'],
                 'data-v3 train/val': [P / 'train_v3a.jsonl', P / 'train_v3b.jsonl', P / 'val_v3.jsonl'], 'test_v30': P / 'test_v30.jsonl'}
# Meta text and file references that must never appear in a training rationale (task rule 3).
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|candidates\.jsonl|EXTRACTION_SPEC')
FILE_REF = re.compile(r'(?:FILE\s+)?(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java|ya?ml)(?::\d+(?:-\d+)?)?')
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
rd = lambda p: [json.loads(l) for l in Path(p).read_text(encoding='utf-8').splitlines() if l.strip()]
dump = lambda p, rows: (Path(p).parent.mkdir(parents=True, exist_ok=True), Path(p).write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8'))


def guard(stage):
    assert_data_v1(stage); assert_data_v2(stage)
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'


# ---------- normalization for de-duplication ----------
def norm_service(s):
    s = (s or '').lower().split(':')[0]
    s = re.sub(r'\.(com|org|io|net|local|dev|app|co|ai)$', '', s)
    return re.sub(r'[^a-z0-9]', '', s)


def norm_path(p):
    p = re.sub(r'\{[^}]*\}|<[^>]*>|:\w+', '{}', (p or '').strip().lower())
    return re.sub(r'/+', '/', p).rstrip('/') or '/'


def key(service, method, path): return (norm_service(service), (method or '').upper(), norm_path(path))


def existing_keys():
    keys = {}
    for name, src in DEDUP_SOURCES.items():
        for p in (src if isinstance(src, list) else [src]):
            if not p.exists(): continue
            for r in rd(p):
                svc = r.get('service') or (r['id'].split(':')[1] if r['id'].startswith('apisguru:') else r.get('project'))
                keys.setdefault(key(svc, r.get('method'), r.get('path')), name)
    return keys


# ---------- candidates -> records ----------
def oas_snippet(c):
    op = dict(c['oas_operation']); op.pop('x-bladed', None)
    fields = c.get('response_schema_fields') or []
    has_schema = any('content' in (v or {}) or 'schema' in (v or {}) for v in (op.get('responses') or {}).values())
    if fields and not has_schema:
        op['responses'] = {**(op.get('responses') or {}), '200': {'description': (op.get('responses') or {}).get('200', {}).get('description', 'OK'),
                           'content': {'application/json': {'schema': {'type': 'object', 'properties': {f: {} for f in fields[:40]}}}}}}
    spec = dict(openapi='3.0.3', info=dict(title=c['service'], version=c.get('tag') or ''), paths={c['path']: {c['method'].lower(): op}})
    if c.get('oas_global_security'): spec['security'] = c['oas_global_security']
    if c.get('oas_security_schemes'): spec['components'] = dict(securitySchemes=c['oas_security_schemes'])
    return json.dumps(spec, ensure_ascii=False)


def security_state(spec, op):
    if op.get('security') == [] and 'security' in spec: return 'explicitly_anonymous'
    return 'declared' if ('security' in op or 'security' in spec) else 'unknown'


def to_record(c, split):
    ident = f"v4{'t' if split == 'test' else ''}-{c['project']}-{hashlib.sha1((c['method'].upper() + ' ' + c['path']).encode()).hexdigest()[:10]}"
    spec = json.loads(oas_snippet(c)); op = spec['paths'][c['path']][c['method'].lower()]
    meta = dict(data_version='data-v4' if split == 'train' else 'test_v31_supp', project=c['project'], repository=c['repository'], commit=c['commit'], tag=c.get('tag'),
                license=c.get('license'), oas_status=c.get('oas_status'), source_locations=c.get('source_locations') or [], auth_summary=c.get('auth_summary', ''),
                permission_doc=c.get('permission_doc', ''))
    if split == 'test':
        meta.update(draft_label=c.get('draft_label'), draft_confidence=c.get('draft_confidence'), evidence=c.get('evidence') or [], draft_reason=c.get('draft_reason', ''),
                    known_vulnerable=bool(c.get('known_vulnerable')), advisory=c.get('advisory'), fix_commit=c.get('fix_commit'), label_status='draft_pending_human_confirmation')
    return dict(id=ident, source='opensource_v4' if split == 'train' else 'test_v31_supp', service=c['service'], method=c['method'].upper(), path=c['path'],
                label=None, oas_snippet=oas_snippet(c), erd_snippet='', security_state=security_state(spec, op), controller_text=(c.get('controller_text') or '').strip(), meta=meta)


def assemble(args):
    guard('start'); OUT.mkdir(parents=True, exist_ok=True)
    seen = existing_keys(); rep = dict(projects={}, duplicates=[], internal_duplicates=[], missing=[])
    for split, projects in (('train', TRAIN_PROJECTS), ('test', TEST_PROJECTS)):
        recs, keys_here = [], {}
        for proj in projects:
            f = RAW / proj / 'candidates.jsonl'
            if not f.exists(): rep['missing'].append(proj); continue
            cands = rd(f); kept = 0
            for c in cands:
                assert c['project'] == proj, (proj, c.get('project'))
                why = EXCLUDE.get((proj, c['method'].upper(), c['path']))
                if why: rep.setdefault('excluded', []).append(dict(project=proj, method=c['method'], path=c['path'], reason=why)); continue
                k = key(c['service'], c['method'], c['path'])
                if k in seen: rep['duplicates'].append(dict(project=proj, method=c['method'], path=c['path'], matched=seen[k])); continue
                if k in keys_here: rep['internal_duplicates'].append(dict(project=proj, method=c['method'], path=c['path'])); continue
                r = to_record(c, split); assert len(r['controller_text']) <= 3000 and r['controller_text'], (proj, c['method'], c['path'])
                keys_here[k] = r['id']; recs.append(r); kept += 1
            rep['projects'][proj] = dict(split=split, candidates=len(cands), kept=kept)
        ids = [r['id'] for r in recs]; assert len(ids) == len(set(ids))
        dump(OUT / ('candidates_train_v4.jsonl' if split == 'train' else 'test_v31_supp_candidates.jsonl'), recs)
    (OUT / 'assemble_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8')
    guard('end'); print(json.dumps({k: v for k, v in rep.items() if k != 'duplicates'} | dict(duplicates=len(rep['duplicates'])), ensure_ascii=False))


# ---------- labeling (train only) ----------
def sft_user(r):
    from training.lora.prepare_lora_inputs import test_record
    return test_record({**r, 'label': None})['oas_code_user']


def sanitize(rationale):
    """Removes file references the model copied from the 'FILE <path>' input line (rule: no file names in rationale). Returns (text, changed)."""
    new = FILE_REF.sub('핸들러 코드', rationale or ''); new = re.sub(r'(핸들러 코드)(\s*[,·]?\s*핸들러 코드)+', r'\1', new)
    return new, new != (rationale or '')


async def label_run(args):
    from training.data import label_v30 as m
    import httpx
    guard('start'); m.configure('v301'); system = m.PROMPT.read_text(encoding='utf-8'); LOG.mkdir(parents=True, exist_ok=True)
    src = OUT / 'candidates_train_v4.jsonl'; out = OUT / 'train_v4_labeled_v301.jsonl'; rows = rd(src)
    done = {r['id']: r for r in rd(out)} if out.exists() else {}
    settings = m.settings_from_env(); sem = asyncio.Semaphore(args.concurrency); lock = asyncio.Lock()
    manifest = dict(prompt_version=m.VERSION, prompt_sha256=m.digest(m.PROMPT), input_sha256=sha(src), model=settings.model, temperature=0, condition='oas_code', records=len(rows), started_at=m.now())
    m.dump(LOG / 'manifest.json', manifest)
    async with httpx.AsyncClient(timeout=180) as client:
        async def one(r):
            if r['id'] in done: return
            payload = json.loads(sft_user(r).split('\n', 1)[1])
            async with sem: res = await m.request(payload, r['id'], system, settings, client, LOG)
            meta = res.pop('meta'); clean, changed = sanitize(res.get('rationale'))
            rec = {**r, **res, 'rationale': clean, 'meta': {**r['meta'], **meta, 'api_original_label': res.get('label'), 'api_original_rationale': res.get('rationale') if changed else None, 'rationale_file_ref_removed': changed}}
            async with lock: m.base5.append(out, rec); done[r['id']] = rec
        await asyncio.gather(*[one(r) for r in rows])
    final = [done[r['id']] for r in rows]; dump(out, final)
    usage = m.read(LOG / 'usage.jsonl'); inp = sum(u['usage'].get('input_tokens', 0) for u in usage); cached = sum((u['usage'].get('input_tokens_details') or {}).get('cached_tokens', 0) for u in usage); outt = sum(u['usage'].get('output_tokens', 0) for u in usage)
    manifest.update(completed_at=m.now(), output_sha256=sha(out), usage=dict(api_responses=len(usage), input_tokens=inp, cached_input_tokens=cached, output_tokens=outt, estimated_usd=round(((inp - cached) * .15 + cached * .075 + outt * .6) / 1e6, 4)))
    m.dump(LOG / 'manifest.json', manifest); guard('end')
    print(json.dumps(dict(records=len(final), errors=sum(r['label'] is None for r in final), labels=Counter(r['label'] for r in final), usage=manifest['usage']), ensure_ascii=False, default=str))


# ---------- selection ----------
def allocate(counts):
    """Largest N <= CAP such that every label can stay <= floor(N * MAX_SHARE); target labels are filled first, then the rest by water-filling."""
    total = sum(counts.values())
    for n in range(min(CAP, total), 0, -1):
        lim = math.floor(n * MAX_SHARE)
        if sum(min(c, lim) for c in counts.values()) >= n: break
    else: return {}
    lim = math.floor(n * MAX_SHARE); take = {l: 0 for l in counts}; left = n
    for l in TARGET:
        if l in counts: take[l] = min(counts[l], lim); left -= take[l]
    rest = sorted([l for l in counts if l not in TARGET], key=lambda l: counts[l])
    while left > 0:
        open_ = [l for l in rest if take[l] < min(counts[l], lim)]
        if not open_: break
        share = max(1, left // len(open_))
        for l in open_:
            add = min(share, min(counts[l], lim) - take[l], left); take[l] += add; left -= add
            if left == 0: break
    if left > 0:  # target labels can absorb the remainder only up to the cap
        for l in TARGET:
            if l in take: add = min(left, min(counts[l], lim) - take[l]); take[l] += add; left -= add
    return take


BACKENDS = re.compile(r'/(s3s?|gcs|azure(?:_spi)?|redis|localfiles|azure_blob)(?=/|$)')


def near_dup_group(r):
    """Label Studio io_storages: the same operation exists once per storage backend with near-identical code. One per group is kept."""
    return (r['meta']['project'], r['method'], BACKENDS.sub('/{backend}', r['path']))


def select(args):
    guard('start'); rows = [r for r in rd(OUT / 'train_v4_labeled_v301.jsonl') if r['label']]
    rng = random.Random(SEED); chosen, rep = [], {}
    groups = defaultdict(list)
    for r in sorted(rows, key=lambda r: r['id']): groups[near_dup_group(r)].append(r)
    rows = [rng.choice(g) for _, g in sorted(groups.items())]; near_dup_dropped = sum(len(g) - 1 for g in groups.values())
    for proj in TRAIN_PROJECTS:
        pr = sorted([r for r in rows if r['meta']['project'] == proj], key=lambda r: r['id'])
        by = defaultdict(list)
        for r in pr: by[r['label']].append(r)
        take = allocate({l: len(v) for l, v in by.items()})
        sel = []
        for l in LABELS:
            if take.get(l): sel += rng.sample(by[l], take[l])
        assert len(sel) <= CAP and all(c <= math.floor(len(sel) * MAX_SHARE) for c in Counter(r['label'] for r in sel).values())
        rep[proj] = dict(labeled=len(pr), labeled_dist=dict(Counter(r['label'] for r in pr)), selected=len(sel), selected_dist=dict(Counter(r['label'] for r in sel)))
        chosen += sorted(sel, key=lambda r: r['id'])
    rep['near_duplicate_backend_variants_dropped'] = near_dup_dropped
    dump(OUT / 'train_v4_selected.jsonl', chosen)
    (OUT / 'select_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end')
    print(json.dumps(rep, ensure_ascii=False))


# ---------- review sheets ----------
def permalink(m):
    locs = m.get('source_locations') or []
    return '\n'.join(f"{m['repository']}/blob/{m['commit']}/{x['file']}#L{x.get('start_line', 1)}-L{x.get('end_line', x.get('start_line', 1))}" for x in locs)


def write_sheet(path, title, header, rows, widths, label_col, defs):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation
    wb = Workbook(); ws = wb.active; ws.title = title; ws.append(header)
    for c in ws[1]: c.font = Font(bold=True); c.fill = PatternFill('solid', fgColor='DDEBF7'); c.alignment = Alignment(wrap_text=True, vertical='top')
    for r in rows: ws.append(r)
    for i, w in enumerate(widths, 1): ws.column_dimensions[ws.cell(1, i).column_letter].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    dv = DataValidation(type='list', formula1='"' + ','.join(LABELS) + '"', allow_blank=True); ws.add_data_validation(dv)
    col = ws.cell(1, label_col).column_letter; dv.add(f'{col}2:{col}{len(rows) + 1}')
    ws.freeze_panes = 'C2'; ws.auto_filter.ref = ws.dimensions
    d = wb.create_sheet('라벨 정의'); d.column_dimensions['A'].width = 140
    for line in defs.splitlines(): d.append([line])
    path.parent.mkdir(parents=True, exist_ok=True); wb.save(path)


def sheets(args):
    guard('start'); system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    defs = '프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip() + '\n\nBLADE 규약: 인가 검사가 빠졌어도 경로·스키마·수정 커밋으로 의도된 정책이 드러나면 그 정책을 label로 한다. membership_required = 요청 대상 그룹·팀의 구성원 관계(구독·등급 아님).'
    # train: label-stratified 20% (ceil per label), seed 42
    sel = rd(OUT / 'train_v4_selected.jsonl'); rng = random.Random(SEED); sample = []
    for proj in TRAIN_PROJECTS:
        for l in LABELS:
            pool = sorted([r for r in sel if r['meta']['project'] == proj and r['label'] == l], key=lambda r: r['id'])
            if pool: sample += rng.sample(pool, max(1, math.ceil(len(pool) * REVIEW_SHARE)))
    rows = [[r['id'], r['meta']['project'], r['method'], r['path'], r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['controller_text'], permalink(r['meta']),
             r['label'], r.get('confidence'), r.get('rationale'), '', '', ''] for r in sample]
    write_sheet(REVIEW / 'v4_train_review.xlsx', 'v4_train_review', ['id', 'project', 'method', 'path', 'auth_summary(추출 요약)', 'permission_doc(문서 권한 문구)', 'controller_text', 'source permalink',
                'LLM label', 'confidence', 'LLM rationale', '검수 label', '검수 사유', '검수자'], rows, [26, 12, 8, 40, 40, 40, 70, 40, 18, 9, 50, 18, 40, 10], 12, defs)
    # extra tab: manual records left out by the 50% cap (labeler held back 66%); lets the reviewer judge whether the holds are real
    from openpyxl import load_workbook
    from openpyxl.styles import Alignment, Font
    sel_ids = {r['id'] for r in sel}; labeled = rd(OUT / 'train_v4_labeled_v301.jsonl'); extra = []
    for proj, n in (('label_studio', 20), ('zulip', 10)):
        pool = sorted([r for r in labeled if r['meta']['project'] == proj and r['label'] == 'manual_review_required' and r['id'] not in sel_ids], key=lambda r: r['id'])
        extra += rng.sample(pool, min(n, len(pool)))
    wb = load_workbook(REVIEW / 'v4_train_review.xlsx'); ws = wb.create_sheet('선정 제외 manual 표본', 1)
    ws.append(['id', 'project', 'method', 'path', 'auth_summary(추출 요약)', 'permission_doc(문서 권한 문구)', 'controller_text', 'source permalink', 'LLM label', 'confidence', 'LLM rationale', '검수 label', '검수 사유', '검수자'])
    for c in ws[1]: c.font = Font(bold=True)
    for r in extra: ws.append([r['id'], r['meta']['project'], r['method'], r['path'], r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['controller_text'], permalink(r['meta']), r['label'], r.get('confidence'), r.get('rationale'), '', '', ''])
    for row in ws.iter_rows(min_row=2):
        for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    for col, w in zip('ABCDEFGHIJKLMN', [26, 12, 8, 40, 40, 40, 70, 40, 18, 9, 50, 18, 40, 10]): ws.column_dimensions[col].width = w
    wb.save(REVIEW / 'v4_train_review.xlsx')
    # test: every record
    test = rd(OUT / 'test_v31_supp_candidates.jsonl')
    ev = lambda m: '\n'.join(f"[{e.get('type')}] {e.get('location', '')}\n{e.get('text', '')}" for e in m.get('evidence') or [])
    rows = [[r['id'], r['meta']['project'], r['service'], r['method'], r['path'], 'Y' if r['meta'].get('known_vulnerable') else '', r['meta'].get('advisory') or '', r['meta'].get('fix_commit') or '',
             r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['meta'].get('draft_label'), r['meta'].get('draft_confidence'), r['meta'].get('draft_reason', ''), ev(r['meta']),
             r['controller_text'], permalink(r['meta']), '', '', '', ''] for r in test]
    write_sheet(REVIEW / 'test_v31_supp_review.xlsx', 'test_v31_supp_review', ['id', 'project', 'service', 'method', 'path', 'known_vulnerable', 'advisory', 'fix_commit', 'auth_summary',
                'permission_doc', '초안 label', '초안 confidence', '초안 근거 설명', '근거(문서·코드 줄·advisory·커밋)', 'controller_text(입력 코드)', 'source permalink', '확정 label', '확정 근거', '검수자', '비고'], rows,
                [26, 12, 12, 8, 40, 8, 26, 30, 40, 36, 18, 9, 50, 60, 70, 40, 18, 40, 10, 20], 17, defs)
    (OUT / 'sheets_report.json').write_text(json.dumps(dict(train_sample=len(sample), train_sample_dist={p: dict(Counter(r['label'] for r in sample if r['meta']['project'] == p)) for p in TRAIN_PROJECTS},
                                                      train_sample_ids=[r['id'] for r in sample], excluded_manual_sample_ids=[r['id'] for r in extra], test_rows=len(test)), ensure_ascii=False, indent=1), encoding='utf-8')
    guard('end'); print('train sample', len(sample), 'test rows', len(test))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('step', choices=['assemble', 'label', 'select', 'sheets'])
    ap.add_argument('--execute', action='store_true'); ap.add_argument('--concurrency', type=int, default=4); a = ap.parse_args()
    if a.step == 'label':
        if not a.execute: raise SystemExit('pass --execute (gpt-4o-mini labeling of data-v4 train candidates, user request 2026-10-27)')
        asyncio.run(label_run(a))
    else: dict(assemble=assemble, select=select, sheets=sheets)[a.step](a)
