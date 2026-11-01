"""data-v5 training additions (task C-3): Dendrite, NodeBB, Taiga extraction candidates (data/raw_v5_train/<project>/candidates.jsonl, auth_checks recorded)
-> records -> code-rule labels (training/data/rule_label_v5.py; no LLM) -> per project <= 150, no label above 50%, target labels first (seed 42)
-> review/v5_train_review.xlsx (label-stratified 20%) [stop point 3] -> after human review: data-v5 = data-v4 + additions, handler-group val split per project,
integrity checks, SFT inputs, hashes [freeze].
Frozen inputs (data-v1..v4, test_v30, test_v31_supp, test_v5 once frozen) are hash-asserted and read only. The test_v5 review sheet and test files are never read for labels
(test keys are used only for the (service, method, path) overlap assert)."""
from __future__ import annotations
import argparse, hashlib, json, math, os, random, re, shutil, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from build_data_v4 import LABELS, CAP, MAX_SHARE, allocate, key, permalink, write_sheet, rd, dump, sha, oas_snippet, security_state
import build_test_v5 as T5
from training.data import rule_label_v5 as RL
RAW = ROOT / 'data/raw_v5_train'; P = ROOT / 'datasets/blade/processed'; D5 = P / 'data_v5'; S4 = ROOT / 'training/lora/data_v4'; S5 = ROOT / 'training/lora/data_v5'; REVIEW = ROOT / 'review'
PROMPT = ROOT / 'training/data/prompts/policy_label_v3.0.1.md'
TRAIN_PROJECTS = ['dendrite', 'nodebb', 'taiga']; TARGET = ['owner_or_admin', 'membership_required']; SEED, REVIEW_SHARE, VAL_SHARE, MAX_SEQ = 42, 0.2, 0.10, 4096
COMMENT_FAMILY = re.compile(r'^/api/v1/history/(epic|userstory|task|issue|wiki)/[{]id[}]/(edit_comment|delete_comment|undelete_comment|comment_versions)$'); COMMENT_KEEP = 2  # 정지 지점 3 결정 4
MANUAL_QUOTA_DIV = 9  # manual = concrete / 9 -> 10% of the additions (정지 지점 3 결정 3)
HOLD = re.compile(r'no concrete label|pending review|manual|cannot determine|cannot be determined|not expressible|보류|판단할 수 없|단일 라벨로 표현되지|확인되지 않아|label이 없|알 수 없', re.I)
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|\bG[1-8]\b|검수|candidates\.jsonl|rule_label|auth_checks')
FILEPATH = re.compile(r'(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java|ya?ml)|\.\w+:\d+')
import build_data_v4 as v4
v4.TARGET = TARGET  # allocate() fills these labels first


def guard(stage): T5.guard(stage)


def to_record(c):
    ident = f"v5-{c['project']}-{hashlib.sha1((c['method'].upper() + ' ' + c['path']).encode()).hexdigest()[:10]}"
    spec = json.loads(oas_snippet(c)); op = spec['paths'][c['path']][c['method'].lower()]
    meta = dict(data_version='data-v5', project=c['project'], repository=c['repository'], commit=c['commit'], tag=c.get('tag'), license=c.get('license'), oas_status=c.get('oas_status'),
                source_locations=c.get('source_locations') or [], auth_summary=c.get('auth_summary', ''), permission_doc=c.get('permission_doc', ''), auth_checks=c.get('auth_checks') or [])
    return dict(id=ident, source='opensource_v5', service=c['service'], method=c['method'].upper(), path=c['path'], label=None, oas_snippet=oas_snippet(c), erd_snippet='',
                security_state=security_state(spec, op), controller_text=(c.get('controller_text') or '').strip(), meta=meta)


def assemble(args):
    guard('start'); D5.mkdir(parents=True, exist_ok=True); seen = T5.existing_keys()
    for r in rd(D5 / 'test_v5_candidates.jsonl'): seen.setdefault(key(r['service'], r['method'], r['path']), 'test_v5_candidates')  # key-only leak check, labels never read
    rep = dict(projects={}, duplicates=[], internal_duplicates=[], missing=[], invalid=[]); recs, keys_here = [], {}
    for proj in TRAIN_PROJECTS:
        f = RAW / proj / 'candidates.jsonl'
        if not f.exists(): rep['missing'].append(proj); continue
        cands = rd(f); kept = 0
        for c in cands:
            assert c['project'] == proj, (proj, c.get('project'))
            if not (c.get('controller_text') or '').strip() or len(c['controller_text']) > 3000 or not c.get('auth_checks'):
                rep['invalid'].append(dict(project=proj, method=c['method'], path=c['path'], text_len=len(c.get('controller_text') or ''), auth_checks=len(c.get('auth_checks') or []))); continue
            k = key(c['service'], c['method'], c['path'])
            if k in seen: rep['duplicates'].append(dict(project=proj, method=c['method'], path=c['path'], matched=seen[k])); continue
            if k in keys_here: rep['internal_duplicates'].append(dict(project=proj, method=c['method'], path=c['path'])); continue
            r = to_record(c); keys_here[k] = r['id']; recs.append(r); kept += 1
        rep['projects'][proj] = dict(candidates=len(cands), kept=kept)
    assert len({r['id'] for r in recs}) == len(recs)
    dump(D5 / 'candidates_train_v5.jsonl', recs); rep['total'] = len(recs)
    (D5 / 'assemble_train_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end')
    print(json.dumps({k: v for k, v in rep.items() if k != 'duplicates'} | dict(duplicates=len(rep['duplicates'])), ensure_ascii=False))


def label_select(args):
    guard('start'); labeled = []
    for c in rd(D5 / 'candidates_train_v5.jsonl'):
        probe = {**c, 'project': c['meta']['project'], 'auth_checks': c['meta']['auth_checks']}
        lab, rule, ev, why = RL.decide(probe); r = dict(c, label=lab)
        r['meta'] = {**c['meta'], 'label_source': 'code_rule_v5', 'rule_v5': rule, 'rule_evidence': ev, 'rule_excluded_reason': why}
        r['rationale'] = RL.rationale(lab, c['meta']['auth_checks']) if lab else None; labeled.append(r)
    dump(D5 / 'train_v5_rule_labeled.jsonl', labeled); ok = [r for r in labeled if r['label']]
    rng = random.Random(SEED); selected, sel_rep = [], {}
    for proj in TRAIN_PROJECTS:
        pr = sorted([r for r in ok if r['meta']['project'] == proj], key=lambda r: r['id']); by = defaultdict(list)
        for r in pr: by[r['label']].append(r)
        take = allocate({l: len(v) for l, v in by.items()}) if pr else {}; sel = []
        for l in LABELS:
            if take.get(l): sel += rng.sample(by[l], take[l])
        assert len(sel) <= CAP and (not sel or max(Counter(r['label'] for r in sel).values()) <= math.floor(len(sel) * MAX_SHARE))
        sel_rep[proj] = dict(candidates=sum(r['meta']['project'] == proj for r in labeled), rule_labeled=len(pr), excluded=dict(Counter((r['meta']['rule_excluded_reason'] or '').split(':')[0] for r in labeled if r['meta']['project'] == proj and not r['label'])),
                             available=dict(Counter(r['label'] for r in pr)), selected=len(sel), selected_dist=dict(Counter(r['label'] for r in sel)))
        selected += sorted(sel, key=lambda r: r['id'])
    # 4. (정지 지점 3 결정) Taiga history comment family (5 resources x same permission expression): keep COMMENT_KEEP per resource (seed 42)
    rng2 = random.Random(SEED); pool = []; fam = defaultdict(list)
    for r in selected:
        m = COMMENT_FAMILY.match(r['path'])
        if m and r['meta']['project'] == 'taiga' and r['label'] == 'owner_or_admin': fam[m.group(1)].append(r)
    keep_ids = set()
    for res in sorted(fam):
        rs = sorted(fam[res], key=lambda r: r['id']); keep_ids |= {r['id'] for r in rng2.sample(rs, min(COMMENT_KEEP, len(rs)))}
    fam_ids = {r['id'] for rs in fam.values() for r in rs}
    for r in selected:
        if r['id'] in fam_ids and r['id'] not in keep_ids: r['meta'] = {**r['meta'], 'pool_reason': 'taiga_comment_family_cap'}; pool.append(r)
    selected = [r for r in selected if r['id'] not in fam_ids or r['id'] in keep_ids]
    # 5. (정지 지점 3 결정) manual quota 10% of the additions (= concrete / MANUAL_QUOTA_DIV, like data-v3b/v4), subtype (rule id) shares kept, largest remainder, seed 42
    rng3 = random.Random(SEED); concrete = [r for r in selected if r['label'] != 'manual_review_required']; manual = [r for r in selected if r['label'] == 'manual_review_required']
    target = round(len(concrete) / MANUAL_QUOTA_DIV); sub = defaultdict(list)
    for r in manual: sub[r['meta']['rule_v5']].append(r)
    exact = {k: target * len(v) / len(manual) for k, v in sub.items()} if manual else {}; quota = {k: math.floor(x) for k, x in exact.items()}
    for k in sorted(exact, key=lambda k: (-(exact[k] - quota[k]), k))[:target - sum(quota.values())]: quota[k] += 1
    keep_manual = set()
    for k in sorted(sub): keep_manual |= {r['id'] for r in rng3.sample(sorted(sub[k], key=lambda r: r['id']), quota[k])}
    for r in manual:
        if r['id'] not in keep_manual: r['meta'] = {**r['meta'], 'pool_reason': 'manual_quota_10pct'}; pool.append(r)
    selected = [r for r in selected if r['label'] != 'manual_review_required' or r['id'] in keep_manual]
    for r in selected + pool: r['meta'] = {**r['meta'], 'license_notice_required': str(r['meta'].get('license') or '').upper().startswith('GPL')}
    for proj in TRAIN_PROJECTS:
        ps = [r for r in selected if r['meta']['project'] == proj]
        assert len(ps) <= CAP and (not ps or max(Counter(r['label'] for r in ps).values()) <= math.floor(len(ps) * MAX_SHARE)), proj
    selected.sort(key=lambda r: r['id']); pool.sort(key=lambda r: r['id'])
    dump(D5 / 'train_v5_selected.jsonl', selected); dump(D5 / 'train_v5_pool.jsonl', pool)
    rep = dict(total=len(labeled), labeled=len(ok), excluded=len(labeled) - len(ok), by_rule=dict(Counter(r['meta']['rule_v5'] for r in ok)), excluded_reasons=dict(Counter(r['meta']['rule_excluded_reason'] for r in labeled if not r['label'])), selection=sel_rep,
               comment_family=dict(total=len(fam_ids), kept=sorted(keep_ids), dropped=sorted(fam_ids - keep_ids)),
               manual_quota=dict(concrete=len(concrete), manual_available=len(manual), target=target, subtype_available={k: len(v) for k, v in sorted(sub.items())}, subtype_quota=dict(sorted(quota.items())), dropped=sorted(r['id'] for r in manual if r['id'] not in keep_manual)),
               pool=len(pool), selected_total=len(selected), selected_dist=dict(Counter(r['label'] for r in selected)), selected_by_project={p: dict(Counter(r['label'] for r in selected if r['meta']['project'] == p)) for p in TRAIN_PROJECTS},
               manual_ratio=round(sum(r['label'] == 'manual_review_required' for r in selected) / len(selected), 4) if selected else 0)
    (D5 / 'label_select_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(rep, ensure_ascii=False, indent=1))


def sheets(args):
    guard('start'); system = PROMPT.read_text(encoding='utf-8')
    defs = '프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip() + '\n\n검수 규약 G1~G8: AGENTS.md data-v4 검수 규약 절(시트 "검수 규약" 탭). 규칙 이름은 training/data/rule_label_v5.py.'
    sel = rd(D5 / 'train_v5_selected.jsonl'); rng = random.Random(SEED); sample = []
    for proj in TRAIN_PROJECTS:
        for l in LABELS:
            pool = sorted([r for r in sel if r['meta']['project'] == proj and r['label'] == l], key=lambda r: r['id'])
            if pool: sample += rng.sample(pool, max(1, math.ceil(len(pool) * REVIEW_SHARE)))
    checks = lambda m: '\n'.join(f"[{c.get('kind')}] {c.get('name', '')} — {c.get('file', '')}:{c.get('line', '')}\n{c.get('text', '')}" for c in m.get('auth_checks') or [])
    rows = [[r['id'], r['meta']['project'], r['method'], r['path'], r['meta'].get('auth_summary', ''), r['meta'].get('permission_doc', ''), r['label'], r['meta']['rule_v5'], checks(r['meta']), r['rationale'],
             r['controller_text'], permalink(r['meta']), '', '', ''] for r in sample]
    write_sheet(REVIEW / 'v5_train_review.xlsx', 'v5_train_review', ['id', 'project', 'method', 'path', 'auth_summary(추출 요약)', 'permission_doc', '규칙 label', '규칙', '인가 검사 목록(kind·함수·줄)', '학습 rationale',
                'controller_text', 'source permalink', '검수 label', '검수 사유', '검수자'], rows, [26, 10, 8, 40, 40, 30, 18, 28, 60, 50, 70, 40, 18, 40, 10], 13, defs)
    from openpyxl import load_workbook
    wb = load_workbook(REVIEW / 'v5_train_review.xlsx'); ws = wb.create_sheet('검수 규약'); ws.column_dimensions['A'].width = 160
    for line in T5.rules_text().splitlines(): ws.append([line])
    wb.save(REVIEW / 'v5_train_review.xlsx')
    rep = dict(selected=len(sel), sample=len(sample), sample_dist={p: dict(Counter(r['label'] for r in sample if r['meta']['project'] == p)) for p in TRAIN_PROJECTS}, sample_ids=[r['id'] for r in sample])
    (D5 / 'sheets_train_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps({k: v for k, v in rep.items() if k != 'sample_ids'}, ensure_ascii=False))


def to_sft(r):
    from training.lora.prepare_lora_inputs import test_record
    rec = test_record(r); target = {'label': r['label'], 'confidence': 0.9, 'rationale': r['rationale'], 'evidence_fields': ['description', 'path_params']}
    return dict(id=r['id'], source='opensource_v5', condition='oas_code', label=r['label'], rationale_source='rule_v5_' + r['meta']['rule_v5'], security_state=rec['security_state'],
                user=rec['oas_code_user'], assistant=json.dumps(target, ensure_ascii=False))


def freeze(args):
    """After human review of review/v5_train_review_reviewed.xlsx ('검수 label'): agreement >= 95% required; then data-v5 = data-v4 + selected additions."""
    from openpyxl import load_workbook
    dry = getattr(args, 'dry_run', False)
    guard('start'); h4 = json.loads((S4 / 'data_v4_hashes.json').read_text(encoding='utf-8'))
    for n, hv in h4['generated'].items(): assert sha(S4 / n) == hv, n
    for n, hv in h4['datasets'].items(): assert sha(P / ('data_v4/' + n if n.startswith('train_v4_rule') else n)) == hv, n
    if (D5 / 'test_v5_manifest.json').exists():
        man5 = json.loads((D5 / 'test_v5_manifest.json').read_text(encoding='utf-8'))
        for rel, hv in man5['sha256'].items(): assert sha(ROOT / rel) == hv, rel
    else:
        # Order change (AGENTS.md 작업 C, user decision 2026-10-31): data-v5 may be frozen before test_v5 because no test_v5 label was ever read here
        # (only the (service, method, path) keys of the candidates, for the overlap assert below). test_v5_inputs.jsonl is then NOT part of this bundle's
        # hash list; run_train.py refuses to predict test_v5 until data_v5/test_v5_manifest.json (its frozen hash) exists.
        man5 = None
    out = dict(train=P / 'train_v5.jsonl', val=P / 'val_v5.jsonl', sft_train=S5 / 'train_sft_v5.jsonl', sft_val=S5 / 'val_sft_v5.jsonl', hashes=S5 / 'data_v5_hashes.json', report=ROOT / 'reports/data_v5/freeze_report.json',
               manifest=D5 / 'train_v5_manifest.json')
    for p in out.values(): assert dry or not p.exists(), f'refusing to overwrite {p}'
    # 1. review agreement: '검수 label' vs the CURRENT rule label (train_v5_rule_labeled.jsonl; the sheet's 규칙 label column predates the 정지 지점 3 rule update).
    #    Rows whose record is now excluded by the rules are listed separately and leave the denominator.
    src = REVIEW / 'v5_train_review_reviewed.xlsx'; ws = load_workbook(src, read_only=True)['v5_train_review']; rows = list(ws.iter_rows(values_only=True)); hd = {n: i for i, n in enumerate(rows[0])}
    cur = {r['id']: r for r in rd(D5 / 'train_v5_rule_labeled.jsonl')}
    reviewed = [(row[hd['id']], (row[hd['규칙 label']] or '').strip(), (row[hd['검수 label']] or '').strip(), (row[hd['검수 사유']] or '').strip()) for row in rows[1:] if row and row[hd['id']]]
    now_excluded = [dict(id=i, sheet_rule=a, review=b, reason=cur[i]['meta']['rule_excluded_reason']) for i, a, b, _ in reviewed if cur[i]['label'] is None]
    done = [(i, cur[i]['label'], b) for i, a, b, _ in reviewed if b and cur[i]['label']]; agree = sum(a == b for _, a, b in done); rate = agree / len(done) if done else 0
    disagreements = [dict(id=i, rule=a, review=b) for i, a, b in done if a != b]
    sheet_agree = sum(a == b for _, a, b, _ in reviewed if b)
    assert rate >= 0.95, f'rule/review agreement {agree}/{len(done)} = {rate:.3f} < 0.95: stop and report; disagreements={disagreements}'
    selected = rd(D5 / 'train_v5_selected.jsonl'); pool = rd(D5 / 'train_v5_pool.jsonl')
    # 2. group split per project by handler (first class/def/func name of the excerpt), ~10% per label (rarest first), never splitting a handler
    rng = random.Random(SEED)
    WRAPPERS = {'MakeAuthAPI', 'MakeAdminAPI', 'MakeExternalAPI', 'MakeHTMLAPI'}  # Dendrite excerpts open with the auth wrapper; group those by the handler's own file instead
    def gkey(r):
        m = re.search(r'^(?:class|def|func(?: \([^)]*\))?) (\w+)|^(?:export )?(?:async )?function (\w+)|^\s*(\w+)\.(?:get|post|put|delete|patch)\(', r['controller_text'], re.M)
        name = next((g for g in (m.groups() if m else ()) if g), None)
        if name in WRAPPERS:
            name = next((l['file'] for l in r['meta'].get('source_locations') or [] if not l['file'].endswith(('httpapi.go', '/routing.go'))), None) or r['path']
        return (r['meta']['project'], name or r['path'])
    v5_train, v5_val = [], []
    for proj in TRAIN_PROJECTS:
        pr = [r for r in selected if r['meta']['project'] == proj]; groups_of = defaultdict(list)
        for r in pr: groups_of[gkey(r)].append(r)
        val_files, cnt = set(), Counter(r['label'] for r in pr)
        for l in sorted(cnt, key=lambda l: (cnt[l], l)):
            want = round(cnt[l] * VAL_SHARE); cand = sorted(g for g, rs in groups_of.items() if any(x['label'] == l for x in rs) and g not in val_files); rng.shuffle(cand)
            for g in cand:
                have = sum(x['label'] == l for f in val_files for x in groups_of[f])
                if have >= want: break
                if sum(x['label'] == l for x in groups_of[g]) + have > max(want, 1) * 2: continue
                val_files.add(g)
        v5_val += [r for r in pr if gkey(r) in val_files]; v5_train += [r for r in pr if gkey(r) not in val_files]
    v5_val.sort(key=lambda r: r['id']); v5_train.sort(key=lambda r: r['id']); assert not ({gkey(r) for r in v5_val} & {gkey(r) for r in v5_train})
    # 3. integrity
    t5c = rd(D5 / 'test_v5_candidates.jsonl'); t5 = rd(P / 'test_v5.jsonl') if (P / 'test_v5.jsonl').exists() else []   # keys only; labels never read
    test_keys = {key(r['service'], r['method'], r['path']) for r in rd(P / 'test_v30.jsonl') + rd(P / 'data_v4/test_v31_supp.jsonl') + t5}
    t5c_keys = {key(r['service'], r['method'], r['path']) for r in t5c}
    checks = dict(hold_in_concrete=[r['id'] for r in selected if r['label'] != 'manual_review_required' and HOLD.search(r['rationale'])], meta_text=[r['id'] for r in selected if META.search(r['rationale'])],
                  file_path=[r['id'] for r in selected if FILEPATH.search(r['rationale'])], test_overlap=[r['id'] for r in selected if key(r['service'], r['method'], r['path']) in test_keys],
                  test_v5_candidate_overlap=[r['id'] for r in selected + pool if key(r['service'], r['method'], r['path']) in t5c_keys])
    assert not any(checks.values()), checks
    # 4. records + SFT (data-v4 SFT rows byte-identical; additions converted; > 4096 tokens excluded)
    if not dry: dump(out['train'], rd(P / 'train_v4.jsonl') + v5_train); dump(out['val'], rd(P / 'val_v4.jsonl') + v5_val)
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained('Qwen/Qwen2.5-7B-Instruct', cache_dir=str(ROOT / '.cache/models')); system = PROMPT.read_text(encoding='utf-8')
    ntok = lambda s: len(tok.apply_chat_template([{'role': 'system', 'content': system}, {'role': 'user', 'content': s['user']}, {'role': 'assistant', 'content': s['assistant']}], tokenize=True))
    over = []
    def conv(rows, split):
        o = []
        for r in rows:
            s = to_sft(r); s['tokens'] = ntok(s)
            if s['tokens'] > MAX_SEQ: over.append(dict(id=r['id'], tokens=s['tokens'], split=split)); continue
            o.append(s)
        return o
    S5.mkdir(parents=True, exist_ok=True); sft_train = rd(S4 / 'train_sft_v4.jsonl') + conv(v5_train, 'train'); sft_val = rd(S4 / 'val_sft_v4.jsonl') + conv(v5_val, 'val')
    m_tr = sum(s['label'] == 'manual_review_required' for s in sft_train)
    split_of = {r['id']: 'train' for r in v5_train} | {r['id']: 'val' for r in v5_val}
    manifest = dict(data_version='data-v5', note='학습 보강분 공개 목록: 코드 본문 없이 id·저장소·커밋·고정 링크·label만. NodeBB(GPL-3.0) 발췌가 든 파일은 .gitignore.',
                    records=[dict(id=r['id'], project=r['meta']['project'], repository=r['meta']['repository'], commit=r['meta']['commit'], tag=r['meta'].get('tag'), license=r['meta'].get('license'),
                                  method=r['method'], path=r['path'], label=r['label'], split=split_of.get(r['id'], 'pool'), permalink=permalink(r['meta'])) for r in selected + pool])
    review_rep = dict(reviewed=len(reviewed), compared=len(done), agree=agree, rate=round(rate, 4), disagreements=disagreements, sheet_column_agree=sheet_agree, now_excluded=now_excluded)
    split_rep = dict(train=len(v5_train), val=len(v5_val), train_dist=dict(Counter(r['label'] for r in v5_train)), val_dist=dict(Counter(r['label'] for r in v5_val)),
                     by_project={p: dict(train=sum(r['meta']['project'] == p for r in v5_train), val=sum(r['meta']['project'] == p for r in v5_val)) for p in TRAIN_PROJECTS})
    if dry:
        rep = dict(dry_run=True, review=review_rep, v5_split=split_rep, sft=dict(train=len(sft_train), val=len(sft_val), manual_train=m_tr, manual_train_ratio=round(m_tr / len(sft_train), 4), over_4096=over), integrity=checks, test_v5_frozen=man5 is not None)
        guard('end'); print(json.dumps(rep, ensure_ascii=False, indent=1)); return
    for p, rows_ in ((out['sft_train'], sft_train), (out['sft_val'], sft_val)):
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            for s in rows_: f.write(json.dumps(s, ensure_ascii=False) + '\n')
    for n in ('test_v30_inputs.jsonl', 'policy_label_v3.0.1.md', 'test_v31_supp_inputs.jsonl'): shutil.copyfile(S4 / n, S5 / n)
    if man5: assert sha(S5 / 'test_v5_inputs.jsonl') == man5['sha256']['training/lora/data_v5/test_v5_inputs.jsonl']
    out['manifest'].write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding='utf-8')
    gen = {n: sha(S5 / n) for n in ('train_sft_v5.jsonl', 'val_sft_v5.jsonl', 'test_v30_inputs.jsonl', 'test_v31_supp_inputs.jsonl', 'policy_label_v3.0.1.md') + (('test_v5_inputs.jsonl',) if man5 else ())}
    hashes = dict(data_version='data-v5', sources={**{n: h4['generated'][n] for n in h4['generated']}, 'train_v4.jsonl': h4['datasets']['train_v4.jsonl'], 'val_v4.jsonl': h4['datasets']['val_v4.jsonl'],
                  **({'test_v5.jsonl': man5['sha256']['datasets/blade/processed/test_v5.jsonl']} if man5 else {}), 'candidates_train_v5.jsonl': sha(D5 / 'candidates_train_v5.jsonl')},
                  test_v5=dict(frozen_at_data_v5_freeze=man5 is not None, note='test_v5_inputs.jsonl is verified by run_train.py against data_v5/test_v5_manifest.json (frozen separately, after this bundle); '
                                                                                'no test_v5 label was read while building data-v5 (candidate keys only: test_v5_candidate_overlap = 0 asserted)'),
                  generated=gen, counts=dict(train=len(sft_train), val=len(sft_val)), format=h4['format'], max_seq_len=MAX_SEQ,
                  datasets={'train_v5_rule_labeled.jsonl': sha(D5 / 'train_v5_rule_labeled.jsonl'), 'train_v5_selected.jsonl': sha(D5 / 'train_v5_selected.jsonl'), 'train_v5_pool.jsonl': sha(D5 / 'train_v5_pool.jsonl'),
                            'train_v5.jsonl': sha(out['train']), 'val_v5.jsonl': sha(out['val']), 'train_v5_manifest.json': sha(out['manifest']), 'rule_label_v5.py': sha(ROOT / 'training/data/rule_label_v5.py'),
                            'v5_train_review_reviewed.xlsx': sha(src)})
    out['hashes'].write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    rep = dict(data_version='data-v5', composition='data-v4 (train_v4 + val_v4) + data-v5 rule-labeled additions (Dendrite, NodeBB, Taiga)', review=review_rep, v5_split=split_rep,
               sft=dict(train=len(sft_train), val=len(sft_val), manual_train=m_tr, manual_train_ratio=round(m_tr / len(sft_train), 4), over_4096=over), integrity=checks, hashes=hashes, hashes_file_sha=sha(out['hashes']))
    out['report'].parent.mkdir(parents=True, exist_ok=True); out['report'].write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8'); guard('end'); print(json.dumps(rep, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('step', choices=['assemble', 'label_select', 'sheets', 'freeze']); ap.add_argument('--dry-run', action='store_true', help='freeze: compute everything, write nothing (test_v5 may be unfrozen)'); a = ap.parse_args()
    dict(assemble=assemble, label_select=label_select, sheets=sheets, freeze=freeze)[a.step](a)
