"""data-v7 build (AGENTS.md "작업 data-v7", user decision 2026-11-07, option B + two evaluation sets moved into training). No model inference, no LLM API, test_v6 never read.

Inputs (frozen, hashes asserted, read only): data-v6d processed + SFT, data_v5 test inputs (test_v30 / test_v31_supp / test_v5 oas_code_user), test_v31_supp.jsonl + test_v5.jsonl (confirmed labels + meta.evidence),
  prompt v3.0.1, re-judgement key + judgements (datasets/blade/processed/data_v7/rejudge/).
Rules:
  1. 615 LLM-labelled rows: apply the re-judged label. OAS-only rows that newly became manual (label_from != manual, label_to == manual) are removed from train AND val and kept in
     data_v7/train_v7_oas_manual_pool.jsonl (option B as computed in stop2_options.json: 256 rows = train 236 + val 20). The 10 rule-labelled audit rows are NOT applied (separate list).
  2. Rows whose label changed (and stay in the set): rationale rewritten in SFT style from the judge's quoted evidence + the label judgement clause (rule_label_v5 JUDGE/TEMPLATE wording),
     no rule IDs / file paths / review meta. Asserted (HOLD in concrete 0, META 0, FILEPATH 0, label named in rationale).
  3. test_v31_supp 222 + test_v5 283 → train (not val). user = the set's oas_code_user (byte-identical to the frozen inputs), assistant = {label (confirmed), confidence 0.9, rationale, evidence_fields}.
     rationale = "description: 핸들러 코드의 <identifiers from meta.auth_summary that occur in the input, or a code evidence quote that occurs in the input> — TEMPLATE[label]; 판단: JUDGE[label]".
     Only tokens that literally occur in the user input are used. Rows over 4096 tokens are excluded and counted.
  4. test_v30 is never added. val = data-v6d val with the re-judged labels applied (and the newly-manual OAS rows removed).
  5. Human-check sheet review/data_v7_human_check.xlsx: all changed rows kept in the set (gitea 21 + OAS 24), 10% blind sample of the unchanged LLM rows, 10% rationale sample of the 505 added rows (seed 42).
Outputs: processed train_v7/val_v7, training/lora/data_v7/{train_sft_v7, val_sft_v7, test_v30_inputs, policy_label_v3.0.1.md, data_v7_hashes.json}, data_v7/train_v7_oas_manual_pool.jsonl,
  reports/data_v7/{freeze_report.json, v7_changes.jsonl, added_rows_rationale.jsonl, human_check_key.json, stop5_build_report.md}."""
from __future__ import annotations
import glob, hashlib, json, random, re, shutil, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
P = ROOT / 'datasets/blade/processed'; D5 = ROOT / 'training/lora/data_v5'; D6 = ROOT / 'training/lora/data_v6d'; D7 = ROOT / 'training/lora/data_v7'; RJ = P / 'data_v7/rejudge'; OUT = ROOT / 'reports/data_v7'
FROZEN = {
    P / 'train_v6d.jsonl': 'aed2b275a76fa684e426a656fb04b1c934a29bc987f45a146fe1c244ced4d372', P / 'val_v6d.jsonl': '159e01780eb2d8aa1710146d2c06533c20c81920a828a60b889ec6db221361cf',
    D6 / 'train_sft_v6d.jsonl': '63c1768949a0e8c7f0747712c6a55e4fb492e1d03baeddfa111884f31ff65b98', D6 / 'val_sft_v6d.jsonl': '1a421c836032ff3c611f3a74380b519374393deb44519c1772db8049d7d671ee',
    D6 / 'data_v6d_hashes.json': '82efda868e7bde511d0838e10bf0e8a5cc3e6aae577c68b15fcbf370a9d94b53',
    D5 / 'test_v30_inputs.jsonl': 'd65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a', D5 / 'test_v31_supp_inputs.jsonl': '97e618e770bbf9950d6846869901819db36fce486d8999d69eb73e286e2a056c',
    D5 / 'test_v5_inputs.jsonl': '9103cd3d5276ab425f577a2866291bf8e27e7a06a18bd725701989673dbe5d82', D5 / 'policy_label_v3.0.1.md': 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef',
    P / 'data_v4/test_v31_supp.jsonl': '803d914902c7ca2042fd15d4a7852d42e71828e58d4ae4d3ac791fb868e63395', P / 'test_v5.jsonl': '7b8e4a940967ec474e0d5dbf6dcdbd6b7e04be439599c2a684664d6b9393fd9c',
    P / 'data_v5/test_v5_manifest.json': '57fd384f46e89e905209e627a7ff7fb9f312e22a7bed222639e91a80bd05fccd',
}
LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
MAX_SEQ = 4096; SEED = 42; REVIEWER = 'Claude(AI)'
HOLD = re.compile(r'no concrete label|pending review|manual|cannot determine|cannot be determined|not expressible|보류|판단할 수 없|단일 라벨로 표현되지|확인되지 않아|label이 없|알 수 없', re.I)
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|\bG[1-8]\b|검수|candidates\.jsonl|rule_label|auth_checks|초안|확신도|C1|C2|advisory|GHSA|취약')
FILEPATH = re.compile(r'(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java|ya?ml)|\.\w+:\d+')
TEMPLATE = {'owner_match': '처리 대상이 요청자 본인으로 고정되어 있어', 'role_required': '역할·권한 검사가 접근 조건이라', 'membership_required': '대상 방·그룹·프로젝트의 구성원 행을 조회해 허용하므로',
            'tenant_match': '자원을 요청자의 활성 조직 범위로 한정하므로', 'owner_or_admin': '소유자 본인 또는 권한 보유자만 통과하는 조건이라', 'public': '인증·권한 검사 없이 익명 호출을 허용하므로', 'manual_review_required': '접근 조건이 하나로 정해지지 않아'}
JUDGE = {'owner_match': '소유자 본인만 허용하는 조건이므로 owner_match', 'role_required': '특정 역할 보유가 실제 접근 조건이므로 role_required', 'public': '인증 요구가 없으므로 public 선택',
         'membership_required': '구성원 여부가 실제 접근 조건이므로 membership_required', 'owner_or_admin': '소유자 또는 관리자 조건이므로 owner_or_admin',
         'tenant_match': '요청자의 tenant와 대상 자원의 tenant가 일치해야 하므로 tenant_match', 'manual_review_required': '접근 조건이 확정되지 않아 보류'}
OAS_TEMPLATE = {'owner_match': '설명이 처리 대상을 인증 사용자 본인으로 고정하고 있어', 'role_required': '설명이 특정 역할·권한 보유를 조건으로 명시하고 있어', 'membership_required': '설명이 대상 그룹의 구성원일 것을 조건으로 명시하고 있어',
                'tenant_match': '설명이 요청자 계정·조직 범위로 자원을 한정하고 있어', 'owner_or_admin': '설명이 소유자 또는 관리자만 허용함을 명시하고 있어', 'public': '인증 없이 호출 가능함이 명시되어 있어', 'manual_review_required': '설명만으로는 요청자와 대상의 관계나 접근 조건이 확정되지 않아'}
IDENT = re.compile(r"@?[A-Za-z_][\w.]*\(|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+|[A-Za-z]*_\w+|\b[a-z]+[A-Z]\w*\b|\b[A-Z][a-z]+[A-Z]\w*\b|'[a-z][\w:.*-]*'")
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
norm = lambda s: re.sub(r'\s+', ' ', s or '').strip()


def tokenizer():
    from tokenizers import Tokenizer
    snap = sorted(glob.glob(str(Path.home() / '.cache/huggingface/hub/models--unsloth--Qwen2.5-7B-Instruct-bnb-4bit/snapshots/*')))[0]
    return Tokenizer.from_file(snap + '/tokenizer.json'), sha(snap + '/tokenizer.json')


def ntok(tok, system, user, assistant): return len(tok.encode(f'<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n{assistant}<|im_end|>\n').ids)


def clean(s):
    t = norm(s); t = FILEPATH.sub('', t); t = re.sub(r'[`"]', '', t); t = re.sub(r'\s*\(\s*\)', '()', t); return norm(t)


def check_rationale(label, rat):
    bad = []
    if label != MANUAL and HOLD.search(rat): bad.append('hold_in_concrete')
    if META.search(rat): bad.append('meta')
    if FILEPATH.search(rat): bad.append('filepath')
    if label != MANUAL and label not in rat: bad.append('label_missing')
    return bad


def rationale_from_judge(kind, label, evidence):
    ev = clean(evidence)[:160]
    if kind == 'oas': return f'description: {ev} — {OAS_TEMPLATE[label]}; 판단: {JUDGE[label]}' if ev else f'description: {OAS_TEMPLATE[label]}; 판단: {JUDGE[label]}'
    return f'description: 핸들러 코드의 {ev} — {TEMPLATE[label]}; 판단: {JUDGE[label]}' if ev else f'description: 핸들러 코드의 접근 검사 — {TEMPLATE[label]}; 판단: {JUDGE[label]}'


def rationale_from_test_meta(label, meta, user):
    """Build the rationale only from tokens that literally occur in the user input: identifiers of meta.auth_summary, else a code evidence quote."""
    u = norm(user); names = []
    for m in IDENT.findall(meta.get('auth_summary') or ''):
        m = m.rstrip('(').strip('.').strip("'")
        if len(m) >= 3 and m in user and m not in names and not FILEPATH.search(m) and '/' not in m: names.append(m)
        if len(names) >= 4: break
    quote = ''
    for e in meta.get('evidence') or []:
        if e.get('type') == 'code' and norm(e.get('text')) and norm(e['text']) in u: quote = norm(e['text'])[:90]; break
    basis = ', '.join(names) if names else quote
    src = 'auth_summary_idents' if names else 'evidence_quote' if quote else 'generic'
    rat = f'description: 핸들러 코드의 {clean(basis)} — {TEMPLATE[label]}; 판단: {JUDGE[label]}' if basis else f'description: 핸들러 코드의 접근 검사 — {TEMPLATE[label]}; 판단: {JUDGE[label]}'
    return rat, src


def main():
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'
    gen6 = json.load(open(D6 / 'data_v6d_hashes.json', encoding='utf-8'))['generated']
    for n, h in gen6.items(): assert sha(D6 / n) == h, n
    tok, tok_sha = tokenizer(); system = (D5 / 'policy_label_v3.0.1.md').read_text(encoding='utf-8')
    key = json.load(open(RJ / 'current_labels_key.json', encoding='utf-8')); guide_sha = sha(RJ / 'REJUDGE_GUIDE.md')
    J = {}
    for f in sorted((RJ / 'out').glob('*.jsonl')):
        for r in rd(f): assert r['id'] in key and r['label'] in LABELS and r['id'] not in J; J[r['id']] = dict(r, chunk=f.stem)
    assert all(i in J for i in key), 'judgement missing'
    sft = {s: rd(D6 / f'{s}_sft_v6d.jsonl') for s in ('train', 'val')}; sft_lines = {s: [l for l in open(D6 / f'{s}_sft_v6d.jsonl', encoding='utf-8').read().split('\n') if l] for s in ('train', 'val')}
    recs = {s: rd(P / f'{s}_v6d.jsonl') for s in ('train', 'val')}; rec_by_id = {r['id']: r for s in recs for r in recs[s]}
    for s in sft: assert len(sft[s]) == len(sft_lines[s])

    # ---- 1. apply re-judgement to the 615 LLM rows -------------------------------------------------------------
    llm = {i for i in key if key[i]['group'] == 'llm'}; assert len(llm) == 615
    drop = {i for i in llm if key[i]['kind'] == 'oas' and key[i]['label'] != MANUAL and J[i]['label'] == MANUAL}; assert len(drop) == 256, len(drop)
    changes = {}
    for i in sorted(llm):   # deterministic order (v7_changes.jsonl / sheet rows)
        if i in drop or J[i]['label'] == key[i]['label']: continue
        rat = rationale_from_judge(key[i]['kind'], J[i]['label'], J[i].get('evidence') or ''); bad = check_rationale(J[i]['label'], rat)
        if bad: rat = rationale_from_judge(key[i]['kind'], J[i]['label'], ''); bad = check_rationale(J[i]['label'], rat)   # evidence quote itself contained a forbidden token: fall back to the generic clause
        assert not bad, (i, bad, rat)
        changes[i] = dict(id=i, kind=key[i]['kind'], project=key[i]['project'], service=key[i]['service'], split=key[i]['split'], label_from=key[i]['label'], label_to=J[i]['label'], confidence=J[i]['confidence'], rule=J[i].get('rule'),
                          evidence=J[i].get('evidence'), note=J[i].get('note'), rationale_from=key[i]['rationale'], rationale_to=rat, reviewer=REVIEWER, chunk=J[i]['chunk'])
    assert len(changes) == 45 and Counter(c['kind'] for c in changes.values()) == Counter(code=21, oas=24), Counter(c['kind'] for c in changes.values())
    with open(OUT / 'v7_changes.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for c in changes.values(): f.write(json.dumps(c, ensure_ascii=False) + '\n')
    not_applied = [dict(id=i, label_current=key[i]['label'], label_judged=J[i]['label'], rule=J[i].get('rule'), note=J[i].get('note')) for i in key if key[i]['group'] == 'audit_rule']
    with open(OUT / 'audit_rule_rows_not_applied.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for r in not_applied: f.write(json.dumps(r, ensure_ascii=False) + '\n')

    # ---- 2. base rows (v6d minus drop, labels/rationale updated) ----------------------------------------------------
    base_sft = {s: [] for s in sft}; base_rec = {s: [] for s in sft}; pool = []; kept_lines = 0
    for s in sft:
        for r, line in zip(sft[s], sft_lines[s]):
            rec = rec_by_id[r['id']]   # processed has 4 extra rows (>4096 tokens, not in SFT); align by id
            if r['id'] in drop:
                rec2 = json.loads(json.dumps(rec, ensure_ascii=False)); rec2['meta']['v7_rejudge'] = dict(label_from=key[r['id']]['label'], label_to=MANUAL, rule=J[r['id']].get('rule'), evidence=J[r['id']].get('evidence'), note=J[r['id']].get('note'), reviewer=REVIEWER, split_from=s, excluded='option B: OAS-only newly manual')
                rec2['label'] = MANUAL; pool.append(rec2); continue
            c = changes.get(r['id'])
            if not c: base_sft[s].append(line); base_rec[s].append(rec); kept_lines += 1; continue
            a = json.loads(r['assistant']); a['label'] = c['label_to']; a['rationale'] = c['rationale_to']; assert list(a) == ['label', 'confidence', 'rationale', 'evidence_fields']
            r2 = dict(r); r2['label'] = c['label_to']; r2['assistant'] = json.dumps(a, ensure_ascii=False); r2['rationale_source'] = 'rejudge_v7'; r2['tokens'] = ntok(tok, system, r2['user'], r2['assistant']); assert r2['tokens'] <= MAX_SEQ
            base_sft[s].append(json.dumps(r2, ensure_ascii=False))
            rec2 = json.loads(json.dumps(rec, ensure_ascii=False)); rec2['label'] = c['label_to']; rec2['rationale'] = c['rationale_to']; rec2['meta']['v7_rejudge'] = dict(label_from=c['label_from'], label_to=c['label_to'], rule=c['rule'], evidence=c['evidence'], reviewer=REVIEWER)
            base_rec[s].append(rec2)
    assert len(pool) == 256 and len(base_sft['train']) == 1274 - 236 and len(base_sft['val']) == 179 - 20

    # ---- 3. added rows: test_v31_supp + test_v5 -> train ------------------------------------------------------------
    added_sft = []; added_rec = []; added_log = []; over = []
    for setname, recfile, inpfile, src_tag in (('test_v31_supp', P / 'data_v4/test_v31_supp.jsonl', D5 / 'test_v31_supp_inputs.jsonl', 'test_v31_supp'), ('test_v5', P / 'test_v5.jsonl', D5 / 'test_v5_inputs.jsonl', 'test_v5')):
        R = {r['id']: r for r in rd(recfile)}; I = {r['id']: r for r in rd(inpfile)}; assert set(R) == set(I)
        for i in sorted(R):
            rec, inp = R[i], I[i]; assert rec['label'] == inp['label'] and rec['label'] in LABELS
            user = inp['oas_code_user']; rat, how = rationale_from_test_meta(rec['label'], rec['meta'], user); bad = check_rationale(rec['label'], rat); assert not bad, (i, bad, rat)
            a = {'label': rec['label'], 'confidence': 0.9, 'rationale': rat, 'evidence_fields': ['description', 'path_params'] if rec.get('path') and '{' in rec['path'] else ['description']}
            asst = json.dumps(a, ensure_ascii=False); n = ntok(tok, system, user, asst)
            row = dict(id=i, condition='oas_code', label=rec['label'], source=inp.get('source'), security_state=inp.get('security_state'), user=user, assistant=asst, rationale_source=f'{src_tag}_confirmed_label+template_v7', tokens=n, split='train')
            added_log.append(dict(id=i, set=setname, project=rec['meta'].get('project'), method=rec['method'], path=rec['path'], label=rec['label'], rationale=rat, basis=how, tokens=n, over_4096=n > MAX_SEQ, auth_summary=rec['meta'].get('auth_summary'), label_status=rec['meta'].get('label_status'), reviewer=rec['meta'].get('reviewer')))
            if n > MAX_SEQ: over.append(i); continue
            added_sft.append(json.dumps({k: v for k, v in row.items() if k != 'split'}, ensure_ascii=False))
            rec2 = json.loads(json.dumps(rec, ensure_ascii=False)); rec2.update(rationale=rat, confidence=0.9, evidence_fields=a['evidence_fields'], prompt_version='policy-label-v3.0.1')
            rec2['meta'].update(split='train', label_source=f'{src_tag}_confirmed', data_version_origin=rec2['meta'].get('data_version'), data_version='data-v7', rationale_basis=how); added_rec.append(rec2)
    with open(OUT / 'added_rows_rationale.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for r in added_log: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    assert len(added_log) == 505

    # ---- 4. write processed / SFT / pool / copies / hashes --------------------------------------------------------
    D7.mkdir(parents=True, exist_ok=True); (P / 'data_v7').mkdir(exist_ok=True)
    train_sft_lines = base_sft['train'] + added_sft; val_sft_lines = base_sft['val']
    (D7 / 'train_sft_v7.jsonl').write_text('\n'.join(train_sft_lines) + '\n', encoding='utf-8', newline='\n'); (D7 / 'val_sft_v7.jsonl').write_text('\n'.join(val_sft_lines) + '\n', encoding='utf-8', newline='\n')
    for s, rows in (('train', base_rec['train'] + added_rec), ('val', base_rec['val'])):
        with open(P / f'{s}_v7.jsonl', 'w', encoding='utf-8', newline='\n') as f:
            for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    with open(P / 'data_v7/train_v7_oas_manual_pool.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for r in pool: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    for n in ('test_v30_inputs.jsonl', 'policy_label_v3.0.1.md'): shutil.copyfile(D5 / n, D7 / n)
    # integrity
    tr = rd(D7 / 'train_sft_v7.jsonl'); va = rd(D7 / 'val_sft_v7.jsonl'); allrows = tr + va
    assert len(tr) == 1038 + 505 - len(over) and len(va) == 159
    ids = [r['id'] for r in allrows]; assert len(ids) == len(set(ids))
    v6d_users = {r['id']: r['user'] for s in sft for r in sft[s]}; assert all(r['user'] == v6d_users[r['id']] for r in allrows if r['id'] in v6d_users)
    I5 = {r['id']: r['oas_code_user'] for r in rd(D5 / 'test_v5_inputs.jsonl')}; I4 = {r['id']: r['oas_code_user'] for r in rd(D5 / 'test_v31_supp_inputs.jsonl')}
    assert all(r['user'] == (I5.get(r['id']) or I4.get(r['id'])) for r in tr if r['id'] not in v6d_users)
    assert all(json.loads(r['assistant'])['label'] == r['label'] for r in allrows) and all(list(json.loads(r['assistant'])) == ['label', 'confidence', 'rationale', 'evidence_fields'] for r in allrows)
    t30 = {r['id'] for r in rd(D5 / 'test_v30_inputs.jsonl')}; assert not (t30 & set(ids)), 'test_v30 leaked into training'
    recount = {r['id']: ntok(tok, system, r['user'], r['assistant']) for r in allrows}; assert max(recount.values()) <= MAX_SEQ
    full = dict(hold_in_concrete=[r['id'] for r in allrows if r['label'] != MANUAL and HOLD.search(json.loads(r['assistant'])['rationale'])], meta=[r['id'] for r in allrows if META.search(json.loads(r['assistant'])['rationale'])], filepath=[r['id'] for r in allrows if FILEPATH.search(json.loads(r['assistant'])['rationale'])])
    full_v6d = dict(hold_in_concrete=[r['id'] for s in sft for r in sft[s] if r['label'] != MANUAL and HOLD.search(json.loads(r['assistant'])['rationale'])], meta=[r['id'] for s in sft for r in sft[s] if META.search(json.loads(r['assistant'])['rationale'])], filepath=[r['id'] for s in sft for r in sft[s] if FILEPATH.search(json.loads(r['assistant'])['rationale'])])
    new_ids = set(ids) - set(v6d_users); assert not [i for i in full['hold_in_concrete'] if i in new_ids or i in changes] and not [i for i in full['meta'] if i in new_ids or i in changes] and not [i for i in full['filepath'] if i in new_ids or i in changes], 'new/changed rows must be clean'
    gen = {n: sha(D7 / n) for n in ('train_sft_v7.jsonl', 'val_sft_v7.jsonl', 'test_v30_inputs.jsonl', 'policy_label_v3.0.1.md')}
    dist = lambda rows: dict(n=len(rows), counts={l: sum(r['label'] == l for r in rows) for l in LABELS}, manual_ratio=round(sum(r['label'] == MANUAL for r in rows) / len(rows), 4))
    def proj(r):
        i = r['id']
        if i.startswith(('v4t-', 'v5t-', 'v4-', 'v5-')): return i.split('-')[1]
        if i.startswith(('v3s1-', 'v3s1b-')): return 'data_v3_pairs'
        if i.startswith('gitea:'): return 'gitea'
        if i.startswith('apisguru:'): return 'apisguru'
        return 'synthetic'
    by_proj = Counter(proj(r) for r in tr)
    hashes = dict(data_version='data-v7', note='data-v6d SFT rows with the 615 LLM-labelled rows re-judged (AI, REJUDGE_GUIDE) — 45 label changes applied with template rationale, 256 OAS-only newly-manual rows removed to train_v7_oas_manual_pool.jsonl (option B, train 236 + val 20) — '
                  'plus test_v31_supp 222 + test_v5 283 (confirmed labels, template rationale from meta.auth_summary identifiers / code evidence present in the input) appended to train. test_v30 never added. User inputs byte-identical to the frozen sources. Prompt policy_label_v3.0.1.md (frozen). Evaluation of data-v7 models must not use test_v5 / test_v31_supp.',
                  sources={str(p.relative_to(ROOT)).replace('\\', '/'): h for p, h in FROZEN.items()}, rejudge=dict(guide_sha256=guide_sha, key_sha256=sha(RJ / 'current_labels_key.json'), outputs={f.name: sha(f) for f in sorted((RJ / 'out').glob('*.jsonl'))}),
                  generated=gen, counts=dict(train=len(tr), val=len(va), pool=len(pool), added=len(added_sft), added_over_4096=len(over)), labels=dict(train=dist(tr)['counts'], val=dist(va)['counts']), max_seq_len=MAX_SEQ,
                  tokenizer=dict(method='tokenizers + manual Qwen2.5 chat template', tokenizer_json_sha256=tok_sha), format='system=prompt v3.0.1; user="Return JSON.\\n"+payload; assistant=JSON {label, confidence, rationale, evidence_fields}')
    (D7 / 'data_v7_hashes.json').write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')

    # ---- 5. human-check sheet --------------------------------------------------------------------------------------
    rnd = random.Random(SEED); unchanged = sorted(i for i in llm if i not in drop and i not in changes); blind = rnd.sample(unchanged, round(len(unchanged) * 0.10))
    rnd2 = random.Random(SEED); added_ok = [r for r in added_log if not r['over_4096']]; rat_sample = rnd2.sample(added_ok, round(len(added_ok) * 0.10))
    import openpyxl
    from openpyxl.styles import Alignment, Font
    wb = openpyxl.Workbook(); ws = wb.active; ws.title = '안내'
    for l in ['data-v7 사람 확인 시트 (2026-11-07). 커밋 금지. 검수자 A/B/C 균등 배정(열 "검수자").', '시트 1 변경_확인: 재판정으로 label이 바뀌어 학습에 들어가는 행 45(gitea 코드 21 + OAS 24). "확정 label"에 7종 중 하나를 적는다(비우면 새 label 수용).',
              '시트 2 블라인드_안바뀐행: 라벨이 바뀌지 않은 LLM 행 314건의 10%(31). 현재 label은 숨김(정답키 reports/data_v7/human_check_key.json). 입력만 보고 "확정 label"을 적는다.',
              '시트 3 추가행_rationale: test_v31_supp·test_v5에서 학습에 추가된 505행의 10%(51). 생성된 rationale이 입력 근거만 쓰고 label과 맞는지 OK/수정으로 표시한다.',
              '판정 기준: G1~G8 + v3.1 정의 + test_v6 보충 규약(datasets/blade/processed/data_v7/rejudge/REJUDGE_GUIDE.md).']: ws.append([l])
    def add_sheet(name, header, rows):
        w = wb.create_sheet(name); w.append(header); [setattr(c, 'font', Font(bold=True)) for c in w[1]]
        for r in rows: w.append(r)
        for col in w.columns: w.column_dimensions[col[0].column_letter].width = 28
        for row in w.iter_rows(min_row=2):
            for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    rv = lambda k: ['A', 'B', 'C'][k % 3]
    add_sheet('변경_확인', ['id', '검수자', 'kind', 'project/service', 'split', '현재 label', '새 label', '재판정 근거(입력 인용)', '재판정 메모', '확신도', '새 rationale', '입력(user)', '확정 label', '확정 근거', '검수 메모'],
              [[c['id'], rv(k), c['kind'], c['service'] or c['project'], c['split'], c['label_from'], c['label_to'], c['evidence'], c['note'], c['confidence'], c['rationale_to'], (v6d_users[c['id']])[:30000], '', '', ''] for k, c in enumerate(changes.values())])
    add_sheet('블라인드_안바뀐행', ['id', '검수자', 'kind', 'project/service', '입력(user)', '확정 label', '확정 근거', '검수 메모'], [[i, rv(k), key[i]['kind'], key[i]['service'] or key[i]['project'], v6d_users[i][:30000], '', '', ''] for k, i in enumerate(blind)])
    add_sheet('추가행_rationale', ['id', '검수자', 'set', 'project', 'method path', 'label(확정)', '생성 rationale', '근거 출처', '입력(user)', '확인(OK/수정)', '수정 rationale', '검수 메모'],
              [[r['id'], rv(k), r['set'], r['project'], f"{r['method']} {r['path']}", r['label'], r['rationale'], r['basis'], (I5.get(r['id']) or I4.get(r['id']))[:30000], '', '', ''] for k, r in enumerate(rat_sample)])
    (ROOT / 'review').mkdir(exist_ok=True); xlsx = ROOT / 'review/data_v7_human_check.xlsx'; wb.save(xlsx)
    json.dump(dict(blind_key={i: key[i]['label'] for i in blind}, blind_judged={i: J[i]['label'] for i in blind}, seed=SEED, n_unchanged=len(unchanged), n_blind=len(blind), n_rationale_sample=len(rat_sample), rationale_sample_ids=[r['id'] for r in rat_sample]), open(OUT / 'human_check_key.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    # ---- 6. freeze report ------------------------------------------------------------------------------------------
    outs = {str(p.relative_to(ROOT)).replace('\\', '/'): dict(sha256=sha(p), rows=len(rd(p)) if p.suffix == '.jsonl' else None) for p in (P / 'train_v7.jsonl', P / 'val_v7.jsonl', D7 / 'train_sft_v7.jsonl', D7 / 'val_sft_v7.jsonl', D7 / 'data_v7_hashes.json', P / 'data_v7/train_v7_oas_manual_pool.jsonl', OUT / 'v7_changes.jsonl', OUT / 'added_rows_rationale.jsonl', OUT / 'audit_rule_rows_not_applied.jsonl', xlsx)}
    rep = dict(train=dist(tr), val=dist(va), v6d=dict(train=dist(sft['train']), val=dist(sft['val'])), pool=dict(n=len(pool), by_split=dict(Counter(r['meta']['v7_rejudge']['split_from'] for r in pool)), label_from=dict(Counter(r['meta']['v7_rejudge']['label_from'] for r in pool))),
               changes=dict(n=len(changes), by_kind=dict(Counter(c['kind'] for c in changes.values())), transitions=dict(Counter(f"{c['label_from']}->{c['label_to']}" for c in changes.values()).most_common()), by_split=dict(Counter(c['split'] for c in changes.values()))),
               added=dict(n_rows=len(added_log), included=len(added_sft), over_4096=over, by_set=dict(Counter(r['set'] for r in added_log if not r['over_4096'])), labels=dict(Counter(r['label'] for r in added_log if not r['over_4096'])), by_project=dict(Counter(r['project'] for r in added_log if not r['over_4096'])),
                          rationale_basis=dict(Counter(r['basis'] for r in added_log if not r['over_4096'])), tokens_max=max(r['tokens'] for r in added_log)),
               train_by_project=dict(by_proj.most_common()), train_by_source=dict(Counter(r['rationale_source'] for r in tr).most_common()), audit_rule_not_applied=len(not_applied),
               integrity=dict(full_set_v7=dict(hold_in_concrete=len(full['hold_in_concrete']), meta=len(full['meta']), filepath=len(full['filepath'])), full_set_v6d={k: len(v) for k, v in full_v6d.items()}, new_changed_rows_clean=True, user_byte_identical=True, test_v30_overlap=0, tokens_max=max(recount.values()), unchanged_v6d_lines_kept=kept_lines),
               human_check=dict(xlsx=str(xlsx.relative_to(ROOT)), changed=len(changes), blind=len(blind), rationale_sample=len(rat_sample), key='reports/data_v7/human_check_key.json'), rejudge=hashes['rejudge'], outputs=outs, hashes_file_sha256=sha(D7 / 'data_v7_hashes.json'), tokenizer_sha256=tok_sha)
    (OUT / 'freeze_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8', newline='\n')
    print(json.dumps({k: rep[k] for k in ('train', 'val', 'pool', 'changes', 'added', 'train_by_project', 'integrity', 'human_check')}, ensure_ascii=False, indent=1)); print('outputs', json.dumps(outs, indent=1)); print('hashes file', rep['hashes_file_sha256'])


if __name__ == '__main__': main()
