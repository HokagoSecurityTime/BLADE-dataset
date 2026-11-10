"""작업 C′ / data-v6d — C1 검수 완료본 반영(label) + C2 rationale 반영 + SFT 재생성 + 동결 해시 (학습·추론 없음, test_v6 미사용, 커밋 금지).

입력(해시 확인 후 읽기만): data-v5 processed train/val, SFT train/val, data_v5_hashes.json, test 입력 사본, 프롬프트 v3.0.1,
  검수 완료본 review/c1_relabel_review_reviewed.xlsx(검수자 Claude(AI)), 블라인드 정답키 reports/data_v6d/c1_audit_key.json, C0 행 표 c0_rows.csv.
규칙(사용자 지시 2026-11-05):
  1. 블라인드 불일치율(확정 label ≠ 현재 label)을 코드 행 / OAS-only 행으로 나눠 보고. 사전 기록대로 5% 초과면 한계로 기록(전수 검수는 마감 후). 블라인드 시트의 판정은 데이터에 반영하지 않는다(감사 표본).
  2. OAS-only 행은 현행 label 유지. 검수 메모의 "AI 의견"은 마감 후 APIs.guru OAS 라벨 일괄 점검 후보로 따로 저장.
  3. 확정 label 반영 + 확정 rationale이 있는 행만 rationale 교체(나머지는 SFT 그대로). 합성 tenant AND membership 3건은 영어 rationale 유지.
     정합성 assert: 구체 label에 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, 4096 토큰 이내. user 입력은 data-v5 SFT와 바이트 동일.
  4. data-v6d 동결 해시(training/lora/data_v6d/data_v6d_hashes.json, reports/data_v6d/freeze_report.json).
토큰 수는 tokenizers 라이브러리 + Qwen2.5 chat template 수동 적용으로 계산한다(transformers 미설치). 이 방식은 data_v6a SFT(transformers로 계산) 1,453행과 전부 일치했다.
"""
from __future__ import annotations
import csv, glob, hashlib, json, re, shutil, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from c0_impact_v6d import read_xlsx, sheet_dicts
P = ROOT / 'datasets/blade/processed'; D5 = ROOT / 'training/lora/data_v5'; D6 = ROOT / 'training/lora/data_v6d'; OUT = ROOT / 'reports/data_v6d'
XLSX = ROOT / 'review/c1_relabel_review_reviewed.xlsx'
FROZEN = {
    P / 'train_v5.jsonl': '528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344', P / 'val_v5.jsonl': '43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9',
    D5 / 'train_sft_v5.jsonl': '2351afe93518f6e29c95ab9305a15b5a1cda7bd6e3c6d18bec7e8e3d45c3216b', D5 / 'val_sft_v5.jsonl': '0df4642f439c812d4e7b9f5ca968c89fd966703bfc59229d6f7ea7f83115748f',
    D5 / 'data_v5_hashes.json': '39c302c5fb33d1b1506487678cd15f40cc83ffd59435449522786388554753ac', D5 / 'test_v30_inputs.jsonl': 'd65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a',
    D5 / 'test_v31_supp_inputs.jsonl': '97e618e770bbf9950d6846869901819db36fce486d8999d69eb73e286e2a056c', D5 / 'test_v5_inputs.jsonl': '9103cd3d5276ab425f577a2866291bf8e27e7a06a18bd725701989673dbe5d82',
    P / 'data_v5/test_v5_manifest.json': '57fd384f46e89e905209e627a7ff7fb9f312e22a7bed222639e91a80bd05fccd', D5 / 'policy_label_v3.0.1.md': 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef',
    XLSX: 'd9f8299ff4a514b409e799515ad5e538c1d3810fba2c0ad8d3a492ad5377136e',
}
LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
MAX_SEQ = 4096; REVIEWER = 'Claude(AI)'
# 정합성 규칙(scripts/build_data_v5.py와 동일)
HOLD = re.compile(r'no concrete label|pending review|manual|cannot determine|cannot be determined|not expressible|보류|판단할 수 없|단일 라벨로 표현되지|확인되지 않아|label이 없|알 수 없', re.I)
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|\bG[1-8]\b|검수|candidates\.jsonl|rule_label|auth_checks|초안|확신도|C1|C2')
FILEPATH = re.compile(r'(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java|ya?ml)|\.\w+:\d+')
STRIP_PATH = [re.compile(r'\s*\((?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java)(?::\d+(?:-\d+)?)?\)'), re.compile(r'(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java)(?::\d+(?:-\d+)?)?')]
SYN_TENANT_AND_MEMBER = re.compile(r'share the tenant AND be a member', re.I)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
lines = lambda p: [l for l in open(p, encoding='utf-8').read().split('\n') if l]


def tokenizer():
    from tokenizers import Tokenizer
    snap = sorted(glob.glob(str(Path.home() / '.cache/huggingface/hub/models--unsloth--Qwen2.5-7B-Instruct-bnb-4bit/snapshots/*')))[0]
    return Tokenizer.from_file(snap + '/tokenizer.json'), sha(snap + '/tokenizer.json')


def ntok(tok, system, user, assistant):
    return len(tok.encode(f'<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{user}<|im_end|>\n<|im_start|>assistant\n{assistant}<|im_end|>\n').ids)


def sanitize(s):
    """Remove source-file path references (not part of the model input) and tidy spacing; returns (text, changed)."""
    t = s.strip()
    for rx in STRIP_PATH: t = rx.sub('', t)
    t = re.sub(r'[ \t]+', ' ', t).strip()   # only the path token is removed; code tokens such as AsUser() stay intact
    return t, t != s.strip()


def main():
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'
    tok, tok_sha = tokenizer(); system = (D5 / 'policy_label_v3.0.1.md').read_text(encoding='utf-8')
    X = read_xlsx(XLSX); sheets = {nm: sheet_dicts(rows) for nm, rows in X.items()}
    key = json.load(open(OUT / 'c1_audit_key.json', encoding='utf-8'))['key']
    c0 = {x['id']: x for x in csv.DictReader(open(OUT / 'c0_rows.csv', encoding='utf-8-sig'))}
    recs = {s: rd(P / f'{s}_v5.jsonl') for s in ('train', 'val')}; sft = {s: rd(D5 / f'{s}_sft_v5.jsonl') for s in ('train', 'val')}; sft_lines = {s: lines(D5 / f'{s}_sft_v5.jsonl') for s in ('train', 'val')}
    sft_by_id = {r['id']: (s, r) for s in sft for r in sft[s]}; rec_by_id = {r['id']: (s, r) for s in recs for r in recs[s]}

    # ---- 1. 블라인드 감사 -----------------------------------------------------------------------------------------
    blind = sheets['무작위5%_블라인드']; assert len(blind) == 68 and all(r['id'] in key for r in blind)
    aud = []
    for r in blind:
        fin = (r.get('확정 label') or '').strip(); assert fin in LABELS, (r['id'], fin); cur = key[r['id']]['label_current']; row = c0[r['id']]
        aud.append(dict(id=r['id'], kind='코드' if row['has_code'] == 'Y' else 'OAS-only', source=row['source'], project=row['project'], label_current=cur, label_blind=fin, mismatch=fin != cur,
                        human_review=row['human_review'], confidence_note=(r.get('검수 메모') or '')[:40], evidence=(r.get('확정 근거(코드 줄·설명 문장)') or '')[:600], reviewer=r.get('검수자')))
    def rate(rows): m = sum(x['mismatch'] for x in rows); return dict(n=len(rows), mismatch=m, rate=round(m / len(rows), 4) if rows else None, to_manual=sum(x['mismatch'] and x['label_blind'] == MANUAL for x in rows))
    audit = dict(reviewer=sorted({x['reviewer'] for x in aud}), overall=rate(aud), by_kind={k: rate([x for x in aud if x['kind'] == k]) for k in ('코드', 'OAS-only')}, by_source={k: rate([x for x in aud if x['source'] == k]) for k in sorted({x['source'] for x in aud})},
                 human_reviewed_rows=rate([x for x in aud if x['human_review']]), confidence=dict(Counter(x['confidence_note'][:6] for x in aud)), transitions=dict(Counter(f"{x['label_current']}->{x['label_blind']}" for x in aud if x['mismatch']).most_common()),
                 rule='사전 기록: 불일치율 > 5%면 한계로 기록, 전수 검수는 마감(2026-11-08 12:00 KST) 후', exceeds_5pct=None, applied_to_data=False, rows=aud)
    audit['exceeds_5pct'] = audit['overall']['rate'] > 0.05
    (OUT / 'c1_blind_audit.json').write_text(json.dumps(audit, ensure_ascii=False, indent=1), encoding='utf-8', newline='\n')

    # ---- 2. 확정 label·rationale 수집 ---------------------------------------------------------------------------------
    dec = {}; oas_cands = []
    for nm in ('판정필요_코드', '판정필요_OAS문구', '변경예상_C2'):
        for r in sheets[nm]:
            i = r['id']; cur = r['현재 label']; fin = (r.get('확정 label') or '').strip(); assert fin in LABELS, (i, fin); assert i in sft_by_id and sft_by_id[i][1]['label'] == cur, i
            rat = (r.get('확정 rationale(자유문, 선택)') or '').strip(); memo = r.get('검수 메모') or ''
            if nm == '판정필요_OAS문구': assert fin == cur, f'OAS-only row must keep its label (user decision): {i}'
            m = re.search(r'AI 의견:\s*(\w+)', memo)
            if m: oas_cands.append(dict(id=i, sheet=nm, split=c0[i]['split'], service=c0[i]['service'], method=r['method'], path=r['path'], label_current=cur, label_kept=fin, ai_opinion=m.group(1), memo=memo, evidence=r.get('확정 근거(코드 줄·설명 문장)') or ''))
            if SYN_TENANT_AND_MEMBER.search(sft_by_id[i][1]['assistant']): assert fin == cur; rat = ''   # 합성 tenant AND membership: 영어 rationale 유지
            assert i not in dec; dec[i] = dict(sheet=nm, label_from=cur, label_to=fin, rationale_new=rat, evidence=r.get('확정 근거(코드 줄·설명 문장)') or '', memo=memo, prior_review=r.get('기존 검수 label·검수자') or '', c2_flag=r.get('C2 재작성 대상') or '', draft=r.get('예상 label(초안)') or '')
    assert all(m['ai_opinion'] in LABELS for m in oas_cands) and all(c0[m['id']]['has_code'] == 'N' for m in oas_cands)
    with open(OUT / 'oas_relabel_candidates_post_deadline.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for m in oas_cands: f.write(json.dumps(m, ensure_ascii=False) + '\n')
    changes = {}
    for i, d in dec.items():
        label_changed = d['label_to'] != d['label_from']; rat_new, stripped = sanitize(d['rationale_new']) if d['rationale_new'] else ('', False)
        if label_changed: assert rat_new, f'label changed without a confirmed rationale: {i}'
        if not label_changed and not rat_new: continue
        s, row = sft_by_id[i]; a = json.loads(row['assistant'])
        changes[i] = dict(id=i, split=s, project=c0[i]['project'], method=rec_by_id[i][1]['method'], path=rec_by_id[i][1]['path'], sheet=d['sheet'], label_from=d['label_from'], label_to=d['label_to'], label_changed=label_changed,
                          rationale_from=a['rationale'], rationale_to=rat_new, rationale_replaced=bool(rat_new), path_refs_stripped=stripped, draft_label=d['draft'], evidence=d['evidence'], memo=d['memo'], prior_review=d['prior_review'], c2_flag=d['c2_flag'], reviewer=REVIEWER)
    # 정합성(변경 행)
    bad = dict(hold_in_concrete=[i for i, c in changes.items() if c['rationale_replaced'] and c['label_to'] != MANUAL and HOLD.search(c['rationale_to'])],
               meta=[i for i, c in changes.items() if c['rationale_replaced'] and META.search(c['rationale_to'])], filepath=[i for i, c in changes.items() if c['rationale_replaced'] and FILEPATH.search(c['rationale_to'])],
               label_in_rationale_missing=[i for i, c in changes.items() if c['rationale_replaced'] and c['label_to'] != MANUAL and c['label_to'] not in c['rationale_to']])
    assert not bad['hold_in_concrete'] and not bad['meta'] and not bad['filepath'], bad
    with open(OUT / 'c1_changes.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for c in changes.values(): f.write(json.dumps(c, ensure_ascii=False) + '\n')

    # ---- 3. processed train_v6d / val_v6d ----------------------------------------------------------------------------
    for s in ('train', 'val'):
        with open(P / f'{s}_v6d.jsonl', 'w', encoding='utf-8', newline='\n') as f:
            for r in recs[s]:
                c = changes.get(r['id'])
                if c:
                    r = json.loads(json.dumps(r, ensure_ascii=False)); r['label'] = c['label_to']
                    if c['rationale_replaced']: r['rationale'] = c['rationale_to']
                    r['meta']['v6d_c1'] = dict(label_from=c['label_from'], label_to=c['label_to'], rationale_replaced=c['rationale_replaced'], sheet=c['sheet'], reviewer=REVIEWER, evidence=c['evidence'], review_file='review/c1_relabel_review_reviewed.xlsx')
                f.write(json.dumps(r, ensure_ascii=False) + '\n')

    # ---- 4. SFT ----------------------------------------------------------------------------------------------------
    D6.mkdir(parents=True, exist_ok=True); stats = {}; redump_ok = 0; n_rows = 0; recount = {}
    for s in ('train', 'val'):
        out = []; same = 0
        for r, line in zip(sft[s], sft_lines[s]):
            n_rows += 1; a = json.loads(r['assistant']); redump_ok += json.dumps(a, ensure_ascii=False) == r['assistant']
            c = changes.get(r['id'])
            if not c: out.append(line); same += 1; recount[r['id']] = ntok(tok, system, r['user'], r['assistant']); continue
            a['label'] = c['label_to']
            if c['rationale_replaced']: a['rationale'] = c['rationale_to']
            assert list(a) == ['label', 'confidence', 'rationale', 'evidence_fields'], (r['id'], list(a))
            r2 = dict(r); r2['label'] = c['label_to']; r2['assistant'] = json.dumps(a, ensure_ascii=False); r2['rationale_source'] = 'c1_review_v6d'; r2['tokens'] = ntok(tok, system, r2['user'], r2['assistant']); recount[r['id']] = r2['tokens']
            assert r2['user'] == r['user']; out.append(json.dumps(r2, ensure_ascii=False))
        (D6 / f'{s}_sft_v6d.jsonl').write_text('\n'.join(out) + '\n', encoding='utf-8', newline='\n')
        new = rd(D6 / f'{s}_sft_v6d.jsonl'); assert len(new) == len(sft[s]) and all(x['id'] == y['id'] and x['user'] == y['user'] for x, y in zip(new, sft[s])), 'user input / order must be byte-identical to data-v5'
        assert all(json.loads(x['assistant'])['label'] == x['label'] for x in new)
        stats[s] = dict(rows=len(new), unchanged_lines=same, changed=len(new) - same, labels_v5=dict(Counter(x['label'] for x in sft[s])), labels_v6d=dict(Counter(x['label'] for x in new)),
                        manual_ratio_v5=round(sum(x['label'] == MANUAL for x in sft[s]) / len(new), 4), manual_ratio_v6d=round(sum(x['label'] == MANUAL for x in new) / len(new), 4),
                        tokens_max_recount=max(recount[x['id']] for x in new), over_4096=[x['id'] for x in new if recount[x['id']] > MAX_SEQ])
        assert not stats[s]['over_4096'], stats[s]['over_4096']
    assert redump_ok == n_rows, f'assistant JSON re-serialisation differs from data-v5 formatting in {n_rows - redump_ok} rows'
    stale = [r['id'] for s in sft for r in sft[s] if r['id'] not in changes and r['tokens'] != recount[r['id']]]   # data-v5 token field is stale in some gitea rows (counted before the data-v3.1 meta cleanup); not used by training
    # 전체 세트 정합성(참고: v5 대비 증가 없음)
    allrows = {s: rd(D6 / f'{s}_sft_v6d.jsonl') for s in ('train', 'val')}
    full = {v: dict(hold_in_concrete=sum(1 for s in rows for r in rows[s] if r['label'] != MANUAL and HOLD.search(json.loads(r['assistant'])['rationale'])), meta=sum(1 for s in rows for r in rows[s] if META.search(json.loads(r['assistant'])['rationale'])),
                    filepath=sum(1 for s in rows for r in rows[s] if FILEPATH.search(json.loads(r['assistant'])['rationale']))) for v, rows in (('v5', sft), ('v6d', allrows))}
    assert all(full['v6d'][k] <= full['v5'][k] for k in full['v5']), full
    for n in ('test_v30_inputs.jsonl', 'test_v31_supp_inputs.jsonl', 'test_v5_inputs.jsonl', 'policy_label_v3.0.1.md'): shutil.copyfile(D5 / n, D6 / n)
    shutil.copyfile(P / 'data_v5/test_v5_manifest.json', D6 / 'test_v5_manifest.json')   # TESTV5 gate file (57fd384f…), not in generated hashes
    gen = {n: sha(D6 / n) for n in ('train_sft_v6d.jsonl', 'val_sft_v6d.jsonl', 'test_v30_inputs.jsonl', 'test_v31_supp_inputs.jsonl', 'policy_label_v3.0.1.md')}
    hashes = dict(data_version='data-v6d', note='data-v5 SFT rows (byte-verified) with the C1-confirmed label and, where a confirmed rationale exists, the rationale replaced in the assistant JSON (key order unchanged: label, confidence, rationale, evidence_fields). '
                  'User inputs, row order and all other rows are byte-identical to data-v5. Prompt policy_label_v3.0.1.md (frozen). test inputs are byte-identical copies of data_v5; test_v5_inputs.jsonl is verified separately against test_v5_manifest.json (TESTV5 gate).',
                  sources={str(p.relative_to(ROOT)).replace('\\', '/'): h for p, h in FROZEN.items()}, generated=gen, counts={s: stats[s]['rows'] for s in stats}, labels={s: stats[s]['labels_v6d'] for s in stats},
                  c1=dict(label_changes=sum(c['label_changed'] for c in changes.values()), rationale_replaced=sum(c['rationale_replaced'] for c in changes.values()), rows_touched=len(changes), reviewer=REVIEWER, review_file='review/c1_relabel_review_reviewed.xlsx', review_sha256=FROZEN[XLSX]),
                  blind_audit={k: audit[k] for k in ('overall', 'by_kind', 'exceeds_5pct', 'applied_to_data')}, max_seq_len=MAX_SEQ, tokenizer=dict(method='tokenizers + manual Qwen2.5 chat template (validated against data_v6a counts, 1453/1453)', tokenizer_json_sha256=tok_sha),
                  format='system=prompt v3.0.1; user="Return JSON.\\n"+payload (unchanged); assistant=JSON {label, confidence, rationale, evidence_fields}')
    (D6 / 'data_v6d_hashes.json').write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
    outs = {str(p.relative_to(ROOT)).replace('\\', '/'): dict(sha256=sha(p), rows=len(rd(p)) if p.suffix == '.jsonl' else None) for p in (P / 'train_v6d.jsonl', P / 'val_v6d.jsonl', D6 / 'train_sft_v6d.jsonl', D6 / 'val_sft_v6d.jsonl', D6 / 'data_v6d_hashes.json', D6 / 'test_v5_inputs.jsonl', OUT / 'c1_changes.jsonl', OUT / 'c1_blind_audit.json', OUT / 'oas_relabel_candidates_post_deadline.jsonl')}
    rep = dict(stats=stats, changes_summary=dict(label_changes=hashes['c1']['label_changes'], rationale_replaced=hashes['c1']['rationale_replaced'], rows_touched=len(changes), by_sheet=dict(Counter(c['sheet'] for c in changes.values())),
                                                 label_shift=dict(Counter(f"{c['label_from']}->{c['label_to']}" for c in changes.values() if c['label_changed']).most_common()), by_project=dict(Counter(c['project'] for c in changes.values() if c['label_changed'])),
                                                 path_refs_stripped=[i for i, c in changes.items() if c['path_refs_stripped']], prior_reviewed_changed=[dict(id=i, prior=c['prior_review'][:160], to=c['label_to'], evidence=c['evidence'][:300]) for i, c in changes.items() if c['label_changed'] and c['prior_review']],
                                                 draft_rejected=[dict(id=i, draft=d['draft'], final=d['label_to'], memo=d['memo'][:120]) for i, d in dec.items() if d['draft'] in LABELS and d['draft'] != d['label_to']],
                                                 oas_candidates=len(oas_cands), synthetic_english_kept=[i for i in dec if SYN_TENANT_AND_MEMBER.search(sft_by_id[i][1]['assistant'])]),
               integrity=dict(changed_rows=bad, full_set=full, user_byte_identical=True, unchanged_lines_byte_identical=True, over_4096=[], tokens_max_recount=max(stats[s]['tokens_max_recount'] for s in stats), stale_token_field_v5=dict(n=len(stale), note='gitea rows; data-v5 tokens field counted before the data-v3.1 meta cleanup; not used by training (run_train re-tokenises)')),
               blind_audit={k: v for k, v in audit.items() if k != 'rows'}, outputs=outs, hashes_file_sha256=sha(D6 / 'data_v6d_hashes.json'))
    (OUT / 'freeze_report.json').write_text(json.dumps(rep, ensure_ascii=False, indent=1), encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in rep.items() if k in ('changes_summary', 'integrity')}, ensure_ascii=False, indent=1)); print('blind', json.dumps({k: audit[k] for k in ('overall', 'by_kind', 'human_reviewed_rows', 'transitions')}, ensure_ascii=False))
    print('stats', json.dumps({s: {k: v for k, v in stats[s].items() if k != 'over_4096'} for s in stats}, ensure_ascii=False)); print('outputs', json.dumps(outs, indent=1)); print('hashes file', rep['hashes_file_sha256'])


if __name__ == '__main__': main()
