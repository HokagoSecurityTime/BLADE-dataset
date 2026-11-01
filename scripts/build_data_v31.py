"""data-v3.1b: data-v3b with review meta text removed from the training targets (rationale). Labels, inputs and record order unchanged; no LLM.
Removes review-sheet references (review_sheet_reviewed.xlsx sheet X, 시트 A #22, "4번과 동일"), reviewer category tags (SELF, VIS, AUTH_ANY, CODE_SHORT,
VIS+SELF data-scope), rule ids in the judgment ("판단: human_review_v2 / R1_self_owner / R4_noauth_public ... 기준으로 <label>") and source file:line
references ("routers/api/v1/user/key.go:263 match "..."" -> 핸들러 코드 "..."). Judgment sentences become the per-label templates already used in data-v3.
Inputs: data-v3b frozen files (hash asserted). Outputs (new files only): datasets/blade/processed/{train_v31b,val_v31,rationale_meta_cleanup_v31}.jsonl,
training/lora/data_v31/{train_sft_v31b,val_sft_v31,test_v30_inputs}.jsonl + policy_label_v3.0.1.md + data_v31_hashes.json. Asserts zero meta text left."""
from __future__ import annotations
import hashlib, json, re, shutil, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
from data_v2_guard import assert_data_v2
P = ROOT / 'datasets/blade/processed'; S3 = ROOT / 'training/lora/data_v3'; S31 = ROOT / 'training/lora/data_v31'
FROZEN = {P / 'train_v3b.jsonl': '723e3b3a784e624033379dce5e46b243c2c3444c34db7efb5032ea2436a696dd', P / 'val_v3.jsonl': '69536f8b10e99538673a1beaf96411aba2b18f341e04f9429f717d9d84cbc109',
          P / 'test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2', S3 / 'train_sft_v3b.jsonl': '85e634a170c83a9bbe209514fa268dc35dc16b9842dbb58dc8aaa0dfac5f92ab',
          S3 / 'val_sft_v3.jsonl': '4de0188e9e6fd73e8f4cefb7e931c9f09e66efb4d1a8e0e86b2843555515ab06', S3 / 'test_v30_inputs.jsonl': 'd65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a',
          S3 / 'policy_label_v3.0.1.md': 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'}
OUT = dict(train=P / 'train_v31b.jsonl', val=P / 'val_v31.jsonl', log=P / 'rationale_meta_cleanup_v31.jsonl', sft_train=S31 / 'train_sft_v31b.jsonl', sft_val=S31 / 'val_sft_v31.jsonl')
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
lines = lambda p: [l for l in Path(p).read_text(encoding='utf-8').splitlines() if l.strip()]

# Meta text that must not survive in any target. Checked on the full rationale after rewriting.
LEAK = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|\bVIS\b|\bSELF\b|data-scope|#\d+|\.go:\d+|번과 동일|test의 |오라벨|기준 통일')
JUDGE = {'owner_match': '소유자 본인만 허용하는 조건이므로 owner_match', 'role_required': '특정 역할 보유가 실제 접근 조건이므로 role_required',
         'public': '인증 요구가 없으므로 public 선택', 'membership_required': '구성원 여부가 실제 접근 조건이므로 membership_required',
         'owner_or_admin': '소유자 또는 관리자 조건이므로 owner_or_admin', 'tenant_match': '요청자의 tenant와 대상 자원의 tenant가 일치해야 하므로 tenant_match',
         'manual_review_required': '접근 조건이 확정되지 않아 보류'}
RULE_JUDGE = re.compile(r'판단: (?:human_review_v2(?:_r\d|_fix)?|R\d+_[A-Za-z_]+) 기준으로 (\w+)$')
SHEET = re.compile(r'review_sheet_reviewed\.xlsx sheet [A-Z]: ')
TAGS = re.compile(r'^(?:(?:SELF|VIS|AUTH_ANY|CODE_SHORT)(?:[·+](?:SELF|VIS|CODE_SHORT))*\.\s*|VIS\+SELF data-scope\s+)')
FILE_MATCH = re.compile(r'[\w./-]+\.go:\d+ (?:match )?("(?:[^"\\]|\\.)*"?)', re.S)
DROP_SENTENCE = re.compile(r'시트 ?[A-Z]|#\d+|번과 동일|test의 |오라벨|override가')
WHOLE = {'VIS+SELF 중 요청자가 데이터 범위인 경우 owner_match로 기준 통일': '요청자 본인의 데이터 범위(star·watch·구독·알림 등)를 다루는 작업'}


def clean_description(d):
    d = SHEET.sub('', d)
    d = WHOLE.get(d, d)
    d = TAGS.sub('', d)
    d = FILE_MATCH.sub(lambda m: '핸들러 코드 ' + m.group(1), d)
    parts = [s for s in re.split(r'(?<=\.)\s+', d.strip()) if s]
    kept = [s for s in parts if not DROP_SENTENCE.search(s)]
    d = ' '.join(kept).strip()
    d = re.sub(r'\s*\((?:오라벨)\)', '', d)
    return d


def rewrite(rationale, label):
    """Returns the rewritten rationale (same 'description: ...; 판단: ...' shape) or the input unchanged when it carries no meta text."""
    if not LEAK.search(rationale) and not RULE_JUDGE.search(rationale): return rationale
    desc, sep, judge = rationale.rpartition('; 판단: ')
    if not sep: desc, judge = rationale, ''
    m = RULE_JUDGE.search('판단: ' + judge) if judge else None
    if m: assert m.group(1) == label, (rationale, label); judge = JUDGE[label]
    head = 'description: '
    assert desc.startswith(head), rationale
    body = clean_description(desc[len(head):]).rstrip('.')
    if not body: body = '핸들러 발췌의 접근 검사'
    return f'{head}{body}; 판단: {judge}' if judge else f'{head}{body}'


def main():
    assert_data_v1('start'); assert_data_v2('start')
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'
    for p in OUT.values(): assert not p.exists(), f'refusing to overwrite {p}'
    S31.mkdir(parents=True, exist_ok=True)
    log, stats = [], Counter()
    for kind, rec_src, sft_src, rec_out, sft_out in (('train', P / 'train_v3b.jsonl', S3 / 'train_sft_v3b.jsonl', OUT['train'], OUT['sft_train']),
                                                     ('val', P / 'val_v3.jsonl', S3 / 'val_sft_v3.jsonl', OUT['val'], OUT['sft_val'])):
        recs = lines(rec_src); new = []
        for l in recs:
            r = json.loads(l); old = r.get('rationale') or ''
            nr = rewrite(old, r['label']) if old else old
            if nr != old:
                r['rationale'] = nr; r['meta'] = {**r['meta'], 'rationale_v31': 'meta_text_removed'} if isinstance(r['meta'], dict) else r['meta']
                stats[f'{kind}_record_changed'] += 1; log.append(dict(split=kind, file='record', id=r['id'], label=r['label'], before=old, after=nr))
                new.append(json.dumps(r, ensure_ascii=False))
            else: new.append(l)
        rec_out.write_text('\n'.join(new) + '\n', encoding='utf-8')
        sft = lines(sft_src); new = []
        for l in sft:
            r = json.loads(l); a = json.loads(r['assistant'])
            assert json.dumps(a, ensure_ascii=False) == r['assistant'], 'assistant serialization differs; cannot rewrite in place'
            nr = rewrite(a['rationale'], r['label'])
            assert a['label'] == r['label']
            if nr != a['rationale']:
                log.append(dict(split=kind, file='sft', id=r['id'], condition=r['condition'], label=r['label'], before=a['rationale'], after=nr))
                a['rationale'] = nr; r['assistant'] = json.dumps(a, ensure_ascii=False); stats[f'{kind}_sft_changed'] += 1
                new.append(json.dumps(r, ensure_ascii=False))
            else: new.append(l)
        sft_out.write_text('\n'.join(new) + '\n', encoding='utf-8')
        # invariants: same ids/order/labels/inputs, zero meta text left
        a_old, a_new = [json.loads(x) for x in sft], [json.loads(x) for x in lines(sft_out)]
        assert [(x['id'], x['condition'], x['label'], x['user']) for x in a_old] == [(x['id'], x['condition'], x['label'], x['user']) for x in a_new]
        assert [json.loads(x)['label'] for x in recs] == [json.loads(x)['label'] for x in lines(rec_out)]
        stats[f'{kind}_sft_meta_before'] = sum(bool(LEAK.search(json.loads(x['assistant'])['rationale'])) for x in a_old)
        stats[f'{kind}_record_meta_before'] = sum(bool(LEAK.search(json.loads(x).get('rationale') or '')) for x in recs)
        left = [x['id'] for x in a_new if LEAK.search(json.loads(x['assistant'])['rationale']) or RULE_JUDGE.search(json.loads(x['assistant'])['rationale'])]
        left_r = [json.loads(x)['id'] for x in lines(rec_out) if LEAK.search(json.loads(x).get('rationale') or '')]
        assert not left and not left_r, (left[:5], left_r[:5])
        stats[f'{kind}_sft_meta_after'] = 0; stats[f'{kind}_record_meta_after'] = 0
    OUT['log'].write_text(''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in log), encoding='utf-8')
    for f in ('test_v30_inputs.jsonl', 'policy_label_v3.0.1.md'): shutil.copyfile(S3 / f, S31 / f)
    hashes = dict(data_version='data-v3.1b', derived_from='data-v3b (train_v3b + val_v3), rationale meta text removed, labels unchanged',
                  sources={p.name: h for p, h in FROZEN.items()}, generated={p.name: sha(p) for p in [OUT['train'], OUT['val'], OUT['log'], OUT['sft_train'], OUT['sft_val'], S31 / 'test_v30_inputs.jsonl', S31 / 'policy_label_v3.0.1.md']},
                  stats=dict(stats))
    (S31 / 'data_v31_hashes.json').write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    assert_data_v1('end'); assert_data_v2('end')
    for p, h in FROZEN.items(): assert sha(p) == h
    print(json.dumps(dict(stats), ensure_ascii=False))
    for x in log[:0]: print(x)


if __name__ == '__main__': main()
