"""data-v4 freeze: data-v3.1b (train_v31b + val_v31, manual quota 10%) + data-v4 train additions (Zulip 12.3, Label Studio 1.23.2) with code-rule labels
(training/data/rule_label_v4.py; LLM first-pass labels unused). Steps: rule labels for all 440 candidates -> Label Studio storage-backend variants collapsed (one per group)
-> per project <= 150, no label above 50% within a project, target labels first (seed 42) -> group split train/val by (project, handler file) ~10% (no handler shared)
-> SFT inputs (test_v30 oas_code payload) -> integrity checks -> hashes. Also writes review/v4_rule_label_sample.xlsx (10 per label, human sample check).
Frozen inputs (data-v1..v3, data-v3.1b, test_v30, test_v31_supp) are hash-asserted and read only. No API, no training. Refuses to overwrite outputs."""
from __future__ import annotations
import hashlib, json, math, os, random, re, shutil, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from build_data_v4 import LABELS, TARGET, TRAIN_PROJECTS, CAP, MAX_SHARE, allocate, near_dup_group, key, permalink, write_sheet, rd, dump, sha, guard
from training.data import rule_label_v4 as RL
from training.lora.prepare_lora_inputs import test_record
P = ROOT / 'datasets/blade/processed'; D4 = P / 'data_v4'; S31 = ROOT / 'training/lora/data_v31'; S4 = ROOT / 'training/lora/data_v4'; REVIEW = ROOT / 'review'
PROMPT = ROOT / 'training/data/prompts/policy_label_v3.0.1.md'; SEED, VAL_SHARE, SAMPLE_PER_LABEL, MAX_SEQ = 42, 0.10, 10, 4096
FROZEN = {P / 'train_v31b.jsonl': None, P / 'val_v31.jsonl': None, S31 / 'train_sft_v31b.jsonl': None, S31 / 'val_sft_v31.jsonl': None, S31 / 'test_v30_inputs.jsonl': None,
          D4 / 'test_v31_supp.jsonl': '803d914902c7ca2042fd15d4a7852d42e71828e58d4ae4d3ac791fb868e63395', S4 / 'test_v31_supp_inputs.jsonl': '97e618e770bbf9950d6846869901819db36fce486d8999d69eb73e286e2a056c',
          D4 / 'candidates_train_v4.jsonl': '291933c2b0b6fe9811df697b139b894d2d29399119cdd2aa81cda60c40b96376', PROMPT: 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'}
for k, v in json.loads((S31 / 'data_v31_hashes.json').read_text(encoding='utf-8'))['generated'].items():
    for p in FROZEN:
        if p.name == k and FROZEN[p] is None: FROZEN[p] = v
OUT = dict(rule=D4 / 'train_v4_rule_labeled.jsonl', train=P / 'train_v4.jsonl', val=P / 'val_v4.jsonl', sft_train=S4 / 'train_sft_v4.jsonl', sft_val=S4 / 'val_sft_v4.jsonl',
           sample=REVIEW / 'v4_rule_label_sample.xlsx', hashes=S4 / 'data_v4_hashes.json', report=ROOT / 'reports/data_v4/freeze_report.json')
HOLD = re.compile(r'no concrete label|pending review|manual|cannot determine|cannot be determined|not expressible|보류|판단할 수 없|단일 라벨로 표현되지|확인되지 않아|label이 없|알 수 없', re.I)
META = re.compile(r'review_sheet|xlsx|human_review|sheet [A-Z]\b|시트 ?[A-Z]|\bR\d+_[A-Za-z_]+|_r\d\b|AUTH_ANY|CODE_SHORT|\bG[1-8]\b|검수|candidates\.jsonl')
FILEPATH = re.compile(r'(?:[\w.-]+/)+[\w.-]+\.(?:py|rb|php|ts|js|go|java|ya?ml)|\.\w+:\d+')


def to_sft(r):
    rec = test_record(r); target = {'label': r['label'], 'confidence': 0.9, 'rationale': r['rationale'], 'evidence_fields': ['description', 'path_params']}
    return dict(id=r['id'], source='opensource_v4', condition='oas_code', label=r['label'], rationale_source='rule_v4_' + r['meta']['rule_v4'], security_state=rec['security_state'],
                user=rec['oas_code_user'], assistant=json.dumps(target, ensure_ascii=False))


def main():
    guard('start')
    for p, h in FROZEN.items(): assert h and sha(p) == h, f'frozen input changed or unknown: {p}'
    for p in OUT.values(): assert not p.exists(), f'refusing to overwrite {p}'
    S4.mkdir(parents=True, exist_ok=True); OUT['report'].parent.mkdir(parents=True, exist_ok=True)
    # 1. rule labels (all candidates; unlabeled ones keep the reason)
    labeled = []
    for c in rd(D4 / 'candidates_train_v4.jsonl'):
        lab, rule, ev, why = RL.decide(c); r = dict(c, label=lab)
        r['meta'] = {**c['meta'], 'label_source': 'code_rule_v4', 'rule_v4': rule, 'rule_evidence': ev, 'rule_excluded_reason': why}
        r['rationale'] = RL.rationale(lab, ev) if lab else None; labeled.append(r)
    dump(OUT['rule'], labeled)
    ok = [r for r in labeled if r['label']]
    # 2. near-duplicate backend variants -> one per group; 3. caps per project
    rng = random.Random(SEED); groups = defaultdict(list)
    for r in sorted(ok, key=lambda r: r['id']): groups[near_dup_group(r)].append(r)
    pool = [rng.choice(g) for _, g in sorted(groups.items())]; near_dup = len(ok) - len(pool)
    selected, sel_rep = [], {}
    for proj in TRAIN_PROJECTS:
        pr = sorted([r for r in pool if r['meta']['project'] == proj], key=lambda r: r['id']); by = defaultdict(list)
        for r in pr: by[r['label']].append(r)
        take = allocate({l: len(v) for l, v in by.items()}); sel = []
        for l in LABELS:
            if take.get(l): sel += rng.sample(by[l], take[l])
        assert len(sel) <= CAP and max(Counter(r['label'] for r in sel).values()) <= math.floor(len(sel) * MAX_SHARE)
        sel_rep[proj] = dict(rule_labeled=sum(r['meta']['project'] == proj for r in ok), after_near_dup=len(pr), available=dict(Counter(r['label'] for r in pr)), selected=len(sel), selected_dist=dict(Counter(r['label'] for r in sel)))
        selected += sel
    # 4. group split by (project, handler = first view class/function of the excerpt): the methods of one handler never straddle train and val.
    #    Per label (rarest first) groups are drawn until val holds round(10%) of that label.
    def gkey(r):
        m = re.search(r'^(?:class|def) (\w+)', r['controller_text'], re.M)
        return (r['meta']['project'], m.group(1) if m else r['path'])
    groups_of = defaultdict(list)
    for r in selected: groups_of[gkey(r)].append(r)
    val_files, cnt = set(), Counter(r['label'] for r in selected)
    for l in sorted(cnt, key=lambda l: (cnt[l], l)):
        want = round(cnt[l] * VAL_SHARE); cand = sorted(g for g, rs in groups_of.items() if any(x['label'] == l for x in rs) and g not in val_files); rng.shuffle(cand)
        for g in cand:
            if sum(x['label'] == l for f in val_files for x in groups_of[f]) >= want: break
            if sum(x['label'] == l for x in groups_of[g]) + sum(x['label'] == l for f in val_files for x in groups_of[f]) > max(want, 1) * 2: continue
            val_files.add(g)
    v4_val = sorted([r for r in selected if gkey(r) in val_files], key=lambda r: r['id']); v4_train = sorted([r for r in selected if gkey(r) not in val_files], key=lambda r: r['id'])
    assert not ({gkey(r) for r in v4_val} & {gkey(r) for r in v4_train})
    # 5. integrity checks on the v4 additions
    test_keys = {key(r['service'], r['method'], r['path']) for r in rd(P / 'test_v30.jsonl') + rd(D4 / 'test_v31_supp.jsonl')}
    checks = dict(hold_in_concrete=[r['id'] for r in selected if r['label'] != 'manual_review_required' and HOLD.search(r['rationale'])],
                  meta_text=[r['id'] for r in selected if META.search(r['rationale'])], file_path=[r['id'] for r in selected if FILEPATH.search(r['rationale'])],
                  test_overlap=[r['id'] for r in selected if key(r['service'], r['method'], r['path']) in test_keys])
    assert not any(checks.values()), checks
    # 6. records and SFT
    base_train, base_val = rd(P / 'train_v31b.jsonl'), rd(P / 'val_v31.jsonl')
    dump(OUT['train'], base_train + v4_train); dump(OUT['val'], base_val + v4_val)
    os.environ.setdefault('HF_HUB_OFFLINE', '1')
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained('Qwen/Qwen2.5-7B-Instruct', cache_dir=str(ROOT / '.cache/models')); system = PROMPT.read_text(encoding='utf-8')
    ntok = lambda s: len(tok.apply_chat_template([{'role': 'system', 'content': system}, {'role': 'user', 'content': s['user']}, {'role': 'assistant', 'content': s['assistant']}], tokenize=True))
    over = []
    def conv(rows, split):
        out = []
        for r in rows:
            s = to_sft(r); s['tokens'] = ntok(s)
            if s['tokens'] > MAX_SEQ: over.append(dict(id=r['id'], tokens=s['tokens'], split=split)); continue
            out.append(s)
        return out
    sft_train = rd(S31 / 'train_sft_v31b.jsonl') + conv(v4_train, 'train'); sft_val = rd(S31 / 'val_sft_v31.jsonl') + conv(v4_val, 'val')
    for p, rows in ((OUT['sft_train'], sft_train), (OUT['sft_val'], sft_val)):
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            for s in rows: f.write(json.dumps(s, ensure_ascii=False) + '\n')
    for n in ('test_v30_inputs.jsonl', 'policy_label_v3.0.1.md'): shutil.copyfile(S31 / n, S4 / n)
    # 7. human sample sheet: 10 per label (seed 42) over the selected v4 additions
    rng2 = random.Random(SEED); sample = []
    for l in LABELS:
        pool_l = sorted([r for r in selected if r['label'] == l], key=lambda r: r['id'])
        sample += rng2.sample(pool_l, min(SAMPLE_PER_LABEL, len(pool_l)))
    rows = [[r['id'], r['meta']['project'], r['method'], r['path'], r['label'], r['meta']['rule_v4'], '\n'.join(r['meta']['rule_evidence']), r['rationale'], r['controller_text'], permalink(r['meta']), '', '', ''] for r in sample]
    defs = '프롬프트 v3.0.1 라벨 정의(발췌)\n\n' + system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip() + '\n\n검수 규약 G1~G7: AGENTS.md data-v4 검수 규약 절. 규칙 이름은 training/data/rule_label_v4.py.'
    write_sheet(OUT['sample'], 'v4_rule_label_sample', ['id', 'project', 'method', 'path', '규칙 label', '규칙', '근거 줄(발췌)', '학습 rationale', 'controller_text', 'source permalink', '검수 label', '검수 사유', '검수자'],
                rows, [26, 12, 8, 40, 18, 28, 60, 50, 70, 40, 18, 40, 10], 11, defs)
    # 8. hashes and report
    m_tr = sum(s['label'] == 'manual_review_required' for s in sft_train)
    rep = dict(data_version='data-v4', composition='data-v3.1b (train_v31b + val_v31) + data-v4 rule-labeled additions', rule_labels=dict(total=len(labeled), labeled=len(ok), unlabeled=len(labeled) - len(ok),
               by_project={p: dict(Counter(r['label'] or 'EXCLUDED:' + (r['meta']['rule_excluded_reason'] or '').split(':')[0] for r in labeled if r['meta']['project'] == p)) for p in TRAIN_PROJECTS},
               by_rule=dict(Counter(r['meta']['rule_v4'] for r in ok))), near_duplicate_dropped=near_dup, selection=sel_rep,
               v4_split=dict(train=len(v4_train), val=len(v4_val), val_groups=sorted(map(list, val_files)), train_dist=dict(Counter(r['label'] for r in v4_train)), val_dist=dict(Counter(r['label'] for r in v4_val))),
               sft=dict(train=len(sft_train), val=len(sft_val), manual_train=m_tr, manual_train_ratio=round(m_tr / len(sft_train), 4), over_4096=over,
                        v4_token_max=max([s['tokens'] for s in sft_train + sft_val if s['source'] == 'opensource_v4'] or [0])), integrity=dict((k, len(v)) for k, v in checks.items()),
               sample_sheet=dict(rows=len(sample), by_label=dict(Counter(r['label'] for r in sample))))
    hashes = dict(data_version='data-v4', sources={p.name: h for p, h in FROZEN.items()}, generated={p.name: sha(p) for p in [OUT['rule'], OUT['train'], OUT['val'], OUT['sft_train'], OUT['sft_val'], S4 / 'test_v30_inputs.jsonl', S4 / 'test_v31_supp_inputs.jsonl', S4 / 'policy_label_v3.0.1.md']},
                  counts=dict(train=len(sft_train), val=len(sft_val)), format='same as data_v3 (system=prompt v3.0.1; user="Return JSON.\\n"+payload; assistant=label JSON)', max_seq_len=MAX_SEQ)
    OUT['hashes'].write_text(json.dumps(hashes, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'); OUT['report'].write_text(json.dumps(rep, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    guard('end')
    for p, h in FROZEN.items(): assert sha(p) == h
    print(json.dumps(rep, ensure_ascii=False, default=str)[:4000])


if __name__ == '__main__': main()
