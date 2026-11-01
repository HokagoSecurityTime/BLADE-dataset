"""data-v2 freeze: val_v2 group split (code records only) -> manual quota 25% on the train part -> train_v2.jsonl / val_v2.jsonl + hashes + docs.
Input train_v2_draft_r3.jsonl (unchanged). data-v1 guard at start/end. No API/training. Writes reports/data_v2_freeze.md."""
from __future__ import annotations
import hashlib, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
import importlib.util
spec = importlib.util.spec_from_file_location('r3', ROOT / 'scripts/apply_review_v2_r3.py'); r3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(r3)
P = ROOT / 'datasets/blade/processed'; IN = P / 'train_v2_draft_r3.jsonl'; TRAIN = P / 'train_v2.jsonl'; VAL = P / 'val_v2.jsonl'; POOL = P / 'train_v2_manual_pool.jsonl'
L, MANUAL = r3.L, r3.MANUAL; rd = r3.rd; mw_names = r3.mw_names; is_human = r3.is_human; reason = r3.reason
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
has_code = lambda r: bool((r.get('controller_text') or '').strip() or ((r.get('controller_signals') or {}).get('raw_snippet') or '').strip())
dist = lambda rs: {l: sum(r['label'] == l for r in rs) for l in L}
SEED = 42

def group_key(r):
    if r['id'].startswith('gitea:'):
        mws = tuple(sorted(set(mw_names(r)) - {'sudo', 'tokenRequiresScopes', 'checkTokenPublicOnly'})); segs = [s for s in r['path'].split('/') if s][:2]
        return 'gitea|' + '/'.join(segs) + '|' + ','.join(mws)
    return 'syn|' + re.sub(r'_variants$', '', r['service'])

def split_val(code_rows):
    groups = defaultdict(list)
    for r in code_rows: groups[group_key(r)].append(r)
    human_groups = {k for k, v in groups.items() if any(is_human(r) for r in v)}
    cands = [k for k in groups if k not in human_groups]; rng = random.Random(SEED); rng.shuffle(cands)
    target = round(len(code_rows) * .10); chosen = []; chosen_size = 0; have = Counter()
    # 1) label coverage: for each label pick the smallest candidate group containing it
    for l in L:
        if have[l]: continue
        opts = sorted([k for k in cands if k not in chosen and any(r['label'] == l for r in groups[k])], key=lambda k: len(groups[k]))
        if opts: chosen.append(opts[0]); chosen_size += len(groups[opts[0]]); have.update(r['label'] for r in groups[opts[0]])
    # 2) fill to ~10% with random candidate groups, preferring small ones so we do not overshoot
    for k in sorted([k for k in cands if k not in chosen], key=lambda k: (len(groups[k]), k)):
        if chosen_size >= target: break
        if chosen_size + len(groups[k]) > target + 5: continue
        chosen.append(k); chosen_size += len(groups[k]); have.update(r['label'] for r in groups[k])
    val = [r for k in chosen for r in groups[k]]; missing = [l for l in L if not have[l]]
    return val, chosen, groups, human_groups, missing, target

def main():
    verified = assert_data_v1('start'); rows = rd(IN); r3_ids = {r['id'] for r in rows}
    assert not TRAIN.exists() and not VAL.exists(), 'train_v2/val_v2 already exist; freeze refused'
    code_rows = [r for r in rows if has_code(r)]; api_rows = [r for r in rows if not has_code(r)]
    val_code, chosen, groups, human_groups, missing, target = split_val(code_rows); val_ids = {r['id'] for r in val_code}
    train_rows = [r for r in rows if r['id'] not in val_ids]
    assert not ({group_key(r) for r in train_rows if has_code(r)} & {group_key(r) for r in val_code})
    # quota on train part
    concrete = [r for r in train_rows if r['label'] != MANUAL]; tgt = int(len(concrete) / 3 + .5)
    fixed = [r for r in train_rows if r['label'] == MANUAL and (not r['id'].startswith('gitea:') or is_human(r))]
    free = [r for r in train_rows if r['label'] == MANUAL and r['id'].startswith('gitea:') and not is_human(r)]
    slots = tgt - len(fixed); tag_of = lambda r: ('복합' if reason(r).startswith('복합') else 'AUTH_ANY' if reason(r).startswith('AUTH_ANY') else 'VIS' if reason(r).startswith('VIS') else '기타')
    pool = []; keep_free = []
    if slots < 0: quota_note = f'fixed manual {len(fixed)} > target {tgt}: no reduction of fixed manual (reported)'; keep_free = []; pool = free
    elif slots >= len(free): quota_note = f'slots {slots} >= free Gitea manual {len(free)}: all kept'; keep_free = free
    else:
        rng = random.Random(SEED); by_tag = defaultdict(list)
        for r in free: by_tag[tag_of(r)].append(r)
        alloc = {t: int(len(v) * slots / len(free)) for t, v in by_tag.items()}
        for t in sorted(by_tag, key=lambda t: -(len(by_tag[t]) * slots / len(free) - alloc[t])):
            if sum(alloc.values()) >= slots: break
            alloc[t] += 1
        for t, v in by_tag.items():
            v = sorted(v, key=lambda r: r['id']); rng.shuffle(v); keep_free += v[:alloc[t]]
            for r in v[alloc[t]:]:
                rec = json.loads(json.dumps(r)); rec['meta']['quota_excluded'] = dict(reason='manual quota 25% (apply_reviews_v2 formula), stratified by tag', tag=t, seed=SEED); pool.append(rec)
        quota_note = f'slots {slots} filled from free Gitea manual {len(free)} by tag {dict(alloc)}'
    keep_ids = {r['id'] for r in concrete} | {r['id'] for r in fixed} | {r['id'] for r in keep_free}
    train = [r for r in train_rows if r['id'] in keep_ids]
    for r in train: r['meta']['data_version'] = 'data-v2'; r['meta']['split'] = 'train'
    val30 = rd(P / 'val_v30.jsonl')
    for r in val_code: r['meta']['data_version'] = 'data-v2'; r['meta']['split'] = 'val'
    val = val30 + val_code
    for p, rs in ((TRAIN, train), (VAL, val), (POOL, pool)):
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            for r in rs: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    assert not ({r['service'] for r in train} & {'quill_blog', 'folio_wiki', 'beacon_iot', 'summit_club', 'netbox', 'VAmPI', 'crAPI', 'juice-shop', 'Pixi', 'DVWS-node', 'vAPI', 'DVRestaurant'})
    assert not ({r['id'] for r in train} & {r['id'] for r in val})
    hashes = {'train_v2.jsonl': sha(TRAIN), 'val_v2.jsonl': sha(VAL), 'train_v2_manual_pool.jsonl': sha(POOL), 'test_v30.jsonl': sha(P / 'test_v30.jsonl'), 'policy_label_v3.0.1.md': sha(ROOT / 'training/data/prompts/policy_label_v3.0.1.md'), 'source_train_v2_draft_r3.jsonl': sha(IN)}
    assert hashes['policy_label_v3.0.1.md'] == 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'
    # stats
    src = lambda r: 'gitea' if r['id'].startswith('gitea:') else ('synthetic' if r['meta'].get('source') == 'synthetic' else 'apisguru')
    def by_src(rs): return dict(Counter(src(r) for r in rs))
    code_train = [r for r in train if has_code(r)]; code_val = [r for r in val if has_code(r)]
    cond = lambda rs: dict(oas=len(rs), oas_code=sum(has_code(r) for r in rs))
    rules = ['human_review_v2', 'human_review_v2_fix', 'human_review_v2_r3', 'R1_self_owner', 'R1_self_split', 'R4_noauth_public', 'variant_intended_policy']
    rule_counts = Counter((r['meta'].get('v2_relabel') or {}).get('rule_id') for r in train + val if r['meta'].get('v2_relabel'))
    criteria = [l[2:] for l in (ROOT / 'AGENTS.md').read_text(encoding='utf-8').split('## data-v2 라벨 기준')[1].split('\n## ')[0].splitlines() if l.startswith('- ') and not l.startswith('- 적용 기록')]
    def table(rs, header, right_from=1):
        return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c) for c in r) + ' |\n' for r in rs)
    t = '# data-v2 동결 보고 — 2026-10-23\n\n'
    t += f"data-v1 해시 assert 통과(시작·종료): {', '.join(k.split('/')[-1] + ' ' + v for k, v in verified.items())}. 입력 train_v2_draft_r3.jsonl({len(rows)}, SHA `{hashes['source_train_v2_draft_r3.jsonl'][:16]}…`, 불변). 프롬프트 v3.0.1 해시 확인. test_v30 불변.\n\n"
    t += '## 1. val_v2 분리 (쿼터 전)\n\n'
    t += f"코드 있는 레코드 {len(code_rows)}건(Gitea {sum(src(r)=='gitea' for r in code_rows)} · 합성 {sum(src(r)=='synthetic' for r in code_rows)}) → 목표 10% = {target}건. 그룹 키: Gitea = 경로 첫 두 세그먼트 + 미들웨어 시그니처, 합성 = 서비스명(variants는 원 서비스로 합침). 그룹 {len(groups)}개 중 사람 검수 포함 그룹 {len(human_groups)}개는 train 고정. 선택 그룹 {len(chosen)}개 → val 코드 {len(val_code)}건. label 7종 val 포함 {'전부 충족' if not missing else '미충족: ' + ', '.join(missing)}.\n\n"
    t += table([[l, dist(val_code)[l], dist(val30)[l], dist(val)[l]] for l in L] + [['합계', len(val_code), len(val30), len(val)]], ['label', 'val 코드(신규)', 'val_v30(APIs.guru, 그대로)', 'val_v2'])
    t += f"\nval_v2 조건별: oas {cond(val)['oas']}건, oas_code {cond(val)['oas_code']}건. 선택 그룹: {', '.join(chosen)}\n\n"
    t += '## 2. manual 쿼터 25% (train 부분)\n\n'
    t += table([['구체 label', len(concrete)], ['manual 목표 round_half_up(C/3)', tgt], ['고정 manual(APIs.guru + 합성 + 검수 Gitea)', len(fixed)], ['  └ APIs.guru', sum(src(r)=='apisguru' for r in fixed)], ['  └ 합성', sum(src(r)=='synthetic' for r in fixed)], ['  └ 검수 Gitea', sum(src(r)=='gitea' for r in fixed)], ['비검수 Gitea manual', len(free)], ['남은 자리 → 선택', len(keep_free)], ['pool로 제외', len(pool)], ['규칙', quota_note]], ['항목', '값'])
    t += f"\n선택된 비검수 Gitea manual 태그: {dict(Counter(tag_of(r) for r in keep_free))}; pool 태그: {dict(Counter(r['meta']['quota_excluded']['tag'] for r in pool))}.\n\n"
    t += '## 3. 동결 결과\n\n'
    t += table([[l, dist(train)[l], f"{dist(train)[l]/len(train):.1%}", dist(code_train)[l], dist(val)[l], dist(code_val)[l]] for l in L] + [['합계', len(train), '100%', len(code_train), len(val), len(code_val)]], ['label', 'train_v2', '비율', 'train 코드 있음', 'val_v2', 'val 코드 있음'])
    t += f"\ntrain_v2 출처: {by_src(train)}; val_v2 출처: {by_src(val)}. 조건별 train: oas {cond(train)['oas']} / oas_code {cond(train)['oas_code']}; val: oas {cond(val)['oas']} / oas_code {cond(val)['oas_code']}.\n"
    t += f"\n**train 전체 manual 비율 {dist(train)[MANUAL]/len(train):.1%}, 코드 있는 레코드 manual 비율 {dist(code_train)[MANUAL]/len(code_train):.1%}** (참고 test_v30 코드 있음 5.7%).\n\n"
    t += '적용 규칙(train+val 레코드의 meta.v2_relabel): ' + ', '.join(f'{k} {rule_counts.get(k, 0)}' for k in rules) + '; VIS cap 1(제외 104, r3 파일), 쿼터 25%(pool ' + str(len(pool)) + ').\n\n'
    t += '## 4. 해시\n\n' + table([[k, v] for k, v in hashes.items()], ['파일', 'SHA-256'])
    t += '\n## 5. 라벨 기준 (AGENTS.md data-v2 라벨 기준)\n\n' + ''.join(f'- {c}\n' for c in criteria)
    t += '\n## 6. 알려진 한계\n\n- VIS(공개/비공개 분기)·AUTH_ANY(인증만, 객체 없음)는 manual로 두었다. test_v30에는 VIS 사례가 거의 없어(취약 API 코드는 단일 저장소) 이 보류의 정답률은 test로 측정되지 않는다.\n- extauth 변형(외부 인가 호출) 19건은 manual 유지. 의도 정책이 코드로 확인되지 않는다는 설계 가정이다.\n- Gitea 라벨은 사람 검수 56건(52+4) 외에는 LLM 라벨 + 규칙(R1\'·R4·variant_intended_policy)이며 사람 확정이 아니다. VIS cap으로 Gitea manual을 시그니처당 1건으로 줄여 Gitea 분포가 실제 API 분포와 다르다.\n- val_v2의 코드 부분은 그룹 분리했지만 합성은 train 합성과 생성 템플릿을 공유한다.\n'
    (ROOT / 'reports/data_v2_freeze.md').write_text(t, encoding='utf-8')
    # hashes json + AGENTS + DATA_CARD
    (ROOT / 'training/lora').mkdir(exist_ok=True); (ROOT / 'training/lora/data_v2').mkdir(exist_ok=True)
    (ROOT / 'training/lora/data_v2/data_v2_hashes.json').write_text(json.dumps(dict(data_version='data-v2', frozen='2026-10-23', sources=hashes, counts=dict(train=len(train), val=len(val), pool=len(pool), test_v30=269)), ensure_ascii=False, indent=2), encoding='utf-8')
    agents = ROOT / 'AGENTS.md'; txt = agents.read_text(encoding='utf-8')
    if '## data-v2 동결' not in txt:
        txt = txt.rstrip('\n') + '\n\n## data-v2 동결 (2026-10-23)\n\n데이터셋 버전 **data-v2** = train_v2 + val_v2 (평가: test_v30, eval-def v2). 프롬프트 v3.0.1 고정. 아래 파일은 이후 수정·재생성 금지. git tag `data-v2`.\n\n| 파일 | 건수 | SHA-256 |\n|---|---:|---|\n'
        txt += f"| datasets/blade/processed/train_v2.jsonl | {len(train)} | `{hashes['train_v2.jsonl']}` |\n| datasets/blade/processed/val_v2.jsonl | {len(val)} | `{hashes['val_v2.jsonl']}` |\n| datasets/blade/processed/train_v2_manual_pool.jsonl | {len(pool)} | `{hashes['train_v2_manual_pool.jsonl']}` |\n| datasets/blade/processed/test_v30.jsonl | 269 | `{hashes['test_v30.jsonl']}` |\n| training/data/prompts/policy_label_v3.0.1.md | - | `{hashes['policy_label_v3.0.1.md']}` |\n\n- 구성: train_v2_draft_r3(사람 검수 56 + 규칙 R1\'·R4·variant_intended_policy + VIS cap 1) → val_v2 그룹 분리(코드 레코드 10%) → train 부분 manual 쿼터 25%. 상세 reports/data_v2_freeze.md, DATA_CARD data-v2 절.\n- val_v2 = val_v30 52건(불변) + 코드 val. 사람 검수 레코드는 train에만 있다.\n"
        agents.write_text(txt, encoding='utf-8')
    card = ROOT / 'datasets/blade/DATA_CARD.md'; ctxt = card.read_text(encoding='utf-8')
    if '## data-v2 (2026-10-23 동결)' not in ctxt:
        sec = f"\n## data-v2 (2026-10-23 동결)\n\n- train_v2.jsonl {len(train)}건(SHA `{hashes['train_v2.jsonl']}`), val_v2.jsonl {len(val)}건(`{hashes['val_v2.jsonl']}`), 쿼터 pool {len(pool)}건. 평가 test_v30(불변) + eval-def v2. 프롬프트 v3.0.1(`{hashes['policy_label_v3.0.1.md'][:16]}…`).\n- 출처별: train {by_src(train)}, val {by_src(val)} (val_v30 52건 그대로 + 코드 val {len(val_code)}건, 그룹 단위 분리).\n- label 분포 train: {dist(train)} / val: {dist(val)}. 조건별 train oas {cond(train)['oas']}·oas_code {cond(train)['oas_code']}, val oas {cond(val)['oas']}·oas_code {cond(val)['oas_code']}. train manual {dist(train)[MANUAL]/len(train):.1%}, 코드 있는 레코드 manual {dist(code_train)[MANUAL]/len(code_train):.1%}.\n- 적용 규칙: human_review_v2(52)·human_review_v2_fix(1)·human_review_v2_r3(4), R1\'(SELF→owner_match, 검증 정밀도 100%), R2\'(검증만, 적용 레코드 0), R4(인증·인가 없음→public), variant_intended_policy(authonly 19), VIS cap 1(시그니처당 1건, 제외 104 보존), 쿼터 25%(apply_reviews_v2 공식). 미적용: R3\'(정밀도 78%).\n- 라벨 기준(AGENTS.md data-v2 라벨 기준):\n" + ''.join(f'  - {c}\n' for c in criteria) + "- 알려진 한계: VIS·AUTH_ANY는 manual로 둠(test_v30에 VIS 사례 거의 없어 검증 불가), extauth 변형은 manual 유지, Gitea 라벨 대부분은 LLM+규칙이며 사람 확정 아님, 합성 val은 train 합성과 템플릿 공유.\n"
        card.write_text(ctxt.rstrip('\n') + '\n' + sec, encoding='utf-8')
    assert_data_v1('end'); print(json.dumps(dict(train=len(train), val=len(val), val_code=len(val_code), pool=len(pool), missing_labels=missing, quota=quota_note, train_manual=round(dist(train)[MANUAL]/len(train), 4), code_manual=round(dist(code_train)[MANUAL]/len(code_train), 4), hashes={k: v[:16] for k, v in hashes.items()}), ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
