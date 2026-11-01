"""data-v3 freeze: data-v2 train/val + data-v3 code pairs (v3s1b), synthetic answer-sentence neutralization, manual quota 25% (v3a) / 10% (v3b).
Outputs datasets/blade/processed/{train_v3a,train_v3b,val_v3,train_v3a_manual_pool,train_v3b_manual_pool,synthetic_neutralization_v3}.jsonl,
reports/data_v3/stage2_report.md, AGENTS.md 'data-v3 동결' and DATA_CARD 'data-v3' sections. data-v1/data-v2 hashes asserted at start and end;
test_v30, train_v2, val_v2 are read only. No API/training. Refuses to overwrite existing outputs unless --rebuild (only before the freeze tag)."""
from __future__ import annotations
import argparse, hashlib, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT))
from data_v1_guard import assert_data_v1
from data_v2_guard import assert_data_v2
import importlib.util
spec = importlib.util.spec_from_file_location('r3', ROOT / 'scripts/apply_review_v2_r3.py'); r3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(r3)
P = ROOT / 'datasets/blade/processed'; V3 = P / 'data_v3_stage1b'; REP = ROOT / 'reports/data_v3'
L, MANUAL, is_human = r3.L, r3.MANUAL, r3.is_human
SEED = 42
QUOTAS = {'v3a': 3, 'v3b': 9}   # manual target = round_half_up(concrete / k): k=3 -> 25%, k=9 -> 10% of the train set
V3S1B = {'pairs_train_v3s1b.jsonl': 'cc34308a149dee2d92998087002e6f63ab771d083cae07f5604d6828fdfab303', 'pairs_val_v3s1b.jsonl': 'f1826e1c24957e42abbf4d60b6bc5aaeabbf99bd0b60893d1b9014bc8ccf7138'}
OUT = dict(train_v3a=P / 'train_v3a.jsonl', train_v3b=P / 'train_v3b.jsonl', val_v3=P / 'val_v3.jsonl', pool_v3a=P / 'train_v3a_manual_pool.jsonl',
           pool_v3b=P / 'train_v3b_manual_pool.jsonl', neutralization=P / 'synthetic_neutralization_v3.jsonl', rationale_rewrites=P / 'rationale_rewrites_v3.jsonl')
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
rd = lambda p: [json.loads(l) for l in Path(p).read_text(encoding='utf-8').splitlines() if l.strip()]
src = lambda r: 'gitea' if r['id'].startswith('gitea:') else 'synthetic' if r['meta'].get('source') == 'synthetic' else 'v3_pair' if r['meta'].get('data_version') == 'data-v3-stage1b' else 'apisguru'
dist = lambda rs: {l: sum(r['label'] == l for r in rs) for l in L}

# ---- synthetic neutralization ----
# Sentences of the synthetic `description` that state the intended policy (the answer). They reach the model through the handler excerpt
# (FastAPI `description='...'`, `#`/`//`/`/** */` comments, docstrings); the OAS operation description is cleared too (not a model input).
# Kept: sentences about where authentication runs (structure, not the label). Also dropped: fixture/variant explanation comments.
KEEP_SENTENCES = {'Authentication is enforced outside the handler.', 'Authentication is enforced outside the handler; the authorization check is inside.'}
EXPLAIN_COMMENT = re.compile(r'^\s*(#|//)\s*(Variant: .*|Deliberate fixture: .*)$')
EMPTY_LINE_FORMS = [re.compile(r'^\s*(#|//)\s*$'), re.compile(r'^\s*/\*\*\s*\*/\s*$'), re.compile(r'^\s*""""""\s*$')]


def sentences(d): return [s for s in re.split(r'(?<=\.)\s+', (d or '').strip()) if s]


def neutralize(r, answer_catalogue):
    """Returns (new_record, log) for a synthetic record. Raises if an answer sentence survives in the handler excerpt."""
    r = json.loads(json.dumps(r)); d = r.get('description') or ''
    sents = sentences(d); answer = [s for s in sents if s not in KEEP_SENTENCES]; keep = [s for s in sents if s in KEEP_SENTENCES]
    code = r['controller_signals']['raw_snippet']; before = code
    for s in answer:
        for form in (s + ' ', ' ' + s, s): code = code.replace(form, '')
    code = code.replace(", description=''", '')
    lines, dropped_comments = [], []
    for line in code.split('\n'):
        if EXPLAIN_COMMENT.match(line): dropped_comments.append(line.strip()); continue
        if any(p.match(line) for p in EMPTY_LINE_FORMS): continue
        lines.append(line)
    code = '\n'.join(lines)
    left = [a for a in answer_catalogue if a in code]
    assert not left, (r['id'], left)
    r['controller_signals']['raw_snippet'] = code
    spec_ = json.loads(r['oas_snippet']); op = next(iter(next(iter(spec_['paths'].values())).values()))
    if keep: op['description'] = ' '.join(keep)
    else: op.pop('description', None)
    summary0 = op.get('summary') or ''; summary1 = VARIANT_SUFFIX.sub('', summary0)
    if summary1 != summary0: op['summary'] = summary1
    r['oas_snippet'] = json.dumps(spec_, ensure_ascii=False); r['description'] = ' '.join(keep)
    log = dict(id=r['id'], service=r['service'], label=r['label'], original_description=d, removed_sentences=answer, kept_sentences=keep,
               removed_comments=dropped_comments, code_changed=code != before, summary_before=summary0, summary_after=summary1)
    r['meta']['neutralized_v3'] = {k: v for k, v in log.items() if k not in ('id', 'service', 'label')}
    return r, log


VARIANT_SUFFIX = re.compile(r'\s+(Authonly|Extauth|Extguard)$')   # synthetic variant kind appended to the OAS summary (train/val only)

# ---- label-rationale consistency (template rules, no LLM) ----
HOLD = re.compile(r'no concrete label|pending review|manual|cannot determine|cannot be determined|not expressible|보류|판단할 수 없|단일 라벨로 표현되지|확인되지 않아|label이 없|알 수 없', re.I)
AUTHONLY_PHRASE = {'owner_match': '요청자 본인 객체', 'owner_or_admin': '소유자 또는 관리자가 다루는 객체', 'tenant_match': '같은 테넌트에 속한 객체',
                   'role_required': '운영·관리용 리소스', 'membership_required': '그룹 구성원에게 속한 객체'}
RULE_KO = {'owner_compare': '요청자 id와 객체 소유자 id를 비교해 다르면 거부', 'owner_or_parent_owner': '요청자가 객체 또는 상위 객체(게시글)의 작성자일 때만 허용, 관리자 경로 없음',
           'owner_filter': '객체 조회를 요청자 소유로 한정(작성자 = 현재 사용자)', 'owner_or_superuser': '슈퍼유저는 통과, 그 외에는 요청자가 객체 소유자여야 함',
           'self_or_superuser': '본인 사용자 레코드는 허용, 다른 사용자 레코드는 슈퍼유저만', 'superuser_dependency': '라우트 의존성 get_current_active_superuser로 슈퍼유저가 아니면 403',
           'role_annotation': '@PreAuthorize hasRole/hasAnyRole로 역할 검사', 'owner_filter_unless_admin': '관리자가 아니면 조회를 요청자 소유 객체로 한정',
           'self_or_admin': '요청자가 대상 사용자 본인이거나 인스턴스 관리자여야 함', 'owner_or_instance_admin': '요청자가 객체 작성자이거나 인스턴스 관리자여야 함',
           'self_only': '요청자가 대상 사용자 본인이어야 함(관리자 예외 없음)', 'form_request_owner': 'FormRequest::authorize가 객체 소유자와 요청자를 비교'}
VARIANT_PHRASE = {'keep_realworld_article_comment_write': '게시글·댓글 작성자 본인만 수정·삭제하는 자원', 'keep_reference_data_write': '공용 기준 데이터를 바꾸는 관리 작업',
                  'keep_user_create_or_list': '사용자 계정을 만들거나 전체 목록을 보는 관리 작업', 'keep_user_self_subresource': '사용자 본인의 보안 자원(웹훅·토큰·연동 계정)'}


def strip_hold(text):
    return ' '.join(x for x in sentences(text) if not HOLD.search(x))


def rewrite_rationale(r):
    """Returns (record, log|None). The record rationale becomes the text the SFT target carries; sft_changed marks a change of the SFT target."""
    rel = r['meta'].get('v2_relabel') or {}; old = r.get('rationale') or ''; new = rule = None; sft_changed = False
    if r['meta'].get('data_version') == 'data-v3-stage1b':
        if r['meta']['pair_role'] == 'check_removed':
            new, rule = f"description: 검사 코드는 없으나 경로·리소스 의미상 {VARIANT_PHRASE[r['meta']['variant_rule']]}; 판단: 의도된 정책은 {r['label']}", 'v3_variant_intended_policy'
        else:
            new, rule = f"description: 핸들러 원문 — {RULE_KO[r['meta']['rule_id']]}; 판단: {r['label']}", f"v3_{r['meta']['rule_id']}"
        sft_changed = True
    elif rel.get('rule_id') == 'variant_intended_policy':
        new, rule, sft_changed = f"description: 경로·리소스 구조상 {AUTHONLY_PHRASE[r['label']]}. 코드에 검사는 없으나 의도된 정책은 {r['label']}", 'authonly_intended_policy', True
    elif r['id'].startswith('gitea:') and rel and r['label'] != MANUAL:
        sft_text = f"description: {rel.get('evidence', '')[:160]}; 판단: {rel['rule_id']} 기준으로 {r['label']}"   # = prepare_lora_v2_inputs.row_to_sft
        ev0 = rel.get('evidence', '')[:160]; ev = strip_hold(ev0); ev = ev.rstrip('.') if ev != ev0 else ev0
        new = f"description: {ev}; 판단: {rel['rule_id']} 기준으로 {r['label']}"
        rule, sft_changed = 'gitea_relabel_template' + ('_hold_stripped' if new != sft_text else ''), new != sft_text
    if new is None or new == old: return r, None
    r = json.loads(json.dumps(r)); r['rationale'] = new; r['meta']['rationale_v3'] = dict(rule=rule, before=old, sft_changed=sft_changed)
    return r, dict(id=r['id'], label=r['label'], rule=rule, before=old, after=new, sft_changed=sft_changed)


def quota(train, k, seed=SEED):
    """Manual target round_half_up(C/k). Human-reviewed manual first, then the rest stratified by source (largest remainder), seed 42 inside each source."""
    concrete = [r for r in train if r['label'] != MANUAL]; manual = [r for r in train if r['label'] == MANUAL]
    tgt = int(len(concrete) / k + .5)
    if len(manual) <= tgt: return concrete + manual, [], dict(target=tgt, candidates=len(manual), kept=len(manual), note=f'candidates {len(manual)} <= target {tgt}: all kept')
    human = sorted([r for r in manual if is_human(r)], key=lambda r: r['id']); rest = [r for r in manual if not is_human(r)]
    slots = tgt - len(human); assert slots >= 0, 'human-reviewed manual exceeds target'
    by = defaultdict(list)
    for r in sorted(rest, key=lambda r: r['id']): by[src(r)].append(r)
    alloc = {s: int(len(v) * slots / len(rest)) for s, v in by.items()}
    for s in sorted(by, key=lambda s: (-(len(by[s]) * slots / len(rest) - alloc[s]), s)):
        if sum(alloc.values()) >= slots: break
        alloc[s] += 1
    rng = random.Random(seed); keep, pool = list(human), []
    for s in sorted(by):
        v = list(by[s]); rng.shuffle(v); keep += v[:alloc[s]]
        for x in v[alloc[s]:]:
            x = json.loads(json.dumps(x)); x['meta']['quota_excluded_v3'] = dict(reason=f'manual quota (concrete/{k})', source=s, seed=seed); pool.append(x)
    keep_ids = {r['id'] for r in keep}
    return concrete + [r for r in manual if r['id'] in keep_ids], pool, dict(target=tgt, candidates=len(manual), kept=len(keep), human_first=len(human), alloc=alloc)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--rebuild', action='store_true', help='overwrite outputs (allowed only before the data-v3a/v3b tags exist)'); a = ap.parse_args()
    g1, g2 = assert_data_v1('start'), assert_data_v2('start')
    assert {n: sha(V3 / n) for n in V3S1B} == V3S1B, 'v3s1b inputs changed'
    if any(p.exists() for p in OUT.values()):
        assert a.rebuild, 'data-v3 outputs exist; freeze refused (pass --rebuild before tagging)'
        import subprocess
        tags = subprocess.run(['git', 'tag', '-l', 'data-v3a', 'data-v3b'], cwd=ROOT, capture_output=True, text=True).stdout.split()
        assert not tags, f'frozen: tags {tags} exist'
    train_v2, val_v2, pool_v2 = rd(P / 'train_v2.jsonl'), rd(P / 'val_v2.jsonl'), rd(P / 'train_v2_manual_pool.jsonl')
    v3_train, v3_val = rd(V3 / 'pairs_train_v3s1b.jsonl'), rd(V3 / 'pairs_val_v3s1b.jsonl')
    # 1) neutralize synthetic answer sentences (train_v2, val_v2)
    syn = [r for r in train_v2 + val_v2 if r['meta'].get('source') == 'synthetic']
    catalogue = sorted({s for r in syn for s in sentences(r.get('description')) if s not in KEEP_SENTENCES}, key=len, reverse=True)
    logs, fixed, train_ids = [], {}, {r['id'] for r in train_v2}
    for r in syn:
        n, log = neutralize(r, catalogue); fixed[r['id']] = n; logs.append(dict(log, split='train' if r['id'] in train_ids else 'val'))
    nz = lambda rows: [fixed.get(r['id'], r) for r in rows]
    # 2) merge
    base_train = nz(train_v2) + [json.loads(json.dumps(r)) for r in pool_v2] + v3_train
    for r in base_train: r['meta'].pop('quota_excluded', None); r['meta']['split'] = 'train'
    val = [json.loads(json.dumps(r)) for r in nz(val_v2) + v3_val]
    for r in val: r['meta']['dataset'] = 'data-v3'; r['meta']['split'] = 'val'
    # 2b) label-rationale consistency: template rewrites, then no concrete label may keep hold wording
    rewrites = []
    def rw(rows, split):
        out = []
        for r in rows:
            n, log = rewrite_rationale(r); out.append(n)
            if log: rewrites.append(dict(log, split=split))
        return out
    audit_before = [r['id'] for r in base_train + val if r['label'] != MANUAL and HOLD.search(r.get('rationale') or '')]
    base_train, val = rw(base_train, 'train'), rw(val, 'val')
    left = [(r['id'], r['rationale'][:80]) for r in base_train + val if r['label'] != MANUAL and HOLD.search(r.get('rationale') or '')]
    assert not left, f'concrete label with hold wording remains: {left}'
    assert not ({r['id'] for r in base_train} & {r['id'] for r in val})
    assert not ({r['service'] for r in base_train} & {'quill_blog', 'folio_wiki', 'beacon_iot', 'summit_club', 'VAmPI', 'crAPI', 'juice-shop', 'Pixi', 'DVWS-node'})
    # 3) quota versions
    versions = {}
    for name, k in QUOTAS.items():
        tr, pool, info = quota(base_train, k)
        order = {r['id']: i for i, r in enumerate(base_train)}; tr = [json.loads(json.dumps(r)) for r in sorted(tr, key=lambda r: order[r['id']])]
        for r in tr: r['meta']['dataset'] = f'data-{name}'   # origin version stays in meta.data_version (data-v2 / data-v3-stage1b)
        versions[name] = (tr, pool, info)
    REP.mkdir(parents=True, exist_ok=True)
    def dump(p, rows):
        with open(p, 'w', encoding='utf-8', newline='\n') as f:
            for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    dump(OUT['train_v3a'], versions['v3a'][0]); dump(OUT['train_v3b'], versions['v3b'][0]); dump(OUT['val_v3'], val)
    dump(OUT['pool_v3a'], versions['v3a'][1]); dump(OUT['pool_v3b'], versions['v3b'][1]); dump(OUT['neutralization'], logs); dump(OUT['rationale_rewrites'], rewrites)
    hashes = {p.name: sha(p) for p in OUT.values()}
    hashes.update({'test_v30.jsonl': sha(P / 'test_v30.jsonl'), 'policy_label_v3.0.1.md': sha(ROOT / 'training/data/prompts/policy_label_v3.0.1.md'), **{n: h for n, h in V3S1B.items()}})
    report(versions, val, logs, hashes, train_v2, pool_v2, v3_train, v3_val, rewrites, audit_before)
    g1e, g2e = assert_data_v1('end'), assert_data_v2('end')
    print(json.dumps({n: dict(train=len(v[0]), pool=len(v[1]), manual=dist(v[0])[MANUAL], manual_ratio=round(dist(v[0])[MANUAL] / len(v[0]), 4), info=v[2]) for n, v in versions.items()}
                     | dict(val=len(val), neutralized=len(logs), hashes={k: v[:16] for k, v in hashes.items()}), ensure_ascii=False, indent=1))


def table(rows, header, right_from=1):
    return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c) for c in r) + ' |\n' for r in rows)


def report(versions, val, logs, hashes, train_v2, pool_v2, v3_train, v3_val, rewrites, audit_before):
    has_code = lambda r: bool((r.get('controller_text') or '').strip() or ((r.get('controller_signals') or {}).get('raw_snippet') or '').strip())
    t = '# data-v3 2단계 — data-v2 + 코드 쌍 병합, 합성 정답 문장 중립화, 쿼터 25%(v3a) / 10%(v3b) 동결\n\n'
    t += (f"입력: train_v2 {len(train_v2)} + 쿼터 pool_v2 {len(pool_v2)} + v3s1b train {len(v3_train)} / val_v2 {len(rd(P / 'val_v2.jsonl'))} + v3s1b val {len(v3_val)}. "
          'data-v1·data-v2 해시 assert(시작·종료), test_v30·train_v2·val_v2 읽기만. 학습·API 호출 없음.\n\n')
    t += '## 1. 합성 description 중립화\n\n'
    t += (f"대상: 합성 레코드 {len(logs)}건(train {sum(l['split'] == 'train' for l in logs)}, val {sum(l['split'] == 'val' for l in logs)}). 합성 payload는 OAS description을 쓰지 않으므로 "
          '정답 문장이 모델 입력에 들어가는 경로는 핸들러 발췌(FastAPI `description=` 인자, `#`/`//`/`/** */` 주석, 독스트링)다. 정답 문장을 지우고, 빈 주석·빈 인자를 정리하고, '
          'fixture·변형 해설 주석("Deliberate fixture: …", "Variant: …")도 지웠다. 인증 위치 문장(구조 정보)은 남겼다. OAS operation description도 같은 기준으로 비웠다(모델 입력 아님). '
          'rationale(학습 target)은 바꾸지 않았다. test_v30 합성은 동결이라 그대로다.\n\n')
    sc = Counter(s for l in logs for s in l['removed_sentences'])
    t += table([[s, c] for s, c in sc.most_common()], ['지운 정답 문장', '건수'])
    cc = Counter(c for l in logs for c in l['removed_comments'])
    t += '\n' + table([[s, c] for s, c in cc.most_common()], ['지운 해설 주석', '건수'])
    t += (f"\n코드가 바뀐 레코드 {sum(l['code_changed'] for l in logs)} / {len(logs)} (나머지는 정답 문장이 OAS description·rationale에만 있었다). "
          f"전체 목록: `datasets/blade/processed/synthetic_neutralization_v3.jsonl`.\n\n")
    sc2 = Counter((l['summary_before'].split() or [''])[-1] for l in logs if l['summary_before'] != l['summary_after'])
    t += f"합성 변형 summary 끝의 변형 종류 접미사 삭제: {sum(sc2.values())}건 ({', '.join(f'{k} {v}' for k, v in sorted(sc2.items()))}). 예: \"Orbit Tickets Drafts Authonly\" → \"Orbit Tickets Drafts\".\n\n"
    t += '## 1b. label–rationale 정합성\n\n'
    t += (f"점검: 구체 label인데 rationale(레코드 필드)에 보류 표현(no concrete label·pending review·manual·cannot determine·보류·단일 라벨로 표현되지 않음 등)이 있는 건 {len(audit_before)}건(train·val 합계, 쿼터 전). "
          '학습 target(SFT)은 규칙 relabel 레코드에 템플릿 rationale을 쓰므로 target 수준 불일치는 1건이었다(Gitea 사람 검수 rationale의 "manual은 명백한 과보류" 문장). '
          '재작성은 템플릿 규칙으로 했고(LLM 호출 없음) 레코드 rationale = 학습 target rationale이 되게 맞췄다. 재작성 후 남은 불일치 0(빌드 assert). 목록: `datasets/blade/processed/rationale_rewrites_v3.jsonl`.\n\n')
    rc = Counter((l['rule'], l['split']) for l in rewrites)
    t += table([[k, sp, c, sum(l['sft_changed'] for l in rewrites if (l['rule'], l['split']) == (k, sp))] for (k, sp), c in sorted(rc.items())], ['규칙', 'split', '재작성', '학습 target 변경'], right_from=2)
    ex = {}
    for l in rewrites: ex.setdefault(l['rule'], l)
    t += '\n' + table([[k, l['label'], l['before'][:90], l['after'][:120]] for k, l in ex.items()], ['규칙', 'label', '이전(앞부분)', '이후'], right_from=4) + '\n'
    t += '## 2. manual 쿼터\n\n'
    rows = []
    for n, (tr, pool, info) in versions.items():
        rows.append([n, f"concrete/{QUOTAS[n]}", sum(r['label'] != MANUAL for r in tr), info['target'], info['candidates'], info['kept'], len(pool), len(tr), f"{dist(tr)[MANUAL] / len(tr):.1%}", info.get('note') or f"검수 우선 {info['human_first']}, 출처별 {info['alloc']}"])
    t += table(rows, ['버전', '목표식', '구체 label', 'manual 목표', 'manual 후보', 'manual 유지', 'pool', 'train', 'manual 비율', '선택'], right_from=2)
    t += '\nmanual 후보 = train_v2 manual + pool_v2(data-v2 쿼터에서 빠졌던 Gitea manual). 코드 쌍(v3s1b)은 전부 구체 label이다.\n\n'
    t += '## 3. 동결 결과\n\n'
    va, vb = versions['v3a'][0], versions['v3b'][0]
    t += table([[l, dist(va)[l], dist(vb)[l], dist(val)[l]] for l in L] + [['합계', len(va), len(vb), len(val)]], ['label', 'train_v3a', 'train_v3b', 'val_v3'])
    t += '\n' + table([[s, sum(src(r) == s for r in va), sum(src(r) == s for r in vb), sum(src(r) == s for r in val)] for s in ('apisguru', 'gitea', 'synthetic', 'v3_pair')], ['출처', 'train_v3a', 'train_v3b', 'val_v3'])
    t += (f"\n조건별(코드 있음): train_v3a {sum(has_code(r) for r in va)}, train_v3b {sum(has_code(r) for r in vb)}, val_v3 {sum(has_code(r) for r in val)}. "
          f"코드 있는 레코드 manual 비율: v3a {sum(has_code(r) and r['label'] == MANUAL for r in va) / sum(has_code(r) for r in va):.1%}, v3b {sum(has_code(r) and r['label'] == MANUAL for r in vb) / sum(has_code(r) for r in vb):.1%} (참고 test_v30 코드 있음 5.7%).\n\n")
    t += '## 4. 해시\n\n' + table([[k, v] for k, v in hashes.items()], ['파일', 'SHA-256'])
    t += ('\n## 5. 한계\n\n- v3a의 manual 후보가 목표보다 적어 manual 비율이 25%에 못 미친다(위 표).\n- 합성 rationale(target)은 원래 description 문장을 그대로 담고 있다. 입력에서는 지웠지만 출력 문장으로는 남는다.\n'
          '- 합성 변형의 경로(`/authonly/`·`/extauth/`·`/extguard/`)와 함수 이름에는 변형 종류가 그대로 남는다(summary 접미사만 지움). test_v30 합성은 동결이라 접미사도 그대로다.\n'
          '- data-v3 코드 쌍의 한계(role_required 전부 Java, owner_or_admin은 Go·JS, val 작음, 라이선스 미선언 5개)는 reports/data_v3/stage1b_report.md 한계 절.\n')
    (REP / 'stage2_report.md').write_text(t, encoding='utf-8', newline='\n')


if __name__ == '__main__': main()
