"""data-v2 r2: rule revisions (R1' VIS+SELF split, R2' write-method middleware rule, R3' order/public condition), re-validation on the 52 reviewed
records (with the user's fix), VIS de-duplication simulation (no label change), and listing of '기타'/'AUTH_ANY(객체 경로 있음)' records.
Input train_v2_draft_r1.jsonl (unchanged) -> output train_v2_draft_r2.jsonl. No API/training/freeze/quota. data-v1 hash guard at start and end."""
from __future__ import annotations
import importlib.util, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
spec = importlib.util.spec_from_file_location('r1', ROOT / 'scripts/apply_review_v2_r1.py'); r1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(r1)
P = ROOT / 'datasets/blade/processed'; IN = P / 'train_v2_draft_r1.jsonl'; OUT = P / 'train_v2_draft_r2.jsonl'; MD = ROOT / 'reports/review_v2_r2.md'
L, MANUAL = r1.L, r1.MANUAL; rd = r1.rd; mw_names = r1.mw_names; self_match = r1.self_match; loc = r1.loc
VIS_MW = {'repoAssignment', 'reqRepoReader', 'reqAnyRepoReader', 'orgAssignment', 'reqTeamReadAccess'}
WRITE_MW = {'reqRepoWriter', 'reqAdmin', 'reqSiteAdmin'}; ADMIN_MW = {'reqAdmin', 'reqSiteAdmin'}; WRITE_METHODS = {'POST', 'PUT', 'PATCH', 'DELETE'}
DATA_SCOPE_FN = ('Star', 'Watch', 'Subscription', 'Subscribe', 'Stopwatch', 'Notification', 'FindNotificationOptions', 'TrackedTime')  # requester is the data scope
ACTOR_PREFIX = ('Create', 'Update', 'Submit', 'Merge', 'Transfer', 'Generate', 'Dispatch', 'Edit', 'Delete', 'Add', 'Remove')             # requester is the actor
FIX = {'gitea:get:/repos/{owner}/{repo}/issues/{index}/subscriptions/check': ('owner_match', 'VIS+SELF 중 요청자가 데이터 범위인 경우 owner_match로 기준 통일')}
CRITERION_LINE = 'VIS+SELF: 요청자가 데이터 범위(본인 star·watch·구독·stopwatch·알림)이면 owner_match, 요청자가 행위자(댓글·머지·리뷰·릴리스·이전·생성·실행)이면 manual'

def self_kind(r):
    """('data'|'actor'|'other', matched string) for a SELF match, by the called function name."""
    s = self_match(r)
    if not s: return None, None
    fn = re.sub(r'\(.*$', '', s, flags=re.S).strip().split('.')[-1]
    if 'UserID' in s or any(k in fn for k in DATA_SCOPE_FN): return 'data', s
    if fn.startswith(ACTOR_PREFIX): return 'actor', s
    return 'other', s

def rule_r1(r):
    if r['label'] != MANUAL: return None
    kind, s = self_kind(r)
    if not kind: return None
    vis = bool(set(mw_names(r)) & VIS_MW)
    if not vis: return ('owner_match', f'SELF {loc(r)} "{s}"')
    if kind == 'data': return ('owner_match', f'VIS+SELF data-scope {loc(r)} "{s}"')
    return ('keep_manual', f'VIS+SELF {kind} "{s}"')

def rule_r2(r):
    if r['meta'].get('v30_override_reason') != 'visibility_dependent' or r['method'] not in WRITE_METHODS: return None
    hit = set(mw_names(r)) & WRITE_MW
    if not hit: return ('list_only', f'write {r["method"]} without write-permission middleware; chain {mw_names(r)}')
    return ('role_required', f'write {r["method"]} + {sorted(hit)} -> role_required (no restore)')

def rule_r3(r):
    if r['meta'].get('api_original_label') != 'public': return None
    s = set(mw_names(r)); kind, m = self_kind(r)
    if kind == 'data' or (kind and not (s & VIS_MW)): return ('owner_match', f'SELF {loc(r)} "{m}"')
    if s & ADMIN_MW: return ('role_required', f'{sorted(s & ADMIN_MW)}')
    if s & VIS_MW: return (MANUAL, f'VIS {sorted(s & VIS_MW)}')
    if 'reqToken' in s and not (s & r1.AUTHZ): return (MANUAL, 'AUTH_ANY: reqToken without authorization middleware')
    if 'reqToken' not in s and not (s & VIS_MW): return ('public', 'no reqToken and no visibility middleware -> public kept')
    return ('hold', f'chain {mw_names(r)} -> 판정 보류')

RULES = {'R1_self_split': rule_r1, 'R2_write_mw': rule_r2, 'R3_public_order': rule_r3, 'R4_noauth_public': r1.rule_r4}
NOCHANGE = {'keep_manual', 'list_only', 'hold'}

def main():
    verified = assert_data_v1('start'); review, criteria = r1.read_review()
    review[next(iter(FIX))] = dict(review[next(iter(FIX))], label=FIX[next(iter(FIX))][0])
    draft = {r['id']: r for r in rd(P / 'train_v2_draft.jsonl')}; rows = rd(IN); byid = {r['id']: r for r in rows}; gitea = [r for r in rows if r['id'].startswith('gitea:')]
    # 0. fix
    fid, (flabel, freason) = next(iter(FIX.items())); fr = byid[fid]; prev = fr['label']
    fr['meta']['v2_relabel'] = dict(**{'from': prev, 'to': flabel}, rule_id='human_review_v2_fix', evidence=freason); fr['label'] = flabel
    fix_changes = [('human_review_v2_fix', fid, prev, flabel)] if prev != flabel else []
    # 4. validation on the 52 (pre-human draft state, human label hidden)
    validation = {}
    for rid, fn in RULES.items():
        fired = []
        for i, rv in review.items():
            d = json.loads(json.dumps(draft[i])); res = fn(d)
            if not res or res[0] in NOCHANGE or res[0] == d['label']: continue
            fired.append((i, res[0], rv['label'], res[1]))
        n = len(fired); ok = sum(p == h for _, p, h, _ in fired)
        validation[rid] = dict(fired=n, correct=ok, precision=round(ok / n, 4) if n else None, applied=(n > 0 and ok / n >= .9), detail=fired)
    # apply in order R2 -> R3 -> R1 -> R4 on non-reviewed, not-yet-relabelled-by-rule records
    changes = list(fix_changes); listed = defaultdict(list); cand = defaultdict(list)
    for rid in ('R2_write_mw', 'R3_public_order', 'R1_self_split', 'R4_noauth_public'):
        fn = RULES[rid]
        for r in gitea:
            if r['meta'].get('human_reviewed_v2'): continue
            res = fn(r)
            if not res: continue
            if res[0] in NOCHANGE: listed[rid].append((r['id'], res[1])); continue
            if res[0] == r['label']: continue
            if not validation[rid]['applied']: cand[rid].append((r['id'], r['label'], res[0], res[1])); continue
            prev_rule = r['meta'].get('v2_relabel')
            r['meta']['v2_relabel'] = dict(**{'from': r['label'], 'to': res[0]}, rule_id=rid, evidence=res[1] + (f' (r1 {prev_rule["rule_id"]} 이후)' if prev_rule else ''))
            changes.append((rid, r['id'], r['label'], res[0])); r['label'] = res[0]
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    # stats helpers
    dist = lambda rs: {l: sum(r['label'] == l for r in rs) for l in L}
    has_code = lambda r: bool((r.get('controller_text') or '').strip() or ((r.get('controller_signals') or {}).get('raw_snippet') or '').strip())
    r1rows = rd(IN); code_r1 = [r for r in r1rows if has_code(r)]; code_r2 = [r for r in rows if has_code(r)]
    def reason(r):
        tags = set(r['meta'].get('review_tags') or []); s = set(mw_names(r)); kind, _ = self_kind(r)
        if r['meta'].get('human_reviewed_v2'):
            if 'VIS' in tags and 'SELF' in tags: return '복합(VIS·SELF, 검수)'
            if 'VIS' in tags: return 'VIS(검수)'
            if 'AUTH_ANY' in tags: return 'AUTH_ANY(검수)'
            return '기타(검수)'
        if (s & VIS_MW) and kind: return f'복합(VIS+SELF {kind})'
        if r['meta'].get('v30_override_reason') == 'visibility_dependent' or s & VIS_MW: return 'VIS'
        if 'reqToken' in s and not (s & r1.AUTHZ) and not re.search(r'\{[^}]+\}', r['path']): return 'AUTH_ANY'
        if 'reqToken' in s and not (s & r1.AUTHZ): return 'AUTH_ANY(객체 경로 있음)'
        return '기타'
    remaining = [r for r in gitea if r['label'] == MANUAL]; rem_reason = Counter(reason(r) for r in remaining)
    # 5. VIS de-dup simulation
    vis_rows = [r for r in remaining if reason(r) in ('VIS', 'VIS(검수)') or reason(r).startswith('복합')]
    sig = lambda r: (r['method'], tuple(sorted(set(mw_names(r)) - {'sudo', 'tokenRequiresScopes', 'checkTokenPublicOnly'})))
    groups = defaultdict(list)
    for r in vis_rows: groups[sig(r)].append(r)
    group_sizes = sorted(((k, len(v)) for k, v in groups.items()), key=lambda x: -x[1])
    def path_template(p): return re.sub(r'\{[^}]+\}', '{}', '/'.join(p.split('/')[:5]))
    sim = {}
    for cap in (1, 2, 3):
        rng = random.Random(42); keep_ids = set()
        for k, v in groups.items():
            pool = sorted(v, key=lambda r: r['id']); rng.shuffle(pool); chosen = []; seen_t = set()
            for r in pool:  # path diversity first
                t = path_template(r['path'])
                if t not in seen_t and len(chosen) < cap: chosen.append(r); seen_t.add(t)
            for r in pool:
                if len(chosen) >= cap: break
                if r not in chosen: chosen.append(r)
            keep_ids.update(r['id'] for r in chosen)
        dropped = {r['id'] for r in vis_rows} - keep_ids
        kept = [r for r in rows if r['id'] not in dropped]; kept_code = [r for r in kept if has_code(r)]
        sim[cap] = dict(vis_remaining=len(vis_rows) - len(dropped), dropped=len(dropped), total=len(kept), code_manual=round(dist(kept_code)[MANUAL] / len(kept_code), 4), manual=round(dist(kept)[MANUAL] / len(kept), 4), dist=dist(kept))
    # 6. listings
    def key_lines(r):
        t = r1.handler_text(r); ls = [l.strip() for l in t.splitlines() if r1.AUTHZ and re.search(r'ctx\.Doer|IsSigned|Forbidden|Permission|\.Can[A-Z]\w*\(|access_model|IsAdmin|IsOwner|HasOrgOrUserVisible|IsOrgMember|Visibility|IsPrivate', l)]
        return ' / '.join(ls[:3])[:300] or t.splitlines()[0][:120] if t else ''
    etc = [(r['id'], r['method'], ', '.join(mw_names(r)) or '(none)', key_lines(r)) for r in remaining if reason(r) == '기타']
    aa = [(r['id'], r['method'], ', '.join(mw_names(r)), key_lines(r)) for r in remaining if reason(r) == 'AUTH_ANY(객체 경로 있음)']
    # report
    def table(rs, header, right_from=1):
        return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c).replace('|', '&#124;') for c in r) + ' |\n' for r in rs)
    chg = Counter(c[0] for c in changes)
    t = '# data-v2 r2 — 규칙 수정·재적용 + VIS 중복 축소 시뮬레이션 (동결 전) — 2026-10-23\n\n'
    t += f"data-v1 해시 assert 통과(시작·종료): {', '.join(k.split('/')[-1] + ' ' + v for k, v in verified.items())}. 입력 train_v2_draft_r1.jsonl(불변) → 출력 train_v2_draft_r2.jsonl(971). 검수 정정 1건(rule_id=human_review_v2_fix): {fid} {prev} → {flabel}.\n\n"
    t += '규칙 적용 순서: 사람 검수(정정 포함) > R2\'(쓰기 메서드 + 쓰기 권한 미들웨어 → role_required) > R3\'(public 재판정: SELF(데이터 범위) → admin → VIS → AUTH_ANY; public 유지는 reqToken 없음 AND 가시성 미들웨어 없음) > R1\'(SELF 분리: 데이터 범위 → owner_match, 행위자 → manual) > R4(인증·인가 미들웨어 없음 → public). 데이터 범위 함수명 상수 DATA_SCOPE_FN=' + str(DATA_SCOPE_FN) + ', 행위자 접두사 ACTOR_PREFIX=' + str(ACTOR_PREFIX) + '.\n\n'
    t += '## 1. 재검증 (검수 52건, 정정 반영, 사람 라벨 가림, draft 원본 상태에 적용)\n\n'
    t += table([[k, v['fired'], v['correct'], v['precision'] if v['precision'] is not None else '-', '적용' if v['applied'] else '미적용(후보만)'] for k, v in validation.items()], ['규칙', '발동', '일치', '정밀도', '판정'])
    for k, v in validation.items():
        if v['detail']: t += f'\n{k} 발동 상세:\n\n' + table([[i, p, h, '○' if p == h else '✗', e[:100]] for i, p, h, e in v['detail']], ['id', '규칙 라벨', '사람 라벨', '일치', '근거'])
    t += '\n## 2. 적용 건수 (r1 이후 추가 변경)\n\n' + table([[k, chg.get(k, 0)] for k in ['human_review_v2_fix'] + list(RULES)], ['rule_id', '변경 건수'])
    for k, lst in listed.items():
        if lst: t += f'\n### {k} 변경 없이 목록만 ({len(lst)}건)\n\n' + table([[i, e[:120]] for i, e in lst], ['id', '사유'])
    for k, lst in cand.items():
        if lst: t += f'\n### {k} 미적용 후보 ({len(lst)}건, 라벨 변경 없음)\n\n' + table([[i, a, b, e[:110]] for i, a, b, e in lst], ['id', '현재', '규칙 제안', '근거'])
    t += '\n## 3. 변경 전후 label 분포 (r1 → r2)\n\n'
    g1 = [r for r in r1rows if r['id'].startswith('gitea:')]
    t += table([[l, dist(r1rows)[l], dist(rows)[l], dist(code_r1)[l], dist(code_r2)[l], dist(g1)[l], dist(gitea)[l]] for l in L] + [['합계', len(r1rows), len(rows), len(code_r1), len(code_r2), len(g1), len(gitea)]], ['label', '전체 r1', '전체 r2', '코드 있음 r1', '코드 있음 r2', 'Gitea r1', 'Gitea r2'])
    t += f"\n코드 있는 레코드 manual 비율: {dist(code_r1)[MANUAL]/len(code_r1):.1%} → {dist(code_r2)[MANUAL]/len(code_r2):.1%}. Gitea manual {dist(g1)[MANUAL]} → {dist(gitea)[MANUAL]}.\n\n"
    t += '## 4. 남은 Gitea manual 사유 분포\n\n' + table(sorted(rem_reason.items(), key=lambda x: -x[1]), ['사유', '건수'])
    t += f"\n## 5. VIS 중복 축소 시뮬레이션 (라벨 변경·적용 없음)\n\n대상: 남은 Gitea manual 중 VIS·VIS(검수)·복합 {len(vis_rows)}건. 시그니처 = HTTP 메서드 + 정규화한 미들웨어 이름 집합(sudo·tokenRequiresScopes·checkTokenPublicOnly 제외). 그룹 {len(groups)}개.\n\n"
    t += table([[m, ', '.join(k) or '(none)', n] for (m, k), n in group_sizes[:25]], ['메서드', '미들웨어 시그니처', '건수']) + (f'\n(상위 25개 그룹만 표시; 나머지 {len(group_sizes)-25}개 그룹)\n' if len(group_sizes) > 25 else '')
    rows_sim = [['축소 없음(현재 r2)', len(vis_rows), 0, len(rows), f"{dist(code_r2)[MANUAL]/len(code_r2):.1%}", f"{dist(rows)[MANUAL]/len(rows):.1%}", ' / '.join(f'{l[:6]} {dist(rows)[l]}' for l in L)]]
    for cap, s in sim.items(): rows_sim.append([f'시그니처당 최대 {cap}건', s['vis_remaining'], s['dropped'], s['total'], f"{s['code_manual']:.1%}", f"{s['manual']:.1%}", ' / '.join(f'{l[:6]} {s["dist"][l]}' for l in L)])
    rows_sim.append(['참고: test_v30 코드 있음', '-', '-', 265, '5.7%', '5.6%', '-'])
    t += '\n' + table(rows_sim, ['안', '남는 VIS', '제외', '전체 건수', '코드 있음 manual', '전체 manual', 'label 분포'], 1)
    t += f"\n## 6. '기타' {len(etc)}건 (라벨 변경 없음, 사용자 확인용)\n\n" + table(etc, ['id', 'method', '미들웨어 체인', '핸들러 핵심 줄'])
    t += f"\n## 7. 'AUTH_ANY(객체 경로 있음)' {len(aa)}건 (라벨 변경 없음)\n\n" + table(aa, ['id', 'method', '미들웨어 체인', '핸들러 핵심 줄'])
    t += '\n## 8. AGENTS.md 추가 기준\n\n- ' + CRITERION_LINE + '\n\n원자료: train_v2_draft_r2.jsonl(meta.v2_relabel), scripts/apply_review_v2_r2.py.\n'
    MD.write_text(t, encoding='utf-8')
    a = ROOT / 'AGENTS.md'; txt = a.read_text(encoding='utf-8')
    if CRITERION_LINE not in txt:
        txt = txt.replace('- 적용 기록: reports/review_v2_r1.md', f'- {CRITERION_LINE}\n- 적용 기록: reports/review_v2_r1.md, reports/review_v2_r2.md', 1); a.write_text(txt, encoding='utf-8')
    assert_data_v1('end')
    print(json.dumps(dict(changes=dict(chg), validation={k: {kk: vv for kk, vv in v.items() if kk != 'detail'} for k, v in validation.items()}, listed={k: len(v) for k, v in listed.items()}, cand={k: len(v) for k, v in cand.items()},
                          code_manual=f"{dist(code_r1)[MANUAL]/len(code_r1):.3f}->{dist(code_r2)[MANUAL]/len(code_r2):.3f}", remaining=dict(rem_reason), vis_groups=len(groups), sim={c: {k: v for k, v in s.items() if k != 'dist'} for c, s in sim.items()}, etc=len(etc), auth_any_obj=len(aa)), ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
