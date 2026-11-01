"""data-v2 r3 (pre-freeze): user-confirmed labels (human_review_v2_r3), synthetic variant relabel (variant_intended_policy), VIS cap = 1 per
middleware signature (seed 42, path diversity first; human-reviewed records always kept). Input train_v2_draft_r2.jsonl (unchanged) ->
train_v2_draft_r3.jsonl + train_v2_draft_r3_vis_excluded.jsonl. Quota 25% is only dry-run reported, never applied. No API/training/freeze."""
from __future__ import annotations
import importlib.util, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
spec = importlib.util.spec_from_file_location('r1', ROOT / 'scripts/apply_review_v2_r1.py'); r1 = importlib.util.module_from_spec(spec); spec.loader.exec_module(r1)
spec2 = importlib.util.spec_from_file_location('r2', ROOT / 'scripts/apply_review_v2_r2.py'); r2 = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(r2)
P = ROOT / 'datasets/blade/processed'; IN = P / 'train_v2_draft_r2.jsonl'; OUT = P / 'train_v2_draft_r3.jsonl'; EXC = P / 'train_v2_draft_r3_vis_excluded.jsonl'; MD = ROOT / 'reports/review_v2_r3.md'
L, MANUAL = r1.L, r1.MANUAL; rd = r1.rd; mw_names = r1.mw_names
HUMAN_R3 = {'gitea:post:/users/{username}/tokens': ('owner_or_admin', 'reqSelfOrAdmin'), 'gitea:patch:/notifications/threads/{id}': ('owner_or_admin', 'getThread: 본인 또는 admin'),
            'gitea:post:/user/actions/variables/{variablename}': ('owner_match', 'ownerID := ctx.Doer.ID'), 'gitea:delete:/user/applications/oauth2/{id}': ('owner_match', 'DeleteOAuth2Application(appID, ctx.Doer.ID)')}
VIS_TAG_MW = r2.VIS_MW | {'reqPackageAccess', 'reqExploreSignIn', 'reqUsersExploreEnabled', 'context.PackageAssignmentAPI'}
CRITERION = '인가 검사가 코드에서 빠졌어도 경로·스키마로 의도된 정책이 드러나면 그 정책을 label로 한다(test_v30 취약 API와 동일). 외부 인가처럼 의도를 코드로 확인할 수 없는 경우만 manual.'
VARIANT_BASE = {}
for y in (ROOT / 'datasets/blade/raw/synthetic_v2/variants').glob('*/intended_labels.yaml'):
    for ep in yaml.safe_load(y.read_text(encoding='utf-8'))['endpoints']: VARIANT_BASE[ep['id']] = (ep.get('base_label'), str(y.relative_to(ROOT)).replace('\\', '/'))

def is_human(r): return bool(r['meta'].get('human_reviewed_v2')) or str((r['meta'].get('v2_relabel') or {}).get('rule_id', '')).startswith('human_review')
def reason(r):
    tags = set(r['meta'].get('review_tags') or []); s = set(mw_names(r)); kind, _ = r2.self_kind(r)
    if is_human(r):
        if 'VIS' in tags and 'SELF' in tags: return '복합(VIS·SELF, 검수)'
        if 'VIS' in tags: return 'VIS(검수)'
        if 'AUTH_ANY' in tags: return 'AUTH_ANY(검수)'
        return '기타(검수)'
    if r['meta'].get('review_r3'): return ('VIS' if 'VIS' in tags else 'AUTH_ANY') + '(사용자 확인, r3)'
    if (s & r2.VIS_MW) and kind: return f'복합(VIS+SELF {kind})'
    if r['meta'].get('v30_override_reason') == 'visibility_dependent' or s & r2.VIS_MW: return 'VIS'
    if 'reqToken' in s and not (s & r1.AUTHZ) and not re.search(r'\{[^}]+\}', r['path']): return 'AUTH_ANY'
    if 'reqToken' in s and not (s & r1.AUTHZ): return 'AUTH_ANY(객체 경로 있음)'
    return '기타'

def main():
    verified = assert_data_v1('start'); rows = rd(IN); byid = {r['id']: r for r in rows}; r2rows = rd(IN)
    gitea = [r for r in rows if r['id'].startswith('gitea:')]; changes = []
    # 1. user-confirmed labels + tags for the remaining 18 of sections 6/7
    pre_etc = [r for r in gitea if r['label'] == MANUAL and reason(r) in ('기타', 'AUTH_ANY(객체 경로 있음)')]
    for i, (lab, ev) in HUMAN_R3.items():
        r = byid[i]; prev = r['label']
        r['meta']['v2_relabel'] = dict(**{'from': prev, 'to': lab}, rule_id='human_review_v2_r3', evidence=ev); r['meta']['human_reviewed_v2'] = True; r['label'] = lab; changes.append(('human_review_v2_r3', i, prev, lab))
    tagged = []
    for r in pre_etc:
        if r['id'] in HUMAN_R3: continue
        s = set(mw_names(r)); tag = 'VIS' if (s & VIS_TAG_MW) or re.search(r'IsUserVisibleToViewer|Visibility|IsPrivate|HasOrgOrUserVisible', r1.handler_text(r)) else 'AUTH_ANY'
        r['meta']['review_tags'] = sorted(set(r['meta'].get('review_tags') or []) | {tag}); r['meta']['review_r3'] = 'manual 유지(사용자 확인)'; tagged.append((r['id'], tag))
    mismatch_keep = [(i, byid[i]['label']) for i in ('gitea:get:/repos/{owner}/{repo}/notifications', 'gitea:get:/repos/{owner}/{repo}/times')]
    # 2. synthetic variants
    variants = [r for r in rows if r['meta'].get('variant_kind') in ('authonly', 'extauth')]; kinds = Counter(r['meta']['variant_kind'] for r in variants)
    for r in variants:
        if r['meta']['variant_kind'] != 'authonly' or r['label'] != MANUAL: continue
        base, src = VARIANT_BASE.get(r['id'], (None, None))
        if base not in L: continue
        r['meta']['v2_relabel'] = dict(**{'from': r['label'], 'to': base}, rule_id='variant_intended_policy', evidence=f'{src}: base_label={base} (authonly: 인가 검사 제거, 경로·스키마로 의도 정책 확인)')
        changes.append(('variant_intended_policy', r['id'], r['label'], base)); r['label'] = base
    syn_manual_other = [(r['id'], r['meta'].get('source', 'synthetic'), (r.get('rationale') or '')[:120], r['meta'].get('variant_kind') or '-') for r in rows if r['meta'].get('source') == 'synthetic' and r['label'] == MANUAL and r['meta'].get('variant_kind') != 'extauth']
    # 3. VIS cap = 1
    vis_rows = [r for r in rows if r['id'].startswith('gitea:') and r['label'] == MANUAL and not is_human(r) and (reason(r) == 'VIS' or reason(r).startswith('복합'))]
    sig = lambda r: (r['method'], tuple(sorted(set(mw_names(r)) - {'sudo', 'tokenRequiresScopes', 'checkTokenPublicOnly'})))
    groups = defaultdict(list)
    for r in vis_rows: groups[sig(r)].append(r)
    path_template = lambda p: re.sub(r'\{[^}]+\}', '{}', '/'.join(p.split('/')[:5]))
    rng = random.Random(42); keep = set(); excluded = []
    for k, v in groups.items():
        pool = sorted(v, key=lambda r: r['id']); rng.shuffle(pool); chosen = pool[0]; keep.add(chosen['id'])
        for r in pool[1:]:
            rec = json.loads(json.dumps(r)); rec['meta']['vis_cap_excluded'] = dict(signature=dict(method=k[0], middleware=list(k[1])), kept_id=chosen['id'], reason='VIS cap 1 per signature (seed 42, path diversity first)'); excluded.append(rec)
    exc_ids = {r['id'] for r in excluded}; final = [r for r in rows if r['id'] not in exc_ids]
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        for r in final: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    with open(EXC, 'w', encoding='utf-8', newline='\n') as f:
        for r in excluded: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    # 4. stats
    dist = lambda rs: {l: sum(r['label'] == l for r in rs) for l in L}
    has_code = lambda r: bool((r.get('controller_text') or '').strip() or ((r.get('controller_signals') or {}).get('raw_snippet') or '').strip())
    def seg(rs): return dict(all=rs, code=[r for r in rs if has_code(r)], gitea=[r for r in rs if r['id'].startswith('gitea:')], synthetic=[r for r in rs if r['meta'].get('source') == 'synthetic'])
    s2, s3 = seg(r2rows), seg(final)
    rem = [r for r in final if r['id'].startswith('gitea:') and r['label'] == MANUAL]; rem_reason = Counter(reason(r) for r in rem)
    # quota dry-run (apply_reviews_v2 formula): fixed = data-v1 manual + synthetic manual; target = round_half_up(C/3)
    concrete = [r for r in final if r['label'] != MANUAL]; fixed = [r for r in final if r['label'] == MANUAL and not r['id'].startswith('gitea:')]  # data-v1 APIs.guru + synthetic (origin not stamped in draft)
    target = int(len(concrete) / 3 + .5); gitea_manual = [r for r in final if r['id'].startswith('gitea:') and r['label'] == MANUAL]
    slots = max(0, target - len(fixed)); excluded_by_quota = max(0, len(gitea_manual) - slots)
    quota = dict(concrete=len(concrete), target=target, fixed=len(fixed), fixed_by_source=dict(data_v1_apisguru=sum(r['meta'].get('source') != 'synthetic' for r in fixed), synthetic=sum(r['meta'].get('source') == 'synthetic' for r in fixed)),
                 gitea_manual=len(gitea_manual), slots_for_gitea=slots, gitea_manual_excluded=excluded_by_quota, human_reviewed_gitea_manual=sum(is_human(r) for r in gitea_manual), note='fixed manual이 target을 넘으면 합성·data-v1은 줄이지 않고 보고')
    # report
    def table(rs, header, right_from=1):
        return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c).replace('|', '&#124;') for c in r) + ' |\n' for r in rs)
    chg = Counter(c[0] for c in changes)
    t = '# data-v2 r3 — 잔여 판정 반영·authonly 재라벨·VIS cap 1 (동결 직전) — 2026-10-23\n\n'
    t += f"data-v1 해시 assert 통과(시작·종료): {', '.join(k.split('/')[-1] + ' ' + v for k, v in verified.items())}. 입력 train_v2_draft_r2.jsonl(971, 불변) → 출력 train_v2_draft_r3.jsonl({len(final)}) + train_v2_draft_r3_vis_excluded.jsonl({len(excluded)}). 쿼터 미적용(dry-run만).\n\n"
    t += '## 1. 사용자 확정 라벨 (rule_id=human_review_v2_r3)\n\n' + table([[i, c[2], c[3], HUMAN_R3[i][1]] for c in changes if c[0] == 'human_review_v2_r3' for i in [c[1]]], ['id', '이전', '확정', '근거'])
    t += f"\n보고서 r2 6·7절의 나머지 {len(tagged)}건은 manual 유지, meta.review_tags 기록: VIS {sum(t_ == 'VIS' for _, t_ in tagged)} · AUTH_ANY {sum(t_ == 'AUTH_ANY' for _, t_ in tagged)}.\n\n" + table(tagged, ['id', '태그'])
    t += '\nR3\' 불일치 2건 사람 라벨 유지 확인: ' + ', '.join(f'{i} = {l}' for i, l in mismatch_keep) + '\n\n'
    t += f"## 2. 합성 변형 재라벨 (rule_id=variant_intended_policy)\n\n변형 38건 유형별: {dict(kinds)}. authonly → base label(intended_labels.yaml base_label), extauth → manual 유지.\n\n"
    t += table([[c[1], c[2], c[3]] for c in changes if c[0] == 'variant_intended_policy'], ['id', '이전', '재라벨'])
    t += f"\n기준 추가(AGENTS.md): {CRITERION}\n\n같은 기준 해당 여부 점검 — 기존 합성 manual(변경 없음, 목록만): {len(syn_manual_other)}건. disputed/council(복합 조건 설계)·subscription(구독 조건)·extauth(외부 인가)는 '의도 정책이 경로·스키마로 드러남'에 해당하지 않아 기준 적용 대상 아님.\n\n" + table(syn_manual_other, ['id', '출처', '설계 사유', 'variant_kind'])
    t += f"\n## 3. VIS cap 적용 (시그니처당 1건, seed 42, 경로 다양성 우선)\n\n대상 {len(vis_rows)}건(검수·human_* 레코드 제외), 시그니처 {len(groups)}개 → 유지 {len(keep)}건, 제외 {len(excluded)}건(train_v2_draft_r3_vis_excluded.jsonl, meta.vis_cap_excluded에 시그니처·kept_id 기록).\n\n"
    t += '## 4. r2 → r3 label 분포\n\n'
    t += table([[l] + [dist(s2[k])[l] for k in ('all', 'code', 'gitea', 'synthetic')] + [dist(s3[k])[l] for k in ('all', 'code', 'gitea', 'synthetic')] for l in L] + [['합계'] + [len(s2[k]) for k in ('all', 'code', 'gitea', 'synthetic')] + [len(s3[k]) for k in ('all', 'code', 'gitea', 'synthetic')]], ['label', 'r2 전체', 'r2 코드', 'r2 Gitea', 'r2 합성', 'r3 전체', 'r3 코드', 'r3 Gitea', 'r3 합성'])
    t += f"\n코드 있는 레코드 manual 비율: {dist(s2['code'])[MANUAL]/len(s2['code']):.1%} → **{dist(s3['code'])[MANUAL]/len(s3['code']):.1%}**; 전체 manual 비율: {dist(s2['all'])[MANUAL]/len(s2['all']):.1%} → **{dist(s3['all'])[MANUAL]/len(s3['all']):.1%}**.\n\n"
    t += '## 5. 25% 쿼터 dry-run (apply_reviews_v2 공식, 적용 안 함)\n\n' + table([[k, v] for k, v in quota.items() if k != 'fixed_by_source'] + [['fixed 출처', json.dumps(quota['fixed_by_source'])]], ['항목', '값'])
    t += f"\n해석: 구체 {quota['concrete']}건 → manual 목표 {quota['target']}건. data-v1 manual + 합성 manual = {quota['fixed']}건이 고정이므로 Gitea manual {quota['gitea_manual']}건 중 {quota['slots_for_gitea']}건만 들어가고 {quota['gitea_manual_excluded']}건이 pool로 빠진다(검수 manual {quota['human_reviewed_gitea_manual']}건 포함 여부는 쿼터 선택 규칙에 따름).\n\n"
    t += '## 6. 남은 Gitea manual 사유·태그 분포 (r3)\n\n' + table(sorted(rem_reason.items(), key=lambda x: -x[1]), ['사유', '건수'])
    t += '\n원자료: train_v2_draft_r3.jsonl, train_v2_draft_r3_vis_excluded.jsonl, scripts/apply_review_v2_r3.py.\n'
    MD.write_text(t, encoding='utf-8')
    a = ROOT / 'AGENTS.md'; txt = a.read_text(encoding='utf-8')
    if CRITERION not in txt: txt = txt.replace('- 적용 기록: reports/review_v2_r1.md, reports/review_v2_r2.md', f'- {CRITERION}\n- 적용 기록: reports/review_v2_r1.md, reports/review_v2_r2.md, reports/review_v2_r3.md', 1); a.write_text(txt, encoding='utf-8')
    assert_data_v1('end')
    print(json.dumps(dict(changes=dict(chg), kinds=dict(kinds), tagged=dict(Counter(t_ for _, t_ in tagged)), vis_target=len(vis_rows), groups=len(groups), excluded=len(excluded), final=len(final),
                          code_manual=f"{dist(s2['code'])[MANUAL]/len(s2['code']):.3f}->{dist(s3['code'])[MANUAL]/len(s3['code']):.3f}", manual=f"{dist(s2['all'])[MANUAL]/len(s2['all']):.3f}->{dist(s3['all'])[MANUAL]/len(s3['all']):.3f}", quota=quota, remaining=dict(rem_reason), syn_manual_other=len(syn_manual_other)), ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
