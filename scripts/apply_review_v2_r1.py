"""Apply the human review (review_sheet_reviewed.xlsx, 52 records) and rules R1-R4 to the Gitea records of train_v2_draft.jsonl.
Writes datasets/blade/processed/train_v2_draft_r1.jsonl (new file) and reports/review_v2_r1.md. Original draft, test_v30 and data-v1 untouched.
No API calls, no training, no freeze, no manual quota.

Precedence: human review (rule_id=human_review_v2) > R2 (visibility override restricted to GET/HEAD) > R3 (public re-judgement) > R1 (SELF -> owner_match) > R4 (no-auth -> public).
Rule validation: each rule is applied to the 52 human-reviewed records with the human label hidden; a rule with precision < 0.90 is not applied (candidates listed only)."""
from __future__ import annotations
import json, re, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
from openpyxl import load_workbook
P = ROOT / 'datasets/blade/processed'; XLSX = ROOT / 'reports/review_v2_sample/review_sheet_reviewed.xlsx'; OUT = P / 'train_v2_draft_r1.jsonl'; MD = ROOT / 'reports/review_v2_r1.md'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
TAGS = ('SELF', 'VIS', 'AUTH_ANY', 'CODE_SHORT')
AUTHN = {'reqToken', 'reqBasicOrRevProxyAuth', 'reqExploreSignIn', 'contextAuthenticatedUser', 'rejectPublicOnly'}
VIS_MW = {'repoAssignment', 'reqRepoReader', 'reqAnyRepoReader'}
WRITE_MW = {'reqRepoWriter', 'reqAdmin'}
ADMIN_MW = {'reqAdmin', 'reqSiteAdmin'}
AUTHZ = {'reqAdmin', 'reqSiteAdmin', 'reqOwner', 'reqSelfOrAdmin', 'reqRepoWriter', 'reqRepoReader', 'reqAnyRepoReader', 'reqOrgOwnership', 'reqOrgMembership', 'reqTeamMembership', 'reqTeamReadAccess', 'reqRepoDangerZone', 'reqPackageAccess', 'reqProjectsUnitAccess', 'reqOrgVisible', 'repoAssignment', 'orgAssignment', 'reqOwnerCheck'}
# R1 SELF patterns: the handler passes ctx.Doer / ctx.Doer.ID as the ownership scope argument
SELF_PATTERNS = [r'\b\w+\(\s*ctx\s*,\s*ctx\.Doer(?:\.ID)?\s*[,)]', r'\b\w+\(\s*ctx\.Doer(?:\.ID)?\s*[,)]', r'UserID:\s*ctx\.Doer\.ID\b', r'\bshared\.\w+\(\s*ctx\s*,\s*ctx\.Doer\.ID\b', r'\b\w+\(\s*ctx\s*,\s*ctx\.Doer\s*,\s*ctx\.Doer\s*\)']
SELF_RE = re.compile('|'.join(SELF_PATTERNS))

def mw_names(r): return [re.sub(r'\(.*$', '', m).strip() for m in (r.get('controller_signals') or {}).get('middleware', [])]
def handler_text(r):
    t = r.get('controller_text') or ''; i = t.find('// ---- handler'); return t[i:] if i >= 0 else t
SELF_EXCLUDE_FN = re.compile(r'^(?:\w+\.)?(?:To[A-Z]\w*|Is[A-Z]\w*|Has[A-Z]\w*|Can[A-Z]\w*)$')  # converters (convert.ToUser) and boolean checks are not ownership scoping
def self_match(r):
    for m in SELF_RE.finditer(handler_text(r)):
        s = m.group(0).strip(); fn = re.sub(r'\(.*$', '', s, flags=re.S).strip()
        if fn and SELF_EXCLUDE_FN.match(fn): continue
        return s
    return None
def loc(r):
    sl = (r.get('meta') or {}).get('source_locations') or []; return f"{sl[0]['file']}:{sl[0]['start_line']}" if sl else 'controller_text'

def rule_r1(r):
    """SELF -> owner_match, for manual records; excluded when the chain also depends on repository visibility."""
    if r['label'] != MANUAL: return None
    ev = self_match(r)
    if not ev: return None
    if set(mw_names(r)) & VIS_MW: return ('excluded_vis_compound', ev)
    return ('owner_match', f'{loc(r)} match "{ev}"')

def rule_r2(r):
    """visibility override only for GET/HEAD; write methods with write-permission middleware are restored, manual restored -> role_required."""
    if r['meta'].get('v30_override_reason') != 'visibility_dependent' or r['method'] in ('GET', 'HEAD'): return None
    mws = set(mw_names(r)); hit = mws & WRITE_MW
    if not hit: return None
    before = r['meta'].get('label_before_override', MANUAL)
    if before == MANUAL: return ('role_required', f'write {r["method"]} + {sorted(hit)} ; restored manual -> role_required')
    return (before, f'write {r["method"]} + {sorted(hit)} ; restored label_before_override')

def rule_r3(r):
    """public re-judgement for records whose original model label was public."""
    if r['meta'].get('api_original_label') != 'public': return None
    mws = mw_names(r); s = set(mws)
    if 'reqToken' not in s: return ('public', 'no reqToken in chain -> public kept')
    if s & ADMIN_MW: return ('role_required', f'reqToken + {sorted(s & ADMIN_MW)}')
    ev = self_match(r)
    if ev: return ('owner_match', f'reqToken + SELF {loc(r)} "{ev}"')
    if s & VIS_MW: return (MANUAL, f'reqToken + {sorted(s & VIS_MW)} -> VIS')
    others = s & AUTHZ
    if not others and not re.search(r'\{[^}]+\}', r['path']): return (MANUAL, 'reqToken only, no object -> AUTH_ANY')
    return ('hold', f'reqToken + {sorted(others)} / object path {r["path"]} -> 판정 보류')

def rule_r4(r):
    """no authentication and no authorization middleware -> public (manual records only)."""
    if r['label'] != MANUAL: return None
    s = set(mw_names(r))
    if s & AUTHN or s & AUTHZ: return None
    return ('public', f'chain {mw_names(r) or ["(none)"]}: no authn/authz middleware')

RULES = {'R1_self_owner': rule_r1, 'R2_vis_readonly': rule_r2, 'R3_public_rejudge': rule_r3, 'R4_noauth_public': rule_r4}

def read_review():
    wb = load_workbook(XLSX, data_only=True); out = {}
    for name in ('A_gitea_info_gap_30', 'B_visibility_10', 'C_declared_public_12'):
        for row in wb[name].iter_rows(min_row=3, values_only=True):
            if not row[0] or not row[11]: continue
            label = str(row[11]).strip(); assert label in L, (name, row[0], label)
            note = str(row[13] or ''); tags = [t for t in TAGS if re.search(r'\b' + t + r'\b', note)]
            out[row[0]] = dict(sheet=name[0], label=label, confidence=str(row[12] or '').strip(), note=note, tags=tags)
    criteria = [wb['검수_집계'].cell(row=i, column=1).value for i in (4, 5, 6, 7)]
    return out, criteria

def main():
    verified = assert_data_v1('start'); review, criteria = read_review(); assert len(review) == 52, len(review)
    draft = rd(P / 'train_v2_draft.jsonl'); rows = [json.loads(json.dumps(r)) for r in draft]
    gitea = [r for r in rows if r['id'].startswith('gitea:')]; byid = {r['id']: r for r in gitea}
    # ---- rule validation on the 52 with human label hidden (rule inputs use the draft state, never the human label) ----
    validation = {}; candidates = {}
    for rid, fn in RULES.items():
        fired = []
        for i, rv in review.items():
            r = byid.get(i)
            if not r: continue
            res = fn(r)
            if not res or res[0] in ('hold', 'excluded_vis_compound'): continue
            if res[0] == r['label']: continue  # no change proposed
            fired.append((i, res[0], rv['label'], res[1]))
        n = len(fired); ok = sum(p == h for _, p, h, _ in fired)
        validation[rid] = dict(fired=n, correct=ok, precision=round(ok / n, 4) if n else None, applied=(n > 0 and ok / n >= .9), detail=fired)
    # ---- step 1: human review ----
    changes = []
    for i, rv in review.items():
        r = byid[i]; r['meta']['review_tags'] = rv['tags']; r['meta']['review_confidence'] = rv['confidence']; r['meta']['review_sheet'] = rv['sheet']
        if rv['label'] != r['label']:
            r['meta']['v2_relabel'] = dict(**{'from': r['label'], 'to': rv['label']}, rule_id='human_review_v2', evidence=f'review_sheet_reviewed.xlsx sheet {rv["sheet"]}: {rv["note"][:160]}')
            changes.append(('human_review_v2', i, r['label'], rv['label'])); r['label'] = rv['label']
        r['meta']['human_reviewed_v2'] = True
    # ---- rules in precedence order on non-reviewed Gitea records ----
    holds = []; excluded_compound = []; cand_lists = {k: [] for k in RULES}
    order = ['R2_vis_readonly', 'R3_public_rejudge', 'R1_self_owner', 'R4_noauth_public']
    for rid in order:
        fn = RULES[rid]
        for r in gitea:
            if r['meta'].get('human_reviewed_v2') or r['meta'].get('v2_relabel'): continue
            res = fn(r)
            if not res: continue
            if res[0] == 'hold': holds.append((r['id'], res[1])); continue
            if res[0] == 'excluded_vis_compound': excluded_compound.append((r['id'], res[1])); continue
            if res[0] == r['label']: continue
            if not validation[rid]['applied']: cand_lists[rid].append((r['id'], r['label'], res[0], res[1])); continue
            r['meta']['v2_relabel'] = dict(**{'from': r['label'], 'to': res[0]}, rule_id=rid, evidence=res[1])
            if rid == 'R2_vis_readonly': r['meta']['v30_override_reason'] = 'visibility_dependent_released_write'
            changes.append((rid, r['id'], r['label'], res[0])); r['label'] = res[0]
    # ---- write output ----
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    # ---- stats ----
    dist = lambda rs: {l: sum(r['label'] == l for r in rs) for l in L}
    has_code = lambda r: bool((r.get('controller_text') or '').strip() or ((r.get('controller_signals') or {}).get('raw_snippet') or '').strip())
    before_all, after_all = dist(draft), dist(rows); code_b = [r for r in draft if has_code(r)]; code_a = [r for r in rows if has_code(r)]
    g_before = [r for r in draft if r['id'].startswith('gitea:')]
    remaining = [r for r in gitea if r['label'] == MANUAL]
    def reason(r):
        tags = set(r['meta'].get('review_tags') or []); s = set(mw_names(r)); sm = self_match(r)
        if r['meta'].get('human_reviewed_v2'):
            if 'VIS' in tags and 'SELF' in tags: return '복합(VIS·SELF, 검수)'
            if 'VIS' in tags: return 'VIS(검수)'
            if 'AUTH_ANY' in tags: return 'AUTH_ANY(검수)'
            return '기타(검수: ' + (','.join(sorted(tags)) or '태그 없음') + ')'
        if (s & VIS_MW) and sm: return '복합(VIS+SELF)'
        if r['meta'].get('v30_override_reason') == 'visibility_dependent' or s & VIS_MW: return 'VIS'
        if 'reqToken' in s and not (s & AUTHZ) and not re.search(r'\{[^}]+\}', r['path']): return 'AUTH_ANY'
        if 'reqToken' in s and not (s & AUTHZ): return 'AUTH_ANY(객체 경로 있음)'
        return '기타'
    remaining_reasons = Counter(reason(r) for r in remaining)
    # ---- 7. consistency checks ----
    concrete93 = [r for r in g_before if r['label'] != MANUAL]
    incons = []
    for r in concrete93:
        s = set(mw_names(r)); exp = None
        if s & ({'reqRepoWriter'} | ADMIN_MW): exp = 'role_required'
        elif s & {'reqOrgMembership', 'reqTeamMembership', 'reqTeamReadAccess'}: exp = 'membership_required'
        if exp and r['label'] != exp: incons.append((r['id'], r['label'], exp, sorted(s & (ADMIN_MW | {'reqRepoWriter', 'reqOrgMembership', 'reqTeamMembership', 'reqTeamReadAccess'}))))
    test = rd(P / 'test_v30.jsonl'); auth_any = []
    AUTH_RE = re.compile(r'401|Unauthorized|get_current_user|jwt|login_required|authenticate|@PreAuthorize\("isAuthenticated|isAuthenticated\(\)|requireAuth|Bearer', re.I)
    OBJ_RE = re.compile(r'owner|user_id|userId|\.id\b|principal|current_user\.|role|admin|tenant|is_staff|hasRole|member', re.I)
    for r in test:
        code = r.get('controller_text') or ''
        if AUTH_RE.search(code) and not OBJ_RE.search(code) and not re.search(r'\{[^}]+\}', r['path']): auth_any.append((r['id'], r['service'], r['method'], r['path'], r['label']))
    # ---- report ----
    def table(rows_, header, right_from=1):
        return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c) for c in r) + ' |\n' for r in rows_)
    chg = Counter(c[0] for c in changes)
    t = '# data-v2 검수 반영 + Gitea 재라벨 규칙 적용 (r1, 동결 전) — 2026-10-23\n\n'
    t += f"data-v1 해시 assert 통과(시작·종료): {', '.join(k.split('/')[-1] + ' ' + v for k, v in verified.items())}. 입력 train_v2_draft.jsonl(971, 불변) → 출력 train_v2_draft_r1.jsonl(971). 검수 파일 reports/review_v2_sample/review_sheet_reviewed.xlsx(52건, mid 포함 전부 확정). 라벨을 바꾼 레코드는 meta.v2_relabel={{from,to,rule_id,evidence}}, 검수 태그는 meta.review_tags.\n\n"
    t += '규칙 우선순위: 사람 검수 > R2(visibility override를 GET/HEAD로 한정) > R3(public 재판정) > R1(SELF→owner_match) > R4(인증 없음→public). R2로 유지된 visibility override(GET)는 R3의 "reqToken 없으면 public 유지"보다 우선한다(검수 기준 3번: 공개/비공개 분기는 manual(VIS)).\n\n'
    t += '## 1. 규칙 검증 (검수 52건, 사람 라벨 가림)\n\n정밀도 = 규칙이 라벨 변경을 제안한 건 중 사람 라벨과 일치한 비율. 90% 미만이면 미적용(후보 목록만).\n\n'
    t += table([[k, v['fired'], v['correct'], v['precision'] if v['precision'] is not None else '-', '적용' if v['applied'] else '미적용(후보만)'] for k, v in validation.items()], ['규칙', '발동', '일치', '정밀도', '판정'], 1)
    for k, v in validation.items():
        if v['detail']: t += f'\n{k} 발동 상세:\n\n' + table([[i, p, h, '○' if p == h else '✗', e[:100]] for i, p, h, e in v['detail']], ['id', '규칙 라벨', '사람 라벨', '일치', '근거'], 1)
    t += '\n## 2. 적용 건수\n\n' + table([[k, chg.get(k, 0)] for k in ['human_review_v2'] + order], ['rule_id', '변경 건수'], 1)
    t += f"\n사람 검수 52건 중 라벨 변경 {chg.get('human_review_v2', 0)}건(나머지는 현재 라벨 확인). R1 제외(VIS 복합) {len(excluded_compound)}건, R3 판정 보류 {len(holds)}건.\n\n"
    for k, lst in cand_lists.items():
        if lst: t += f'### {k} 미적용 후보 {len(lst)}건 (라벨 변경 없음)\n\n' + table([[i, a, b, e[:110]] for i, a, b, e in lst], ['id', '현재', '규칙 제안', '근거'], 1) + '\n'
    t += '## 3. 변경 전후 label 분포\n\n'
    t += table([[l, before_all[l], after_all[l], dist(code_b)[l], dist(code_a)[l], dist(g_before)[l], dist(gitea)[l]] for l in L] + [['합계', len(draft), len(rows), len(code_b), len(code_a), len(g_before), len(gitea)]], ['label', '전체 전', '전체 후', '코드 있음 전', '코드 있음 후', 'Gitea 전', 'Gitea 후'], 1)
    t += f"\n코드 있는 레코드의 manual 비율: {dist(code_b)[MANUAL]/len(code_b):.1%} → {dist(code_a)[MANUAL]/len(code_a):.1%}. Gitea manual: {dist(g_before)[MANUAL]} → {dist(gitea)[MANUAL]}.\n\n"
    t += '## 4. 남은 Gitea manual의 사유·태그 분포\n\n' + table(sorted(remaining_reasons.items(), key=lambda x: -x[1]), ['사유', '건수'], 1)
    t += '\n## 5. R3 판정 보류 목록 (라벨 변경 없음)\n\n' + (table(holds, ['id', '근거'], 1) if holds else '없음\n')
    t += '\n## 6. R1 제외(VIS 복합, manual 유지)\n\n' + (table([[i, e] for i, e in excluded_compound], ['id', 'SELF 매칭'], 1) if excluded_compound else '없음\n')
    t += f"\n## 7. 라벨 체계 일관성 점검\n\n기존 Gitea 구체 label 93건 중 미들웨어 기준(쓰기·admin → role_required, org/팀 멤버십 → membership_required)과 다르게 붙은 건: {len(incons)}건 (변경 없음, id만).\n\n" + (table(incons, ['id', '현재 label', '미들웨어 기준', '근거 미들웨어'], 1) if incons else '없음\n')
    t += f"\ntest_v30에서 AUTH_ANY 유형(인증 검사만 있고 대상 객체·역할·소유 검사 없음, 경로 파라미터 없음; 휴리스틱 정규식) 후보: {len(auth_any)}건.\n\n" + (table(auth_any, ['id', 'service', 'method', 'path', '정답 label'], 1) if auth_any else '없음\n')
    t += '\n## 8. AGENTS.md에 옮긴 판정 기준\n\n' + ''.join(f'- {c}\n' for c in criteria)
    t += '\n원자료: train_v2_draft_r1.jsonl(meta.v2_relabel·review_tags), scripts/apply_review_v2_r1.py(SELF 패턴·미들웨어 집합 상수).\n'
    MD.write_text(t, encoding='utf-8')
    # AGENTS.md criteria
    a = ROOT / 'AGENTS.md'; txt = a.read_text(encoding='utf-8')
    if '## data-v2 라벨 기준' not in txt:
        txt = txt.rstrip('\n') + '\n\n## data-v2 라벨 기준 (2026-10-23, 검수_집계 시트 판정 기준 4줄 그대로)\n\n' + ''.join(f'- {c}\n' for c in criteria) + '\n- 적용 기록: reports/review_v2_r1.md, train_v2_draft_r1.jsonl(meta.v2_relabel). 검수 52건은 rule_id=human_review_v2.\n'
        a.write_text(txt, encoding='utf-8')
    assert_data_v1('end')
    print(json.dumps(dict(changes=dict(chg), validation={k: {kk: vv for kk, vv in v.items() if kk != 'detail'} for k, v in validation.items()}, holds=len(holds), excluded_compound=len(excluded_compound), candidates={k: len(v) for k, v in cand_lists.items()}, code_manual=f"{dist(code_b)[MANUAL]/len(code_b):.3f}->{dist(code_a)[MANUAL]/len(code_a):.3f}", remaining=dict(remaining_reasons), incons=len(incons), test_auth_any=len(auth_any)), ensure_ascii=False, indent=1))

if __name__ == '__main__': main()
