"""data-v5 code-rule labels for the training additions (Dendrite, NodeBB, Taiga).
Input: extraction candidates whose `auth_checks` list records every authorization check found in the handler chain with a `kind`
(anonymous | auth_only | self_target | owner_field | owner_or_privileged | membership_row | group_role | global_role | visibility_branch | setting_dependent | compound_and)
and the decisive source line. Rules are derived only from the training projects' code (data/raw_v5_train/<project>/SOURCE.md) and AGENTS.md 검수 규약 G1~G7;
test files and test error lists are never read. A record gets a label only when exactly one rule fires; otherwise it is excluded with a reason (no LLM fill-in).
Rationale = label template sentence + names of the deciding functions/expressions only (no file paths, sheet names, rule ids, review wording)."""
from __future__ import annotations
import re

LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']
HOLD_KINDS = {'visibility_branch', 'setting_dependent', 'compound_and'}
# Kind refinements by check name (apply to every project; derived from the training projects' SOURCE.md notes):
#  - group_role whose only basis is Matrix event auth (gomatrixserverlib.Allowed / PerformInvite): the outcome depends on the room's power-level values, which the
#    handler does not inspect -> kind event_auth -> record excluded (no label) unless a hold kind (visibility/setting) already decides manual.
#  - group_role written as "<power level> OR the target is the caller" (self-kick): role OR self after membership -> excluded, same as NodeBB chat kick.
KIND_OVERRIDES = [('group_role', re.compile(r'^event auth \(gomatrixserverlib\.(Allowed|PerformInvite)'), 'event_auth'),
                  ('group_role', re.compile(r'\bOR\b.*\b(caller|self)\b', re.I), 'role_or_self')]
# Superuser bypass (Taiga `enough_perms = IsSuperUser()`, recorded as bypass=true): it is a real admin bypass only when the handler loads the target by its
# path id and compares the owner (IsTheSameUser, obj.owner == request.user, owner_field). When the target is filtered/assigned from request.user
# (queryset.filter(user=request.user), obj.owner = request.user, /me, change_password) the superuser still only reaches own rows -> owner_match (G4).
OWNER_COMPARE = re.compile(r'IsTheSameUser|IsOwner|IsCommentOwner|==\s*request\.user|request\.user\s*==|obj\.(owner|user)\s*==|owner_field|\.owner_id\s*==|owner\s*==')


OR_HINT = re.compile(r'\|\||(?<!\|)\s\|\s(?!\|)|\bOR\b|\bor\b')


def kinds_of(r):
    out = []
    for c in r.get('auth_checks') or []:
        k = c.get('kind'); name = c.get('name') or ''
        for kind0, npat, kind in KIND_OVERRIDES:
            if k == kind0 and npat.search(name): k = kind
        out.append((k, name, c.get('text') or '', bool(c.get('bypass'))))
    return out


def decide(r):
    """Returns (label, rule_id, evidence_lines, excluded_reason). Rules (AGENTS.md G1~G7):
    G6 hold  : any visibility_branch / compound_and / setting_dependent check (setting_dependent + self_target is excluded as ambiguous: the setting may only gate the feature)
    G7 public: anonymous only (a superuser bypass does not change it)
    G6 auth  : auth_only only -> manual (object relationship/role not checked)
    G4 owner : self_target / owner_field only -> owner_match; owner_or_admin (G5) only when a privileged bypass entry (bypass=true) coexists with an owner comparison
               on a path-addressed object (OWNER_COMPARE), or with an explicit OR with a global role; request.user-filtered/created targets stay owner_match
    G5       : owner_or_privileged summary entry whose components are owner/role kinds -> owner_or_admin
    G2       : membership_row only (plus superuser bypass) -> membership_required; membership_row + self_target (member acting on own row in the named room) -> membership_required
    G5 room  : membership_row + owner_field + group_role (owner OR room power level after membership) -> owner_or_admin
    event_auth (Dendrite: no power-level check in the handler, event auth decides) -> excluded; role_or_self (power level OR self target after membership) -> excluded
    G3       : group_role / global_role (after membership or alone) -> role_required
    excluded : everything else (two rules would fire, or AND of independent conditions such as membership + self, membership + (owner | role))."""
    checks = kinds_of(r)
    if not checks: return None, None, [], 'no_auth_checks'
    if any(c.get('unlocated') for c in r.get('auth_checks') or []): return None, None, [], 'check_unlocated'
    main = [c for c in checks if not c[3]]; bypass = [c for c in checks if c[3]]
    K = [k for k, _, _, _ in main]; S = set(K); ev = [t for _, _, t, _ in checks if t]; has_bypass = bool(bypass)
    hold = S & HOLD_KINDS
    if hold:
        if hold == {'setting_dependent'} and 'self_target' in S: return None, None, [], 'ambiguous:setting_with_self_target'
        return 'manual_review_required', 'G6_hold_' + '_'.join(sorted(hold)), ev, None
    if 'event_auth' in S: return None, None, [], 'ambiguous:event_auth_power_level_dependent'
    if 'role_or_self' in S: return None, None, [], 'ambiguous:role_or_self_after_' + ','.join(sorted(S - {'role_or_self', 'auth_only'}))
    core = S - {'auth_only'}
    if core == {'anonymous'}: return 'public', 'G7_anonymous', ev, None
    if not core: return 'manual_review_required', 'G6_auth_only', ev, None
    if 'anonymous' in core: return None, None, [], 'conflict:anonymous_with_' + ','.join(sorted(core - {'anonymous'}))
    if 'owner_or_privileged' in core:
        if core <= {'owner_or_privileged', 'owner_field', 'self_target', 'group_role', 'global_role'}: return 'owner_or_admin', 'G5_owner_or_privileged', ev, None
        return None, None, [], 'ambiguous:owner_or_privileged_with_' + ','.join(sorted(core - {'owner_or_privileged'}))
    if core <= {'self_target', 'owner_field'}:
        compares_owner = 'owner_field' in core or any(k == 'self_target' and OWNER_COMPARE.search(n + ' ' + t) for k, n, t, _ in main)
        if has_bypass and compares_owner: return 'owner_or_admin', 'G5_owner_with_superuser_bypass', ev, None
        return 'owner_match', 'G4_' + ('self_target' if 'self_target' in core else 'owner_field'), ev, None
    if core == {'self_target', 'global_role'} or core == {'owner_field', 'global_role'}:
        if any(OR_HINT.search(n + ' ' + t) for _, n, t, _ in main): return 'owner_or_admin', 'G5_owner_or_global_role', ev, None
        return None, None, [], 'ambiguous:owner_and_or_global_role'
    if core == {'membership_row'}: return 'membership_required', 'G2_membership_row', ev, None
    if core == {'membership_row', 'self_target'}: return 'membership_required', 'G2_membership_self_action', ev, None  # member of the named room acting on own row (AGENTS.md 정지 지점 1 통일 판단)
    if core == {'membership_row', 'owner_field', 'group_role'}: return 'owner_or_admin', 'G5_owner_or_room_role', ev, None  # after membership: object owner OR room power/role
    if core <= {'membership_row', 'group_role', 'global_role'}:
        if core == {'membership_row', 'global_role'}: return None, None, [], 'ambiguous:membership_and_or_global_role'
        return 'role_required', 'G3_' + ('group_role' if 'group_role' in core else 'global_role'), ev, None
    return None, None, [], 'ambiguous:' + ','.join(sorted(core))


TEMPLATE = {'owner_match': '처리 대상이 요청자 본인으로 고정되어 있어', 'role_required': '역할·권한 검사가 접근 조건이라', 'membership_required': '대상 방·그룹·프로젝트의 구성원 행을 조회해 허용하므로',
            'tenant_match': '자원을 요청자의 활성 조직 범위로 한정하므로', 'owner_or_admin': '소유자 본인 또는 권한 보유자만 통과하는 조건이라',
            'public': '인증·권한 검사 없이 익명 호출을 허용하므로', 'manual_review_required': '접근 조건이 하나로 정해지지 않아'}
JUDGE = {'owner_match': '소유자 본인만 허용하는 조건이므로 owner_match', 'role_required': '특정 역할 보유가 실제 접근 조건이므로 role_required',
         'public': '인증 요구가 없으므로 public 선택', 'membership_required': '구성원 여부가 실제 접근 조건이므로 membership_required',
         'owner_or_admin': '소유자 또는 관리자 조건이므로 owner_or_admin', 'tenant_match': '요청자의 tenant와 대상 자원의 tenant가 일치해야 하므로 tenant_match',
         'manual_review_required': '접근 조건이 확정되지 않아 보류'}
IDENT = re.compile(r"@?[A-Za-z_][\w.]*\(|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+|[A-Za-z]*_\w+|\b[a-z]+[A-Z]\w*\b|\b[A-Z][a-z]+[A-Z]\w*\b|'[a-z][\w:.*-]*'")
BAD = re.compile(r'/|\.(py|go|js|ts|yaml)\b|:\d+|\{')


def rationale(label, checks):
    names = []
    for c in [c for c in checks if c.get('kind') != 'auth_only'] or checks:
        for m in IDENT.findall(c.get('name') or ''):
            m = m.rstrip('(').rstrip(')').strip('.')
            if len(m) > 2 and not BAD.search(m) and m not in names: names.append(m)
    cue = ', '.join(names[:3]) if names else '접근 검사'
    return f'description: 핸들러 코드의 {cue} — {TEMPLATE[label]}; 판단: {JUDGE[label]}'
