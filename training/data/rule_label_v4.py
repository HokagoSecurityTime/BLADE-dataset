"""data-v4 rule labels for the train additions (Zulip 12.3, Label Studio 1.23.2). Deterministic, no LLM; the gpt-4o-mini first-pass labels are not used.
Rules come only from these two projects' code and the review conventions G1-G7 (AGENTS.md 'data-v4 검수 규약'); no test / test_v31_supp file is read.
Each labeled record keeps meta.rule_v4 (rule name), meta.rule_evidence (excerpt lines that matched). A record where no rule fires, or where rules of
different labels fire at the same priority, is left unlabeled (label None, meta.rule_excluded_reason) and is not used for training.
Validation against the 71 reviewed records (review/v4_train_review_reviewed.xlsx, both sheets) is printed by `--check`."""
from __future__ import annotations
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Label Studio: boilerplate the extractor appended to every excerpt (settings, HasObjectPermission, make_perm loop). Removed before matching.
LS_BOILER = [re.compile(r"\s*'DEFAULT_PERMISSION_CLASSES': \[.*?\],\n", re.S), re.compile(r'class HasObjectPermission\(BasePermission\):.*?obj\.has_permission\(request\.user\)\n', re.S),
             re.compile(r'def make_perm\(name, pred, overwrite=False\):.*?make_perm\(permission_name, rules\.is_authenticated\)\n', re.S)]
OBJ_HAS_PERM = re.compile(r'def has_permission\(self, user\):')


def lines_with(text, pat):
    return [l.strip() for l in text.splitlines() if re.search(pat, l)][:4]


def label_studio(r):
    t = r['controller_text']
    for b in LS_BOILER: t = b.sub('\n', t)
    path, method = r['path'], r['method']; has_pk = bool(re.search(r'\{[^}]+\}', path))
    hits = []  # (priority, label, rule, pattern)
    if re.search(r'AllowAny', t): hits.append((0, 'public', 'ls_allow_any', r'AllowAny'))
    if re.search(r'class \w+\((?:TokenRefreshView|TokenBlacklistView|TokenViewBase)', t) or re.search(r'(?:TokenRefreshView|TokenBlacklistView)\.as_view', t):
        hits.append((0, 'public', 'ls_simplejwt_token_view', r'TokenRefreshView|TokenBlacklistView'))
    # target fixed to request.user (current-user endpoints, actions that ignore pk and change request.user)
    if path.startswith('/api/current-user'): hits.append((1, 'owner_match', 'ls_current_user', r'request\.user|def get_object'))
    if re.search(r'request\.user\.(avatar|hotkeys|reset_token|token)\b|return self\.request\.user\b|return request\.user\b', t):
        hits.append((1, 'owner_match', 'ls_target_request_user', r'request\.user\.(avatar|hotkeys|reset_token|token)\b|return (self\.)?request\.user\b'))
    # organization addressed by path pk + OrganizationMember(user, org) row lookup
    if re.search(r'^/api/organizations/\{pk\}', path) and re.search(r'OrganizationMember\.objects\.filter\(user=user, organization=self', t):
        hits.append((1.5, 'membership_required', 'ls_org_member_row', r'OrganizationMember\.objects\.filter\(user=user, organization=self'))
    org_filter = r'active_organization|\.for_user\('
    explicit_obj_check = r'validate_storage_instance\(|\.has_permission\(request\.user\)|check_object_permissions\('
    if method == 'POST' and not has_pk and re.search(explicit_obj_check, t):
        hits.append((2, 'tenant_match', 'ls_existing_object_org_check', explicit_obj_check))
    elif re.search(org_filter, t) or (has_pk and OBJ_HAS_PERM.search(t)):
        if method == 'POST' and not has_pk and not re.search(r'def (create|post)\(.*\n(?:.*\n){0,25}?.*(active_organization|has_permission|check_object_permissions)', t):
            pass  # create with the body's project/task: organization check of the body is not visible in the excerpt -> no rule
        else:
            hits.append((2, 'tenant_match', 'ls_active_organization_scope', org_filter + r'|def has_permission\(self, user\)|check_object_permissions'))
    if not has_pk and not re.search(org_filter, t) and not re.search(r'request\.user\.', t) and method == 'GET':
        hits.append((3, 'manual_review_required', 'ls_authenticated_only_no_object', r'IsAuthenticated|permission_required|def get\('))
    return hits, t


ADMIN = r'@require_realm_admin|@require_realm_owner|check_if_user_can_manage_default_streams\(|@require_server_admin'
G6_USER = r'\bcheck_can_access_user\('
G6 = r'\baccess_message(?:_and_usermessage)?\(|\baccess_stream_(?:by_id|by_name|common|for_send_message)\(|\baccess_streams\(|\bget_streams_for_user\(|filter_stream_authorization_for_adding_subscribers|\bhas_permission\(|\bvalidate_attachment_request(?:_for_spectator_access)?\(|\bcan_manage_group\b|\baccess_user_group_for_(?:update|setting)\(|\bcheck_basic_stream_access\(|access_user_group_to_read_membership\('
OWNER_ADMIN = r'\baccess_bot_by_id\(|\baccess_invite_by_id\(|\baccess_multiuse_invite_by_id\('
SCOPED = r'user_profile=user_profile|\buser=user_profile\b|filter\(user_profile=|\(\s*user_profile\s*,|\(user_profile\)|acting_user=user_profile'


def zulip(r):
    t = r['controller_text']; path = r['path']; hits = []
    view_sig = re.search(r'def \w+\(\s*request: HttpRequest,?\s*(\w+)?', t)
    first = view_sig.group(1) if view_sig else None
    if 'allow_anonymous_user_web' in t or (first or '').startswith('maybe_user_profile'):
        hits.append((0, 'manual_review_required', 'zulip_conditional_anonymous', r'allow_anonymous_user_web|maybe_user_profile'))
    elif view_sig and first in (None, '') or re.search(r'def \w+\(request: HttpRequest, \*,', t):
        if not re.search(r'user_profile: UserProfile', t.split('\n\n')[1] if '\n\n' in t else t):
            hits.append((0, 'public', 'zulip_no_user_profile_view', r'def \w+\(request: HttpRequest|@csrf_exempt|@require_post'))
    if re.search(ADMIN, t) or 'x-requires-administrator' in r['oas_snippet']:
        hits.append((1, 'role_required', 'zulip_realm_admin', ADMIN + r'|x-requires-administrator'))
    if re.search(OWNER_ADMIN, t): hits.append((2, 'owner_or_admin', 'zulip_owner_or_admin_access', OWNER_ADMIN))
    own = path.startswith('/api/v1/users/me')
    # on /users/me paths the processed object is the requester's own list; check_can_access_user there only validates the referenced user
    g6 = G6 if own else G6 + '|' + G6_USER
    if re.search(g6, t): hits.append((3, 'manual_review_required', 'zulip_or_branch_access', g6))
    if own or re.search(SCOPED, t):
        hits.append((4, 'owner_match', 'zulip_target_is_requester', r'users/me|' + SCOPED))
    elif '{' not in path and re.search(r'user_profile: UserProfile', t) and not hits:
        hits.append((5, 'manual_review_required', 'zulip_authenticated_only_no_object', r'user_profile: UserProfile'))
    return hits, t


def decide(r):
    proj = r['meta']['project']
    hits, text = (zulip if proj == 'zulip' else label_studio)(r)
    if not hits: return None, None, [], 'no_rule'
    top = min(h[0] for h in hits); best = {(h[1], h[2], h[3]) for h in hits if h[0] == top}
    labels = {b[0] for b in best}
    if len(labels) > 1: return None, None, [], 'conflict:' + ','.join(sorted(labels))
    label, rule, pat = sorted(best)[0]
    return label, rule, lines_with(text, pat) or lines_with(r['path'], pat), None


TEMPLATE = {'owner_match': '처리 대상이 요청자 본인으로 고정되어 있어', 'role_required': '관리자 역할 검사가 접근 조건이라', 'membership_required': '대상 조직의 구성원 행을 조회해 허용하므로',
            'tenant_match': '자원을 요청자의 활성 조직 범위로 한정하므로', 'owner_or_admin': '소유자 또는 관리자만 통과하는 접근 함수라',
            'public': '인증·권한 검사 없이 익명 호출을 허용하므로', 'manual_review_required': '접근 조건이 하나로 정해지지 않아'}
JUDGE = {'owner_match': '소유자 본인만 허용하는 조건이므로 owner_match', 'role_required': '특정 역할 보유가 실제 접근 조건이므로 role_required',
         'public': '인증 요구가 없으므로 public 선택', 'membership_required': '구성원 여부가 실제 접근 조건이므로 membership_required',
         'owner_or_admin': '소유자 또는 관리자 조건이므로 owner_or_admin', 'tenant_match': '요청자의 tenant와 대상 자원의 tenant가 일치해야 하므로 tenant_match',
         'manual_review_required': '접근 조건이 확정되지 않아 보류'}
NAME = re.compile(r'@?[A-Za-z_][\w.]*\(?|AllowAny|active_organization')


def rationale(label, evidence):
    """Template sentence + only the function/decorator names from the evidence lines (no file paths, sheet names, rule ids)."""
    names = []
    for line in evidence:
        for m in re.findall(r'@\w+|\b(?:access_\w+|check_\w+|validate_\w+|require_\w+|can_manage_group|has_permission|for_user|active_organization|OrganizationMember|AllowAny|TokenRefreshView|TokenBlacklistView|allow_anonymous_user_web|user_profile=user_profile|request\.user\.\w+)\b', line):
            if m not in names: names.append(m)
    cue = ', '.join(names[:3]) if names else '핸들러 코드'
    return f'description: 핸들러 코드의 {cue} — {TEMPLATE[label]}; 판단: {JUDGE[label]}'
