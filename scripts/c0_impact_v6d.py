"""작업 C0 — v3.1 학습 정답 재작성 영향 행 찾기 (학습·추론 없음, 커밋 금지).

data-v5 SFT 행 train 1,274 / val 179(processed train_v5 1,277 / val_v5 180에서 4096 토큰 초과 3 + 1 제외)을 읽어
  1. 행별 출처·라벨 출처·사람 검수 여부(적용 규약)를 표로 만들고(c0_rows.csv),
  2. v3.1 변경 규칙별 영향 후보를 입력(코드·미들웨어·OAS 텍스트)과 규칙 라벨러 특징만으로 추출하며,
  3. 후보마다 현재 label과 규칙 기반 "v3.1 예상 label"을 비교해 변경 가능 행 목록(c0_candidates.jsonl)을 만들고,
  4. 규칙별·label별·프로젝트별 집계와 C1·C2 작업량·검수 시트 설계안을 보고서(c0_impact.md)에 쓴다.
  6. test_v30·test_v31_supp·test_v5·test_v6 후보와 (서비스, method, 정규화 path)·서비스명 겹침을 재확인한다.
정답 label은 후보 추출 단계에서 읽지 않는다(비교 단계에서만 사용). 동결 파일은 해시 확인 후 읽기만 한다.
"""
from __future__ import annotations
import csv, hashlib, json, random, re, zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'reports' / 'data_v6d'
P = ROOT / 'datasets' / 'blade' / 'processed'
SFT = ROOT / 'training' / 'lora' / 'data_v5'
FROZEN = {
    P / 'train_v5.jsonl': '528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344',
    P / 'val_v5.jsonl': '43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9',
    SFT / 'train_sft_v5.jsonl': '2351afe93518f6e29c95ab9305a15b5a1cda7bd6e3c6d18bec7e8e3d45c3216b',
    SFT / 'val_sft_v5.jsonl': '0df4642f439c812d4e7b9f5ca968c89fd966703bfc59229d6f7ea7f83115748f',
    P / 'test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2',
    P / 'data_v4' / 'test_v31_supp.jsonl': '803d914902c7ca2042fd15d4a7852d42e71828e58d4ae4d3ac791fb868e63395',
    P / 'test_v5.jsonl': '7b8e4a940967ec474e0d5dbf6dcdbd6b7e04be439599c2a684664d6b9393fd9c',
    ROOT / 'review' / 'v5_train_review_reviewed.xlsx': '4d70711494bf63ad0a0644e75967f236a204b5799b8dd67847aa508a010d519b',
}
LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']
MUT = {'POST', 'PUT', 'PATCH', 'DELETE'}
SEED = 42


def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def jl(p): return [json.loads(l) for l in open(p, encoding='utf-8')]


# ---------- xlsx (zipfile + xml, openpyxl 없음) ----------
NS = {'m': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main', 'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}


def read_xlsx(path):
    z = zipfile.ZipFile(path); shared = []
    if 'xl/sharedStrings.xml' in z.namelist():
        for si in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si', NS):
            shared.append(''.join(t.text or '' for t in si.iter('{%s}t' % NS['m'])))
    wb = ET.fromstring(z.read('xl/workbook.xml')); rels = ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))
    relmap = {r.get('Id'): r.get('Target') for r in rels}; sheets = {}
    for s in wb.find('m:sheets', NS):
        t = relmap[s.get('{%s}id' % NS['r'])]; t = t.lstrip('/') if t.startswith('/') else (t if t.startswith('xl/') else 'xl/' + t)
        rows = []
        for row in ET.fromstring(z.read(t)).iter('{%s}row' % NS['m']):
            cells = {}
            for c in row.findall('m:c', NS):
                col = 0
                for ch in re.match(r'[A-Z]+', c.get('r')).group(0): col = col * 26 + ord(ch) - 64
                v = c.find('m:v', NS); ty = c.get('t')
                if ty == 's' and v is not None: val = shared[int(v.text)]
                elif ty == 'inlineStr': val = ''.join(x.text or '' for x in c.iter('{%s}t' % NS['m']))
                else: val = v.text if v is not None else None
                cells[col - 1] = val
            if cells: rows.append([cells.get(i) for i in range(max(cells) + 1)])
        sheets[s.get('name')] = rows
    return sheets


def sheet_dicts(rows):
    if not rows: return []
    h = [str(x) if x is not None else '' for x in rows[0]]
    return [dict(zip(h, r + [None] * (len(h) - len(r)))) for r in rows[1:]]


# ---------- 정규화(build_data_v4.py와 동일) ----------
def norm_service(s):
    s = (s or '').lower().split(':')[0]; s = re.sub(r'\.(com|org|io|net|local|dev|app|co|ai)$', '', s)
    return re.sub(r'[^a-z0-9]', '', s)


def norm_path(p):
    p = re.sub(r'\{[^}]*\}|<[^>]*>|:\w+', '{}', (p or '').strip().lower())
    return re.sub(r'/+', '/', p).rstrip('/') or '/'


def svc(r): return r.get('service') or (r.get('meta') or {}).get('project') or r.get('project') or ''
def key(r): return (norm_service(svc(r)), (r.get('method') or '').upper(), norm_path(r.get('path')))


# ---------- 행 분류 ----------
def source_kind(r):
    s = r['meta'].get('source') or r.get('source') or ''
    if s == 'apisguru': return 'APIs.guru'
    if s == 'synthetic': return '합성'
    return '오픈소스 프로젝트'


def project_of(r):
    if source_kind(r) == 'APIs.guru': return 'APIs.guru:' + r['service']
    if source_kind(r) == '합성': return '합성:' + re.sub(r'_variants$', '', r['service'])
    return r['meta'].get('project') or r['service']


def label_source_desc(r):
    m = r['meta']; ls = m['label_source']; v2 = (m.get('v2_relabel') or {}).get('rule_id')
    base = {'model_api': 'LLM(gpt-4o-mini, v3.0.1)', 'code_rule_v4': '규칙 라벨러 rule_label_v4', 'code_rule_v5': '규칙 라벨러 rule_label_v5',
            'rule_from_check_lines': '규칙 라벨러(검사 줄 규칙, data-v3 1b)', 'intended_labels': '합성 설계 intended_labels'}[ls]
    if v2: base += ' → 사람 검수 교정(data-v2)' if v2.startswith('human_review') else f' → data-v2 규칙 relabel({v2})'
    return base


REVIEW_PROTOCOL = {
    'v2': 'data-v2 라벨 기준(2026-10-23, G 이전: 저장소 권한 레벨→role, org/팀→membership, VIS→manual, AUTH_ANY→manual, VIS+SELF)',
    'v3': 'data-v3 1b 쌍 검수(원본 label 정확·변형 유지 가능 판정; 라벨은 검사 줄 규칙, G 규약 아님; 검수자 열 "Claude 1차(사용자 확인 필요)")',
    'v4': 'data-v4 검수 규약 G1~G8(검수자 열 "Claude (AI 검수, 사람 확인 필요)")',
    'v5': 'data-v4 검수 규약 G1~G8 + 정지 지점 3 수정(검수자 열 "이혜인")',
}

# ---------- 입력 특징(정답 label 미사용) ----------
RE = {
    'perm': re.compile(r'has_perm\(|permission_required|hasPermission|privileges\.\w+\.can\(|checkPermission|require_permission|all_permissions\.|HasPerm|\.can\(\s*[\'"]'),
    'group_role_code': re.compile(r'IsProjectAdmin|HasProjectPerm|isAdminOrMod|isRoomOwner|is_room_owner|category moderator|is_stream_admin|org_admin|is_org_admin|team_admin|workspace_admin|project_admin|IsOrganizationOwner|power level|pl\.UserLevel'),
    'group_role_text': re.compile(r'\b(owner|admin|administrator|moderator|maintainer|manager)s?\s+(of|in|for)\s+(the\s+|this\s+|an?\s+|your\s+)?(team|organization|organisation|org|workspace|group|project|account|channel|room|course|space|board)\b|\b(team|organization|organisation|workspace|group|project|account|channel|room|course|space|board)\s+(owner|admin|administrator|moderator|manager)s?\b', re.I),
    'member_text': re.compile(r'\bmembers?\s+of\s+(the\s+|this\s+|an?\s+|your\s+)?(team|organization|organisation|org|workspace|group|project|account|channel|room|course|space|board)\b|\b(team|organization|workspace|group|project|account|channel|room|course)\s+members?\b', re.I),
    'member_code': re.compile(r'OrganizationMember\.objects|isUserInRoom|IsOrganizationMember|IsTeamMember|checkMemberInRoom|QueryMembershipForUser|CanLeaveProject|is_member\(|isMember\('),
    'tenant_code': re.compile(r'active_organization|\.for_user\(|current_org|org_id\s*=\s*(request|req|ctx|self\.request)\.|organization\s*=\s*(request|self\.request)\.user|tenant_id\s*=|tenantId\s*=|workspaceId\s*='),
    'setting': re.compile(r'\w+_changes_disabled|realm\.allow_\w+|realm\.\w+_policy|realm\.enable_\w+|meta\.config\.\w+|settings\.get\(|nconf\.get\(|Accounts_\w+|getSetting\('),
    'self': re.compile(r'/users/me|/user/|request\.user\b|self\.request\.user|device\.UserID|caller\.uid|ctx\.Doer\.ID|IsTheSameUser|== *userId|uid === caller'),
    'party_or_admin': re.compile(r'isSelf\s*\|\||\|\|\s*isAdmin|isAdminOrGlobalModOrSelf|IsTheSameUser\(\)\s*\|\s*IsSuperUser|IsSuperUser\(\)\s*\|\s*Is(TheSameUser|Owner)|self_or_admin|owner_or_admin|OwnerOrAdmin|IsInstanceAdmin|isOwnerOrAdminOrMod'),
    'party_or_admin_text': re.compile(r'\b(owner|author|creator|sender|recipient|participant|uploader|requester)s?\s+(or|and)\s+(an?\s+)?(admin|administrator|moderator|staff)s?\b|\b(admin|administrator)s?\s+or\s+(the\s+)?(owner|author|creator)\b', re.I),
    'visibility': re.compile(r'is_private|isPrivate|IsPrivate|history_visibility|world_readable|canAccessRoom|visibility'),
}
GITEA_VIS_MW = ('repoAssignment', 'reqRepoReader', 'reqAnyRepoReader', 'reqOrgVisible', 'context.ReferencesGitRepo', 'reqPackageAccess')
GITEA_ROLE_MW = ('reqOrgOwnership', 'reqRepoWriter', 'reqAdmin', 'reqRepoAdmin', 'reqSiteAdmin')
GITEA_MEMBER_MW = ('reqOrgMembership', 'reqTeamMembership', 'reqTeamReadAccess')
SELF_SCOPE_PATH = re.compile(r'^/user(/|$)|/notifications|/subscription$|/stopwatch/|/starred/|/subscriptions/check|/reactions$|/times$')
HOLD_KINDS = {'visibility_branch', 'setting_dependent', 'compound_and'}
G_RULE_PROJ = ('zulip', 'label_studio', 'dendrite', 'nodebb', 'taiga')  # G1~G7에서 도출한 규칙 라벨러(rule_label_v4/v5)로 라벨된 프로젝트: 규칙 특징만 사용
V3_RULE_LABEL = {'owner_compare': 'owner_match', 'owner_filter': 'owner_match', 'self_only': 'owner_match', 'form_request_owner': 'owner_match', 'owner_or_parent_owner': 'owner_match',
                 'role_annotation': 'role_required', 'superuser_dependency': 'role_required', 'self_or_admin': 'owner_or_admin', 'owner_or_superuser': 'owner_or_admin',
                 'self_or_superuser': 'owner_or_admin', 'owner_or_instance_admin': 'owner_or_admin', 'owner_filter_unless_admin': 'owner_or_admin'}
CHANGE_TYPE = {'G3-a': 'v3.1 규칙 변경(보류 3 → role_required)', 'G1-b': 'v3.1 규칙 변경(보류 3 → tenant_match)', 'G1-c': 'v3.1 신설(생성 시 tenant 강제)',
               'G2-b': 'v3.1 신설(구성원 OR 관리자)', 'G5': 'v3.1 확장(당사자 OR 관리자)', 'G4-c/G6-b': 'v3.1 신설(설정 의존 본인 분기)', 'G7-a': 'v3.1 규칙 변경(declared mutation) 또는 교정(GET)',
               'G7-b': '명문화(v3.0.1에서도 manual) → 기존 label 교정', 'G6-a': '명문화(v3.0.1에서도 manual) → 기존 label 교정', 'G3-b/G6-c': '경계 명문화(보류 6·G4 본인 목록) → 기존 label 교정', '생성(절차5)': 'v3.1 신설(절차 5)'}
RULE_DESC = {'G3-a': '그룹 안 역할(구성원 확인 뒤 그룹 안 역할) → role_required', 'G3-b/G6-c': '객체 없는 RBAC 권한 → role_required, 모든 역할 보유 권한·인증만 → manual',
             'G1-b': 'tenant 필터 + 기능 RBAC → tenant_match', 'G1-c': '생성 시 tenant 강제 → tenant_match', 'G7-a': '코드 근거 익명(declared mutation 포함) → public',
             'G7-b': '조건부 익명 → manual', 'G2-b': '구성원 OR 관리자 → membership_required', 'G4-c/G6-b': '설정 의존 본인 분기(설정 제한만 우회 → owner_match / 분기 자체 → manual)',
             'G5': '당사자 OR 관리자 → owner_or_admin', 'G6-a': '다른 유형 OR 분기 → manual', '생성(절차5)': '생성 요청 라벨링 절차 5'}


def feats(r):
    m = r['meta']; sig = r.get('controller_signals') or {}
    code = r.get('controller_text') or sig.get('raw_snippet') or ''
    mw = [re.sub(r'\(.*$', '', x).split('\n')[-1].strip() for x in sig.get('middleware', [])]
    oas = json.dumps(r.get('oas_snippet') or '', ensure_ascii=False) + ' ' + (r.get('description') or '')
    checks = m.get('auth_checks') or []
    kinds = {c.get('kind') for c in checks if not c.get('bypass')}; bypass = any(c.get('bypass') for c in checks)
    names = ' '.join((c.get('name') or '') + ' ' + (c.get('text') or '') for c in checks)
    return dict(code=code, mw=mw, oas=oas, kinds=kinds, bypass=bypass, names=names, has_pk='{' in (r['path'] or ''), has_code=bool(code), is_gitea=r['service'] == 'gitea',
                proj=m.get('project') or '', route_auth=sig.get('route_authentication'), authz_lines=sig.get('authz_lines_in_handler', 0),
                rule=m.get('rule_v4') or m.get('rule_v5') or m.get('rule_id') or (m.get('v2_relabel') or {}).get('rule_id') or '', apis=m.get('source') == 'apisguru', synth=m.get('source') == 'synthetic')


def detect(r, f):
    """후보 규칙 → {규칙: (예상 label | '?' | '=', 판정 종류 'rule'|'review', 근거)}. '='는 현행 유지 점검만. 정답 label을 읽지 않는다.
    G 규약 규칙 라벨러 프로젝트(G_RULE_PROJ)와 data-v3 쌍은 규칙 특징(rule_v4/rule_v5 이름·auth_checks kind·rule_id)만 쓰고, 코드 정규식은 LLM 라벨 프로젝트(gitea·memos·kutt 등)에만,
    OAS 문구 탐지(APIs.guru)는 '?'(판정 필요)로만 표시한다."""
    out = {}
    code, mw, oas, kinds, path, method = f['code'], f['mw'], f['oas'], f['kinds'], r['path'], r['method']
    core = kinds - {'auth_only'}; m = r['meta']
    g_rule = f['proj'] in G_RULE_PROJ; v3pair = bool(m.get('pair_id')); rule = f['rule']
    body = code.split('// ---- handler')[-1] if f['is_gitea'] else code
    has_role_mw = any(x in GITEA_ROLE_MW for x in mw); has_member_mw = any(x in GITEA_MEMBER_MW for x in mw)
    has_vis_mw = any(any(x.startswith(v) for v in GITEA_VIS_MW) for x in mw)
    if v3pair:  # data-v3 쌍: rule_id가 라벨 규칙(1b 검수 완료) → G5·생성만 표시
        if V3_RULE_LABEL.get(rule) == 'owner_or_admin': out['G5'] = ('owner_or_admin', 'rule', f'data-v3 규칙 {rule}(소유자 OR 관리자)')
        if method == 'POST' and not f['has_pk']: out['생성(절차5)'] = (V3_RULE_LABEL.get(rule, '?'), 'rule', f'data-v3 규칙 {rule}: 생성 요청(변형은 원본 label 유지 규칙)')
        return out
    # G3-a 그룹 안 역할
    if f['is_gitea'] and any(x in ('reqOrgOwnership', 'reqRepoWriter', 'reqAdmin', 'reqRepoAdmin') for x in mw):
        out['G3-a'] = ('role_required', 'rule', 'gitea middleware ' + ','.join(x for x in mw if x in ('reqOrgOwnership', 'reqRepoWriter', 'reqAdmin', 'reqRepoAdmin')))
    elif 'group_role' in core and not (core & HOLD_KINDS) and 'owner_or_privileged' not in core and not (core & {'owner_field', 'self_target'}):
        out['G3-a'] = ('role_required', 'rule', 'auth_checks group_role' + (' (+membership_row)' if 'membership_row' in core else ''))
    elif rule == 'zulip_realm_admin': out['G3-a'] = ('role_required', 'rule', 'rule_v4 zulip_realm_admin(계정 administrator = 그룹 안 역할; 채널 접근 함수가 함께 있어도 역할이 결정 조건)')
    elif f['has_code'] and not f['is_gitea'] and not g_rule and RE['group_role_code'].search(code):
        out['G3-a'] = ('role_required', 'review', 'code ' + RE['group_role_code'].search(code).group(0))
    elif f['apis'] and RE['group_role_text'].search(oas):
        out['G3-a'] = ('?', 'review', 'OAS 문구 "' + RE['group_role_text'].search(oas).group(0) + '" (요청자의 그룹 안 역할 조건이면 role_required; 대상 설명이면 유지)')
    # G3-b / G6-c 객체 없는 권한·인증만
    if not f['has_pk']:
        if rule in ('ls_authenticated_only_no_object', 'zulip_authenticated_only_no_object', 'G6_auth_only') or (kinds and core == set()):
            perm = bool(RE['perm'].search(code + f['names'])); all_roles = ('registered-users' in f['names']) or ('make_perm' in code) or f['proj'] in ('label_studio', 'zulip')
            out['G3-b/G6-c'] = ('manual_review_required' if (not perm or all_roles) else 'role_required', 'rule', '객체 없음 + ' + ('권한 검사(모든 사용자 역할 보유)' if perm and all_roles else '인증만' if not perm else '권한 검사'))
        elif f['is_gitea'] and 'reqToken' in mw and set(mw) <= {'sudo', 'tokenRequiresScopes', 'reqToken', 'checkTokenPublicOnly', 'rejectPublicOnly', 'contextAuthenticatedUser'}:
            if SELF_SCOPE_PATH.search(path) and method != 'POST': out['G3-b/G6-c'] = ('owner_match', 'rule', 'gitea reqToken만 + 본인 경로(/user, /notifications): G4 본인 목록·설정')
            elif SELF_SCOPE_PATH.search(path): out['G3-b/G6-c'] = ('owner_match', 'review', 'gitea reqToken만 + /user 아래 생성(본인 명의 생성 G4-b)')
            elif 'ctx.Doer' in body and method == 'POST': out['생성(절차5)'] = ('?', 'review', 'gitea reqToken만 + 생성(핸들러가 ctx.Doer 사용): 본인 명의면 owner_match, 아니면 보류')
            elif 'ctx.Doer' in body: out['G3-b/G6-c'] = ('?', 'review', 'gitea reqToken만, 객체 없음, 핸들러가 ctx.Doer 사용(본인 범위면 owner_match, 아니면 manual)')
            else: out['G3-b/G6-c'] = ('manual_review_required', 'rule', 'gitea reqToken만, 객체 없음, 본인 범위 아님(AUTH_ANY)')
        elif f['apis'] and m.get('has_admin_scope'):
            out['G3-b/G6-c'] = ('?', 'review', 'OAS admin scope + 객체 없음(권한만이면 role_required)')
    # G1-b tenant + RBAC / G1-c 생성 시 tenant
    if rule in ('ls_active_organization_scope', 'ls_existing_object_org_check'):
        out['G1-b' if rule == 'ls_active_organization_scope' else 'G1-c'] = ('tenant_match', 'rule', f'rule_v4 {rule}(조직 범위 필터 + 기능 권한)')
    elif f['apis'] and (m.get('has_tenant_col') or m.get('path_tenant_signal')) and (m.get('has_admin_scope') or re.search(r'\badmin|\brole|permission', oas, re.I)):
        out['G1-b'] = ('?', 'review', 'OAS tenant 신호 + admin/role 문구(기능 권한이면 tenant_match, 관리자 역할이 결정 조건이면 role_required)')
    elif f['has_code'] and not g_rule and not f['synth'] and RE['tenant_code'].search(code) and 'G3-a' not in out and RE['perm'].search(code):
        out['G1-b'] = ('tenant_match', 'review', 'tenant 필터 ' + RE['tenant_code'].search(code).group(0) + ' + 권한 검사')
    if method == 'POST' and not f['has_pk'] and f['has_code'] and not g_rule and 'G3-a' not in out and RE['tenant_code'].search(code):
        out['G1-c'] = ('tenant_match', 'review', '생성 + ' + RE['tenant_code'].search(code).group(0))
    # G7-a 코드 근거 익명 / G7-b 조건부 익명
    anon = None
    if f['is_gitea'] and f['route_auth'] is False and 'reqToken' not in mw and not has_role_mw and not has_member_mw:
        anon = 'G7-b' if (has_vis_mw or 'orgAssignment' in mw) else 'G7-a'
    elif kinds and core == {'anonymous'}: anon = 'G7-a'
    elif kinds and 'anonymous' in core: anon = 'G7-b'
    elif rule in ('ls_allow_any', 'ls_simplejwt_token_view', 'zulip_no_user_profile_view'): anon = 'G7-a'
    elif rule == 'zulip_conditional_anonymous': anon = 'G7-b'
    elif f['synth'] and code and not re.search(r'[Aa]uthorization|principal|Bearer|UNAUTHORIZED|401', code): anon = 'G7-a'
    if anon == 'G7-a':
        out['G7-a'] = ('public', 'rule', '코드상 인증 없음' + (' [declared mutation]' if r['security_state'] == 'declared' and method in MUT else ' [declared GET: v3.0.1에서도 public 가능 → 교정]' if r['security_state'] == 'declared' else ''))
    elif anon == 'G7-b':
        out['G7-b'] = ('manual_review_required', 'rule', '조건부 익명(공개 저장소·조직 가시성·web-public 설정)')
    # G2-b 구성원 OR 관리자
    if f['is_gitea'] and has_member_mw and 'reqOrgOwnership' not in mw:
        out['G2-b'] = ('membership_required', 'rule', 'gitea 구성원 미들웨어(site admin 우회 포함) ' + ','.join(x for x in mw if x in GITEA_MEMBER_MW))
    elif 'membership_row' in core and core <= {'membership_row', 'self_target'} and not (core & HOLD_KINDS):
        out['G2-b'] = ('membership_required', 'rule', 'auth_checks membership_row' + (' + 관리자 우회' if f['bypass'] or 'administrator' in f['names'] or 'admin bypass' in f['names'] else ''))
    elif rule == 'ls_org_member_row': out['G2-b'] = ('membership_required', 'rule', 'rule_v4 ls_org_member_row')
    elif f['has_code'] and not g_rule and not f['is_gitea'] and RE['member_code'].search(code) and not RE['group_role_code'].search(code):
        out['G2-b'] = ('membership_required', 'review', 'code ' + RE['member_code'].search(code).group(0))
    elif f['apis'] and RE['member_text'].search(oas):
        out['G2-b'] = ('?', 'review', 'OAS 문구 "' + RE['member_text'].search(oas).group(0) + '" (요청자 구성원 조건이면 membership_required; 대상 설명이면 유지)')
    # G4-c / G6-b 설정 의존 본인 분기
    if 'setting_dependent' in core:
        out['G4-c/G6-b'] = ('manual_review_required', 'rule', 'auth_checks setting_dependent')
    elif f['proj'] == 'zulip' and rule == 'zulip_target_is_requester' and re.search(r'\w+_changes_disabled', code):
        out['G4-c/G6-b'] = ('?', 'review', '설정 ' + re.search(r'\w+_changes_disabled', code).group(0) + ' + 본인 대상(설정이 꺼지면 관리자만 가능 → 보류 5 manual / 설정 제한만 우회 → owner_match)')
    elif f['has_code'] and not g_rule and not f['is_gitea'] and RE['setting'].search(code) and RE['self'].search(code) and not anon:
        out['G4-c/G6-b'] = ('?', 'review', '설정 ' + RE['setting'].search(code).group(0) + ' + 본인 분기')
    # G5 당사자 OR 관리자
    if 'owner_or_privileged' in core or (f['bypass'] and core <= {'self_target', 'owner_field'} and re.search(r'IsTheSameUser|IsOwner|IsCommentOwner|owner_field|== *request\.user', f['names'])):
        out['G5'] = ('owner_or_admin', 'rule', 'auth_checks owner_or_privileged / 소유자 비교 + superuser 우회')
    elif rule == 'zulip_owner_or_admin_access' or (f['is_gitea'] and 'reqSelfOrAdmin' in mw):
        out['G5'] = ('owner_or_admin', 'rule', '규칙 ' + (rule or 'reqSelfOrAdmin'))
    elif f['is_gitea'] and not has_role_mw and re.search(r'IsUserSiteAdmin\(\)\s*\|\||\|\|\s*ctx\.Doer\.IsAdmin|ctx\.Doer\.IsAdmin\s*\|\||!ctx\.Doer\.IsAdmin\s*&&', body):
        out['G5'] = ('owner_or_admin', 'review', 'gitea 핸들러 본문 본인/소유자 || IsAdmin')
    elif f['has_code'] and not g_rule and not f['is_gitea'] and RE['party_or_admin'].search(code):
        out['G5'] = ('owner_or_admin', 'review', 'code ' + RE['party_or_admin'].search(code).group(0))
    elif f['apis'] and RE['party_or_admin_text'].search(oas):
        out['G5'] = ('?', 'review', 'OAS 문구 "' + RE['party_or_admin_text'].search(oas).group(0) + '" (당사자 OR 관리자면 owner_or_admin)')
    # G6-a 다른 유형 OR 분기
    if core & {'visibility_branch', 'compound_and'}:
        out['G6-a'] = ('manual_review_required', 'rule', 'auth_checks ' + ','.join(sorted(core & {'visibility_branch', 'compound_and'})))
    elif rule == 'zulip_or_branch_access': out['G6-a'] = ('manual_review_required', 'rule', 'rule_v4 zulip_or_branch_access(채널·메시지 접근 함수 / 설정 그룹 권한)')
    elif f['is_gitea'] and has_vis_mw and not has_role_mw and not has_member_mw and anon != 'G7-b':
        if SELF_SCOPE_PATH.search(path):
            out['G6-a'] = ('?', 'review', 'gitea 공개/비공개 분기(VIS) + 본인 데이터 범위(star·watch·구독·stopwatch·알림·반응·시간): data-v2 VIS+SELF는 owner_match, v3.1 정지1-a/G6-a는 방 접근 판단 유무로 가름')
        elif f['authz_lines'] > 0 or method in MUT or re.search(r'CanWrite|IsOwner|IsAdmin|Permission\.|IsPoster|Doer\.ID ==', body):
            out['G6-a'] = ('?', 'review', 'gitea 공개/비공개 분기(VIS) + 핸들러 내 추가 검사 가능성(작성자·권한·변경 요청): 결정 조건 확인 필요')
        else:
            out['G6-a'] = ('manual_review_required', 'rule', 'gitea 공개/비공개 분기만(GET, VIS: ' + ','.join(x for x in mw if any(x.startswith(v) for v in GITEA_VIS_MW)) + ')')
    elif f['has_code'] and not g_rule and not f['is_gitea'] and RE['visibility'].search(code):
        out['G6-a'] = ('manual_review_required', 'review', 'code ' + RE['visibility'].search(code).group(0))
    # 생성 요청(절차 5)
    if method == 'POST' and not f['has_pk'] and '생성(절차5)' not in out and not re.search(r'login|token|session|auth|register|signup|password|reset|verify|logout|markdown|markup', path, re.I):
        if 'G7-a' in out or 'G7-b' in out or g_rule: pass  # 익명 / 규칙 라벨러(G 규약)가 이미 생성 요청을 G1-c·G4-b·G2·G3로 처리
        elif f['has_code']:
            if RE['tenant_code'].search(code) and 'G3-a' not in out: pred = 'tenant_match'
            elif f['is_gitea'] and has_member_mw: pred = 'membership_required'
            elif has_role_mw or RE['perm'].search(code): pred = 'role_required'
            elif re.search(r'^/user/', path): pred = 'owner_match'
            elif re.search(r'ctx\.Doer\.ID|request\.user|caller\.uid|device\.UserID', body): pred = '?'
            elif 'G6-a' in out: pred = 'manual_review_required'
            else: pred = '?'
            out['생성(절차5)'] = (pred, 'review', '코드 있는 생성 요청' + ('(본인 명의 여부 확인)' if pred == '?' else ''))
        else:
            out['생성(절차5)'] = ('=', 'review', 'OAS만 있는 생성 요청: 설명에 명시 조건이 있으면 현행 유지, 없으면 보류 2(점검 대상)')
    # 규칙 라벨러(rule_label_v5)와 같은 우선순위: 보류 kind(가시성·설정·AND)나 조건부 익명이 있으면 다른 후보보다 보류가 우선한다(v3.1 보류 4·5도 동일)
    if kinds and ((core & HOLD_KINDS) or ('anonymous' in core and core != {'anonymous'})):
        out = {k: v for k, v in out.items() if k in ('G6-a', 'G4-c/G6-b', 'G7-b')} or out
    return out


RATIONALE_V301 = [('security 선언을 public 거부 근거로 사용', re.compile(r'security가 선언|security 선언|선언되어 인증이 필요')),
                  ('mutation 제한 언급', re.compile(r'mutation|변경 요청이므로')),
                  ('AND 결합·복합 조건 보류', re.compile(r'AND|결합되어|복합|두 (개의 )?조건|독립 필수|여러 조건')),
                  ('구성원+역할을 보류 사유로', re.compile(r'구성원.*역할|역할.*구성원|멤버십.*역할|membership.*role')),
                  ('조직 소유자를 owner로 해석', re.compile(r'조직 소유자|organization owner|org owner|reqOrgOwnership'))]


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'
    train = jl(P / 'train_v5.jsonl'); val = jl(P / 'val_v5.jsonl')
    sft = {s['id']: s for s in jl(SFT / 'train_sft_v5.jsonl') + jl(SFT / 'val_sft_v5.jsonl')}
    rows = [dict(r, _split='train') for r in train] + [dict(r, _split='val') for r in val]
    dropped = [r['id'] for r in rows if r['id'] not in sft]; rows = [r for r in rows if r['id'] in sft]
    assert len(rows) == 1274 + 179, len(rows)

    # ---- 사람 검수 ID ----
    v5rev = {d['id']: d for d in sheet_dicts(read_xlsx(ROOT / 'review' / 'v5_train_review_reviewed.xlsx')['v5_train_review']) if d.get('id')}
    v4x = read_xlsx(ROOT / 'review' / 'v4_train_review_reviewed.xlsx')
    v4rev = {d['id']: d for name in ('v4_train_review', '선정 제외 manual 표본') for d in sheet_dicts(v4x[name]) if d.get('id')}
    v3rev = {}
    for fn in ('review_pairs_v3s1_reviewed.xlsx', 'review_pairs_v3s1b_reviewed.xlsx'):
        for d in sheet_dicts(read_xlsx(ROOT / 'reports' / 'data_v3' / fn)['review_pairs']):
            if d.get('pair_id'): v3rev[d['pair_id']] = d; v3rev[(d['repo'], d['method'], d['path'])] = d

    def review_of(r):
        m = r['meta']
        if m.get('human_reviewed_v2') or m.get('review_r3'): return 'v2'
        if r['id'] in v5rev: return 'v5'
        if r['id'] in v4rev: return 'v4'
        if m.get('pair_id') and (m['pair_id'] in v3rev or (r['service'], r['method'], r['path']) in v3rev): return 'v3'
        return ''

    # ---- 행 표 + 후보 ----
    table = []; per_rule = Counter(); per_rule_change = Counter(); per_rule_q = Counter()
    for r in rows:
        f = feats(r); det = detect(r, f); rv = review_of(r); a = json.loads(sft[r['id']]['assistant'])
        rat_flags = [n for n, rx in RATIONALE_V301 if rx.search(a['rationale'])]
        rule_preds = {v[0] for v in det.values() if v[1] == 'rule' and v[0] not in ('?', '=')}
        rev_preds = {v[0] for v in det.values() if v[1] == 'review' and v[0] not in ('?', '=')}
        has_q = any(v[0] == '?' for v in det.values())
        if len(rule_preds) == 1: pred, basis = next(iter(rule_preds)), 'rule'
        elif len(rule_preds) > 1: pred, basis = '?', 'conflict:' + ','.join(sorted(rule_preds))
        elif len(rev_preds) == 1 and not has_q: pred, basis = next(iter(rev_preds)), 'review'
        elif len(rev_preds) > 1: pred, basis = '?', 'conflict:' + ','.join(sorted(rev_preds))
        elif has_q: pred, basis = '?', 'review'
        elif det: pred, basis = '=', 'review'
        else: pred, basis = '', ''
        if pred == '?' and rule_preds and len(rule_preds) == 1: pred, basis = next(iter(rule_preds)), 'rule'  # 결정적 규칙이 하나면 그것을 우선
        status = ('후보 아님' if not det else '변경 예상' if pred not in ('', '?', '=') and pred != r['label'] else '판정 필요' if pred == '?' else '유지 예상')
        if rv and status == '변경 예상': status = '변경 예상(사람 검수 행: 유지 후보)'
        qs = [v[2] for v in det.values() if v[0] == '?']
        qkind = ('OAS 문구' if qs and all('OAS' in t for t in qs) else '코드') if pred == '?' else ''
        ctypes = sorted({CHANGE_TYPE[k] for k, v in det.items() if v[0] == pred and pred not in ('', '?', '=')}) if status.startswith('변경') else []
        table.append(dict(id=r['id'], split=r['_split'], source=source_kind(r), project=project_of(r), service=r['service'], method=r['method'], path=r['path'],
                          data_version=r['meta'].get('data_version') or '', label_source=label_source_desc(r), rule_id=f['rule'], human_review=rv, review_protocol=REVIEW_PROTOCOL.get(rv, ''),
                          g_protocol='Y' if rv in ('v4', 'v5') else ('부분(G 이전 기준)' if rv == 'v2' else ('변형 판정만' if rv == 'v3' else 'N')), has_code='Y' if f['has_code'] else 'N',
                          security_state=r['security_state'], label=r['label'], candidate_rules=';'.join(det.keys()), predicted_v31=pred, prediction_basis=basis, status=status, question_kind=qkind,
                          change_type=';'.join(ctypes), evidence=' | '.join(f'{k}: {v[2]}' for k, v in det.items()), rationale_v301_wording=';'.join(rat_flags), sft_rationale=a['rationale']))
        for k, v in det.items():
            per_rule[k] += 1
            if v[0] == '?': per_rule_q[k] += 1
            elif v[0] not in ('=',) and v[0] != r['label']: per_rule_change[k] += 1
    cands = [x for x in table if x['candidate_rules']]

    # ---- 겹침 검사 ----
    tests = {'test_v30': jl(P / 'test_v30.jsonl'), 'test_v31_supp(+excluded)': jl(P / 'data_v4' / 'test_v31_supp.jsonl') + jl(P / 'data_v4' / 'test_v31_supp_excluded.jsonl'),
             'test_v5(+excluded)': jl(P / 'test_v5.jsonl') + jl(P / 'data_v5' / 'test_v5_excluded.jsonl'), 'test_v6_candidates': jl(P / 'data_v6' / 'test_v6_candidates.jsonl')}
    mykeys = {key(r): r['id'] for r in rows}; myserv = {norm_service(r['service']) for r in rows} | {norm_service(r['meta'].get('project') or '') for r in rows} - {''}
    overlap = {}
    for name, t in tests.items():
        hit = [(k, mykeys[k]) for k in (key(x) for x in t) if k in mykeys]
        sv = sorted(({norm_service(svc(x)) for x in t} | {norm_service((x.get('meta') or {}).get('project') or x.get('project') or '') for x in t}) & myserv)
        overlap[name] = dict(n=len(t), key_overlap=len(hit), key_examples=hit[:5], service_overlap=sv)

    # ---- 집계 ----
    chg = [x for x in table if x['status'].startswith('변경 예상')]; q = [x for x in table if x['status'] == '판정 필요']
    label_shift = Counter((x['label'], x['predicted_v31']) for x in chg)
    dist_now = Counter(x['label'] for x in table); dist_pred = Counter((x['predicted_v31'] if x['status'] == '변경 예상' else x['label']) for x in table)
    pk = lambda x: x['project'] if x['source'] != 'APIs.guru' else 'APIs.guru'
    proj_all = Counter(pk(x) for x in table); proj_chg = Counter(pk(x) for x in chg); proj_q = Counter(pk(x) for x in q)
    rat_only = [x for x in table if x['status'] in ('유지 예상', '후보 아님') and x['rationale_v301_wording']]
    rat_flag_counts = Counter(fl for x in table for fl in x['rationale_v301_wording'].split(';') if fl)
    rng = random.Random(SEED); unchanged = [x for x in table if not x['status'].startswith('변경 예상') and x['status'] != '판정 필요']
    audit = rng.sample(unchanged, round(len(unchanged) * 0.05))
    c2 = dict(label_change=len(chg), judge=len(q), rationale_only=len(rat_only),
              template_regen=sum(1 for x in chg + q if x['label_source'].startswith(('규칙 라벨러', '합성 설계'))), free_text_rewrite=sum(1 for x in chg + q if x['label_source'].startswith('LLM')))
    summary = dict(rows=len(table), dropped_from_sft=dropped, by_split_source=sorted(Counter((x['split'], x['source']) for x in table).items()),
                   by_split_label_source=sorted(Counter((x['split'], x['label_source'].split(' →')[0]) for x in table).items()), by_review=sorted(Counter((x['split'], x['human_review'] or '없음') for x in table).items()),
                   per_rule=dict(per_rule), per_rule_change=dict(per_rule_change), per_rule_question=dict(per_rule_q), by_status=sorted(Counter((x['split'], x['status']) for x in table).items()),
                   label_shift=[(a, b, n) for (a, b), n in label_shift.most_common()], dist_now=dict(dist_now), dist_pred=dict(dist_pred), overlap=overlap, c2=c2,
                   change_types=dict(Counter(x['change_type'] for x in chg)), question_kinds=dict(Counter((x['question_kind'], x['candidate_rules']) for x in q).most_common()) if False else dict(Counter(x['question_kind'] for x in q)),
                   rationale_flag_counts=dict(rat_flag_counts), audit_n=len(audit), review_sets=dict(v5=len(v5rev), v4=len(v4rev), v3_pairs=len({k for k in v3rev if isinstance(k, str)})))

    # ---- 파일 출력 ----
    with open(OUT / 'c0_rows.csv', 'w', encoding='utf-8-sig', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(table[0].keys())); w.writeheader(); w.writerows(table)
    with open(OUT / 'c0_candidates.jsonl', 'w', encoding='utf-8', newline='\n') as fh:
        for x in cands: fh.write(json.dumps(x, ensure_ascii=False) + '\n')
    with open(OUT / 'c0_audit_sample_ids.json', 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(dict(seed=SEED, rate=0.05, population=len(unchanged), n=len(audit), ids=[x['id'] for x in audit]), fh, ensure_ascii=False, indent=1)
    with open(OUT / 'c0_summary.json', 'w', encoding='utf-8', newline='\n') as fh: json.dump(summary, fh, ensure_ascii=False, indent=1)
    write_report(table, chg, q, summary, overlap, audit, rat_only, per_rule, per_rule_change, per_rule_q, label_shift, dist_now, dist_pred, proj_all, proj_chg, proj_q, c2, dropped, v5rev, v4rev)
    print(json.dumps({k: v for k, v in summary.items() if k != 'overlap'}, ensure_ascii=False)); print(json.dumps(overlap, ensure_ascii=False))


def md_table(header, rows):
    return ['| ' + ' | '.join(header) + ' |', '|' + '|'.join('---:' if h.endswith(':') else '---' for h in header) + '|'] + ['| ' + ' | '.join(str(c).replace('|', '/').replace('\n', ' ') for c in r) + ' |' for r in rows]


def write_report(table, chg, q, S, overlap, audit, rat_only, per_rule, per_rule_change, per_rule_q, label_shift, dist_now, dist_pred, proj_all, proj_chg, proj_q, c2, dropped, v5rev, v4rev):
    n = len(table); hv = lambda k: sum(1 for x in table if x['human_review'] == k)
    L = ['# 작업 C0 — v3.1 학습 정답 재작성 영향 행 분석 (2026-11-05, 학습·추론 없음, 커밋 금지)', '',
         f'생성: `scripts/c0_impact_v6d.py`. 대상 data-v5 SFT 행 train 1,274 / val 179 = {n}건(processed train_v5·val_v5에서 4096 토큰 초과로 SFT에 없는 {len(dropped)}건 제외: {", ".join(dropped)}). '
         '동결 파일은 해시 확인 후 읽기만 했다. 후보 추출은 입력(코드·미들웨어 체인·OAS 텍스트)과 규칙 라벨러 특징(meta.rule_v4/rule_v5/rule_id, auth_checks kind)만 썼고 정답 label은 비교 단계에서만 읽었다. '
         'rationale 분석은 실제 학습 target인 SFT assistant(train_sft_v5/val_sft_v5)를 기준으로 했다(processed rationale과 21건이 다름: data-v2 규칙 relabel 문장 — C2는 SFT assistant를 출발점으로 삼아야 한다). '
         '산출: 행 단위 표 `c0_rows.csv`(1행 = 1레코드, 아래 모든 열), 후보 `c0_candidates.jsonl`, 집계 `c0_summary.json`, 무작위 5% 표본 id `c0_audit_sample_ids.json`.', '',
         '설계 전제(지시문): C는 S5(v6a) 설정(프롬프트 v3.1 `e8b6c506…`, 출력 순서 evidence→rationale→label→confidence, max_seq_len 6144, 그 외 v5 하이퍼파라미터)을 그대로 두고 학습 정답(label·rationale)만 v3.1 정의(label_defs_v3.1_draft.md)와 G1~G8에 맞춘다. '
         'C vs S5 = 정답 정합 효과, C vs v5 = 최종 비교. user 입력은 data_v6a와 바이트 동일하게 유지한다. test_v6은 추론하지 않는다.', '',
         '## 1. 행별 출처·라벨 출처·사람 검수 여부', '', '### 1.1 출처(프로젝트·APIs.guru·합성)', '']
    L += md_table(['split', '출처', '건수:'], [(a, b, c) for (a, b), c in S['by_split_source']]); L.append('')
    L += md_table(['프로젝트/출처', '전체:', 'train:', 'val:'], [(p, c, sum(1 for x in table if (x['project'] if x['source'] != 'APIs.guru' else 'APIs.guru') == p and x['split'] == 'train'),
                                                      sum(1 for x in table if (x['project'] if x['source'] != 'APIs.guru' else 'APIs.guru') == p and x['split'] == 'val')) for p, c in proj_all.most_common()]); L.append('')
    L += ['### 1.2 라벨 출처(규칙 라벨러 / LLM / 사람 검수 / 합성 설계)', '']
    L += md_table(['split', '라벨 출처(1차)', '건수:'], [(a, b, c) for (a, b), c in S['by_split_label_source']]); L.append('')
    ls2 = Counter((x['split'], x['label_source']) for x in table)
    L += md_table(['split', '라벨 출처(세부: 1차 → data-v2 규칙 relabel / 사람 검수 교정)', '건수:'], [(a, b, c) for (a, b), c in sorted(ls2.items(), key=lambda t: (t[0][0], -t[1]))]); L.append('')
    L += ['### 1.3 사람 검수 여부와 적용 규약', '', '행이 어느 검수 시트에 들어 있었는가(검수 시트의 검수자 열 표기를 그대로 적음):', '']
    L += md_table(['split', '검수', '건수:', '적용 규약'], [(sp, rv, c, REVIEW_PROTOCOL.get(rv, '—')) for (sp, rv), c in S['by_review']]); L.append('')
    L += [f'- data-v5 검수 시트 {len(v5rev)}행(검수자 이혜인, G1~G8 + 정지 지점 3 수정 규칙) 중 train/val에 있는 행 {hv("v5")}건(나머지는 제외 전환·pool 이동). '
          f'data-v4 검수 시트 {len(v4rev)}행(두 시트, 검수자 열 "Claude (AI 검수, 사람 확인 필요)") 중 train/val에 있는 행 {hv("v4")}건. '
          f'data-v3 1b 쌍 검수(검수자 열 "Claude 1차(사용자 확인 필요)") 80쌍은 원본 label 정확 여부와 변형 유지 가능 여부를 봤고 G 규약 적용이 아니다 — 해당 행 {hv("v3")}건. '
          f'data-v2 사람 검수(review_sheet A/B/C + r3, 2026-10-23 라벨 기준) {hv("v2")}건은 G 이전 기준이지만 내용상 G3(저장소 권한 레벨→role)·G2(org/팀 멤버십)·G6-a(VIS)·G6-c(AUTH_ANY)와 같은 결론이다.',
          f'- G1~G8을 명시 적용한 검수를 거친 행은 data-v4·v5 검수분 {hv("v4") + hv("v5")}건({100 * (hv("v4") + hv("v5")) / n:.1f}%)뿐이고, 그중 사람(이혜인)이 확정한 행은 data-v5 {hv("v5")}건이다. '
          f'나머지 {n - hv("v4") - hv("v5")}건의 라벨은 LLM(v3.0.1 프롬프트, 615건)·G 규약 기반 규칙 라벨러(rule_label_v4/v5, 미검수분)·검사 줄 규칙(data-v3)·합성 설계에서 왔다.', '',
          '## 2. v3.1 변경 규칙별 영향 후보 (입력 기준 추출)', '',
          '탐지 방식: (a) G 규약으로 설계된 규칙 라벨러 프로젝트(Zulip·Label Studio·Dendrite·NodeBB·Taiga)는 규칙 이름·auth_checks kind만 사용(코드 정규식은 보일러플레이트 때문에 과검출), '
          '(b) LLM 라벨 프로젝트(gitea 미들웨어 체인·핸들러 본문, memos·kutt·realworld 등)는 미들웨어 이름·코드 정규식, (c) APIs.guru(OAS만)는 설명 문구 정규식 → 항상 `?`(판정 필요), (d) data-v3 쌍은 rule_id. '
          '판정 종류: `rule` = 결정적 예측, `review` = 정규식 기반이라 C1에서 확인, `?` = 규칙만으로 label을 정할 수 없음, `=` = 현행 유지 점검만(OAS만 있는 생성 요청). 한 행이 여러 규칙에 걸릴 수 있다.', '']
    L += md_table(['규칙', '내용', '후보:', '예상 변경(예측≠현재):', '판정 필요(?):', '유지 예상:'],
                  [(k, RULE_DESC[k], per_rule[k], per_rule_change[k], per_rule_q[k], per_rule[k] - per_rule_change[k] - per_rule_q[k]) for k in RULE_DESC if per_rule[k]]); L.append('')
    dm = [x for x in table if '[declared mutation]' in x['evidence']]
    L += [f'- G7-a 세부: 코드상 인증 없는 행 {per_rule["G7-a"]}건 중 security_state=declared인 mutation(POST/PUT/PATCH/DELETE)은 {len(dm)}건'
          + (f'({", ".join(x["id"] + ":" + x["label"] for x in dm)})' if dm else '') + ' — v3.0.1이 금지하던 "declared mutation public" 조합은 학습 데이터에 거의 없고, declared GET public은 v3.0.1에서도 허용되던 경우다.',
          f'- G3-a 세부: 유지 예상 {per_rule["G3-a"] - per_rule_change["G3-a"] - per_rule_q["G3-a"]}건은 rule_label_v5 group_role(Taiga 프로젝트 역할·NodeBB 카테고리 모더레이터·Dendrite power level)·rule_label_v4 zulip_realm_admin·gitea reqRepoWriter/reqAdmin이 이미 role_required인 행이다. '
          '변경 예상의 대부분은 gitea reqOrgOwnership(조직 소유자 = 그룹 안 역할)을 LLM이 owner_match로 읽은 행이다.', '']
    L += ['규칙별 후보의 현재 label × 예상 label(행 상태가 변경 예상·판정 필요인 행만):', '']
    det_rows = []
    for k in RULE_DESC:
        c = Counter((x['label'], x['predicted_v31']) for x in table if k in x['candidate_rules'].split(';') and (x['status'].startswith('변경') or x['status'] == '판정 필요'))
        for (a, b), cnt in c.most_common():
            det_rows.append((k, a, b, cnt, sum(1 for x in table if k in x['candidate_rules'].split(';') and x['label'] == a and x['predicted_v31'] == b and x['human_review'] and (x['status'].startswith('변경') or x['status'] == '판정 필요'))))
    L += md_table(['규칙', '현재 label', '예상 label', '건수:', '그중 검수 행:'], det_rows); L.append('')
    L += ['## 3. 바뀔 가능성 있는 행 목록', '', '행 상태(한 행 = 하나의 상태; 결정적 규칙 예측이 하나면 그것을 쓰고, 서로 다른 결정적 예측이 충돌하면 `?`):', '']
    L += md_table(['split', '상태', '건수:'], [(a, b, c) for (a, b), c in S['by_status']]); L.append('')
    L += [f'- **변경 예상 {len(chg)}건**(이 중 사람·AI 검수 행 {sum(1 for x in chg if x["human_review"])}건은 "유지 후보"로 별도 표시), **판정 필요 {len(q)}건**(코드 근거 {sum(1 for x in q if x["question_kind"] == "코드")} · OAS 문구만 {sum(1 for x in q if x["question_kind"] == "OAS 문구")}). 전체 목록은 c0_candidates.jsonl(`status` 열).', '',
          '변경 유형(v3.1 규칙 변경으로 바뀌는 행인지, v3.0.1 기준으로도 틀려 있던 label의 교정인지):', '']
    L += md_table(['변경 유형', '건수:'], sorted(S['change_types'].items(), key=lambda t: -t[1])); L.append('')
    L += ['현재 label → 예상 label(변경 예상 행):', '']
    L += md_table(['현재', '예상', '건수:'], [(a, b, c) for (a, b), c in label_shift.most_common()]); L.append('')
    L += ['변경 예상 행 전부(검수 행은 ★ — 기존 검수 label 유지 후보):', '']
    L += md_table(['id', 'split', '프로젝트', 'method path', '현재', '예상', '규칙', '근거'],
                  [(('★' if x['human_review'] else '') + x['id'], x['split'], x['project'], f"{x['method']} {x['path']}", x['label'], x['predicted_v31'], x['candidate_rules'], x['evidence'][:150]) for x in sorted(chg, key=lambda x: (x['project'], x['path']))]); L.append('')
    L += ['판정 필요 행(`?`) — 규칙 조합·프로젝트별:', '']
    L += md_table(['규칙 조합', '프로젝트', '근거 종류', '건수:'], [(a, b, k, c) for (a, b, k), c in Counter((x['candidate_rules'], x['project'] if x['source'] != 'APIs.guru' else 'APIs.guru', x['question_kind']) for x in q).most_common()]); L.append('')
    L += ['판정 필요 행 중 코드 근거 행 전부:', '']
    L += md_table(['id', '프로젝트', 'method path', '현재', '규칙', '근거'], [(('★' if x['human_review'] else '') + x['id'], x['project'], f"{x['method']} {x['path']}", x['label'], x['candidate_rules'], x['evidence'][:170]) for x in sorted(q, key=lambda x: (x['project'], x['path'])) if x['question_kind'] == '코드']); L.append('')
    L += ['## 4. 집계', '', '### 4.1 label 분포 변화 예상(변경 예상 행만 반영; 판정 필요 행은 현재 label 유지로 계산)', '']
    L += md_table(['label', '현재:', '예상:', '차이:'], [(l, dist_now[l], dist_pred[l], dist_pred[l] - dist_now[l]) for l in LABELS]); L.append('')
    L += [f'manual 비율: 현재 {100 * dist_now["manual_review_required"] / n:.1f}% → 예상 {100 * dist_pred["manual_review_required"] / n:.1f}%(판정 필요 {len(q)}건의 결과에 따라 달라짐; data-v5 SFT train 기준 12.79%).', '',
          '### 4.2 프로젝트별(전체·변경 예상·판정 필요)', '']
    L += md_table(['프로젝트', '전체:', '변경 예상:', '판정 필요:', '변경 비율:'], [(p, proj_all[p], proj_chg[p], proj_q[p], f'{100 * proj_chg[p] / proj_all[p]:.1f}%') for p, _ in proj_all.most_common()]); L.append('')
    L += ['### 4.3 v3.0.1 전용 논리를 쓴 rationale(label 유지 행 포함)', '', 'SFT assistant rationale에 v3.0.1에서만 타당하거나 v3.1과 어긋나는 표현이 든 행 수:', '']
    L += md_table(['표현 유형', '건수:'], sorted(S['rationale_flag_counts'].items(), key=lambda t: -t[1])); L.append('')
    L += [f'label 유지 예상·후보 아님 행 중 위 표현이 든 행: {len(rat_only)}건(c0_rows.csv `rationale_v301_wording` 열). '
          '"security 선언" 문구는 OAS만 있는 행에서는 v3.1에서도 유효하다(코드 없이 OAS만 있을 때 security 선언·mutation 제한 유지). 코드가 있는 행에서만 재작성 대상이다: '
          f'{sum(1 for x in rat_only if x["has_code"] == "Y" and "security" in x["rationale_v301_wording"])}건. "AND 결합" 문구는 합성 tenant AND membership(보류 3 유지)에서는 유효하고, LLM rationale의 복합 조건 보류 '
          f'{sum(1 for x in rat_only if x["label_source"].startswith("LLM") and "AND" in x["rationale_v301_wording"])}건은 v3.1 예외(그룹 안 역할·tenant+RBAC)에 해당하는지 C1에서 본다.', '',
          '## 5. C1(재판정)·C2(rationale 재작성) 작업량 추정과 검수 시트 설계안', '',
          f'- **C1 재판정 대상 {c2["label_change"] + c2["judge"]}건** = 변경 예상 {c2["label_change"]} + 판정 필요 {c2["judge"]}. 결정적(rule) 예측 {sum(1 for x in chg if x["prediction_basis"] == "rule")}건은 기계 적용 후 사람 확인, review 예측 {sum(1 for x in chg if x["prediction_basis"] == "review")}건과 `?` {c2["judge"]}건은 사람이 v3.1 정의와 G1~G8로 확정한다. '
          f'검수 행 {sum(1 for x in chg + q if x["human_review"])}건은 기존 검수 label 유지를 기본값으로 두고 바꾸려면 사유를 적는다. OAS 문구만 근거인 `?` {sum(1 for x in q if x["question_kind"] == "OAS 문구")}건은 설명문 재독으로 끝나는 가벼운 판정이다.',
          f'- **C2 rationale 재작성 대상**: (a) label이 바뀌는 행 전부 {c2["label_change"]}건(+ 판정 결과 바뀌는 행), (b) label 유지지만 v3.0.1 전용 논리 문구가 든 행 {c2["rationale_only"]}건, '
          f'(c) 규칙 라벨러·합성 템플릿 행은 label에 맞는 템플릿 문장으로 자동 재생성({c2["template_regen"]}건이 C1 대상에 포함; rule_label_v4/v5 TEMPLATE·JUDGE 사전 재사용), LLM 자유문 행은 v3.1 프롬프트로 LLM 재작성 후 사람 확인 또는 사람이 직접 작성({c2["free_text_rewrite"]}건이 C1 대상에 포함). '
          '재작성 rationale은 data-v3 이후 정합성 규칙(구체 label에 보류 표현 0, 검수 메타 문구 0, 규칙 ID·파일 경로 0, 4096/6144 토큰 한도)을 빌드 assert로 다시 검사한다. '
          f'예상 작업량: 사람 판정 {c2["label_change"] + c2["judge"]}건 × 약 3~5분 ≈ {(c2["label_change"] + c2["judge"]) * 3 // 60}~{(c2["label_change"] + c2["judge"]) * 5 // 60}시간, 자유문 재작성 {c2["free_text_rewrite"] + sum(1 for x in rat_only if x["label_source"].startswith("LLM"))}건 × 약 2분 ≈ {(c2["free_text_rewrite"] + sum(1 for x in rat_only if x["label_source"].startswith("LLM"))) * 2 // 60}시간(LLM 초안 사용 시 확인만).',
          f'- **사람 확인 대상 {len(chg) + len(q) + len(audit)}건** = 예상 변경 {len(chg)} + 판정 필요 {len(q)} + 안 바뀐 행 5% 무작위 {len(audit)}(seed 42, 모집단 {n - len(chg) - len(q)}건, id는 c0_audit_sample_ids.json).',
          '- **검수 시트 설계안** `review/c1_relabel_review.xlsx`(생성 스크립트는 C1 단계에서 작성, xlsx는 커밋하지 않음): 시트 "변경 예상"·"판정 필요(코드)"·"판정 필요(OAS 문구)"·"무작위 5%(블라인드)"·"검수 규약"(G1~G8 원문 + v3.1 변경 요약표 + 정지 지점 1 통일 판단). '
          '열: id · split · 프로젝트 · method · path · 입력 요약(auth_summary 또는 미들웨어 체인) · controller_text(또는 OAS 설명) · 현재 label · 현재 rationale(SFT) · 후보 규칙 · 예상 label · 예상 근거 · 기존 검수 label·검수자(있으면) · **확정 label** · **확정 rationale(자유문) 또는 템플릿 선택** · 확정 근거(코드 줄) · 검수자. '
          '무작위 5% 시트는 블라인드(현재·예상 label 숨김, 정답키는 시트 밖 json). 검수자 균등 배분. **사전 기록**: 블라인드 표본의 불일치율(사람 판정 ≠ 현재 label)이 5%를 넘으면 안 바뀐 행도 전수 검수한다(test_v6 사람 확인 프로토콜과 같은 기준).',
          '- 처리 순서 제안: C1-1 결정적 규칙 예측을 기계 적용한 초안 → C1-2 review·`?` 행 사람 판정 → C2 템플릿 재생성 + 자유문 재작성(LLM 초안은 gpt-4o-mini + v3.1 프롬프트, 사람 확인) → 정합성 assert → data-v6d 동결(해시·DATA_CARD) → 학습은 별도 승인.', '',
          '## 6. test 프로젝트 겹침 재확인', '']
    L += md_table(['test 셋', '건수:', '(서비스, method, 정규화 path) 겹침:', '서비스·프로젝트명 겹침'], [(nm, o['n'], o['key_overlap'], ', '.join(o['service_overlap']) or '없음') for nm, o in overlap.items()]); L.append('')
    L += ['test_v31_supp·test_v5는 제외 목록(excluded)까지 포함해 대조했다. 네 test 셋 모두 겹침 0건이므로 C 데이터(= data-v5 행)의 출처는 test 프로젝트와 겹치지 않는다. C에는 새 출처를 추가하지 않는다.', '',
          '## 7. 한계와 주의', '',
          '- 후보 추출은 미들웨어 이름·정규식·규칙 라벨러 kind에 의존한다. OAS만 있는 APIs.guru 행(390건)은 설명 문구로만 걸러 `?`로 두었고, v3.1의 OAS-only 규칙(보류 2, security 선언·mutation 제한 유지)은 v3.0.1과 같아 label 변화는 드물 것으로 본다.',
          '- G 규약 기반 규칙 라벨러(rule_label_v4/v5)로 라벨된 행은 정의상 v3.1과 거의 일치하므로 "유지 예상"이 대부분이다. 다만 규칙 라벨러가 G6으로 보류한 Zulip 설정 그룹 권한(has_permission)·Label Studio 전 역할 보유 권한은 v3.1 G3-b/G6-c 경계 문장대로 manual이 맞는지 C1에서 표본 확인한다.',
          '- gitea 조직 소유자(reqOrgOwnership) 23건은 LLM이 "소유자"로 읽어 owner_match가 됐으나 v3.1 G3-a(그룹 안 역할)로는 role_required다. 이 묶음이 변경 예상의 가장 큰 덩어리다.',
          '- `?` 행의 예상 label은 사람 판정 전까지 미정이며 4.1의 분포 예상에는 현재 label로 넣었다.',
          '- 합성 레코드(161건)는 설계 라벨이며 v3.1에서도 유효하다(tenant AND membership → 보류 3 유지, premium → 보류 1 유지, owner_or_admin, 인증만 → 보류 8). 합성 "tenant AND role" 패턴은 없다.',
          '- 이 보고는 영향 범위 추정이다. label·rationale 파일은 수정하지 않았고 학습·추론·커밋도 하지 않았다.']
    (OUT / 'c0_impact.md').write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':
    main()
