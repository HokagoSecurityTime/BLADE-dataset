"""작업 C1 — 결정적 규칙 예측 기계 적용 초안 + 검수 시트 생성 (학습·추론 없음, 커밋 금지, xlsx 미커밋).

입력: reports/data_v6d/c0_rows.csv(C0 행 표), c0_audit_sample_ids.json(5% 무작위 표본, seed 42), data-v5 train/val(해시 확인, 읽기만),
      SFT train/val(assistant = C2 출발점), 검수 시트(v5·v4·v3 pairs)의 기존 검수 label.
출력: reports/data_v6d/c1_draft_deterministic.jsonl(결정적 32건 초안: label + 템플릿 rationale 초안; 동결 파일은 수정하지 않음),
      review/c1_relabel_review.xlsx(시트 5개: 안내·검수 규약 / 무작위5%_블라인드 / 판정 필요(코드) / 판정 필요(OAS 문구) / 변경 예상·C2),
      reports/data_v6d/c1_audit_key.json(블라인드 정답키, 시트 밖), reports/data_v6d/c1_sheet_report.md.
openpyxl이 없어 xlsx는 zipfile + OOXML(inlineStr)로 직접 쓴다.
"""
from __future__ import annotations
import csv, hashlib, json, random, re, sys, zipfile
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from c0_impact_v6d import FROZEN, P, SFT, jl, read_xlsx, sheet_dicts, sha, RULE_DESC  # noqa: E402

OUT = ROOT / 'reports' / 'data_v6d'
XLSX = ROOT / 'review' / 'c1_relabel_review.xlsx'
SEED = 42
REVIEWERS = ['A', 'B', 'C']
CELL_MAX = 30000
TEMPLATE = {'owner_match': '처리 대상이 요청자 본인으로 고정되어 있어', 'role_required': '역할·권한 검사가 접근 조건이라', 'membership_required': '대상 방·그룹·조직의 구성원 행을 조회해 허용하므로',
            'tenant_match': '자원을 요청자의 활성 조직 범위로 한정하므로', 'owner_or_admin': '소유자 본인 또는 권한 보유자만 통과하는 조건이라',
            'public': '인증·권한 검사 없이 익명 호출을 허용하므로', 'manual_review_required': '접근 조건이 하나로 정해지지 않아'}
JUDGE = {'owner_match': '소유자 본인만 허용하는 조건이므로 owner_match', 'role_required': '특정 역할 보유가 실제 접근 조건이므로 role_required',
         'public': '인증 요구가 없으므로 public 선택', 'membership_required': '구성원 여부가 실제 접근 조건이므로 membership_required',
         'owner_or_admin': '소유자 또는 관리자 조건이므로 owner_or_admin', 'tenant_match': '요청자의 tenant와 대상 자원의 tenant가 일치해야 하므로 tenant_match',
         'manual_review_required': '접근 조건이 확정되지 않아 보류'}

GUIDE = [
    'C1 재판정 검수 시트 (작업 C′ / data-v6d, 2026-11-05). 학습 정답(label·rationale)만 v3.1 정의와 G1~G8에 맞춰 교정한다. 입력(user)은 data-v5와 바이트 동일하게 유지한다.',
    '',
    '★ 순서: 반드시 "무작위5%_블라인드" 시트를 먼저 끝낸 뒤 다른 시트로 간다. 블라인드 시트에는 현재 label·예상 label·rationale이 없다(정답키는 시트 밖 json). 다른 시트를 먼저 보면 블라인드 표본이 오염된다.',
    '사전 기록: 블라인드 표본의 불일치율(확정 label ≠ 현재 label)이 5%를 넘으면 한계로 기록하고, 안 바뀐 행 전수 검수는 마감(2026-11-08 12:00 KST) 후에 한다.',
    '',
    '시트: (1) 무작위5%_블라인드 68건 — 코드·OAS만 보고 확정 label을 적는다. (2) 판정필요_코드 39건 — 규칙이 label을 정하지 못한 코드 행. (3) 판정필요_OAS문구 22건 — OAS 설명 문구만 근거인 행(설명 재독으로 판정; 근거 없으면 현행 유지).',
    '(4) 변경예상_C2 — 결정적 규칙 초안 32건 + review 1건(초안 label을 확인·수정) + C2 전용 13건(label 유지, rationale에 v3.0.1 전용 문구가 있어 재작성 여부만 판단).',
    '',
    '채워야 하는 열: 확정 label(7종 중 하나) · 확정 근거(코드 줄·설명 문장) · 확정 rationale(자유문; 비우면 C2에서 템플릿/LLM 초안으로 작성 후 재확인) · 검수 메모 · 검수자(배정된 A/B/C, 바꾸면 사유).',
    '기존 검수 행(기존 검수 label 열에 값이 있음)은 기존 label 유지를 기본값으로 두고, 바꾸려면 검수 메모에 사유를 쓴다.',
    'C2 재작성 대상 열: Y(label 변경) = 확정 label이 바뀌면 rationale 재작성, Y(v3.0.1 문구) = label 유지라도 rationale 재작성 후보, C1 결과에 따름 = 판정 결과 바뀌면 재작성. C2 출발점은 SFT assistant rationale(현재 rationale 열)이다.',
    '',
    'label 7종: public · role_required · membership_required · tenant_match · owner_match · owner_or_admin · manual_review_required',
    '',
    '— v3.1 변경 요약(label_defs_v3.1_draft.md) —',
    '그룹 안 역할(계정 administrator·방 owner/moderator·조직 owner·강좌 교사): 구성원 확인 뒤 역할이 결정 조건이면 role_required (v3.0.1 보류 3 아님) [G3-a]',
    '객체 없는 기능의 RBAC 권한 검사 → role_required. 단 모든 사용자 역할이 보유한 권한·인증만 → manual_review_required (통합·API 키 주체 제외) [G3-b/G6-c]',
    'tenant 필터 + 기능 RBAC 권한 → tenant_match [G1-b]; 생성 시 자원 tenant를 요청자 tenant로 강제 → tenant_match [G1-c]',
    '구성원 OR 전역 관리자 우회 → membership_required [G2-b]; 소유자·당사자(작성자·발신자/수신자) OR 관리자 우회 → owner_or_admin, 우회 없으면 owner_match [G5]',
    '관리자 조건이 본인 대상의 설정 제한만 우회 → owner_match; 설정이 본인 분기 자체를 켜고 끄면(꺼지면 관리자만) → manual(보류 5) [G4-c/G6-b]',
    '서로 다른 유형의 조건이 OR로 분기(공개/비공개 가시성·방 종류별 접근 함수·모드별 정책) → manual(보류 4) [G6-a]; 조건부 익명(web-public 등) → manual [G7-b]',
    '코드가 인증 없이 처리함을 보이면 security 선언·mutation 여부와 무관하게 public; OAS만 있으면 security 선언·mutation 제한 유지 [G7-a]',
    '생성 요청: 본인 명의 → owner_match, 요청자 tenant 강제 → tenant_match, 대상 그룹 지정 + 구성원 확인 → membership_required, 역할·권한만 → role_required, 그 외 보류 [절차 5]',
    '본인 구독·본인 행만 변경하고 방 접근 판단이 없으면 owner_match, 방 비구성원을 거부하면 membership_required [정지 지점 1]',
    '',
    '— data-v4 검수 규약 G1~G8 (AGENTS.md 원문) —',
    'G1 (tenant_match): 서버가 자원의 조직·워크스페이스·테넌트를 요청자의 현재 테넌트(세션·토큰의 active organization, activeWorkspaceId, API 키 tenant)와 비교하거나 그것으로 필터. 경로·본문에 대상 테넌트 ID 없음. 라우트 RBAC 권한(checkPermission 등)이 함께 있어도 기능 권한으로 보고 tenant_match. 생성 시 자원 테넌트를 요청자 테넌트로 강제하는 것도 포함.',
    'G2 (membership_required): 요청(경로·본문·쿼리)이 대상 그룹(account, workspace, organization, 채널, 강좌, 사용자 그룹)을 지정하고 (요청자, 그룹) 구성원 행을 조회해 허용. 구성원 OR 관리자 우회도 membership_required.',
    'G3 (role_required): 전역 역할, 또는 그룹 구성원 확인 뒤 그룹 안 역할(계정 administrator, 그룹 moderator, 강좌 교사)이 결정 조건이면 role_required. 객체 없는 기능에 RBAC 권한만 있는 경우도 포함.',
    'G4 (owner_match): 처리 대상이 인증 사용자 본인으로 고정(/me, request.user, 본인 목록·설정·플래그·기기, 본인 명의 생성) 또는 객체 소유자 == 요청자. 관리자 조건이 타인 대상 우회가 아니라 설정 우회일 뿐이면 owner_match.',
    'G5 (owner_or_admin): 소유자·당사자(작성자, 발신자/수신자, 관계 당사자) OR 관리자 우회가 실제 조건. 관리자 우회가 없으면 owner_match.',
    'G6 (manual_review_required): 서로 다른 유형의 조건이 OR로 분기(공개/비공개 가시성, 쿼리 모드별·action별 정책), 조직 설정에 따라 허용 주체가 바뀜, 인증만 확인(객체 없음 포함).',
    'G7 (public): 조건 없는 익명 허용만 public(AllowAny, 로그인·토큰 갱신, 무인증 개발용). 익명이 web-public 등 조건부로만 허용되면 manual_review_required.',
    'G8: test 제외 규칙 — 학습 데이터에는 적용하지 않는다(경계·미확정 건은 manual이 아니라 검수 메모에 사유를 적고 가장 타당한 label 또는 manual을 고른다).',
    '',
    '— gitea 참고 — reqOrgOwnership/reqRepoWriter/reqAdmin = 조직·저장소 안 역할(G3-a → role_required). reqOrgMembership/reqTeamMembership = 구성원(site admin 우회 포함, G2-b). repoAssignment+reqRepoReader/reqAnyRepoReader/reqOrgVisible = 공개/비공개 분기(VIS). reqToken만 + /user·/notifications = 본인 목록(G4).',
]

COLS = ['id', 'split', '프로젝트', 'method', 'path', 'security_state', '입력 요약', '코드/OAS 본문', '현재 label', '현재 rationale(SFT)', '후보 규칙', '예상 label(초안)', '예상 근거', '초안 rationale(템플릿)',
        '기존 검수 label·검수자', 'C2 재작성 대상', '확정 label', '확정 근거(코드 줄·설명 문장)', '확정 rationale(자유문, 선택)', '검수 메모', '검수자']
BLIND_COLS = ['id', 'split', '프로젝트', 'method', 'path', 'security_state', '입력 요약', '코드/OAS 본문', '확정 label', '확정 근거(코드 줄·설명 문장)', '검수 메모', '검수자']
WIDTHS = {'id': 34, 'split': 6, '프로젝트': 14, 'method': 8, 'path': 40, 'security_state': 12, '입력 요약': 50, '코드/OAS 본문': 80, '현재 label': 18, '현재 rationale(SFT)': 50, '후보 규칙': 14,
          '예상 label(초안)': 18, '예상 근거': 50, '초안 rationale(템플릿)': 50, '기존 검수 label·검수자': 30, 'C2 재작성 대상': 16, '확정 label': 20, '확정 근거(코드 줄·설명 문장)': 50, '확정 rationale(자유문, 선택)': 50, '검수 메모': 40, '검수자': 8}


# ---------- 최소 xlsx 작성기 ----------
BAD_XML = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def col_letter(i):
    s = ''
    while True:
        s = chr(65 + i % 26) + s; i = i // 26 - 1
        if i < 0: return s


def cell(ref, v, style):
    if v is None or v == '': return ''
    if isinstance(v, (int, float)) and not isinstance(v, bool): return f'<c r="{ref}" s="{style}"><v>{v}</v></c>'
    t = BAD_XML.sub('', str(v))
    if len(t) > CELL_MAX: t = t[:CELL_MAX] + '\n…[잘림: 원문은 데이터 파일 참조]'
    return f'<c r="{ref}" t="inlineStr" s="{style}"><is><t xml:space="preserve">{escape(t)}</t></is></c>'


def sheet_xml(header, rows, widths, freeze=True, guide=False):
    cols = ''.join(f'<col min="{i + 1}" max="{i + 1}" width="{widths.get(h, 16)}" customWidth="1"/>' for i, h in enumerate(header))
    out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">']
    if freeze: out.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>')
    out.append(f'<sheetFormatPr defaultRowHeight="15"/><cols>{cols}</cols><sheetData>')
    out.append('<row r="1">' + ''.join(cell(f'{col_letter(i)}1', h, 1 if not guide else 3) for i, h in enumerate(header)) + '</row>')
    for ri, r in enumerate(rows, start=2):
        out.append(f'<row r="{ri}">' + ''.join(cell(f'{col_letter(i)}{ri}', v, 2) for i, v in enumerate(r)) + '</row>')
    out.append('</sheetData>')
    if freeze and rows: out.append(f'<autoFilter ref="A1:{col_letter(len(header) - 1)}{len(rows) + 1}"/>')
    out.append('</worksheet>')
    return ''.join(out)


def write_xlsx(path, sheets):
    """sheets: list of (name, header, rows, widths, freeze, guide)."""
    styles = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<fonts count="2"><font><sz val="10"/><name val="Malgun Gothic"/></font><font><b/><sz val="10"/><name val="Malgun Gothic"/></font></fonts>'
              '<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFDDEBF7"/><bgColor indexed="64"/></patternFill></fill></fills>'
              '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
              '<cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
              '<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
              '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
              '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf></cellXfs>'
              '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>')
    ct = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>',
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
          '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>']
    wb = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>']
    rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for i, (name, header, rows, widths, freeze, guide) in enumerate(sheets, start=1):
            ct.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            wb.append(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i}"/>')
            rels.append(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>')
            z.writestr(f'xl/worksheets/sheet{i}.xml', sheet_xml(header, rows, widths, freeze, guide))
        n = len(sheets)
        rels.append(f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        wb.append('</sheets></workbook>'); ct.append('</Types>')
        z.writestr('[Content_Types].xml', ''.join(ct)); z.writestr('xl/workbook.xml', ''.join(wb)); z.writestr('xl/_rels/workbook.xml.rels', ''.join(rels)); z.writestr('xl/styles.xml', styles)
        z.writestr('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')


# ---------- 행 내용 ----------
def input_summary(r):
    m = r['meta']; sig = r.get('controller_signals') or {}
    if m.get('auth_summary'): return '추출 요약: ' + str(m['auth_summary'])
    if sig.get('middleware'):
        mw = [re.sub(r'\(.*$', '', x).split('\n')[-1].strip() for x in sig['middleware']]
        return '라우트 미들웨어: ' + ' → '.join(mw) + (f" | 핸들러 {sig.get('handler')}" if sig.get('handler') else '') + (' | 핸들러 내 인가 줄 있음' if sig.get('authz_lines_in_handler') else '')
    if sig.get('raw_snippet'): return '합성 핸들러(아래 코드)'
    oas = r.get('oas_snippet') or ''
    if not isinstance(oas, str): oas = json.dumps(oas, ensure_ascii=False)
    return 'OAS만(코드 없음): ' + re.sub(r'\s+', ' ', oas)[:400]


def body_text(r):
    sig = r.get('controller_signals') or {}
    t = r.get('controller_text') or sig.get('raw_snippet') or ''
    if t: return t
    oas = r.get('oas_snippet') or ''
    return oas if isinstance(oas, str) else json.dumps(oas, ensure_ascii=False, indent=1)


def prior_review(r, v5rev, v4rev, v3rev):
    m = r['meta']; i = r['id']
    if i in v5rev: return f"data-v5 검수: {v5rev[i].get('검수 label')} ({v5rev[i].get('검수자')}) — {str(v5rev[i].get('검수 사유') or '')[:200]}"
    if i in v4rev: return f"data-v4 검수: {v4rev[i].get('검수 label')} ({v4rev[i].get('검수자')}) — {str(v4rev[i].get('검수 사유') or '')[:200]}"
    if m.get('human_reviewed_v2') or m.get('review_r3'):
        v2 = m.get('v2_relabel') or {}
        return f"data-v2 사람 검수(시트 {m.get('review_sheet') or 'r3'}, 태그 {m.get('review_tags')}): {v2.get('to') or r['label']} — {str(v2.get('evidence') or '')[:200]}"
    pid = m.get('pair_id')
    if pid and (pid in v3rev or (r['service'], r['method'], r['path']) in v3rev):
        d = v3rev.get(pid) or v3rev[(r['service'], r['method'], r['path'])]
        return f"data-v3 1b 쌍 검수(label_correct {d.get('label_correct (Y/N)')}, {d.get('reviewer')}): {str(d.get('note') or '')[:200]}"
    return ''


def draft_rationale(x, r):
    lab = x['predicted_v31']; sig = r.get('controller_signals') or {}
    mw = [re.sub(r'\(.*$', '', y).split('\n')[-1].strip() for y in sig.get('middleware', [])]
    cue = ', '.join([y for y in mw if y in ('reqOrgOwnership', 'reqRepoWriter', 'reqAdmin', 'reqSelfOrAdmin', 'reqToken')][:2]) or '라우트 미들웨어'
    if x['candidate_rules'].startswith('G3-b') and lab == 'owner_match': cue = 'reqToken, 본인(/user·/notifications) 경로'
    if lab == 'public': cue = '인증 미들웨어 없음'
    return f'description: 라우트 체인의 {cue} — {TEMPLATE[lab]}; 판단: {JUDGE[lab]} (C1 기계 초안, C2에서 확정)'


def assign(rows, rng):
    idx = list(range(len(rows))); rng.shuffle(idx)
    for k, i in enumerate(idx): rows[i]['_reviewer'] = REVIEWERS[k % 3]


def main():
    for p, h in FROZEN.items(): assert sha(p) == h, f'frozen file changed: {p}'
    table = {x['id']: x for x in csv.DictReader(open(OUT / 'c0_rows.csv', encoding='utf-8-sig'))}
    audit_ids = json.load(open(OUT / 'c0_audit_sample_ids.json', encoding='utf-8'))['ids']
    recs = {r['id']: r for r in jl(P / 'train_v5.jsonl') + jl(P / 'val_v5.jsonl')}
    sft = {s['id']: json.loads(s['assistant']) for s in jl(SFT / 'train_sft_v5.jsonl') + jl(SFT / 'val_sft_v5.jsonl')}
    v5rev = {d['id']: d for d in sheet_dicts(read_xlsx(ROOT / 'review' / 'v5_train_review_reviewed.xlsx')['v5_train_review']) if d.get('id')}
    v4x = read_xlsx(ROOT / 'review' / 'v4_train_review_reviewed.xlsx'); v4rev = {d['id']: d for nm in ('v4_train_review', '선정 제외 manual 표본') for d in sheet_dicts(v4x[nm]) if d.get('id')}
    v3rev = {}
    for fn in ('review_pairs_v3s1_reviewed.xlsx', 'review_pairs_v3s1b_reviewed.xlsx'):
        for d in sheet_dicts(read_xlsx(ROOT / 'reports' / 'data_v3' / fn)['review_pairs']):
            if d.get('pair_id'): v3rev[d['pair_id']] = d; v3rev[(d['repo'], d['method'], d['path'])] = d

    groups = {'det': [], 'rev': [], 'qcode': [], 'qoas': [], 'c2only': []}
    for x in table.values():
        if x['status'] == '변경 예상': groups['det' if x['prediction_basis'] == 'rule' else 'rev'].append(x)
        elif x['status'] == '판정 필요': groups['qcode' if x['question_kind'] == '코드' else 'qoas'].append(x)
        elif x['rationale_v301_wording']: groups['c2only'].append(x)
    audit = [table[i] for i in audit_ids]
    assert not ({x['id'] for g in groups.values() for x in g} & set(audit_ids)), 'audit sample overlaps review rows'
    for g in groups.values(): g.sort(key=lambda x: (x['project'], x['path'], x['method']))
    rng = random.Random(SEED)
    for g in [groups['det'] + groups['rev'] + groups['c2only'], groups['qcode'], groups['qoas'], audit]: assign(g, rng)

    def c2flag(x, kind):
        if kind == 'change': return 'Y(label 변경)'
        if kind == 'c2only': return 'Y(v3.0.1 문구: ' + x['rationale_v301_wording'] + ')'
        return 'C1 결과에 따름'

    def row(x, kind):
        r = recs[x['id']]; a = sft[x['id']]
        pred = x['predicted_v31'] if kind in ('change',) else ('' if kind == 'c2only' else '?')
        return [x['id'], x['split'], x['project'], x['method'], x['path'], x['security_state'], input_summary(r), body_text(r), x['label'], a['rationale'],
                x['candidate_rules'] if kind != 'c2only' else '(C2 전용: label 유지)', pred, x['evidence'] if kind != 'c2only' else 'rationale에 v3.0.1 전용 문구: ' + x['rationale_v301_wording'],
                draft_rationale(x, r) if kind == 'change' and x['prediction_basis'] == 'rule' else '', prior_review(r, v5rev, v4rev, v3rev), c2flag(x, kind),
                x['predicted_v31'] if kind == 'change' and x['prediction_basis'] == 'rule' else '', '', '', '', x['_reviewer']]

    def blind_row(x):
        r = recs[x['id']]
        return [x['id'], x['split'], x['project'], x['method'], x['path'], x['security_state'], input_summary(r), body_text(r), '', '', '', x['_reviewer']]

    change_rows = [row(x, 'change') for x in groups['det'] + groups['rev']] + [row(x, 'c2only') for x in groups['c2only']]
    sheets = [('안내·검수 규약', ['C1 검수 안내와 규약 (블라인드 시트부터!)'], [[g] for g in GUIDE], {'C1 검수 안내와 규약 (블라인드 시트부터!)': 160}, False, True),
              ('무작위5%_블라인드', BLIND_COLS, [blind_row(x) for x in audit], WIDTHS, True, False),
              ('판정필요_코드', COLS, [row(x, 'q') for x in groups['qcode']], WIDTHS, True, False),
              ('판정필요_OAS문구', COLS, [row(x, 'q') for x in groups['qoas']], WIDTHS, True, False),
              ('변경예상_C2', COLS, change_rows, WIDTHS, True, False)]
    XLSX.parent.mkdir(exist_ok=True); write_xlsx(XLSX, sheets)

    # 기계 적용 초안(결정적 32건) — 동결 파일은 건드리지 않는 별도 파일
    with open(OUT / 'c1_draft_deterministic.jsonl', 'w', encoding='utf-8', newline='\n') as fh:
        for x in groups['det']:
            r = recs[x['id']]
            fh.write(json.dumps(dict(id=x['id'], split=x['split'], project=x['project'], method=x['method'], path=x['path'], label_current=x['label'], label_draft=x['predicted_v31'],
                                     rule=x['candidate_rules'], evidence=x['evidence'], rationale_sft_current=sft[x['id']]['rationale'], rationale_draft=draft_rationale(x, r),
                                     status='기계 초안 — 사람 확인 전', reviewer=x['_reviewer']), ensure_ascii=False) + '\n')
    key = {x['id']: dict(label_current=x['label'], status=x['status'], candidate_rules=x['candidate_rules'], predicted_v31=x['predicted_v31'], human_review=x['human_review'], reviewer=x['_reviewer']) for x in audit}
    with open(OUT / 'c1_audit_key.json', 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(dict(seed=SEED, n=len(audit), rule='불일치율(확정 label ≠ label_current) > 5%면 한계로 기록, 전수 검수는 마감 후', key=key), fh, ensure_ascii=False, indent=1)

    # 보고
    dist = lambda g: dict(sorted(Counter(x['_reviewer'] for x in g).items()))
    L = ['# C1 검수 시트 생성 보고 (2026-11-05, 작업 C′ / data-v6d — 생성 후 정지, 커밋 금지)', '',
         f'생성 `scripts/build_c1_review_sheet.py`(seed {SEED}). 동결 파일(data-v5 train/val, SFT, test)은 해시 확인 후 읽기만 했다. xlsx는 커밋하지 않는다.', '',
         '## 산출', '',
         f'- `review/c1_relabel_review.xlsx` SHA-256 `{sha(XLSX)}` — 시트 5개: 안내·검수 규약 / 무작위5%_블라인드 {len(audit)} / 판정필요_코드 {len(groups["qcode"])} / 판정필요_OAS문구 {len(groups["qoas"])} / 변경예상_C2 {len(change_rows)}(결정적 초안 {len(groups["det"])} + review {len(groups["rev"])} + C2 전용 {len(groups["c2only"])}).',
         f'- `reports/data_v6d/c1_draft_deterministic.jsonl` {len(groups["det"])}건 — 결정적 규칙 예측의 기계 적용 초안(label_draft + 템플릿 rationale_draft). 사람 확인 전이며 train_v5·SFT 파일은 수정하지 않았다.',
         f'- `reports/data_v6d/c1_audit_key.json` — 블라인드 표본 정답키(시트 밖). 사전 기록: 불일치율 > 5%면 한계로 기록, 전수 검수는 마감 후.', '',
         '## 검수자 배분(A/B/C, 시트별 seed 42 셔플 후 순환)', '']
    L += ['| 시트 | 건수 | A | B | C |', '|---|---:|---:|---:|---:|']
    for nm, g in [('무작위5%_블라인드', audit), ('판정필요_코드', groups['qcode']), ('판정필요_OAS문구', groups['qoas']), ('변경예상_C2', groups['det'] + groups['rev'] + groups['c2only'])]:
        d = dist(g); L.append(f'| {nm} | {len(g)} | {d.get("A", 0)} | {d.get("B", 0)} | {d.get("C", 0)} |')
    tot = audit + groups['qcode'] + groups['qoas'] + groups['det'] + groups['rev'] + groups['c2only']; d = dist(tot)
    L += [f'| 합계 | {len(tot)} | {d.get("A", 0)} | {d.get("B", 0)} | {d.get("C", 0)} |', '',
          '## 열과 규칙', '',
          '- 공통 열: ' + ' · '.join(COLS) + '. 블라인드 시트는 현재 label·예상 label·rationale·후보 규칙·기존 검수 열을 뺀 ' + ' · '.join(BLIND_COLS) + '.',
          '- 결정적 초안 32건은 "확정 label" 열에 초안 label을 미리 채웠고(사람이 확인·수정), 나머지는 비어 있다. "초안 rationale(템플릿)"은 C2용 초안이며 확정이 아니다.',
          '- C2 재작성 대상 열: Y(label 변경) ' + str(len(groups['det']) + len(groups['rev'])) + ' · Y(v3.0.1 문구) ' + str(len(groups['c2only'])) + ' · C1 결과에 따름 ' + str(len(groups['qcode']) + len(groups['qoas'])) + '. C2 출발점은 SFT assistant rationale("현재 rationale(SFT)" 열)이다.',
          f'- 기존 검수 label이 있는 행: {sum(1 for x in tot if x["human_review"])}건(기존 label 유지가 기본값, 변경 시 사유 기재).',
          '- 안내 시트 첫 줄에 "블라인드 시트부터" 순서를 명시했다. 블라인드 표본은 C0 c0_audit_sample_ids.json(seed 42, 모집단 1,359)과 동일하며 다른 시트 행과 겹치지 않는다(assert).', '',
          '## 다음 단계(승인 후)', '', '검수 완료본 `review/c1_relabel_review_reviewed.xlsx` 수령 → 블라인드 불일치율 계산·보고 → 확정 label 반영 + C2 rationale 재작성(템플릿/LLM 초안 + 사람 확인) → 정합성 assert → data-v6d 동결(정지 지점) → C′ 학습은 별도 승인. 중단 규칙: 2026-11-08 12:00 KST까지 결과 없거나 미달이면 C′ 중단.']
    (OUT / 'c1_sheet_report.md').write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
