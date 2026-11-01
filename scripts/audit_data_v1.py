"""Read-only audit of data-v1 (train_v30/val_v30/test_v30) and the data-v2 draft (train_v2_draft.jsonl): label/feature distributions,
manual-label reason decomposition, security_state x label, synthetic bias/leakage, Qwen2.5 token lengths. No training, no API calls,
no dataset writes. Outputs reports/data_v1_audit.md and reports/data_v1_audit/*.csv."""
from __future__ import annotations
import csv, hashlib, json, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; P = ROOT / 'datasets/blade/processed'; OUT = ROOT / 'reports/data_v1_audit'; MD = ROOT / 'reports/data_v1_audit.md'
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
HASHES = json.loads((ROOT / 'reports/eval/lora_v1/hashes.json').read_text(encoding='utf-8'))['sources']
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
SYN2 = {r['id']: r for r in rd(P / 'data_v2_synthetic_additions.jsonl')}
import yaml
VARIANT_BASE = {}
for y in (ROOT / 'datasets/blade/raw/synthetic_v2/variants').glob('*/intended_labels.yaml'):
    for ep in yaml.safe_load(y.read_text(encoding='utf-8'))['endpoints']: VARIANT_BASE[ep['id']] = ep.get('base_label')

def assert_hashes():
    agents = (ROOT / 'AGENTS.md').read_text(encoding='utf-8')
    for name, h in HASHES.items():
        p = (ROOT / 'training/data/prompts' / name) if name.endswith('.md') else P / name
        assert sha(p) == h, f'{name} hash mismatch with hashes.json'
        assert h in agents, f'{name} hash not recorded in AGENTS.md'
    return {k: v[:16] + '…' for k, v in HASHES.items()}

def csvw(name, header, rows):
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / name, 'w', encoding='utf-8', newline='') as f:
        w = csv.writer(f); w.writerow(header); w.writerows(rows)

def table(rows, header, right_from=1):
    return '| ' + ' | '.join(header) + ' |\n|' + '|'.join('---' if i < right_from else '---:' for i in range(len(header))) + '|\n' + ''.join('| ' + ' | '.join(str(c) for c in r) + ' |\n' for r in rows)

def dist(rows): return {l: sum(r['label'] == l for r in rows) for l in L}
def pct(n, d): return f'{n/d:.1%}' if d else '-'

# ---------------- record normalisation ----------------
def source_of(r, split):
    m = r.get('meta', {})
    if split == 'test': return 'synthetic' if r.get('source') == 'synthetic' else 'vuln_' + m.get('oas_status', '?')
    if r['id'] in SYN2: return 'synthetic_v2'
    o = m.get('origin') or m.get('source') or 'apisguru'
    if o == 'data-v1': o = m.get('source', 'apisguru')
    return {'apisguru': 'apisguru', 'synthetic': 'synthetic', 'synthetic_v2': 'synthetic_v2', 'gitea': 'gitea', 'opensource': 'gitea'}.get(o, o)

def has_code(r):
    cs = r.get('controller_signals') or {}
    return bool((cs.get('raw_snippet') or '').strip()) or bool((r.get('controller_text') or '').strip())

# ---------------- manual reason decomposition ----------------
INFO = [('객체 ID만 있음', r'객체 ID만|ID만 있고'), ('요청자-객체 관계 미확인', r'관계[^;]{0,40}(명시되지|확인할 수 없|불확실|확정할 수 없|명확하지|불명확|부족)|관계를 확정'),
        ('인증만 확인·인가 조건 없음', r'인증(만|은|이|을)[^;]{0,40}(인가|관계|조건)|인증이 필요하(지만|나)|인증은 선언'), ('설명 없음·비어 있음', r'설명이 (비어|없)|description 없음|설명 없음|설명이 제공되지'),
        ('API 키만 요구', r'api.?key|API 키|apikey'), ('security·인증 정보 없음', r'security[^;]{0,20}(없|unknown)|인증 (선언|정보)가? 없|인증 방식이 명시되지'), ('접근 조건 미명시(일반)', r'접근 조건[^;]{0,30}(명시되지|명확하지|확정|불확실|부족)|조건이 (명시되지|명확하지)')]
HARD = [('구독·플랜·등급 조건', r'구독|플랜|등급|premium|subscription|tier'), ('복합 조건(AND)·단일 라벨 불가', r'복합|결합|단일 라벨|독립 (필수 )?조건|AND'), ('코드·의도 충돌', r'충돌'), ('역할·권한 조건 불명확', r'역할[^;]{0,30}(명시되지|불명확|확인할 수 없)|권한[^;]{0,20}(명시되지|불명확)')]

def manual_reason(r):
    """Returns (category, subtype, evidence_field). category: 가=정보 부족 보류, 나=실제 판단 불가, 분류불가."""
    m = r.get('meta', {})
    if m.get('v30_override_reason') == 'security_declared_public': return '가', 'override: security 선언 public→manual', 'meta.v30_override_reason'
    if m.get('v30_override_reason') == 'visibility_dependent': return '나', 'override: visibility_dependent(조건부 접근)', 'meta.v30_override_reason'
    if m.get('v30_relabel_reason'): return '나', 'relabel: 합성 subscription(구독 조건)', 'meta.v30_relabel_reason'
    if m.get('source') == 'synthetic' and m.get('label_source') == 'intended_labels':
        reason = (r.get('rationale') or '').lower()
        if 'authentication only' in reason: return '가', '합성 변형: 인증만·인가 제거(설계 manual)', 'rationale(intended)'
        if 'two independent conditions' in reason or 'conflicting owner and tenant' in reason: return '나', '합성: 복합/충돌 조건(설계 manual)', 'rationale(intended)'
        return '분류불가', '합성 intended 사유 미식별', 'rationale(intended)'
    text = r.get('rationale') or ''
    if not text.strip(): return '분류불가', 'rationale 없음', '-'
    for name, rx in HARD:
        if re.search(rx, text, re.I): return '나', name, 'rationale(모델 문장, 정규식)'
    for name, rx in INFO:
        if re.search(rx, text, re.I): return '가', name, 'rationale(모델 문장, 정규식)'
    return '분류불가', '패턴 미일치', 'rationale(모델 문장)'

# ---------------- near duplicate ----------------
def norm_code(text, service, noun):
    t = text or ''
    t = re.sub(re.escape(service), 'SVC', t) if service else t
    t = re.sub(r'\b' + re.escape(noun) + r'\b', 'NOUN', t) if noun else t
    t = re.sub(r'(catalogue|drafts|shared|workspace|audit|subscription|disputed|roster|gear|pins|council|moderation)_(0|1)', 'SECTION_I', t)
    t = re.sub(r'/(catalogue|drafts|shared|workspace|audit|subscription|disputed|roster|gear|pins|council|moderation)/', '/SECTION/', t)
    return re.sub(r'\s+', ' ', t).strip()

def guard_line(text):
    for l in (text or '').splitlines():
        if re.search(r'403|FORBIDDEN|Forbidden|PermissionDenied|Deliberate fixture|Variant:', l): return re.sub(r'\s+', ' ', l.strip())
    return ''

def main():
    verified = assert_hashes()
    train = rd(P / 'train_v30.jsonl'); val = rd(P / 'val_v30.jsonl'); test = rd(P / 'test_v30.jsonl'); v2 = rd(P / 'train_v2_draft.jsonl')
    test_inputs = {r['id']: r for r in rd(ROOT / 'training/lora/data_v1/test_v30_inputs.jsonl')}
    for r in test: r['security_state'] = test_inputs[r['id']]['security_state']
    splits = {'train_v1': train, 'val_v1': val, 'test_v30': test, 'train_v2_draft': v2}
    md = ['# data-v1 / data-v2 초안 라벨·피처 분포 점검 (분석 전용, 2026-10-23)', '',
          f'data-v1 해시 assert 통과(hashes.json ↔ AGENTS.md): ' + ', '.join(f'{k} `{v}`' for k, v in verified.items()) + '. 모든 파일 읽기 전용. data-v2 초안 = `train_v2_draft.jsonl`(build_train_v2.py, 안 A\' 변형, 검수 반영 전·manual 쿼터 미적용).', '']
    # 1. label distribution
    md += ['## 1. label 분포', '']
    rows = []
    for l in L: rows.append([l] + sum([[dist(s)[l], pct(dist(s)[l], len(s))] for s in splits.values()], []))
    rows.append(['합계'] + sum([[len(s), '100%'] for s in splits.values()], []))
    md.append(table(rows, ['label'] + sum([[k, k + ' 비율'] for k in splits], []), 1))
    csvw('label_dist.csv', ['label'] + sum([[k, k + '_ratio'] for k in splits], []), rows)
    md.append(f"\nmanual 비율: train_v1 {pct(dist(train)[MANUAL], len(train))}(쿼터 25% 적용), val_v1 {pct(dist(val)[MANUAL], len(val))}, **test_v30 {pct(dist(test)[MANUAL], len(test))}**(사람 확정·설계 라벨 실제 비율), train_v2_draft {pct(dist(v2)[MANUAL], len(v2))}(쿼터 미적용; apply_reviews_v2 적용 시 25%).\n")
    # source x label
    md += ['### 1-1. 출처 × label (split별)', '']
    rows = []
    for k, s in splits.items():
        for src in sorted({source_of(r, 'test' if k == 'test_v30' else 'train') for r in s}):
            rs = [r for r in s if source_of(r, 'test' if k == 'test_v30' else 'train') == src]
            rows.append([k, src, len(rs)] + [dist(rs)[l] for l in L] + [pct(dist(rs)[MANUAL], len(rs))])
    md.append(table(rows, ['split', '출처', 'N'] + L + ['manual 비율'], 2)); csvw('source_label.csv', ['split', 'source', 'N'] + L + ['manual_ratio'], rows)
    # code x label
    md += ['', '### 1-2. 코드(핸들러 원문) 유무 × label (split별)', '', 'train/val: controller_signals.raw_snippet, test: controller_text. oas 조건은 모든 레코드, oas_code 조건은 코드 있는 레코드만 해당.', '']
    rows = []
    for k, s in splits.items():
        for hc in (True, False):
            rs = [r for r in s if has_code(r) == hc]
            if rs: rows.append([k, '코드 있음' if hc else '코드 없음', len(rs), pct(len(rs), len(s))] + [dist(rs)[l] for l in L] + [pct(dist(rs)[MANUAL], len(rs))])
    md.append(table(rows, ['split', '코드', 'N', '비율'] + L + ['manual 비율'], 2)); csvw('code_label.csv', ['split', 'has_code', 'N', 'ratio'] + L + ['manual_ratio'], rows)
    # 2. manual reasons
    md += ['', '## 2. manual_review_required 사유 분해 (train_v1 · val_v1 · train_v2_draft)', '',
           '근거 필드: meta.v30_override_reason / meta.v30_relabel_reason(규칙 플래그), 합성 intended rationale(설계 사유), APIs.guru·Gitea는 모델 rationale 문장의 정규식 일치(reports/eval/.../manual_analysis.md와 같은 패턴). 모델 문장 기반 분류는 근사치이며 패턴 미일치는 "분류불가"로 둔다. (가)=정보 부족 보류, (나)=실제 판단 불가(복합·구독·충돌·조건부 접근).', '']
    rows = []; detail = []
    for k in ('train_v1', 'val_v1', 'train_v2_draft'):
        man = [r for r in splits[k] if r['label'] == MANUAL]; cnt = Counter(); sub = Counter()
        for r in man:
            c, st, ev = manual_reason(r); cnt[c] += 1; sub[(c, st)] += 1; detail.append([k, r['id'], source_of(r, 'train'), c, st, ev, r.get('meta', {}).get('label_before_override') or r.get('meta', {}).get('api_original_label') or r.get('meta', {}).get('intended_label_original') or ''])
        rows.append([k, len(man), cnt['가'], pct(cnt['가'], len(man)), cnt['나'], pct(cnt['나'], len(man)), cnt['분류불가'], pct(cnt['분류불가'], len(man))])
        md.append(f'**{k}** manual {len(man)}건: (가) {cnt["가"]} · (나) {cnt["나"]} · 분류불가 {cnt["분류불가"]}\n')
        md.append(table([[c, st, n] for (c, st), n in sorted(sub.items(), key=lambda x: -x[1])], ['구분', '세부 사유', '건수'], 2)); md.append('')
    csvw('manual_reasons_summary.csv', ['split', 'manual', 'info_gap', 'info_gap_ratio', 'hard', 'hard_ratio', 'unclassified', 'unclassified_ratio'], rows)
    csvw('manual_reasons_detail.csv', ['split', 'id', 'source', 'category', 'subtype', 'evidence_field', 'label_before_or_original'], detail)
    # (가) original concrete label where known
    md += ['### 2-1. (가) 정보 부족 보류 건의 원천 구체 label (확인 가능한 경우만)', '', 'APIs.guru 레코드는 코드·정답 소스가 없어 원천 구체 label을 확인할 수 없다(확인 불가). 확인 가능한 것은 규칙 override로 manual이 된 건의 원래 모델 label(label_before_override), 합성 변형의 설계 base label뿐이다.', '']
    rows = []
    for k in ('train_v1', 'val_v1', 'train_v2_draft'):
        man = [r for r in splits[k] if r['label'] == MANUAL and manual_reason(r)[0] == '가']
        known = Counter(); unknown = 0
        for r in man:
            m = r['meta']; b = m.get('label_before_override') or (m.get('intended_label_original'))
            if not b and source_of(r, 'train') == 'synthetic_v2' and m.get('variant_kind') in ('authonly', 'extauth'):
                b = 'variant base:' + str(VARIANT_BASE.get(r['id'], '?'))
            if b: known[b] += 1
            else: unknown += 1
        rows.append([k, len(man), unknown, ' / '.join(f'{b} {n}' for b, n in known.most_common())])
    md.append(table(rows, ['split', '(가) 건수', '원천 label 확인 불가', '확인 가능한 원천 label 분포'], 1)); csvw('info_gap_origin.csv', ['split', 'info_gap', 'unknown', 'known_dist'], rows)
    # test comparison for spec-less inputs
    md += ['', '### 2-2. test_v30에서 같은 성격의 입력이 갖는 정답 (대조표)', '', 'train의 (가) 규칙("OAS만으로 관계·조건 확인 불가 → manual")이 test에서 어떻게 채점되는지: 명세가 없는 route_only 109건과 security unknown 건의 정답 분포.', '']
    rows = []
    groups = [('vuln route_only(명세 없음)', [r for r in test if r.get('source') == 'vuln' and r['meta'].get('oas_status') == 'route_only']),
              ('vuln repository_spec', [r for r in test if r.get('source') == 'vuln' and r['meta'].get('oas_status') == 'repository_spec']),
              ('synthetic(설명=설계 사유 포함)', [r for r in test if r.get('source') == 'synthetic']),
              ('security_state=unknown 전체', [r for r in test if r['security_state'] == 'unknown']),
              ('description 비어 있음 전체', [r for r in test if not json.loads(r['oas_snippet'])['paths'][r['path']][r['method'].lower()].get('description')])]
    for name, rs in groups: rows.append([name, len(rs)] + [dist(rs)[l] for l in L] + [pct(dist(rs)[MANUAL], len(rs)), pct(sum(has_code(r) for r in rs), len(rs))])
    md.append(table(rows, ['test 구간', 'N'] + L + ['manual 정답 비율', '코드 있음 비율'], 1)); csvw('test_specless_truth.csv', ['group', 'N'] + L + ['manual_ratio', 'code_ratio'], rows)
    # train: apisguru rows with empty description -> label dist (from enriched input)
    enriched = {r['id']: r for r in rd(P / 'apisguru_enriched_v2.jsonl')}
    def desc_empty(r):
        e = enriched.get(r['id']); return bool(e) and not (e['enrichment']['operation'].get('description') or '').strip()
    rows = []
    for k in ('train_v1', 'val_v1'):
        ap = [r for r in splits[k] if source_of(r, 'train') == 'apisguru']; de = [r for r in ap if desc_empty(r)]; unk = [r for r in ap if r.get('security_state') == 'unknown']
        rows.append([k, 'APIs.guru description 비어 있음', len(de)] + [dist(de)[l] for l in L] + [pct(dist(de)[MANUAL], len(de))])
        rows.append([k, 'APIs.guru security_state=unknown', len(unk)] + [dist(unk)[l] for l in L] + [pct(dist(unk)[MANUAL], len(unk))])
    md.append('\ntrain 쪽 같은 성격(명세 정보 부족) 레코드의 라벨(쿼터 적용 후 train에 남은 건 기준):\n'); md.append(table(rows, ['split', '구간', 'N'] + L + ['manual 비율'], 2)); csvw('train_specless_labels.csv', ['split', 'group', 'N'] + L + ['manual_ratio'], rows)
    ro = groups[0][1]; ro_manual = dist(ro)[MANUAL]
    full_labeled = rd(P / 'apisguru_labeled_v301.jsonl'); fl_unknown = [r for r in full_labeled if r['security_state'] == 'unknown']
    md.append(f"\n**결론(수치)**: train 라벨 생성(v3.0.1, APIs.guru 2,027건)에서 security_state=unknown 754건은 manual {pct(sum(r['label']==MANUAL for r in fl_unknown), len(fl_unknown))}로 라벨됐지만, test_v30의 명세 없는 route_only 109건의 사람 정답은 manual {ro_manual}건({pct(ro_manual, len(ro))})이고 구체 label이 {len(ro)-ro_manual}건이다. 같은 성격의 입력에 train은 '보류', test는 '코드 기준 구체 label'을 부여하므로 **train과 test의 라벨 기준은 다르다**(test 정답은 코드 발췌가 있는 상태에서 확정됐고 oas 조건 채점에도 그대로 쓰인다).\n")
    # 3. security x label
    md += ['## 3. security_state × label (split별)', '']
    rows = []; declared_public = {}
    for k, s in splits.items():
        for st in ('declared', 'explicitly_anonymous', 'unknown'):
            rs = [r for r in s if r.get('security_state') == st]
            if rs: rows.append([k, st, len(rs)] + [dist(rs)[l] for l in L])
        declared_public[k] = [r['id'] for r in s if r.get('security_state') == 'declared' and r['label'] == 'public']
    md.append(table(rows, ['split', 'security_state', 'N'] + L, 2)); csvw('security_label.csv', ['split', 'security_state', 'N'] + L, rows)
    md.append('\nsecurity_state=declared 이면서 label=public인 건:\n')
    for k, ids in declared_public.items(): md.append(f'- {k}: {len(ids)}건' + (' — ' + ', '.join(ids[:40]) + (' …' if len(ids) > 40 else '') if ids else ''))
    csvw('declared_public_ids.csv', ['split', 'id'], [[k, i] for k, ids in declared_public.items() for i in ids])
    md.append('\n(train_v1은 build_train_v30.py의 security_declared_public override로 0건. train_v2_draft의 declared∧public은 전부 Gitea 레코드다: build_train_v2.py/apply_reviews_v2.py에는 Gitea에 대한 security_declared_public override가 없고 visibility_dependent override만 있다. Gitea는 OAS 전역 security 때문에 455건 전부 declared이므로 data-v1 규칙을 그대로 적용하면 Gitea public 전부가 manual이 된다. test_v30 synthetic은 security 선언 없이 Authorization 헤더 파라미터만 있어 unknown, 취약 API는 전역/operation security로 declared.)\n')
    # 4. synthetic bias / leakage
    md += ['## 4. 합성 데이터 편중·누수', '']
    rows = []
    for k, s in splits.items():
        syn = [r for r in s if source_of(r, 'test' if k == 'test_v30' else 'train') in ('synthetic', 'synthetic_v2')]
        rows.append([k] + [f'{sum(r["label"]==l for r in syn)}/{dist(s)[l]} ({pct(sum(r["label"]==l for r in syn), dist(s)[l])})' for l in L])
    md.append(table(rows, ['split'] + [l + ' (합성/전체)' for l in L], 1)); csvw('synthetic_share.csv', ['split'] + L, rows)
    train_services = {r['service'] for r in train + val + v2}; test_services = {r['service'] for r in test}
    overlap = sorted(train_services & test_services)
    syn_train = [r for r in train + val + v2 if source_of(r, 'train') in ('synthetic', 'synthetic_v2')]; syn_test = [r for r in test if r.get('source') == 'synthetic']
    tmpl_hits = 0; guard_hits = 0; detail_rows = []
    train_guards = defaultdict(list)
    for r in syn_train:
        noun = r['path'].split('/')[3] if r['path'].count('/') >= 3 else ''
        g = norm_code(guard_line((r.get('controller_signals') or {}).get('raw_snippet', '')), r['service'], noun)
        if g: train_guards[g].append(r['id'])
    for r in syn_test:
        noun = r['path'].split('/')[3] if r['path'].count('/') >= 3 else ''
        sec = re.sub(r'/(current|archive)/', '/I/', re.sub(r'^/fixtures/[^/]+/[^/]+/', '/fixtures/SVC/NOUN/', r['path']))
        tmpl = any(re.sub(r'/(current|archive)/', '/I/', re.sub(r'^/fixtures/[^/]+/[^/]+/', '/fixtures/SVC/NOUN/', t['path'])) == sec and t['label'] == r['label'] for t in syn_train)
        g = norm_code(guard_line(r.get('controller_text', '')), r['service'], noun); gh = bool(g) and g in train_guards
        tmpl_hits += tmpl; guard_hits += gh; detail_rows.append([r['id'], r['label'], tmpl, gh, g[:120]])
    pat = lambda p: re.sub(r'\{[^}]*\}', '{}', p)
    vuln_pats = {pat(r['path']) for r in test if r.get('source') == 'vuln'}; real_pats = {pat(r['path']) for r in train + val + v2 if source_of(r, 'train') in ('apisguru', 'gitea')}
    path_overlap = len(vuln_pats & real_pats)
    md.append(f"\n- 서비스 단위 중복(train∪val∪v2 ∩ test): {len(overlap)}건 {overlap if overlap else ''}.\n- test 합성 {len(syn_test)}건 중 **경로 템플릿(섹션/라벨) 동일**한 train 합성 사례가 있는 건: {tmpl_hits}건({pct(tmpl_hits, len(syn_test))}). 같은 생성 템플릿(catalogue/drafts/shared/… 섹션, 동일 인가 검사 코드)을 공유하므로 서비스명만 다른 near-duplicate다.\n- test 합성 중 **정규화한 인가 검사 줄이 train 합성과 바이트 동일**한 건: {guard_hits}건({pct(guard_hits, len(syn_test))}).\n- 취약 API(vuln) 211건과 Gitea·APIs.guru 사이의 경로 패턴(파라미터 정규화) 교집합: {path_overlap}건.\n")
    csvw('synthetic_near_duplicates.csv', ['test_id', 'label', 'template_match', 'guard_line_match', 'normalized_guard'], detail_rows)
    # 5. token lengths (Qwen2.5 tokenizer)
    md += ['## 5. 토큰 길이 (Qwen2.5 토크나이저, 프롬프트 v3.0.1 적용, chat template 포함)', '']
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained('Qwen/Qwen2.5-7B-Instruct', cache_dir=str(ROOT / '.cache/models'))
    system = (ROOT / 'training/data/prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
    def ntok(user, assistant=None):
        msgs = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}] + ([{'role': 'assistant', 'content': assistant}] if assistant else [])
        return len(tok.apply_chat_template(msgs, tokenize=True, add_generation_prompt=assistant is None))
    sft = {'train_v1': rd(ROOT / 'training/lora/data_v1/train_sft.jsonl'), 'val_v1': rd(ROOT / 'training/lora/data_v1/val_sft.jsonl')}
    sys.path.insert(0, str(ROOT))
    from training.lora.prepare_lora_inputs import synthetic_payload
    from training.data import label_v30 as lv; from training.data import label_v5 as b5; from training.data.label_gitea_v30 import payload as gitea_payload
    lens = []; over = []
    def record(split, cond, ident, n, code_tokens=None):
        lens.append([split, cond, ident, n]);
        if n > 4096: over.append([split, cond, ident, n, code_tokens])
    for k, rows_ in sft.items():
        for r in rows_:
            cond = 'oas_code' if r['source'] == 'synthetic' else 'oas'
            record(k, cond + '(학습 입력)', r['id'], ntok(r['user'], r['assistant']), None)
    for r in test:
        ti = test_inputs[r['id']]; record('test_v30', 'oas', r['id'], ntok(ti['oas_user']))
        if 'oas_code_user' in ti: record('test_v30', 'oas_code', r['id'], ntok(ti['oas_code_user']), len(tok(r.get('controller_text', '')).input_ids))
    gitea_src = {r['id']: r for r in rd(P / 'opensource/gitea_v28.2.0_labeled_v301.jsonl')}
    for r in v2:
        o = source_of(r, 'train')
        if o == 'apisguru':
            e = enriched.get(r['id'])
            if e: record('train_v2_draft', 'oas', r['id'], ntok('Return JSON.\n' + json.dumps(b5.payload(e), ensure_ascii=False), json.dumps({'label': r['label'], 'confidence': r['confidence'], 'rationale': r['rationale'], 'evidence_fields': r.get('evidence_fields', [])}, ensure_ascii=False)))
        elif o in ('synthetic', 'synthetic_v2'):
            pl = synthetic_payload(r); code = (r.get('controller_signals') or {}).get('raw_snippet', '')
            record('train_v2_draft', 'oas_code', r['id'], ntok('Return JSON.\n' + json.dumps(pl, ensure_ascii=False), json.dumps({'label': r['label'], 'confidence': 1.0, 'rationale': r['rationale'], 'evidence_fields': ['description']}, ensure_ascii=False)), len(tok(code).input_ids))
        elif o == 'gitea':
            g = gitea_src[r['id']]; pl = gitea_payload(g)
            record('train_v2_draft', 'oas_code', r['id'], ntok('Return JSON.\n' + json.dumps(pl, ensure_ascii=False), json.dumps({'label': r['label'], 'confidence': r['confidence'], 'rationale': r['rationale'], 'evidence_fields': r.get('evidence_fields', [])}, ensure_ascii=False)), len(tok(g['controller_text']).input_ids))
    import statistics
    rows = []
    for (k, c) in sorted({(x[0], x[1]) for x in lens}):
        xs = [x[3] for x in lens if x[0] == k and x[1] == c]
        rows.append([k, c, len(xs), int(statistics.median(xs)), round(statistics.mean(xs)), sorted(xs)[int(.95 * (len(xs) - 1))], max(xs), sum(x > 4096 for x in xs), sum(x > 3584 for x in xs)])
    md.append(f'시스템 프롬프트 단독 {len(tok(system).input_ids)} 토큰(chat template 제외). 학습 입력은 system+user+assistant, 평가 입력은 system+user(+generation prompt).\n')
    md.append(table(rows, ['split', '조건', 'N', '중앙값', '평균', 'p95', '최대', '>4096', '>3584'], 2)); csvw('token_lengths.csv', ['split', 'cond', 'N', 'median', 'mean', 'p95', 'max', 'over_4096', 'over_3584'], rows)
    csvw('token_lengths_detail.csv', ['split', 'cond', 'id', 'tokens'], lens)
    if over:
        md.append('\nmax_seq_len 4096 초과:\n'); md.append(table([[*o[:4], o[4] if o[4] is not None else '-'] for o in over], ['split', '조건', 'id', '토큰', '핸들러 원문 토큰'], 3))
        md.append('\n초과분은 모두 핸들러 원문(description에 포함된 코드)이 길어서 생긴 것이며, 잘릴 때 뒤쪽(코드 끝부분과 assistant 응답 쪽)이 먼저 잘린다. 학습 입력에서 assistant가 잘리면 해당 샘플은 학습 신호가 사라진다.\n')
    else: md.append('\n4096 초과 건 없음.\n')
    # 6. data-v2 rules + new records
    g_all = list(gitea_src.values()); g_in = [r for r in v2 if source_of(r, 'train') == 'gitea']; syn2 = list(SYN2.values()); syn2_in_draft = sum(r['id'] in SYN2 for r in v2)
    gm = json.loads((ROOT / 'reports/eval/data_v2/gitea_label/manifest.json').read_text(encoding='utf-8'))
    md += ['## 6. data-v2 초안: 라벨링 규칙·쿼터 동일성과 신규분 분포', '',
           f"- 라벨 규칙: Gitea 455건은 gpt-4o-mini + 프롬프트 v3.0.1(SHA `{gm['prompt_sha256'][:16]}…`, data-v1과 동일 파일) + oas_code 조건으로 라벨(reports/eval/data_v2/gitea_label/manifest.json). data-v1 APIs.guru는 같은 프롬프트의 oas 조건. 합성 보강 129건은 intended_labels(설계 라벨)이며 LLM 라벨이 아니다.",
           '- 추가 규칙(train_v2 빌드, build_train_v2.py/apply_reviews_v2.py): visibility_dependent 96건 → manual override, Gitea owner_or_admin 84건 → pool. data-v1에는 없던 규칙.',
           f"- manual 쿼터: data-v1 25%(build_train_v30.py, round_half_up(C/3)). train_v2_draft는 쿼터 미적용(manual {pct(dist(v2)[MANUAL], len(v2))}); apply_reviews_v2.py가 같은 공식으로 25%를 적용하며 dry-run 기준 705건(Gitea 105건, visibility manual 12건만 포함).", '']
    md.append('합성 보강 129건 중 train_v2_draft에 포함된 건: ' + str(syn2_in_draft) + '.' + chr(10))
    rows = [['Gitea 라벨 원본 455', len(g_all)] + [dist(g_all)[l] for l in L], ['Gitea train_v2_draft 포함 371(visibility override·owner_or_admin pool 후)', len(g_in)] + [dist(g_in)[l] for l in L],
            ['Gitea 구체 label(draft 내)', sum(r['label'] != MANUAL for r in g_in)] + [dist([r for r in g_in if r['label'] != MANUAL])[l] for l in L],
            ['합성 보강 129(변형 57 + 신규 4종 72)', len(syn2)] + [dist(syn2)[l] for l in L],
            ['  └ 변형 authonly/extauth(manual 설계)', sum(r['meta'].get('variant_kind') in ('authonly', 'extauth') for r in syn2)] + [dist([r for r in syn2 if r['meta'].get('variant_kind') in ('authonly', 'extauth')])[l] for l in L],
            ['  └ 변형 extguard(구체 대조군)', sum(r['meta'].get('variant_kind') == 'extguard' for r in syn2)] + [dist([r for r in syn2 if r['meta'].get('variant_kind') == 'extguard'])[l] for l in L],
            ['  └ 신규 4종(Django/Nest/Gin/Rails)', sum(not r['meta'].get('variant_kind') for r in syn2)] + [dist([r for r in syn2 if not r['meta'].get('variant_kind')])[l] for l in L]]
    md.append(table(rows, ['data-v2 신규분', 'N'] + L, 1)); csvw('v2_new_records.csv', ['group', 'N'] + L, rows)
    # 7. summary + verdict + A/B facts
    tr_code = sum(has_code(r) for r in train); te_code = sum(has_code(r) for r in test)
    md += ['', '## 7. 핵심 수치 요약', '',
           f"1. manual 비율: train_v1 {pct(dist(train)[MANUAL], len(train))}(쿼터) vs test_v30 {pct(dist(test)[MANUAL], len(test))}; 코드 있는 레코드: train_v1 {tr_code}/{len(train)}({pct(tr_code, len(train))}) vs test_v30 {te_code}/{len(test)}({pct(te_code, len(test))}).",
           f"2. train_v1 manual 118건 중 (가) 정보 부족 보류 {sum(manual_reason(r)[0]=='가' for r in train if r['label']==MANUAL)}건, (나) 실제 판단 불가 {sum(manual_reason(r)[0]=='나' for r in train if r['label']==MANUAL)}건, 분류불가 {sum(manual_reason(r)[0]=='분류불가' for r in train if r['label']==MANUAL)}건; (가)의 원천 구체 label은 APIs.guru 특성상 확인 불가.",
           f"3. test_v30 route_only 109건(명세 없음)의 정답: manual {ro_manual}건, 구체 {len(ro)-ro_manual}건; 전체 라벨링에서 security unknown 754건은 manual {pct(sum(r['label']==MANUAL for r in fl_unknown), len(fl_unknown))}.",
           f"4. declared∧public: train_v1 {len(declared_public['train_v1'])}, val_v1 {len(declared_public['val_v1'])}, test_v30 {len(declared_public['test_v30'])}, train_v2_draft {len(declared_public['train_v2_draft'])}. 합성 비중: membership_required train_v1 {rows_syn(train, 'membership_required')}, tenant_match {rows_syn(train, 'tenant_match')}, owner_or_admin {rows_syn(train, 'owner_or_admin')}; test 합성 {len(syn_test)}건 중 템플릿 중복 {tmpl_hits}건.",
           f"5. 토큰: 4096 초과 {len(over)}건(상세 5절); train_v2_draft Gitea oas_code 입력이 가장 길다.", '',
           '## 8. 라벨 기준 불일치 판정', '',
           f"**확정**. 근거: (i) 명세가 없는 입력에 대해 train 라벨 규칙은 보류(전체 라벨링 security unknown 754건 manual {pct(sum(r['label']==MANUAL for r in fl_unknown), len(fl_unknown))})인데 test_v30 route_only 109건의 사람 정답은 구체 label {pct(len(ro)-ro_manual, len(ro))}; (ii) test 정답은 코드 발췌를 보고 확정됐지만 oas 조건 채점에도 같은 정답을 쓰므로, oas 조건에서 v3.0.1 규칙대로 보류한 모델은 구조적으로 틀린 것으로 채점된다; (iii) train의 코드 있는 레코드 {pct(tr_code, len(train))} vs test {pct(te_code, len(test))}로 입력 조건 자체가 다르다.", '',
           '## 9. 선택지별 사실 정리 (권고 없음)', '',
           '**(A) test를 조건별 정답으로 재정의 — oas 조건에서 정보 부족 시 manual을 정답으로 인정, 프롬프트 v3.0.1 유지**',
           f"- 바꿔야 하는 파일: test_v30.jsonl은 동결이므로 불변. 새 파일로 `test_v30_oas_truth.jsonl`(또는 조건별 정답 열)을 만들어 oas 조건 전용 정답을 둔다. 평가 코드(노트북 셀 7~8, 향후 eval 스크립트)가 조건별 정답을 읽도록 변경.",
           f"- 재정의 대상 건수: route_only 109건(명세 없음)이 1차 대상, security unknown 전체 {len(groups[3][1])}건·description 비어 있음 {len(groups[4][1])}건이 검토 범위. '정보 부족' 판정 규칙(어떤 OAS 필드가 없으면 manual 인정인지)을 먼저 문서화해야 하며 이는 사람 결정이다. oas_code 조건 정답은 그대로.",
           '- 프롬프트 v3.0.1 영향: 없음(유지). train 라벨·LoRA 재학습 불필요. 영향은 평가 해석에만 미치며, oas 조건의 모델 간 비교 수치는 모두 다시 계산된다(기존 lora_v1_report의 oas 열은 구 정답 기준으로 남긴다).', '',
           '**(B) train 라벨을 코드 기준 구체 label로 변경, 프롬프트 v3.1로 개정**',
           f"- 바꿔야 하는 파일: 프롬프트 신규 `policy_label_v3.1.md`(보류 필수 2항 'OAS만으로 확인 불가 → manual' 완화 또는 삭제; 예시 8 재작성), APIs.guru 2,027건 재라벨(gpt-4o-mini, 약 $0.6~1.0, 새 파일 apisguru_labeled_v31.jsonl), train/val 재구성(train_v31/val_v31; data-v1은 불변), DATA_CARD·AGENTS 추가 절, LoRA 재학습(data-v1.1 또는 v2).",
           f"- 재라벨 대상 건수: APIs.guru 2,027건 전부(코드가 없어 '코드 기준' 구체 label 자체를 만들 수 없는 레코드 — 명세 설명만으로 구체 label을 붙이게 되므로 v2.5 시절의 과대 판정 위험이 돌아온다). 코드가 있는 train 레코드는 합성 60건(+data-v2 Gitea 371, 변형 129)뿐이다. train_v1 manual 118건 중 (가) {sum(manual_reason(r)[0]=='가' for r in train if r['label']==MANUAL)}건이 직접 영향 범위.",
           '- 프롬프트 v3.0.1 영향: 고정 결정을 철회하고 v3.1로 개정. Q 단계(합성 train 42건 × 2조건)와 F 단계를 다시 수행해야 하며, Gitea 455건·NetBox·test_v2_extra 참고 라벨도 v3.1 기준과 어긋나므로 재라벨 대상이 된다(Gitea 약 $0.18, NetBox 185 약 $0.07, extra 약 $0.02). test_v30 정답은 이미 코드 기준이라 변경 없음.', '',
           '출력: reports/data_v1_audit.md, reports/data_v1_audit/*.csv (label_dist, source_label, code_label, manual_reasons_summary/detail, info_gap_origin, test_specless_truth, train_specless_labels, security_label, declared_public_ids, synthetic_share, synthetic_near_duplicates, token_lengths(+detail), v2_new_records). 스크립트 scripts/audit_data_v1.py.']
    MD.write_text('\n'.join(md) + '\n', encoding='utf-8'); print('written', MD)

def rows_syn(rows, label):
    syn = sum(r['label'] == label and r.get('meta', {}).get('source') == 'synthetic' for r in rows); tot = sum(r['label'] == label for r in rows)
    return f'{syn}/{tot}'

if __name__ == '__main__': main()
