"""data-v7 step 1/2 — re-judgement of the 615 LLM-labelled training rows (AGENTS.md "작업 data-v7").

  build      : from data-v6d (frozen, hashes asserted) select the rows whose label source is the LLM (processed meta.label_source == 'model_api';
               gitea code 225 + APIs.guru OAS-only 390) plus the rule-labelled rows among the C' blind-audit mismatches (reports/data_v6d/c1_blind_audit.json),
               write judge inputs WITHOUT the current label (datasets/blade/processed/data_v7/rejudge/inputs/<chunk>.jsonl: id, kind, user) and the hidden key
               (current_labels_key.json: id -> current label, rationale, project, split, kind, group), and the judging guide REJUDGE_GUIDE.md (verbatim excerpts of
               G1~G8, the v3.1 label definitions, the test_v6 supplementary rules and the stop-point decisions, plus the output format).
  aggregate  : read data_v7/rejudge/out/*.jsonl (one judgement per row), compare with the key, write reports/data_v7/stop2_rejudge.json and stop2_rejudge_report.md
               (transitions, per project, code/OAS, whole-training-set label distribution before/after, manual ratio with the 20% warning, confidence).
No model inference, no LLM API call, test_v6 never read. Nothing is written into the frozen data-v6d files."""
from __future__ import annotations
import argparse, hashlib, json, re, statistics as st, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
D6 = ROOT / 'training/lora/data_v6d'; P6 = ROOT / 'datasets/blade/processed'; OUT = P6 / 'data_v7/rejudge'; REP = ROOT / 'reports/data_v7'
HASHES6 = dict(file=D6 / 'data_v6d_hashes.json', sha='82efda868e7bde511d0838e10bf0e8a5cc3e6aae577c68b15fcbf370a9d94b53')
PROCESSED6 = {'train_v6d.jsonl': 'aed2b275a76fa684e426a656fb04b1c934a29bc987f45a146fe1c244ced4d372', 'val_v6d.jsonl': '159e01780eb2d8aa1710146d2c06533c20c81920a828a60b889ec6db221361cf'}
L = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']; MANUAL = 'manual_review_required'
CHUNK_CODE, CHUNK_OAS = 25, 45
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def load_v6d():
    assert sha(HASHES6['file']) == HASHES6['sha'], 'data_v6d_hashes.json differs from the frozen one'
    gen = json.load(open(HASHES6['file'], encoding='utf-8'))['generated']
    for n, h in gen.items(): assert sha(D6 / n) == h, f'data_v6d/{n} hash mismatch'
    for n, h in PROCESSED6.items(): assert sha(P6 / n) == h, f'{n} hash mismatch'
    sft = [dict(r, split='train') for r in rd(D6 / 'train_sft_v6d.jsonl')] + [dict(r, split='val') for r in rd(D6 / 'val_sft_v6d.jsonl')]
    pro = {r['id']: r for r in rd(P6 / 'train_v6d.jsonl') + rd(P6 / 'val_v6d.jsonl')}
    return sft, pro


def section(text, heading_prefix):
    """Return the markdown section (heading line + body) whose '## ' heading starts with heading_prefix."""
    lines = text.splitlines(); out = []; on = False
    for ln in lines:
        if ln.startswith('## '):
            if on: break
            on = ln.startswith(heading_prefix)
        if on: out.append(ln)
    assert out, heading_prefix
    return '\n'.join(out)


def build():
    sft, pro = load_v6d()
    audit = json.load(open(ROOT / 'reports/data_v6d/c1_blind_audit.json', encoding='utf-8'))
    mism = [r['id'] for r in audit['rows'] if r['mismatch']]
    rows = []
    for r in sft:
        m = pro[r['id']]['meta']; src = m.get('label_source'); kind = 'code' if r['condition'] == 'oas_code' else 'oas'
        if src == 'model_api': group = 'llm'
        elif r['id'] in mism: group = 'audit_rule'
        else: continue
        proj = pro[r['id']].get('service') or m.get('source_file') or '?'
        if kind == 'oas': proj = 'apisguru'
        elif r['id'].startswith('v4-') or r['id'].startswith('v5-') or r['id'].startswith('v3s1b-'): proj = r['id'].split('-')[1] if r['id'].count('-') >= 2 else proj
        rows.append(dict(id=r['id'], kind=kind, group=group, project=proj, split=r['split'] if 'split' in r else m.get('split'), label=json.loads(r['assistant'])['label'],
                         rationale=json.loads(r['assistant'])['rationale'], user=r['user'], label_source=src, rule_id=m.get('rule_id'), service=pro[r['id']].get('service')))
    llm = [r for r in rows if r['group'] == 'llm']; extra = [r for r in rows if r['group'] == 'audit_rule']
    assert len(llm) == 615 and Counter(r['kind'] for r in llm) == Counter(code=225, oas=390), Counter(r['kind'] for r in llm)
    assert all(json.loads(next(s for s in sft if s['id'] == r['id'])['assistant'])['label'] == r['label'] for r in rows[:5])
    # chunks: gitea code by 25 (sorted by path), OAS by service then path by 45, audit extras one chunk
    (OUT / 'inputs').mkdir(parents=True, exist_ok=True); (OUT / 'out').mkdir(exist_ok=True)
    for f in (OUT / 'inputs').glob('*.jsonl'): f.unlink()
    code = sorted((r for r in llm if r['kind'] == 'code'), key=lambda r: (r['id'])); oas = sorted((r for r in llm if r['kind'] == 'oas'), key=lambda r: (r['service'] or '', r['id']))
    chunks = {}
    for i in range(0, len(code), CHUNK_CODE): chunks[f'code_gitea_{i // CHUNK_CODE + 1:02d}'] = code[i:i + CHUNK_CODE]
    for i in range(0, len(oas), CHUNK_OAS): chunks[f'oas_apisguru_{i // CHUNK_OAS + 1:02d}'] = oas[i:i + CHUNK_OAS]
    if extra: chunks['audit_rule_01'] = sorted(extra, key=lambda r: r['id'])
    for name, rs in chunks.items():
        with open(OUT / 'inputs' / f'{name}.jsonl', 'w', encoding='utf-8', newline='\n') as f:
            for r in rs: f.write(json.dumps(dict(id=r['id'], kind=r['kind'], user=r['user']), ensure_ascii=False) + '\n')
    key = {r['id']: dict(label=r['label'], rationale=r['rationale'], project=r['project'], split=r['split'], kind=r['kind'], group=r['group'], label_source=r['label_source'], rule_id=r['rule_id'], service=r['service'],
                         chunk=next(n for n, rs in chunks.items() if any(x['id'] == r['id'] for x in rs))) for r in rows}
    json.dump(key, open(OUT / 'current_labels_key.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    # guide
    ag = (ROOT / 'AGENTS.md').read_text(encoding='utf-8'); defs = (ROOT / 'reports/eval/human_agreement_v5/label_defs_v3.1_draft.md').read_text(encoding='utf-8')
    # NOTE: this slice starts at the first occurrence of '## 고정 라벨', which is inside the draft's status paragraph; the guide the judges actually read
    # (2026-11-07, sha recorded by aggregate) therefore carries that status sentence before the definitions. Kept as-is so `build` reproduces that guide byte-identically.
    defs_body = defs[defs.index('## 고정 라벨'):defs.index('## 반영하지 않은 규약')]
    g18 = section(ag, '## data-v4 검수 규약'); supp = section(ag, '## test_v31_supp 검수 규약')
    s0 = section(ag, '## 작업 S0'); t6 = s0[s0.index('- **test_v6 검수 규약 보충**'):]; t6 = t6[:t6.index('\n- ', t6.index('8. 근거 부족'))]
    c = section(ag, '## 작업 C:'); stop1 = next(l for l in c.splitlines() if l.startswith('- 정지 지점 1 결정')); stop3 = next(l for l in c.splitlines() if l.startswith('- **정지 지점 3 결정'))
    guide = f"""# data-v7 재판정 안내 (REJUDGE_GUIDE) — 2026-11-07

당신은 BLADE 정책 라벨 검수자다. 입력 파일의 각 행(`id`, `kind`, `user`)에 대해 `user` 텍스트(모델이 보는 OpenAPI 명세 + 있으면 핸들러 코드 발췌)만 보고 7종 label 중 하나를 고른다.
**다른 파일을 열지 않는다.** 이 안내문과 지정된 입력 파일만 읽는다. 저장소의 다른 데이터·정답·보고서·코드를 읽지 않는다(현재 라벨을 보면 재판정이 무효가 된다).

## 출력 형식

출력 파일(지정 경로)에 입력과 같은 순서로 한 행에 JSON 하나:
`{{"id": "...", "label": "<7종 중 하나>", "confidence": <0.5|0.7|0.9>, "rule": "<근거 규약: G1~G7, 보류1~8, G3-a 등>", "evidence": "<입력에서 그대로 인용한 핵심 문구·코드 줄 1~3개, 120자 이내>", "note": "<판단 한 줄, 한국어>"}}`
- label 7종: public, role_required, membership_required, tenant_match, owner_match, owner_or_admin, manual_review_required.
- confidence: 0.9 = 근거가 입력에 명시, 0.7 = 근거는 있으나 해석 필요, 0.5 = 경계·추정(이 경우 보류를 우선 검토).
- 모든 행을 빠뜨리지 말고 id를 그대로 쓴다. 입력 행 수와 출력 행 수가 같아야 한다.

## 입력 종류별 규칙

- `kind: "oas"` (명세만, 코드 없음): **보류 2를 엄격히 적용**한다. description·summary에 접근 조건이 문장으로 명시돼 있어야 구체 label을 고른다("관리자만", "본인 계정의", "인증 없이", "organization member" 등). path에 ID가 있다는 것, owner_cols/tenant_cols에 필드가 있다는 것, 자원 이름(me, my, admin)만으로 관계를 단정하지 않는다 → manual_review_required. security 선언·mutation 제한은 OAS-only에서 유지한다: PUT/POST/PATCH/DELETE는 security가 명시적으로 비어 있을(`security_state: explicitly_anonymous`) 때만 public이고, `declared`·`unknown`이면 public이 아니다. GET이라도 익명 허용의 긍정 근거(explicitly_anonymous 또는 "no authentication required" 같은 설명)가 없으면 public이 아니다. `/me`, `/user/...`처럼 경로 자체가 인증 사용자 본인으로 고정됨을 설명이 뒷받침하면 owner_match(G4).
- `kind: "code"` (gitea 핸들러 + 미들웨어 체인): 실제 허용·거부를 결정하는 조건을 찾는다. 미들웨어 주석 설명을 근거로 쓴다. 인증만(reqToken 등) 있고 객체·역할 조건이 없으면 보류 8(manual). reqOrgOwnership·reqOrgMembership·reqRepoWriter·reqAdmin·reqSiteAdmin 등은 아래 정의(그룹 안 역할 → role_required, 구성원 → membership_required)대로. 공개/비공개 저장소 가시성 분기(reqRepoReader·repoAssignment 가시성)만으로 허용이 갈리면 보류 4(manual). 본인 자원(/user/..., ctx.Doer 기준 처리)은 owner_match.

## 라벨 정의 v3.1 (test_v5·test_v6 정답 기준)

{defs_body.strip()}

## 검수 규약 G1~G8 (원문)

{g18.strip()}

## test_v31_supp 검수 규약 (원문)

{supp.strip()}

## test_v6 검수 규약 보충 (원문)

{t6.strip()}

## 정지 지점 결정 (원문)

{stop1}
{stop3}

## data-v2 라벨 기준(gitea 관련, 원문)

{section(ag, '## data-v2 라벨 기준').strip()}
"""
    (OUT / 'REJUDGE_GUIDE.md').write_text(guide, encoding='utf-8', newline='\n')
    summ = dict(rows=len(rows), llm=len(llm), llm_by_kind=dict(Counter(r['kind'] for r in llm)), llm_by_split=dict(Counter(r['split'] for r in llm)), audit_rule_extra=len(extra), extra_ids=[r['id'] for r in extra],
                chunks={n: len(rs) for n, rs in chunks.items()}, user_chars={n: sum(len(x['user']) for x in rs) for n, rs in chunks.items()}, guide_chars=len(guide), current_label_dist=dict(Counter(r['label'] for r in llm)))
    json.dump(summ, open(OUT / 'build_summary.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1); print(json.dumps(summ, ensure_ascii=False, indent=1))


def aggregate():
    sft, pro = load_v6d(); key = json.load(open(OUT / 'current_labels_key.json', encoding='utf-8'))
    J = {}
    for f in sorted((OUT / 'out').glob('*.jsonl')):
        for r in rd(f):
            assert r['id'] in key, f"unknown id {r['id']} in {f.name}"; assert r['label'] in L, (f.name, r['id'], r['label'])
            assert r['id'] not in J, f"duplicate {r['id']}"; J[r['id']] = dict(r, chunk=f.stem)
    missing = [i for i in key if i not in J]; assert not missing, f'{len(missing)} rows without judgement, e.g. {missing[:5]}'
    def agg(ids):
        ch = [(key[i]['label'], J[i]['label']) for i in ids]; n = len(ids); changed = [i for i in ids if key[i]['label'] != J[i]['label']]
        tr = Counter(f'{a}->{b}' for a, b in ch if a != b)
        return dict(n=n, changed=len(changed), changed_ratio=round(len(changed) / n, 4) if n else None, to_manual=sum(J[i]['label'] == MANUAL and key[i]['label'] != MANUAL for i in ids), from_manual=sum(key[i]['label'] == MANUAL and J[i]['label'] != MANUAL for i in ids),
                    transitions=dict(tr.most_common()), label_before=dict(Counter(a for a, _ in ch)), label_after=dict(Counter(b for _, b in ch)), manual_before=sum(a == MANUAL for a, _ in ch), manual_after=sum(b == MANUAL for _, b in ch),
                    confidence=dict(Counter(str(J[i]['confidence']) for i in ids)), confidence_changed=dict(Counter(str(J[i]['confidence']) for i in changed)), rules=dict(Counter(J[i].get('rule', '?') for i in ids).most_common(15)))
    llm_ids = [i for i in key if key[i]['group'] == 'llm']; extra_ids = [i for i in key if key[i]['group'] == 'audit_rule']
    A = dict(all_llm=agg(llm_ids), code=agg([i for i in llm_ids if key[i]['kind'] == 'code']), oas=agg([i for i in llm_ids if key[i]['kind'] == 'oas']),
             by_split={s: agg([i for i in llm_ids if key[i]['split'] == s]) for s in ('train', 'val')}, audit_rule_extra=agg(extra_ids) if extra_ids else None,
             by_project={p: agg([i for i in llm_ids if key[i]['project'] == p]) for p in sorted({key[i]['project'] for i in llm_ids})})
    # OAS by service (top changed)
    svc = defaultdict(list)
    for i in llm_ids:
        if key[i]['kind'] == 'oas': svc[key[i]['service']].append(i)
    A['oas_by_service_top'] = sorted(({'service': s, 'n': len(v), 'changed': sum(key[i]['label'] != J[i]['label'] for i in v), 'to_manual': sum(J[i]['label'] == MANUAL and key[i]['label'] != MANUAL for i in v)} for s, v in svc.items()), key=lambda d: -d['changed'])[:25]
    # whole training set distribution before/after (SFT 1453; split train/val)
    cur = {r['id']: json.loads(r['assistant'])['label'] for r in sft}; new = dict(cur); new.update({i: J[i]['label'] for i in llm_ids})   # extras not applied (separate decision)
    def dist(d, ids): c = Counter(d[i] for i in ids); n = len(ids); return dict(n=n, counts={l: c.get(l, 0) for l in L}, manual_ratio=round(c.get(MANUAL, 0) / n, 4))
    tr_ids = [r['id'] for r in sft if r['split'] == 'train']; va_ids = [r['id'] for r in sft if r['split'] == 'val']
    A['trainset'] = dict(all_before=dist(cur, list(cur)), all_after=dist(new, list(cur)), train_before=dist(cur, tr_ids), train_after=dist(new, tr_ids), val_before=dist(cur, va_ids), val_after=dist(new, va_ids))
    A['manual_warning'] = A['trainset']['train_after']['manual_ratio'] > 0.20
    A['changed_rows'] = [dict(id=i, kind=key[i]['kind'], project=key[i]['project'], service=key[i]['service'], split=key[i]['split'], label_from=key[i]['label'], label_to=J[i]['label'], confidence=J[i]['confidence'], rule=J[i].get('rule'), evidence=J[i].get('evidence'), note=J[i].get('note'), chunk=J[i]['chunk']) for i in llm_ids + extra_ids if key[i]['label'] != J[i]['label']]
    A['judgements_file_count'] = len(list((OUT / 'out').glob('*.jsonl'))); A['n_judged'] = len(J)
    A['guide_sha256'] = sha(OUT / 'REJUDGE_GUIDE.md'); A['inputs_sha256'] = {f.name: sha(f) for f in sorted((OUT / 'inputs').glob('*.jsonl'))}; A['outputs_sha256'] = {f.name: sha(f) for f in sorted((OUT / 'out').glob('*.jsonl'))}
    REP.mkdir(parents=True, exist_ok=True)
    json.dump(A, open(REP / 'stop2_rejudge.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    with open(REP / 'rejudge_changes.jsonl', 'w', encoding='utf-8', newline='\n') as f:
        for r in A['changed_rows']: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    write_report(A, key, J)


def write_report(A, key, J):
    o = []; w = o.append; S = {'public': 'public', 'role_required': 'role', 'membership_required': 'member', 'tenant_match': 'tenant', 'owner_match': 'owner', 'owner_or_admin': 'own+adm', 'manual_review_required': 'manual'}
    def tbl(a, title):
        w(f'### {title}\n'); w(f"- n {a['n']}, 변경 {a['changed']}({a['changed_ratio'] * 100:.1f}%), → manual {a['to_manual']}, manual → 구체 {a['from_manual']}, manual {a['manual_before']} → {a['manual_after']}; 확신도 {a['confidence']}(변경 행 {a['confidence_changed']})")
        w('\n| 현재 \\ 새 | ' + ' | '.join(S[l] for l in L) + ' | 합 |\n|---|' + '---:|' * 8)
        for a_ in L:
            row = [sum(1 for i in ids_of(a) if key[i]['label'] == a_ and J[i]['label'] == b_) for b_ in L]
            if sum(row): w(f'| **{S[a_]}** | ' + ' | '.join(f'**{x}**' if a_ == L[k] and x else str(x) for k, x in enumerate(row)) + f' | {sum(row)} |')
        w('')
    def ids_of(a): return a['_ids']
    # attach ids for the matrix
    llm_ids = [i for i in key if key[i]['group'] == 'llm']
    for name, sel in (('all_llm', lambda i: True), ('code', lambda i: key[i]['kind'] == 'code'), ('oas', lambda i: key[i]['kind'] == 'oas')): A[name]['_ids'] = [i for i in llm_ids if sel(i)]
    for s in ('train', 'val'): A['by_split'][s]['_ids'] = [i for i in llm_ids if key[i]['split'] == s]
    if A['audit_rule_extra']: A['audit_rule_extra']['_ids'] = [i for i in key if key[i]['group'] == 'audit_rule']
    w('# data-v7 2단계 보고 — LLM 라벨 615행 재판정 집계 (2026-11-07, 정지 지점 — 사용자 승인 대기)\n')
    w(f"사전 기록 AGENTS.md \"작업 data-v7\". 대상 = data-v6d SFT 1,453행 중 라벨 출처가 LLM(gpt-4o-mini, v3.0.1)인 615행(gitea 코드 225 + APIs.guru OAS-only 390; train 535·val 80). 재판정자 Claude(AI) 서브에이전트 {A['judgements_file_count']}개 청크(코드 25행·OAS 45행 단위), 입력은 SFT user 필드(코드/명세)만이며 현재 label·rationale은 키 파일에 분리해 집계에서만 읽었다. 기준: G1~G8 + v3.1 정의 + test_v6 보충 규약 + 정지 지점 결정, OAS-only는 보류 2 엄격 적용(data_v7/rejudge/REJUDGE_GUIDE.md). 학습·추론·LLM API 호출 없음, 커밋 없음. 판정 원본 data_v7/rejudge/out/*.jsonl, 변경 행 목록 reports/data_v7/rejudge_changes.jsonl.\n")
    a = A['all_llm']
    w('## 1. 요약\n')
    w(f"- 615행 중 label 변경 **{a['changed']}건({a['changed_ratio'] * 100:.1f}%)**: 코드(gitea) {A['code']['changed']}/{A['code']['n']}({A['code']['changed_ratio'] * 100:.1f}%), OAS-only {A['oas']['changed']}/{A['oas']['n']}({A['oas']['changed_ratio'] * 100:.1f}%). 구체 → manual {a['to_manual']}건, manual → 구체 {a['from_manual']}건, 구체 → 다른 구체 {a['changed'] - a['to_manual'] - a['from_manual']}건.")
    T = A['trainset']
    w(f"- 학습셋 전체(SFT) manual 비율: train {T['train_before']['manual_ratio'] * 100:.1f}% → **{T['train_after']['manual_ratio'] * 100:.1f}%**{' ⚠️ 20% 초과 경고' if A['manual_warning'] else '(20% 이하)'}, val {T['val_before']['manual_ratio'] * 100:.1f}% → {T['val_after']['manual_ratio'] * 100:.1f}%, 전체 {T['all_before']['manual_ratio'] * 100:.1f}% → {T['all_after']['manual_ratio'] * 100:.1f}%.")
    if A['audit_rule_extra']: e = A['audit_rule_extra']; w(f"- C′ 블라인드 불일치 28건 중 규칙 라벨러 행 {e['n']}건(615와 별도 집계): 변경 {e['changed']}, → manual {e['to_manual']}. 이 행들은 data-v7 변경에 자동 반영하지 않는다(3단계 사람 확인 대상 후보).")
    w(f"- 확신도 분포(615): {a['confidence']}; 변경 행 {a['confidence_changed']}. 상위 근거 규약: " + ', '.join(f'{k} {v}' for k, v in list(a['rules'].items())[:10]) + '.\n')
    w('## 2. 전이표 (현재 label 행 → 새 label 열)\n'); tbl(A['all_llm'], '전체 615'); tbl(A['code'], 'gitea 코드 225'); tbl(A['oas'], 'APIs.guru OAS-only 390')
    w('### split별\n\n| split | n | 변경 | → manual | manual → 구체 | manual 전 → 후 |\n|---|---:|---:|---:|---:|---|')
    for s in ('train', 'val'): b = A['by_split'][s]; w(f"| {s} | {b['n']} | {b['changed']} | {b['to_manual']} | {b['from_manual']} | {b['manual_before']} → {b['manual_after']} |")
    if A['audit_rule_extra']: w(''); tbl(A['audit_rule_extra'], 'C′ 블라인드 불일치 중 규칙 라벨러 행(별도)')
    w('## 3. 프로젝트·서비스별\n\n| 프로젝트 | n | 변경 | → manual | manual 전 → 후 |\n|---|---:|---:|---:|---|')
    for p, b in A['by_project'].items(): w(f"| {p} | {b['n']} | {b['changed']} | {b['to_manual']} | {b['manual_before']} → {b['manual_after']} |")
    w('\nOAS-only 서비스 중 변경 많은 순(상위 25):\n\n| service | n | 변경 | → manual |\n|---|---:|---:|---:|')
    for d in A['oas_by_service_top']: w(f"| {d['service']} | {d['n']} | {d['changed']} | {d['to_manual']} |")
    w('\n## 4. 학습셋 전체 label 분포 변화 (SFT, 615행 재판정 반영 가정; 별도 집계 행은 미반영)\n\n| 구간 | n | ' + ' | '.join(S[l] for l in L) + ' | manual 비율 |\n|---|---:|' + '---:|' * 7 + '---:|')
    for k, nm in (('train_before', 'train 현재'), ('train_after', 'train 재판정 후'), ('val_before', 'val 현재'), ('val_after', 'val 재판정 후'), ('all_before', '전체 현재'), ('all_after', '전체 재판정 후')):
        d = T[k]; w(f"| {nm} | {d['n']} | " + ' | '.join(str(d['counts'][l]) for l in L) + f" | {d['manual_ratio'] * 100:.1f}% |")
    w(f"\n{'**경고: train manual 비율이 20%를 넘는다.** 사전 기록대로 보고하고 멈춘다. 3단계 진행 여부(manual 쿼터 적용·OAS-only manual 행 일부 제외 등)는 사용자 결정.' if A['manual_warning'] else 'train manual 비율 20% 이하.'}\n")
    w('## 5. 변경 행 예시 (전이 유형별 최대 3건, 전체는 rejudge_changes.jsonl)\n')
    by_tr = defaultdict(list)
    for r in A['changed_rows']:
        if r['id'] in A['all_llm']['_ids']: by_tr[f"{r['label_from']}->{r['label_to']}"].append(r)
    for k, rs in sorted(by_tr.items(), key=lambda kv: -len(kv[1])):
        w(f"### {S[k.split('->')[0]]} → {S[k.split('->')[1]]} ({len(rs)}건)\n")
        for r in rs[:3]: w(f"- `{r['id']}` [{r['kind']}, conf {r['confidence']}, {r['rule']}] {r['note']} — 근거: `{(r['evidence'] or '').replace('`', '').replace(chr(10), ' ')[:140]}`")
        w('')
    w('## 6. 다음 단계 (승인 후, 사전 기록 3단계)\n')
    nm = a['to_manual']; nc = a['changed'] - nm; nu = a['n'] - a['changed']
    w(f"- 사람 확인 시트: manual로 바뀐 행 전부 {nm} + 그 외 변경 행 30%({round(nc * 0.3)}) + 안 바뀐 행 10% 블라인드({round(nu * 0.1)}) ≈ {nm + round(nc * 0.3) + round(nu * 0.1)}행, seed 42. 검수자 A/B/C 균등.")
    w('- 바뀐 행 rationale 재작성(SFT 형식, 입력 근거만, 규칙 ID·경로·메타 문구 금지) → 정합성 assert → data-v7 동결 → 학습 번들(v5 설정, 7B). 중단 규칙 2026-11-09 18:00 KST.')
    w('- 한계: 재판정자는 사람이 아니라 Claude(AI)이며 OAS-only 보류 2 엄격 적용은 data-v5의 gpt-4o-mini 라벨(confidence ≥ 0.6 포함)과 기준이 다르다. 변경 수가 많다면 그 차이가 주 원인이다. gitea 코드 행은 C′에서 36건이 이미 교정됐고 이번은 그 위에서 다시 판정한 결과다.')
    (REP / 'stop2_rejudge_report.md').write_text('\n'.join(o) + '\n', encoding='utf-8', newline='\r\n')
    print(json.dumps(dict(changed=a['changed'], to_manual=a['to_manual'], from_manual=a['from_manual'], code=A['code']['changed'], oas=A['oas']['changed'], train_manual_after=A['trainset']['train_after']['manual_ratio'], warning=A['manual_warning']), ensure_ascii=False))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('cmd', choices=['build', 'aggregate']); a = ap.parse_args()
    build() if a.cmd == 'build' else aggregate()
