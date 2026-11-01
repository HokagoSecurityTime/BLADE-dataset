"""Task 1: data dictionary (field inventory) for the BLADE datasets. Read-only; writes reports/data_dictionary.{md,html} and reports/data_dictionary/*.csv."""
from __future__ import annotations
import csv, html, json, re, statistics, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / 'scripts'))
from data_v1_guard import assert_data_v1
P = ROOT / 'datasets/blade/processed'; OUT = ROOT / 'reports/data_dictionary'
FILES = {'train_v30': P / 'train_v30.jsonl', 'val_v30': P / 'val_v30.jsonl', 'test_v30': P / 'test_v30.jsonl', 'train_v2_draft': P / 'train_v2_draft.jsonl',
         'gitea_labeled_455': P / 'opensource/gitea_v28.2.0_labeled_v301.jsonl', 'synthetic_v2_129': P / 'data_v2_synthetic_additions.jsonl', 'apisguru_labeled_2027': P / 'apisguru_labeled_v301.jsonl'}
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()]
CODE_FIELDS = {'controller_signals.raw_snippet', 'controller_text', 'oas_snippet', 'erd_snippet'}
# usage classification: which code reads which record fields (evidence file:line found at runtime by grep)
USAGE = {
    'method': ('입력', 'training/data/label_v3.py', r'method=row\[.method.\]'), 'path': ('입력', 'training/data/label_v3.py', r'path=row\[.path.\]'),
    'oas_snippet': ('입력', 'training/data/label_v3.py', r'json\.loads\(row\[.oas_snippet.\]\)'), 'erd_snippet': ('입력', 'training/data/label_v30.py', r'erd_cols\(row\[.erd_snippet.\]\)'),
    'controller_signals.raw_snippet': ('입력(oas_code, 합성)', 'training/data/label_v30.py', r'code=sig\[.raw_snippet.\]'), 'controller_text': ('입력(oas_code, test·Gitea·취약 API)', 'training/data/label_gitea_v30.py', r'r\[.controller_text.\]'),
    'meta.owner_cols': ('입력', 'training/data/label_v3.py', r'owner_cols=row\[.meta.\]\[.owner_cols.\]'), 'meta.tenant_cols': ('입력', 'training/data/label_v3.py', r'tenant_cols=row\[.meta.\]\[.tenant_cols.\]'),
    'meta.source_file': ('입력(코드 위치 표시)', 'training/data/label_v30.py', r'FILE .\+row\[.source_file.\]'), 'meta.source_locations': ('입력(코드 위치 표시, test)', 'training/lora/prepare_lora_inputs.py', r'source_locations'),
    'enrichment.operation.summary': ('입력', 'training/data/label_v3.py', r'summary=op\.get\(.summary.\)'), 'enrichment.operation.description': ('입력', 'training/data/label_v3.py', r'description=op\.get\(.description.\)'),
    'enrichment.security.effective': ('입력', 'training/data/label_v3.py', r'security=enrich\[.security.\]\[.effective.\]'), 'enrichment.trees': ('입력(schema_fields 유도)', 'training/data/label_v3.py', r'trees=enrich\.get\(.trees.'), 'enrichment.references': ('입력(schema_fields 유도)', 'training/data/label_v3.py', r'refs=enrich\.get\(.references.'),
    'label': ('정답', 'training/lora/prepare_lora_inputs.py', r"target = \{'label': row\['label'\]"), 'rationale': ('정답', 'training/lora/prepare_lora_inputs.py', r"'rationale': rationale"),
    'confidence': ('정답', 'training/lora/prepare_lora_inputs.py', r"'confidence': conf"), 'evidence_fields': ('정답', 'training/lora/prepare_lora_inputs.py', r"ev = row\['evidence_fields'\]"),
    'security_state': ('파생 입력(저장값은 메타; 입력 시 OAS에서 재계산)', 'training/data/label_v5.py', r"def security_state"),
}

def flatten(obj, prefix=''):
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f'{prefix}.{k}' if prefix else k
            if isinstance(v, dict) and v: out.update(flatten(v, key))
            else: out[key] = v
    return out

def jtype(v):
    if v is None: return 'null'
    if isinstance(v, bool): return 'bool'
    if isinstance(v, int): return 'int'
    if isinstance(v, float): return 'float'
    if isinstance(v, str): return 'str'
    if isinstance(v, list): return 'list[dict]' if v and isinstance(v[0], dict) else 'list'
    return type(v).__name__

def grep_line(rel, pattern):
    try:
        for i, l in enumerate((ROOT / rel).read_text(encoding='utf-8').splitlines(), 1):
            if re.search(pattern, l): return f'{rel}:{i}'
    except FileNotFoundError: pass
    return rel + ':?'

def main():
    verified = assert_data_v1('start'); OUT.mkdir(parents=True, exist_ok=True)
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained('Qwen/Qwen2.5-7B-Instruct', cache_dir=str(ROOT / '.cache/models'))
    data = {k: rd(p) for k, p in FILES.items()}
    flat = {k: [flatten(r) for r in rows] for k, rows in data.items()}
    fields = sorted({f for rows in flat.values() for r in rows for f in r})
    presence, fieldinfo, values_rows = [], [], []
    for f in fields:
        types = Counter(); missing = 0; empty = 0; total = 0; uniq = set(); texts = []; listlens = []; subkeys = set(); per_file = {}
        for k, rows in flat.items():
            n_present = 0
            for r in rows:
                total += 1
                if f not in r: missing += 1; continue
                v = r[f]; n_present += 1; types[jtype(v)] += 1
                if v is None or v == '' or v == [] or v == {}: empty += 1
                try: uniq.add(json.dumps(v, ensure_ascii=False, sort_keys=True))
                except TypeError: uniq.add(str(v))
                if isinstance(v, str): texts.append(v)
                if isinstance(v, list):
                    listlens.append(len(v))
                    for x in v:
                        if isinstance(x, dict): subkeys.update(x.keys())
            per_file[k] = (n_present, len(rows))
        presence.append([f] + [f'{per_file[k][0]}/{per_file[k][1]}' for k in FILES])
        main_type = '/'.join(t for t, _ in types.most_common())
        categorical = len(uniq) <= 50 and not (set(types) & {'list[dict]'})
        text_stats = ''
        if texts and 'str' in types and not categorical:
            lens = sorted(len(x) for x in texts); sample = [texts[i] for i in sorted({0, len(texts) // 2, len(texts) - 1})]
            tk = sorted(len(tok(x).input_ids) for x in (texts if len(texts) <= 3000 else texts[::max(1, len(texts) // 3000)]))
            text_stats = f"chars median {lens[len(lens)//2]} p95 {lens[int(.95*(len(lens)-1))]} max {lens[-1]}; tokens median {tk[len(tk)//2]} p95 {tk[int(.95*(len(tk)-1))]} max {tk[-1]}"
            examples = ' ‖ '.join(x[:300].replace('\n', '⏎') for x in sample)
        else: examples = ''
        list_stats = ''
        if listlens: list_stats = f"len median {sorted(listlens)[len(listlens)//2]} max {max(listlens)}" + (f"; subkeys {sorted(subkeys)}" if subkeys else '')
        usage, ev_file, ev_pat = USAGE.get(f, ('메타', '', ''))
        if f.startswith('llm_reference'): usage = '참고(사람 정답 전 LLM 라벨)'
        evidence = grep_line(ev_file, ev_pat) if ev_file else '빌드·프롬프트 코드에서 읽지 않음'
        fieldinfo.append(dict(field=f, type=main_type, in_files=','.join(k for k in FILES if per_file[k][0]), missing_ratio=round(missing / total, 4), empty_ratio=round(empty / max(1, total - missing), 4), unique=len(uniq),
                              categorical=categorical, text_stats=text_stats, examples=examples, list_stats=list_stats, usage=usage, evidence=evidence))
        if categorical:
            cnt = {k: Counter(json.dumps(r[f], ensure_ascii=False, sort_keys=True) if not isinstance(r[f], str) else r[f] for r in rows if f in r) for k, rows in flat.items()}
            for val in sorted({v for c in cnt.values() for v in c}, key=lambda v: -sum(c[v] for c in cnt.values())):
                values_rows.append([f, val[:120]] + [cnt[k][val] for k in FILES])
    # csv outputs
    with open(OUT / 'fields.csv', 'w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=list(fieldinfo[0].keys())); w.writeheader(); w.writerows(fieldinfo)
    with open(OUT / 'field_presence.csv', 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh); w.writerow(['field'] + list(FILES)); w.writerows(presence)
    with open(OUT / 'field_values.csv', 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh); w.writerow(['field', 'value'] + list(FILES)); w.writerows(values_rows)
    mapping = [('controller_signals.raw_snippet', 'controller_text', '핸들러 원문 발췌(train 합성·synthetic_v2 ↔ test·Gitea·취약 API). train은 함수 전체, test는 403 검사 근처 2~3줄, Gitea는 미들웨어 정의+핸들러 60줄 상한', '추정(의미 동일, 범위 다름)'),
               ('meta.source_file', 'meta.source_locations[].file', '코드 위치. train 합성은 파일 경로 문자열, test·Gitea·NetBox는 {file,start_line,end_line} 리스트', '추정'),
               ('enrichment.operation.description (apisguru 2027·enriched)', 'description (합성 train) / OAS op.description (test·Gitea oas_snippet 내)', 'OAS operation 설명. train_v30 APIs.guru 레코드는 slim 저장이라 enriched_v2에서 다시 읽음', '추정'),
               ('rationale (APIs.guru·Gitea: 모델 문장)', 'rationale (합성: intended reason 영어 문장)', '같은 필드명이지만 출처가 다름(LLM 생성 vs 설계 사유)', '확인'),
               ('label (train: LLM/설계 라벨)', 'label (test: 사람 확정·설계 라벨) / llm_reference_label (NetBox·test_v2_extra 후보)', '정답 지위가 다름. meta.label_source로 구분', '확인'),
               ('meta.known_vulnerable', 'intended_labels.yaml vulnerable', '합성 취약 변형 표시', '확인'),
               ('security_state (train 저장값)', 'test_v30_inputs.security_state (OAS에서 계산)', 'label_v5.security_state 규칙 동일; test 레코드에는 저장돼 있지 않음', '확인'),
               ('meta.v30_override_reason / meta.label_before_override', 'meta.v30_relabel_reason / meta.intended_label_original', '빌드 시 라벨 변경 기록(APIs.guru·Gitea override vs 합성 relabel)', '확인'),
               ('service', 'meta.project (Gitea·NetBox) / source (test: vuln|synthetic)', '출처 식별자 계층이 다름', '추정')]
    with open(OUT / 'name_mapping.csv', 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh); w.writerow(['field_a', 'field_b', 'meaning', 'status']); w.writerows(mapping)
    # representative records + model inputs
    def trunc(rec):
        rec = json.loads(json.dumps(rec, ensure_ascii=False))
        def walk(o, prefix=''):
            if isinstance(o, dict):
                for k, v in o.items():
                    key = f'{prefix}.{k}' if prefix else k
                    if isinstance(v, str) and (key in CODE_FIELDS or len(v) > 800): o[k] = v[:800] + ('…[truncated]' if len(v) > 800 else '')
                    else: walk(v, key)
            elif isinstance(o, list):
                for x in o: walk(x, prefix)
        walk(rec); return rec
    test = data['test_v30']
    reps = {'apisguru (train_v30)': next(r for r in data['train_v30'] if r['meta'].get('source') == 'apisguru'),
            'gitea (gitea_labeled_455)': next(r for r in data['gitea_labeled_455'] if r['label'] == 'owner_match'),
            'synthetic (train_v30)': next(r for r in data['train_v30'] if r['meta'].get('source') == 'synthetic'),
            'synthetic_v2 (129)': next(r for r in data['synthetic_v2_129'] if r['meta'].get('variant_kind') == 'extauth'),
            'vuln_route_only (test_v30)': next(r for r in test if r.get('source') == 'vuln' and r['meta'].get('oas_status') == 'route_only'),
            'vuln_repository_spec (test_v30)': next(r for r in test if r.get('source') == 'vuln' and r['meta'].get('oas_status') == 'repository_spec')}
    from training.data import label_v5 as b5; from training.data import label_v30 as lv; from training.data.label_gitea_v30 import payload as gpayload
    from training.lora.prepare_lora_inputs import synthetic_payload
    enriched = {r['id']: r for r in rd(P / 'apisguru_enriched_v2.jsonl')}
    test_inputs = {r['id']: r for r in rd(ROOT / 'training/lora/data_v1/test_v30_inputs.jsonl')}
    examples = {}
    a = reps['apisguru (train_v30)']; examples['apisguru / oas'] = 'Return JSON.\n' + json.dumps(b5.payload(enriched[a['id']]), ensure_ascii=False); examples['apisguru / oas_code'] = '(코드 없음 — oas_code 조건 해당 없음)'
    g = reps['gitea (gitea_labeled_455)']; gp = gpayload(g); examples['gitea / oas_code'] = 'Return JSON.\n' + json.dumps(gp, ensure_ascii=False)
    gp_oas = dict(gp); gp_oas['description'] = (json.loads(g['oas_snippet'])['paths'][g['path']][g['method'].lower()].get('description') or ''); examples['gitea / oas'] = 'Return JSON.\n' + json.dumps(gp_oas, ensure_ascii=False)
    v = reps['vuln_repository_spec (test_v30)']; examples['vuln_repository_spec / oas'] = test_inputs[v['id']]['oas_user']; examples['vuln_repository_spec / oas_code'] = test_inputs[v['id']].get('oas_code_user', '(코드 없음)')
    # markdown
    md = ['# 데이터 사전 (피처 인벤토리) — 2026-10-23', '', 'data-v1 해시 assert 통과(시작·종료): ' + ', '.join(f'{k.split("/")[-1]} `{v}`' for k, v in verified.items()) + '. 모든 파일 읽기 전용. 상세·필터 UI는 reports/data_dictionary.html, 원시 표는 reports/data_dictionary/*.csv.', '',
          '## 대상 파일', '', '| 파일 키 | 경로 | 건수 |', '|---|---|---:|'] + [f'| {k} | {p.relative_to(ROOT).as_posix()} | {len(data[k])} |' for k, p in FILES.items()]
    md += ['', '## 필드 요약 (존재 파일 · 타입 · 결측 · 고유값 · 용도)', '', '용도 판정 근거: 프롬프트 페이로드 빌더(label_v3.payload → label_v5.payload, label_v30.q_payload, label_gitea_v30.payload, prepare_lora_inputs.test_inputs)와 SFT 타깃(prepare_lora_inputs.sft_rows)이 실제로 읽는 필드. 나머지는 메타.', '',
           '| 필드 | 타입 | 존재 파일 | 결측 | 빈값 | 고유값 | 용도 | 근거 |', '|---|---|---|---:|---:|---:|---|---|']
    for fi in fieldinfo: md.append(f"| {fi['field']} | {fi['type']} | {fi['in_files']} | {fi['missing_ratio']:.0%} | {fi['empty_ratio']:.0%} | {fi['unique']} | {fi['usage']} | {fi['evidence']} |")
    md += ['', '## 파일별 존재 여부 (존재 건수/전체)', '', '| 필드 | ' + ' | '.join(FILES) + ' |', '|---|' + '---:|' * len(FILES)] + ['| ' + ' | '.join(str(c) for c in r) + ' |' for r in presence]
    md += ['', '## 범주형 필드 값 (고유값 50개 이하)', '']
    for f in sorted({r[0] for r in values_rows}):
        rows_f = [r for r in values_rows if r[0] == f]
        md += [f'**{f}**', '', '| 값 | ' + ' | '.join(FILES) + ' |', '|---|' + '---:|' * len(FILES)] + ['| ' + ' | '.join(str(c) for c in r[1:]) + ' |' for r in rows_f[:50]] + ['']
    md += ['## 텍스트·리스트 필드 통계', '', '| 필드 | 텍스트 길이(문자·Qwen 토큰) | 리스트 통계 | 예시(300자) |', '|---|---|---|---|']
    for fi in fieldinfo:
        if fi['text_stats'] or fi['list_stats']: md.append(f"| {fi['field']} | {fi['text_stats']} | {fi['list_stats']} | {fi['examples'][:600].replace('|', '&#124;')} |")
    md += ['', '## 같은 의미·다른 이름 매핑', '', '| 필드 A | 필드 B | 의미 | 상태 |', '|---|---|---|---|'] + [f'| {a} | {b} | {m} | {s} |' for a, b, m, s in mapping]
    md += ['', '## 출처별 대표 레코드 (코드 필드 800자 절단)', '']
    for name, rec in reps.items(): md += [f'### {name}', '', '```json', json.dumps(trunc(rec), ensure_ascii=False, indent=1), '```', '']
    md += ['## 실제 모델 입력 예시 (v3.0.1 user 메시지 원문; system은 프롬프트 전문)', '']
    for name, text in examples.items(): md += [f'### {name}', '', '```', text, '```', '']
    (ROOT / 'reports/data_dictionary.md').write_text('\n'.join(md) + '\n', encoding='utf-8')
    # html
    payload = dict(files=list(FILES), fields=fieldinfo, presence=presence, values=values_rows, mapping=mapping, reps={k: trunc(v) for k, v in reps.items()}, examples=examples, verified=verified)
    js = json.dumps(payload, ensure_ascii=False).replace('</', '<\\/')
    page = '''<!doctype html><html lang="ko"><meta charset="utf-8"><title>BLADE 데이터 사전</title>
<style>body{font:14px/1.5 system-ui,sans-serif;margin:20px;max-width:1400px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:4px 6px;vertical-align:top;font-size:13px}th{background:#f3f3f3;position:sticky;top:0}
.ctl{margin:8px 0;display:flex;gap:12px;flex-wrap:wrap}details{margin:4px 0}summary{cursor:pointer;font-weight:600}pre{background:#f7f7f7;padding:8px;white-space:pre-wrap;word-break:break-all;max-height:400px;overflow:auto}
.tag{display:inline-block;padding:0 6px;border-radius:8px;background:#e8eef9;margin-right:4px}.u입력{background:#d9f2d9}.u정답{background:#fde2b3}.u메타{background:#eee}</style>
<h1>BLADE 데이터 사전</h1><p id="verified"></p>
<div class="ctl"><label>파일 필터 <select id="file"><option value="">전체</option></select></label><label>용도 <select id="usage"><option value="">전체</option><option>입력</option><option>정답</option><option>메타</option></select></label><label>검색 <input id="q" placeholder="필드명"></label></div>
<table id="t"><thead><tr><th>필드</th><th>타입</th><th>존재 파일</th><th>결측</th><th>빈값</th><th>고유값</th><th>용도</th><th>근거</th></tr></thead><tbody></tbody></table>
<h2>같은 의미·다른 이름</h2><table id="map"><thead><tr><th>A</th><th>B</th><th>의미</th><th>상태</th></tr></thead><tbody></tbody></table>
<h2>출처별 대표 레코드</h2><div id="reps"></div><h2>모델 입력 예시</h2><div id="ex"></div>
<script>const D=__DATA__;document.getElementById('verified').textContent='data-v1 해시 검증: '+Object.entries(D.verified).map(([k,v])=>k.split('/').pop()+' '+v).join(', ');
const fs=document.getElementById('file');D.files.forEach(f=>{const o=document.createElement('option');o.textContent=f;fs.appendChild(o)});
function esc(s){return String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(){const file=fs.value,usage=document.getElementById('usage').value,q=document.getElementById('q').value.toLowerCase();const tb=document.querySelector('#t tbody');tb.innerHTML='';
D.fields.filter(f=>(!file||f.in_files.split(',').includes(file))&&(!usage||f.usage.startsWith(usage))&&(!q||f.field.toLowerCase().includes(q))).forEach(f=>{const vals=D.values.filter(v=>v[0]===f.field);const pres=D.presence.find(p=>p[0]===f.field);
const detail=`<details><summary>${esc(f.field)}</summary><p><b>파일별 존재:</b> ${D.files.map((n,i)=>n+' '+pres[i+1]).join(' · ')}</p>${f.text_stats?'<p><b>텍스트:</b> '+esc(f.text_stats)+'</p><p><b>예시:</b> '+esc(f.examples)+'</p>':''}${f.list_stats?'<p><b>리스트:</b> '+esc(f.list_stats)+'</p>':''}${vals.length?'<table><tr><th>값</th>'+D.files.map(n=>'<th>'+n+'</th>').join('')+'</tr>'+vals.map(v=>'<tr><td>'+esc(v[1])+'</td>'+v.slice(2).map(c=>'<td>'+c+'</td>').join('')+'</tr>').join('')+'</table>':''}</details>`;
const tr=document.createElement('tr');tr.innerHTML=`<td>${detail}</td><td>${esc(f.type)}</td><td>${f.in_files.split(',').map(x=>'<span class=tag>'+esc(x)+'</span>').join('')}</td><td>${(f.missing_ratio*100).toFixed(0)}%</td><td>${(f.empty_ratio*100).toFixed(0)}%</td><td>${f.unique}</td><td><span class="tag u${esc(f.usage.slice(0,2))}">${esc(f.usage)}</span></td><td>${esc(f.evidence)}</td>`;tb.appendChild(tr)})}
['file','usage','q'].forEach(id=>document.getElementById(id).addEventListener('input',render));render();
document.querySelector('#map tbody').innerHTML=D.mapping.map(m=>'<tr>'+m.map(c=>'<td>'+esc(c)+'</td>').join('')+'</tr>').join('');
document.getElementById('reps').innerHTML=Object.entries(D.reps).map(([k,v])=>`<details><summary>${esc(k)}</summary><pre>${esc(JSON.stringify(v,null,1))}</pre></details>`).join('');
document.getElementById('ex').innerHTML=Object.entries(D.examples).map(([k,v])=>`<details><summary>${esc(k)}</summary><pre>${esc(v)}</pre></details>`).join('');</script></html>'''
    (ROOT / 'reports/data_dictionary.html').write_text(page.replace('__DATA__', js), encoding='utf-8')
    assert_data_v1('end'); print('fields', len(fields), 'categorical', len({r[0] for r in values_rows}), 'written md/html/csv')

if __name__ == '__main__': main()
