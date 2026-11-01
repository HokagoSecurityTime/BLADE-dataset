"""Label the Gitea v28.2.0 extracted endpoints with gpt-4o-mini + prompt v3.0.1 (oas_code). User approval 2026-10-21 (<= $0.25).
Adds meta.public_candidate / meta.visibility_dependent flags independently of the model label. Prompt unchanged. No runtime mutations."""
import argparse, asyncio, json, re
from collections import Counter
from pathlib import Path
import httpx
from training.data import label_v30 as m
from training.lora.prepare_lora_inputs import schema_fields

ROOT = m.ROOT; SRC = ROOT / 'datasets/blade/processed/opensource/gitea_v28.2.0_endpoints.jsonl'
OUT = ROOT / 'datasets/blade/processed/opensource/gitea_v28.2.0_labeled_v301.jsonl'; LOG = ROOT / 'reports/eval/data_v2/gitea_label'
VIS = re.compile(r'reqAnyRepoReader|reqRepoReader|reqOrgVisible|HasOrgOrUserVisible|IsPrivate|Visibility|HasAnyUnitAccess|\.CanRead\(|IsUserRepoReader')
AUTH_MW = ('reqToken', 'reqBasicOrRevProxyAuth', 'reqExploreSignIn')

def flags(r):
    cs = r['controller_signals']; chain = [m.re.sub(r'\(.*$', '', x) for x in cs['middleware']]
    authn = any(c in AUTH_MW for c in chain); authz = bool(cs['route_authorization']); inner = cs['authz_lines_in_handler'] > 0
    public_candidate = not authn and not authz and not inner
    visibility_dependent = (not authn) and (bool(VIS.search(r['controller_text'])) or 'repoAssignment' in chain or 'orgAssignment' in chain)
    return public_candidate, visibility_dependent

def payload(r):
    spec = json.loads(r['oas_snippet']); op = spec['paths'][r['path']][r['method'].lower()]; params = op.get('parameters', [])
    state = 'explicitly_anonymous' if op.get('security') == [] and 'security' in spec else 'declared' if ('security' in op or spec.get('security')) else 'unknown'
    desc = (op.get('description') or '').strip()
    desc = (desc + '\n' if desc else '') + '핸들러 원문(근거). 라우트 미들웨어 체인 정의와 핸들러 발췌(routers/api/v1). 요약된 미들웨어는 주석으로 표시.\n' + r['controller_text']
    return dict(method=r['method'], path=r['path'], path_params=[p['name'] for p in params if p.get('in') == 'path'], query_params=[p['name'] for p in params if p.get('in') == 'query'],
                summary=op.get('summary') or '', description=desc, security=op.get('security', spec.get('security', [])), security_state=state, schema_fields=schema_fields(spec, op),
                schema_provenance='Fields extracted from API response schema; not a verified database ERD', owner_cols=[], tenant_cols=[])

async def run(args):
    m.configure('v301'); rows = m.read(SRC); system = m.PROMPT.read_text(encoding='utf-8'); LOG.mkdir(parents=True, exist_ok=True)
    done = {r['id']: r for r in m.read(OUT)} if OUT.exists() else {}
    settings = m.settings_from_env(); sem = asyncio.Semaphore(args.concurrency); lock = asyncio.Lock()
    manifest = dict(prompt_version=m.VERSION, prompt_sha256=m.digest(m.PROMPT), input_sha256=m.digest(SRC), model=settings.model, temperature=0, condition='oas_code', records=len(rows), started_at=m.now())
    m.dump(LOG / 'manifest.json', manifest)
    async with httpx.AsyncClient(timeout=180) as client:
        async def one(r):
            if r['id'] in done: return
            async with sem: res = await m.request(payload(r), r['id'], system, settings, client, LOG)
            pc, vd = flags(r); meta = res.pop('meta')
            rec = {**r, **res, 'label_reference_only': False, 'meta': {**r['meta'], **meta, 'public_candidate': pc, 'visibility_dependent': vd, 'api_original_label': res.get('label')}}
            async with lock: m.base5.append(OUT, rec); done[r['id']] = rec
        await asyncio.gather(*[one(r) for r in rows])
    final = [done[r['id']] for r in rows]
    OUT.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in final), encoding='utf-8')
    usage = m.read(LOG / 'usage.jsonl'); inp = sum(u['usage'].get('input_tokens', 0) for u in usage); cached = sum((u['usage'].get('input_tokens_details') or {}).get('cached_tokens', 0) for u in usage); outt = sum(u['usage'].get('output_tokens', 0) for u in usage)
    cost = dict(api_responses=len(usage), input_tokens=inp, cached_input_tokens=cached, output_tokens=outt, estimated_usd=round(((inp - cached) * .15 + cached * .075 + outt * .6) / 1e6, 5), billing_invoice=False)
    L = m.LABELS; lab = lambda rs: {l: sum(x['label'] == l for x in rs) for l in L}
    pc = [r for r in final if r['meta']['public_candidate']]; vd = [r for r in final if r['meta']['visibility_dependent']]
    rep = dict(records=len(final), label_errors=sum(r['label'] is None for r in final), labels=lab(final), manual_ratio=round(sum(r['label'] == 'manual_review_required' for r in final) / len(final), 4),
               public_candidate=dict(count=len(pc), labels=lab(pc)), visibility_dependent=dict(count=len(vd), labels=lab(vd)), by_package={}, usage=cost, output_sha256=m.digest(OUT),
               confidence_bins={k: sum(r['confidence'] is not None and m.base5.bin_index(r['confidence']) == i for r in final) for i, k in enumerate(m.base5.BINS)}, mean_inference_ms=round(sum(r['inference_ms'] for r in final) / len(final), 1))
    for r in final:
        p = (r['controller_signals']['handler'] or '?').split('.')[0]; rep['by_package'].setdefault(p, Counter())[r['label']] += 1
    rep['by_package'] = {k: dict(v) for k, v in rep['by_package'].items()}
    m.dump(LOG / 'metrics.json', rep); manifest.update(completed_at=m.now(), output_sha256=rep['output_sha256'], usage=cost); m.dump(LOG / 'manifest.json', manifest)
    # report.md
    t = f"# Gitea v28.2.0 라벨링 결과 — gpt-4o-mini + 프롬프트 v3.0.1 + oas_code, {len(final)}건\n\n프롬프트 SHA `{manifest['prompt_sha256']}`, 입력 SHA `{manifest['input_sha256']}`, 출력 `{OUT.name}` SHA `{rep['output_sha256']}`. 응답 {cost['api_responses']}회, 입력 {inp:,}(캐시 {cached:,})·출력 {outt:,}토큰, 추정 ${cost['estimated_usd']}(청구서 아님). 평균 {rep['mean_inference_ms']} ms, 출력 오류 {rep['label_errors']}.\n\n"
    t += '라벨은 LLM 제안이며 사람 확정 전이다(data-v2 train 후보). 모든 레코드가 OAS 전역 security 때문에 security_state=declared다.\n\n## label 분포\n\n| label | 건수 | 비율 |\n|---|---:|---:|\n' + ''.join(f'| {l} | {c} | {c/len(final):.1%} |\n' for l, c in rep['labels'].items())
    t += f"\n## public_candidate (미들웨어·핸들러 모두에 인증·인가 없음) {len(pc)}건의 모델 label\n\n| label | 건수 |\n|---|---:|\n" + ''.join(f'| {l} | {c} |\n' for l, c in rep['public_candidate']['labels'].items() if c)
    t += f"\n## visibility_dependent (저장소·조직 공개 여부에 따라 접근이 달라짐, 인증 미들웨어 없음) {len(vd)}건의 모델 label\n\n원칙: 조건부 접근이므로 사람 검수 기준은 manual_review_required.\n\n| label | 건수 |\n|---|---:|\n" + ''.join(f'| {l} | {c} |\n' for l, c in rep['visibility_dependent']['labels'].items() if c)
    t += '\n## 패키지별 label\n\n| 패키지 | ' + ' | '.join(L) + ' |\n|---|' + '---:|' * len(L) + '\n' + ''.join('| ' + p + ' | ' + ' | '.join(str(v.get(l, 0)) for l in L) + ' |\n' for p, v in sorted(rep['by_package'].items()))
    t += f"\nconfidence 구간: {rep['confidence_bins']}\n\n원자료: {OUT.name}, gitea_label/{{usage.jsonl,metrics.json,manifest.json}}; raw_responses.jsonl은 git 미추적.\n"
    (LOG / 'report.md').write_text(t, encoding='utf-8')
    # review sample
    import random; rng = random.Random(42); chosen = []; seen = set()
    for l in L:
        pool = sorted([r for r in final if r['label'] == l and not r['meta']['public_candidate'] and not r['meta']['visibility_dependent']], key=lambda r: r['id'])
        for r in (rng.sample(pool, 10) if len(pool) > 10 else pool): chosen.append((l + ' 10', r)); seen.add(r['id'])
    for r in sorted(pc, key=lambda r: r['id']):
        if r['id'] not in seen: chosen.append(('public_candidate 전수', r)); seen.add(r['id'])
    vpool = sorted([r for r in vd if r['id'] not in seen], key=lambda r: r['id'])
    for r in (rng.sample(vpool, 10) if len(vpool) > 10 else vpool): chosen.append(('visibility_dependent 10', r)); seen.add(r['id'])
    cell = lambda x: str(x).replace('|', '&#124;').replace('\r', '').replace('\n', '<br>')
    defs = system.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
    lines = ['# review_sample_gitea — Gitea v28.2.0 사람 검수용 표본', '', '기준: **visibility_dependent(저장소·조직 공개 여부에 따라 접근이 달라지는 엔드포인트)는 조건부 접근이므로 원칙적으로 manual_review_required.** public_candidate는 발췌에 인증·인가가 전혀 없는 건이며 라벨과 별개 표시다. 라벨 열은 LLM 제안, 검수 열은 비움. 프롬프트 v3.0.1 정의는 아래.', '', '## v3.0.1 라벨 정의(발췌)', '', defs, '', '## 표본', '',
             '| 그룹 | id | 미들웨어 체인 | 핸들러 | public_candidate | visibility_dependent | LLM label | confidence | rationale | 검수 | 검수 사유 |', '|---|---|---|---|---|---|---|---:|---|---|---|']
    for g, r in chosen:
        cs = r['controller_signals']
        lines.append('| ' + ' | '.join(cell(x) for x in [g, r['id'], ', '.join(cs['middleware']) or '(none)', cs['handler'], r['meta']['public_candidate'], r['meta']['visibility_dependent'], r['label'], r['confidence'], r['rationale']]) + ' | | |')
    (ROOT / 'training/data/review_sample_gitea.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in rep.items() if k in ('records', 'labels', 'manual_ratio', 'public_candidate', 'visibility_dependent', 'usage')}, ensure_ascii=False))
    print('review sample', dict(Counter(g for g, _ in chosen)))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--execute', action='store_true'); ap.add_argument('--concurrency', type=int, default=4); a = ap.parse_args()
    if not a.execute: raise SystemExit('pass --execute (user approved 2026-10-21, <= $0.25)')
    asyncio.run(run(a))
