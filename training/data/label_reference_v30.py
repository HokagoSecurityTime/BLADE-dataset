"""LLM reference labels (gpt-4o-mini + prompt v3.0.1 + oas_code) for human-truth candidate files. The reference label is written to a NEW file
(<name>_llmref.jsonl) in the `llm_reference_label` field; `label` (human ground truth) stays empty. User approval 2026-10-21:
NetBox held-out subset 185 (<= $0.10) and test_v2_extra 56 (<= $0.03). Never touches test.jsonl / test_v30.jsonl."""
import argparse, asyncio, json
from collections import Counter
import httpx
from training.data import label_v30 as m
from training.lora.prepare_lora_inputs import schema_fields

ROOT = m.ROOT; P = ROOT / 'datasets/blade/processed'
TARGETS = {'netbox': dict(src=P / 'opensource/netbox_v4.7.3_endpoints.jsonl', out=P / 'opensource/netbox_v4.7.3_heldout185_llmref.jsonl', log=ROOT / 'reports/eval/data_v2/netbox_llmref', filt=lambda r: r['meta'].get('heldout_subset_proposed')),
           'test_v2_extra': dict(src=P / 'test_v2_extra_candidates.jsonl', out=P / 'test_v2_extra_candidates_llmref.jsonl', log=ROOT / 'reports/eval/data_v2/test_v2_extra_llmref', filt=lambda r: True)}

def priority(r):
    cs = r.get('controller_signals', {})
    if r['service'] != 'netbox': return None
    if cs.get('nonstandard_path') or cs.get('permission_override'): return 1
    if cs.get('app') == 'users': return 2
    return 3

def payload(r):
    spec = json.loads(r['oas_snippet']); op = spec['paths'][r['path']][r['method'].lower()]; params = op.get('parameters', [])
    state = 'explicitly_anonymous' if op.get('security') == [] and 'security' in spec else 'declared' if ('security' in op or spec.get('security')) else 'unknown'
    desc = (op.get('description') or '').strip(); code = (r.get('controller_text') or '').strip()
    if code: desc = (desc + '\n' if desc else '') + '핸들러 원문(근거). 인가 관련 코드 발췌이며 다른 검사가 더 있을 수 있다.\n' + code
    return dict(method=r['method'], path=r['path'], path_params=[p['name'] for p in params if isinstance(p, dict) and p.get('in') == 'path'], query_params=[p['name'] for p in params if isinstance(p, dict) and p.get('in') == 'query'],
                summary=op.get('summary') or '', description=desc, security=op.get('security', spec.get('security', [])), security_state=state, schema_fields=schema_fields(spec, op),
                schema_provenance='Fields extracted from API response schema; not a verified database ERD', owner_cols=[], tenant_cols=[])

async def run(name, args):
    t = TARGETS[name]; m.configure('v301'); rows = [r for r in m.read(t['src']) if t['filt'](r)]; system = m.PROMPT.read_text(encoding='utf-8'); t['log'].mkdir(parents=True, exist_ok=True)
    if t['out'].exists(): raise SystemExit(f"{t['out']} exists; refusing to overwrite")
    settings = m.settings_from_env(); sem = asyncio.Semaphore(args.concurrency); results = {}
    m.dump(t['log'] / 'manifest.json', dict(target=name, prompt_version=m.VERSION, prompt_sha256=m.digest(m.PROMPT), input_sha256=m.digest(t['src']), records=len(rows), model=settings.model, temperature=0, condition='oas_code', reference_only=True, started_at=m.now()))
    async with httpx.AsyncClient(timeout=180) as client:
        async def one(r):
            async with sem: results[r['id']] = await m.request(payload(r), r['id'], system, settings, client, t['log'])
        await asyncio.gather(*[one(r) for r in rows])
    out = []
    for r in rows:
        res = results[r['id']]; rec = dict(r); rec['label'] = None
        rec['llm_reference_label'] = res.get('label'); rec['llm_reference'] = dict(label=res.get('label'), confidence=res.get('confidence'), rationale=res.get('rationale'), evidence_fields=res.get('evidence_fields'), model_id=res.get('model_id'), prompt_version=m.VERSION, inference_ms=res.get('inference_ms'), meta=res.get('meta'))
        if name == 'netbox': rec['meta'] = {**rec['meta'], 'heldout_priority': priority(r)}
        out.append(rec)
    t['out'].write_text(''.join(json.dumps(x, ensure_ascii=False) + '\n' for x in out), encoding='utf-8')
    usage = m.read(t['log'] / 'usage.jsonl'); inp = sum(u['usage'].get('input_tokens', 0) for u in usage); cached = sum((u['usage'].get('input_tokens_details') or {}).get('cached_tokens', 0) for u in usage); outt = sum(u['usage'].get('output_tokens', 0) for u in usage)
    cost = dict(api_responses=len(usage), input_tokens=inp, cached_input_tokens=cached, output_tokens=outt, estimated_usd=round(((inp - cached) * .15 + cached * .075 + outt * .6) / 1e6, 5), billing_invoice=False)
    rep = dict(records=len(out), label_errors=sum(x['llm_reference_label'] is None for x in out), reference_labels=dict(Counter(x['llm_reference_label'] for x in out)), usage=cost, output_sha256=m.digest(t['out']),
               by_priority={str(p): dict(Counter(x['llm_reference_label'] for x in out if x['meta'].get('heldout_priority') == p)) for p in (1, 2, 3)} if name == 'netbox' else None,
               by_project={s: dict(Counter(x['llm_reference_label'] for x in out if x['service'] == s)) for s in sorted({x['service'] for x in out})})
    m.dump(t['log'] / 'metrics.json', rep); print(name, json.dumps(rep, ensure_ascii=False))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--target', choices=sorted(TARGETS), required=True); ap.add_argument('--execute', action='store_true'); ap.add_argument('--concurrency', type=int, default=4); a = ap.parse_args()
    if not a.execute: raise SystemExit('pass --execute (user approved 2026-10-21)')
    asyncio.run(run(a.target, a))
