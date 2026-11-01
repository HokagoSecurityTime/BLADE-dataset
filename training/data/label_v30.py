"""Prompt v3.0 labeling. Stage q: synthetic train-only check set (no human labels).
Stage full: all 2,027 APIs.guru candidates (new files only). Human corrections unused.
Never reads test.jsonl or test-only synthetic services. No runtime mutations."""
import argparse, asyncio, json, os, re, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import httpx, yaml
from common.labels import Label
from pipeline.classifier import llm
from training.data import label_v3 as base3
from training.data import label_v5 as base5
from training.experiments import application_guard as guard

ROOT=base3.ROOT; HERE=base3.HERE; DATA=base3.DATA
SYN=ROOT/'datasets/blade/raw/synthetic'; PARTITION=HERE/'synthetic_partition.json'
TAGS={'v30':'3.0','v301':'3.0.1'}
def configure(tag):
    """Select the prompt version; every output path carries the tag so versions never overwrite each other."""
    global TAG,PROMPT,VERSION,QOUT,FOUT,FULL_PARTIAL,FULL_FINAL
    TAG=tag; ver=TAGS[tag]
    PROMPT=HERE/f'prompts/policy_label_v{ver}.md'; VERSION=f'policy-label-v{ver}'
    QOUT=ROOT/f'reports/eval/classification_quality/prompt_{tag}_q'; FOUT=ROOT/f'reports/eval/classification_quality/prompt_{tag}_full'
    FULL_PARTIAL=DATA/f'apisguru_{tag}_openai.partial.jsonl'; FULL_FINAL=DATA/f'apisguru_labeled_{tag}.jsonl'
configure('v30')
LABELS=[x.value for x in Label]; CONDITIONS=['oas','oas_code']
PRICE=dict(input=.15,cached_input=.075,output=.6)  # USD per 1M tokens, gpt-4o-mini (same constants as label_v5.costs)
read=base3.read; dump=base3.dump; digest=base3.digest; StopRun=base3.StopRun
def now():return datetime.now(timezone.utc).isoformat()

# ---------- Q set: train-only synthetic services ----------
def q_rows():
    part=json.loads(PARTITION.read_text(encoding='utf8')); services=part['train_services']
    assert not set(services)&set(part['test_services'])
    records={r['id']:r for p in (DATA/'train.jsonl',DATA/'val.jsonl') for r in read(p) if r['meta'].get('source')=='synthetic'}
    rows=[]
    for service in services:
        spec=yaml.safe_load((SYN/service/'intended_labels.yaml').read_text(encoding='utf8'))
        assert spec['service']==service
        for ep in spec['endpoints']:
            rec=records[ep['id']]; assert rec['service']==service and rec['method']==ep['method'] and rec['path']==ep['path']
            sig=rec['controller_signals']; assert sig and sig.get('raw_snippet')
            expected_v30='manual_review_required' if ep['reason'].lower().startswith('a premium plan') else ep['label']
            # vulnerable=true variants authenticate but implement no authorization guard: code evidence alone supports no concrete label.
            expected_v30_code='manual_review_required' if ep['vulnerable'] else expected_v30
            rows.append(dict(id=ep['id'],service=service,method=ep['method'],path=ep['path'],intended_label=ep['label'],intended_reason=ep['reason'],vulnerable=bool(ep['vulnerable']),
                expected_v30=expected_v30,expected_v30_code=expected_v30_code,oas_snippet=rec['oas_snippet'],erd_snippet=rec['erd_snippet'],code=sig['raw_snippet'],source_file=rec['meta']['source_file'],
                meta=dict(source='synthetic',partition='train_services')))
    assert len(rows)==42
    return rows

def erd_cols(erd):
    cols=re.findall(r'\b([A-Za-z_]+)\s+(?:TEXT|INTEGER|BOOLEAN|REAL)',erd)
    owner=[c for c in cols if re.search(r'owner|user_id|author|created_by',c,re.I)]; tenant=[c for c in cols if re.search(r'tenant|org',c,re.I)]
    return cols,owner,tenant

def q_payload(row,condition):
    oas=json.loads(row['oas_snippet']); op=next(iter(next(iter(oas['paths'].values())).values()))
    params=op.get('parameters',[]); cols,owner,tenant=erd_cols(row['erd_snippet'])
    description=''
    if condition=='oas_code':
        description='핸들러 원문(근거). 이 함수가 해당 엔드포인트의 전체 처리 코드이며 다른 인가 검사는 없다.\nFILE '+row['source_file']+'\n'+row['code']
    return dict(method=row['method'],path=row['path'],path_params=[p['name'] for p in params if p.get('in')=='path'],
        query_params=[p['name'] for p in params if p.get('in')=='query'],summary=op.get('summary') or '',description=description,
        security=op.get('security',[]),security_state='unknown',schema_fields=[],
        schema_provenance='Fields extracted from API response schema; not a verified database ERD',owner_cols=owner,tenant_cols=tenant)

# ---------- synthetic handler -> fixture grammar for application_guard (guard itself unchanged) ----------
ATOM_PATTERNS=[(r'plan',"actor['subscription'] == 'premium'"),(r'owner_id',"actor['id'] == resource['owner_id']"),
    (r'tenant_id',"actor['tenant_id'] == resource['tenant_id']"),(r'role',"'admin' in actor['roles']")]
HEAD='def access(actor, resource, memberships):\n    return '
def bridge(code):
    """Deterministic translation of the three synthetic templates only. Returns dict(source, reason).
    source=None means the guard cannot evaluate (fixture grammar has no authentication-only state)."""
    lines=[l.strip() for l in code.splitlines()]
    if not any('principal' in l for l in lines):return dict(source=HEAD+'True\n',reason='anonymous_allow')
    deny=[l for l in lines if re.search(r'\b(403|FORBIDDEN)\b',l)]
    if not deny:return dict(source=None,reason='authenticated_no_authorization_guard')
    if len(deny)!=1:return dict(source=None,reason='multiple_deny_branches')
    cond=deny[0]
    if re.search(r'if\s*\(\s*true\s*\)|if True',cond):return dict(source=HEAD+'False\n',reason='deny_all')
    m=re.search(r'if\s*\((.*)\)\s*(throw|return|raise)|if (.*?):\s*raise',cond)
    if not m:return dict(source=None,reason='unrecognized_guard_syntax')
    expr=(m.group(1) or m.group(3)); terms=[t.strip() for t in re.split(r'&&| and ',expr)]
    atoms=[]
    for t in terms:
        if not re.search(r'!=|!==|^!',t):return dict(source=None,reason='unrecognized_guard_syntax')  # synthetic guards deny on negated equality
        hits=[a for k,a in ATOM_PATTERNS if re.search(k,t)]
        if len(hits)!=1:return dict(source=None,reason='unrecognized_atom')
        atoms.append(hits[0])
    return dict(source=HEAD+' or '.join(atoms)+'\n',reason='translated')

# ---------- transport ----------
async def request(payload,ident,system,settings,client,out):
    user='Return JSON.\n'+json.dumps(payload,ensure_ascii=False); corrected=False; error='unknown'; usage=[]; started=time.perf_counter()
    for attempt in range(5):
        try:
            url,headers,body=llm._request(settings,system,user,base3.Output.model_json_schema());body['temperature']=0
            response=await client.post(url,headers=headers,json=body)
            fatal=base3.quota_error(response)
            if fatal:raise StopRun(fatal)
            if response.status_code in {401,403}:raise StopRun('authentication_or_permission_error')
            response.raise_for_status();data=response.json()
            base5.append(out/'raw_responses.jsonl',dict(id=ident,at=now(),response=data))
            entry=dict(id=ident,at=now(),response_id=data.get('id'),model=data.get('model'),usage=data.get('usage',{}))
            base5.append(out/'usage.jsonl',entry);usage.append(entry['usage'])
            output=base3.Output.model_validate_json(llm._text('openai',data))
            bad=base5.invalid_evidence(output.evidence_fields,payload)
            if bad and not corrected:
                corrected=True;user+='\nYour previous evidence_fields contained invalid references: '+json.dumps(bad)+'. Return corrected JSON with only real input references.';continue
            result=output.model_dump(mode='json')
            return dict(id=ident,**result,security_state=payload['security_state'],provider='openai',model_id=settings.model,model_id_returned=data.get('model'),
                prompt_version=VERSION,labeled_at=now(),inference_ms=round((time.perf_counter()-started)*1000,1),usage_attempts=usage,
                meta=dict(label_error=False,evidence_invalid=bool(bad),invalid_evidence_fields=bad,evidence_correction_requested=corrected,
                          flag_review=payload['method'].upper() in {'PUT','POST','PATCH','DELETE'} and result['label']=='public' and payload['security_state']!='explicitly_anonymous',
                          low_conf=result['confidence']<.6,label_source='model_api'))
        except httpx.HTTPStatusError as exc:
            error='HTTP_'+str(exc.response.status_code)
            if exc.response.status_code!=429 and exc.response.status_code<500:break
        except (ValueError,httpx.TransportError,llm.LLMError) as exc:error=type(exc).__name__
        if attempt<3:await asyncio.sleep(2**attempt)
        else:break
    return dict(id=ident,label=None,confidence=None,rationale=None,evidence_fields=[],security_state=payload['security_state'],inference_ms=round((time.perf_counter()-started)*1000,1),usage_attempts=usage,meta=dict(label_error=True,label_error_reason=error))

def settings_from_env():
    from training.data.label import read_env
    read_env(ROOT/'.env'); provider=os.getenv('BLADE_LABEL_PROVIDER','openai'); model=os.getenv('BLADE_LABEL_MODEL','gpt-4o-mini')
    if provider!='openai' or model not in {'gpt-4o-mini','gpt-4o-mini-2024-07-18'}:raise StopRun('requires_openai_gpt4omini')
    key=os.getenv('OPENAI_API_KEY','').strip()
    if not key:raise StopRun('missing_openai_api_key')
    return llm.Settings(provider,model,key)

def tokens(text):
    import tiktoken; return len(tiktoken.get_encoding('o200k_base').encode(text))

# ---------- metrics ----------
def prf(rows,truth_key,pred_key):
    out={}
    for label in LABELS:
        tp=sum(r[truth_key]==label and r[pred_key]==label for r in rows); fp=sum(r[truth_key]!=label and r[pred_key]==label for r in rows); fn=sum(r[truth_key]==label and r[pred_key]!=label for r in rows)
        p=tp/(tp+fp) if tp+fp else 0.; rc=tp/(tp+fn) if tp+fn else 0.; f=2*p*rc/(p+rc) if p+rc else 0.
        out[label]=dict(support=sum(r[truth_key]==label for r in rows),precision=round(p,4),recall=round(rc,4),f1=round(f,4))
    supported=[l for l in LABELS if out[l]['support']]
    return dict(per_label=out,macro_f1_supported=round(sum(out[l]['f1'] for l in supported)/len(supported),4) if supported else None,supported_labels=supported,
        confusion={a:{b:sum(r[truth_key]==a and r[pred_key]==b for r in rows) for b in LABELS+['output_error']} for a in LABELS})

# ---------- Q stage ----------
async def q_stage(args):
    QOUT.mkdir(parents=True,exist_ok=True); rows=q_rows(); system=PROMPT.read_text(encoding='utf8')
    inputs=[dict(id=r['id'],service=r['service'],method=r['method'],path=r['path'],intended_label=r['intended_label'],intended_reason=r['intended_reason'],vulnerable=r['vulnerable'],
                 expected_v30=r['expected_v30'],expected_v30_code=r['expected_v30_code'],inputs={c:q_payload(r,c) for c in CONDITIONS},bridge=bridge(r['code'])) for r in rows]
    inputs_path=QOUT/'inputs.jsonl'
    if not inputs_path.exists():inputs_path.write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in inputs),encoding='utf8')
    elif read(inputs_path)!=inputs:raise StopRun('q_inputs_changed_since_freeze')
    sys_tokens=tokens(system); per=[(x['id'],c,tokens('Return JSON.\n'+json.dumps(x['inputs'][c],ensure_ascii=False))) for x in inputs for c in CONDITIONS]
    calls=len(per); inp=sum(sys_tokens+t for _,_,t in per); out_est=calls*130
    estimate=dict(calls=calls,records=len(rows),conditions=CONDITIONS,system_prompt_tokens=sys_tokens,input_tokens_total=inp,output_tokens_assumed=out_est,
        usd_no_cache=round((inp*PRICE['input']+out_est*PRICE['output'])/1e6,4),
        usd_if_system_prefix_cached=round(((inp-(calls-1)*sys_tokens)*PRICE['input']+(calls-1)*sys_tokens*PRICE['cached_input']+out_est*PRICE['output'])/1e6,4),
        evidence_correction_retries='up to +1 call per record when evidence_fields invalid',pricing_usd_per_million=PRICE,prompt_sha256=digest(PROMPT),inputs_sha256=digest(inputs_path))
    dump(QOUT/'estimate.json',estimate); print(json.dumps(estimate,ensure_ascii=False,indent=1))
    if not args.execute:return
    settings=settings_from_env()
    manifest=dict(stage='q',prompt_version=VERSION,prompt_sha256=digest(PROMPT),inputs_sha256=digest(inputs_path),implementation_sha256=digest(Path(__file__)),
        guard_sha256=digest(Path(guard.__file__)),model=settings.model,temperature=0,seed=42,conditions=CONDITIONS,human_corrections_used=False,test_files_read=False,started_at=now())
    dump(QOUT/'manifest.json',manifest)
    sem=asyncio.Semaphore(args.concurrency)
    async with httpx.AsyncClient(timeout=180) as client:
        async def one(x,c):
            async with sem:
                r=await request(x['inputs'][c],x['id'],system,settings,client,QOUT); r['condition']=c; return r
        results=await asyncio.gather(*[one(x,c) for x in inputs for c in CONDITIONS])
    byid={x['id']:x for x in inputs}; decisions=[]
    for r in results:
        x=byid[r['id']]; g=None
        if r['condition']=='oas_code':
            src=x['bridge']['source']
            g=guard.verify(r,src or 'unsupported',complete_context=src is not None,fixture_bindings=src is not None); g['bridge_reason']=x['bridge']['reason']
        decisions.append(dict(**r,intended_label=x['intended_label'],expected_v30=x['expected_v30'],expected_v30_code=x['expected_v30_code'],vulnerable=x['vulnerable'],guard=g))
    for c in CONDITIONS:
        (QOUT/f'predictions_{c}.jsonl').write_text(''.join(json.dumps(d,ensure_ascii=False)+'\n' for d in decisions if d['condition']==c),encoding='utf8')
    metrics={}
    for c in CONDITIONS:
        ds=[d for d in decisions if d['condition']==c]
        for d in ds:d['pred']=d['label'] or 'output_error'
        m=dict(records=len(ds),label_errors=sum(d['label'] is None for d in ds),manual_ratio=round(sum(d['pred']=='manual_review_required' for d in ds)/len(ds),4),
            mean_inference_ms=round(sum(d['inference_ms'] for d in ds)/len(ds),1),
            agreement_intended=round(sum(d['pred']==d['intended_label'] for d in ds)/len(ds),4),agreement_expected_v30=round(sum(d['pred']==d['expected_v30'] for d in ds)/len(ds),4),
            agreement_expected_v30_code=round(sum(d['pred']==d['expected_v30_code'] for d in ds)/len(ds),4),
            agreement_expected_v30_by_vulnerable={str(v):round(sum(d['pred']==d['expected_v30'] for d in ds if d['vulnerable']==v)/max(1,sum(d['vulnerable']==v for d in ds)),4) for v in (False,True)},
            vs_intended=prf(ds,'intended_label','pred'),vs_expected_v30=prf(ds,'expected_v30','pred'),vs_expected_v30_code=prf(ds,'expected_v30_code','pred'),evidence_invalid=sum(bool(d['meta'].get('evidence_invalid')) for d in ds),
            confidence_bins={k:sum(d['confidence'] is not None and base5.bin_index(d['confidence'])==i for d in ds) for i,k in enumerate(base5.BINS)})
        if c=='oas_code':
            reasons=Counter(d['guard']['reason'] for d in ds); bridge_reasons=Counter(d['guard']['bridge_reason'] for d in ds)
            correct=[d for d in ds if d['pred']==d['expected_v30_code'] and d['pred'] in guard.PATTERNS]
            m['guard']=dict(reasons=dict(reasons),bridge_reasons=dict(bridge_reasons),unsupported_bridge=sum(byid[d['id']]['bridge']['source'] is None for d in ds),
                correct_concrete=len(correct),correct_concrete_blocked=sum(not d['guard']['semantic_candidate_pass'] for d in correct),
                wrong_concrete_passed=sum(d['guard']['semantic_candidate_pass'] and d['pred']!=d['expected_v30_code'] for d in ds),
                note='guard v1 fixes role_required to the operator atom; synthetic audit endpoints require admin, so correct role_required labels are expected to be flagged (v1 limitation, not a model error)')
        metrics[c]=m
    usage=read(QOUT/'usage.jsonl'); inp=sum(u['usage'].get('input_tokens',0) for u in usage); cached=sum((u['usage'].get('input_tokens_details') or {}).get('cached_tokens',0) for u in usage); outt=sum(u['usage'].get('output_tokens',0) for u in usage)
    metrics['usage']=dict(api_responses=len(usage),input_tokens=inp,cached_input_tokens=cached,output_tokens=outt,estimated_usd=round(((inp-cached)*PRICE['input']+cached*PRICE['cached_input']+outt*PRICE['output'])/1e6,5),billing_invoice=False)
    metrics['gate']=dict(threshold=.6,basis='agreement_expected_v30 on oas_code (intended label; subscription->manual per v3.0). agreement_intended (raw yaml) and agreement_expected_v30_code (implementation-based) reported alongside for the user decision',
        passed=metrics['oas_code']['agreement_expected_v30']>=.6)
    dump(QOUT/'metrics.json',metrics); manifest.update(completed_at=now(),prompt_sha256_after=digest(PROMPT)); dump(QOUT/'manifest.json',manifest)
    print(json.dumps({k:v for k,v in metrics.items() if k in ('usage','gate')},ensure_ascii=False))
    for c in CONDITIONS:print(c,'intended',metrics[c]['agreement_intended'],'expected_v30',metrics[c]['agreement_expected_v30'],'manual',metrics[c]['manual_ratio'])

# ---------- Full stage: all 2,027 APIs.guru candidates, new files only ----------
INPUT=DATA/'apisguru_enriched_v2.jsonl'; V5=DATA/'apisguru_labeled_v5_openai.jsonl'

def slim(row):
    e=row.get('enrichment',{})
    return {**{k:v for k,v in row.items() if k!='enrichment'},'enrichment':{k:e.get(k) for k in ('status','source_file','source_sha256','spec_version')}}

async def full_stage(args):
    FOUT.mkdir(parents=True,exist_ok=True); rows=read(INPUT); ids=[r['id'] for r in rows]
    if len(rows)!=2027 or len(set(ids))!=2027:raise StopRun('input_id_mismatch')
    system=PROMPT.read_text(encoding='utf8'); payloads={r['id']:base5.payload(r) for r in rows}  # preflight; raw specs read only
    sys_tokens=tokens(system); per={i:tokens('Return JSON.\n'+json.dumps(p,ensure_ascii=False)) for i,p in payloads.items()}
    inp=sum(sys_tokens+t for t in per.values()); calls=len(rows); out_est=calls*130
    estimate=dict(calls=calls,system_prompt_tokens=sys_tokens,input_tokens_total=inp,input_tokens_mean_payload=round(sum(per.values())/calls,1),output_tokens_assumed=out_est,
        usd_no_cache=round((inp*PRICE['input']+out_est*PRICE['output'])/1e6,4),
        usd_if_system_prefix_cached=round(((inp-(calls-1)*sys_tokens)*PRICE['input']+(calls-1)*sys_tokens*PRICE['cached_input']+out_est*PRICE['output'])/1e6,4),
        evidence_correction_retries='up to +1 call per record when evidence_fields invalid',pricing_usd_per_million=PRICE,prompt_sha256=digest(PROMPT),input_sha256=digest(INPUT))
    dump(FOUT/'estimate.json',estimate); print(json.dumps(estimate,ensure_ascii=False,indent=1))
    if not args.execute:return
    settings=settings_from_env()
    manifest=dict(stage='full',prompt_version=VERSION,prompt_sha256=digest(PROMPT),input_sha256=digest(INPUT),v5_sha256=digest(V5),model=settings.model,temperature=0,seed=42,
        human_corrections_used=False,test_files_read=False,ids=ids)
    stamp=FULL_PARTIAL.with_suffix('.manifest.json')
    if stamp.exists():
        if json.loads(stamp.read_text(encoding='utf8'))!=manifest:raise StopRun('checkpoint_manifest_mismatch')
    elif FULL_PARTIAL.exists():raise StopRun('checkpoint_missing_manifest')
    else:dump(stamp,manifest)
    done={r['id']:r for r in read(FULL_PARTIAL)}
    if not set(done)<=set(ids):raise StopRun('invalid_checkpoint_ids')
    todo=[r for r in rows if r['id'] not in done]; sem=asyncio.Semaphore(args.concurrency); lock=asyncio.Lock(); counter=[0]
    async with httpx.AsyncClient(timeout=180) as client:
        async def one(row):
            async with sem:res=await request(payloads[row['id']],row['id'],system,settings,client,FOUT)
            meta=res.pop('meta'); original=res.get('label')
            record={**slim(row),**res,'lookup_status':'unresolved' if res.get('label') in {'owner_match','owner_or_admin','tenant_match'} else 'not_applicable',
                'training_target_fields':['label','rationale'],'meta':{**row['meta'],**meta,'api_original_label':original,'confidence_label_overridden':False}}
            async with lock:
                base5.append(FULL_PARTIAL,record);done[row['id']]=record;counter[0]+=1
                if counter[0]%100==0:print(json.dumps(dict(state='running',completed=len(done),target=len(rows),at=now())),flush=True)
        await asyncio.gather(*[one(r) for r in todo])
    final=[done[i] for i in ids]
    if any(r['meta'].get('label_error') for r in final):raise StopRun('full_label_errors_require_review')
    FULL_FINAL.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in final),encoding='utf8')
    old={r['id']:r for r in read(V5)}; summary=base5.summary(final,old)
    usage=read(FOUT/'usage.jsonl'); inp=sum(u['usage'].get('input_tokens',0) for u in usage); cached=sum((u['usage'].get('input_tokens_details') or {}).get('cached_tokens',0) for u in usage); outt=sum(u['usage'].get('output_tokens',0) for u in usage)
    cost=dict(api_responses=len(usage),input_tokens=inp,cached_input_tokens=cached,output_tokens=outt,estimated_usd=round(((inp-cached)*PRICE['input']+cached*PRICE['cached_input']+outt*PRICE['output'])/1e6,5),billing_invoice=False)
    states=sorted({r['security_state'] for r in final})
    by_security={s:{l:sum(r['security_state']==s and r['label']==l for r in final) for l in LABELS} for s in states}
    public_declared=[r['id'] for r in final if r['label']=='public' and r['security_state']=='declared']
    manual_ratio=summary['labels']['manual_review_required']/len(final)
    report={**summary,'usage':cost,'mean_inference_ms':round(sum(r['inference_ms'] for r in final)/len(final),1),'manual_ratio':round(manual_ratio,4),
        'by_security_state':by_security,'public_with_security_declared':len(public_declared),'public_with_security_declared_ids':public_declared,
        'train_build_blocked_manual_ratio_above_70_percent':manual_ratio>.7,'prompt_version':VERSION,'prompt_sha256':manifest['prompt_sha256']}
    dump(HERE/f'label_report_{TAG}.json',report)
    lines=[f'# label_report_{TAG} (prompt {VERSION}, full 2,027)','','```json',json.dumps({k:v for k,v in report.items() if k not in ('transitions','public_with_security_declared_ids')},ensure_ascii=False,indent=2),'```','',f'| v2.5 \\ {VERSION} | '+' | '.join(LABELS)+' |','|---|'+'---:|'*7]
    for label in LABELS:lines.append('| '+label+' | '+' | '.join(str(report['transitions'][label][b]) for b in LABELS)+' |')
    (HERE/f'label_report_{TAG}.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    dump(DATA/f'labeled_{TAG}.manifest.json',{**{k:v for k,v in manifest.items() if k!='ids'},'implementation_sha256':digest(Path(__file__)),'records':len(final),'output_sha256':digest(FULL_FINAL),'completed_at':now(),'usage':cost,'returned_models':sorted({r['model_id_returned'] for r in final})})
    print(json.dumps(dict(state='complete',records=len(final),labels=summary['labels'],manual_ratio=round(manual_ratio,4),public_with_security_declared=len(public_declared),usage=cost),ensure_ascii=False))

def main():
    p=argparse.ArgumentParser();p.add_argument('--stage',choices=['q','full'],required=True);p.add_argument('--tag',choices=sorted(TAGS),default='v30');p.add_argument('--execute',action='store_true');p.add_argument('--concurrency',type=int,default=4);a=p.parse_args()
    configure(a.tag)
    try:asyncio.run(q_stage(a) if a.stage=='q' else full_stage(a))
    except StopRun as exc:print(json.dumps(dict(stopped=str(exc))));raise SystemExit(3)
if __name__=='__main__':main()
