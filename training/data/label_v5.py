"""API-only v2.5 labeling with a gated stratified pilot. No runtime mutations."""
import argparse, asyncio, hashlib, json, os, random, re
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
import httpx, yaml
from common.labels import Label
from pipeline.classifier import llm
from training.data import label_v3 as previous
from training.data.enrich_candidates import SOURCE, OpenAPILoader
ROOT=previous.ROOT; HERE=previous.HERE; DATA=previous.DATA
PROMPT=HERE/'prompts/policy_label_v2.5.md'
INPUT=DATA/'apisguru_enriched_v2.jsonl'; OLD=DATA/'apisguru_labeled_v3_openai.jsonl'
VERSION='policy-label-v2.5'
LABELS=[x.value for x in Label]
read=previous.read; dump=previous.dump; digest=previous.digest
StopRun=previous.StopRun
BINS=['[0,0.5]','(0.5,0.7)','[0.7,0.9)','[0.9,1]']

def now():return datetime.now(timezone.utc).isoformat()
def status(state,**extra):
    value=dict(version=VERSION,state=state,updated_at=now(),**extra)
    (HERE/'LABELING_STATUS_V5.md').write_text('# v2.5 status\n\n```json\n'+json.dumps(value,indent=2,ensure_ascii=False)+'\n```\n',encoding='utf8')
    print(json.dumps(value,ensure_ascii=False),flush=True)

@lru_cache(maxsize=400)
def source(relative):
    path=(SOURCE/relative).resolve()
    if not path.is_relative_to(SOURCE.resolve()):raise ValueError('invalid source path')
    return yaml.load(path.read_text(encoding='utf8'),Loader=OpenAPILoader)

def security_state(spec,operation):
    if operation.get('security')==[] and 'security' in spec:return 'explicitly_anonymous'
    if 'security' in operation or 'security' in spec:return 'declared'
    return 'unknown'

def payload(row):
    value=previous.payload(row)
    spec=source(row['enrichment']['source_file'])
    operation=spec['paths'][row['path']][row['method'].lower()]
    value['security_state']=security_state(spec,operation)
    value['schema_provenance']='Fields extracted from API response schema; not a verified database ERD'
    return value

def invalid_evidence(refs,value):
    invalid=[]
    for ref in refs:
        if ref in previous.FIELDS|{'security_state'}:continue
        prefix,sep,name=ref.partition(':')
        pool=[]
        if prefix=='path_segment':pool=[x for x in value['path'].split('/') if x]
        elif prefix in {'schema_fields','owner_cols','tenant_cols'}:pool=value[prefix]
        elif prefix in {'path_params','query_params'}:pool=[x.get('name') if isinstance(x,dict) else x for x in value[prefix]]
        if not sep or not name or name not in pool:invalid.append(ref)
    return invalid

def bin_index(conf):return 0 if conf<=.5 else 1 if conf<.7 else 2 if conf<.9 else 3

def summary(rows,old):
    good=[r for r in rows if not r['meta'].get('label_error')]
    counts=Counter(r['label'] for r in good); bins=Counter(bin_index(r['confidence']) for r in good)
    n=len(rows); transitions={a:{b:0 for b in LABELS} for a in LABELS}
    for r in good:transitions[old[r['id']]['label']][r['label']]+=1
    invalid=sum(bool(r['meta'].get('evidence_invalid')) for r in good)
    mutations=sum(r['method'].upper() in {'PUT','POST','PATCH','DELETE'} and r['label']=='public' and r.get('security_state')!='explicitly_anonymous' for r in good)
    reasons=[]
    if len(good)!=n:reasons.append('label_errors')
    if invalid/n>.1:reasons.append('evidence_invalid_above_10_percent')
    if max(bins.values(),default=0)/n>=.7:reasons.append('confidence_bin_at_least_70_percent')
    return dict(records=n,labels={k:counts[k] for k in LABELS},confidence={k:bins[i] for i,k in enumerate(BINS)},evidence_invalid=invalid,mutation_public=mutations,flag_review=mutations,label_errors=n-len(good),transitions=transitions,stop_reasons=reasons)

def review_flag(row):
    return row['method'].upper() in {'PUT','POST','PATCH','DELETE'} and row.get('label')=='public' and row.get('security_state')!='explicitly_anonymous'

def select(old):
    rng=random.Random(42); ids=[]
    for label in LABELS:
        group=[r['id'] for r in old if r['label']==label]
        ids.extend(rng.sample(group,20 if label=='membership_required' else 30))
    return ids

def append(path,record):
    with path.open('a',encoding='utf8',newline='\n') as stream:
        stream.write(json.dumps(record,ensure_ascii=False)+'\n');stream.flush();os.fsync(stream.fileno())

async def request(row,system,settings,client,ledger):
    value=payload(row); user='Return JSON.\n'+json.dumps(value,ensure_ascii=False)
    corrected=False; error='unknown'; usage=[]
    for attempt in range(5):
        try:
            url,headers,body=llm._request(settings,system,user,previous.Output.model_json_schema());body['temperature']=0
            response=await client.post(url,headers=headers,json=body)
            fatal=previous.quota_error(response)
            if fatal:raise StopRun(fatal)
            if response.status_code in {401,403}:raise StopRun('authentication_or_permission_error')
            response.raise_for_status();data=response.json()
            entry=dict(id=row['id'],at=now(),response_id=data.get('id'),model=data.get('model'),usage=data.get('usage',{}))
            append(ledger,entry);usage.append(entry['usage'])
            output=previous.Output.model_validate_json(llm._text('openai',data))
            bad=invalid_evidence(output.evidence_fields,value)
            if bad and not corrected:
                corrected=True;user+='\nYour previous evidence_fields contained invalid references: '+json.dumps(bad)+'. Return corrected JSON with only real input references.'
                continue
            result=output.model_dump(mode='json'); original=result['label']
            return {**row,**result,'security_state':value['security_state'],'provider':'openai','model_id':settings.model,'model_id_returned':data.get('model'),
                'prompt_version':VERSION,'labeled_at':now(),'lookup_status':'unresolved' if result['label'] in {'owner_match','owner_or_admin','tenant_match'} else 'not_applicable',
                'training_target_fields':['label','rationale'],'usage_attempts':usage,
                'meta':{**row['meta'],'flag_review':review_flag({**row,**result,'security_state':value['security_state']}),'label_source':'model_api','label_error':False,'low_conf':result['confidence']<.6,'evidence_invalid':bool(bad),'invalid_evidence_fields':bad,'evidence_correction_requested':corrected,'confidence_label_overridden':original!=result['label'],'api_original_label':original}}
        except httpx.HTTPStatusError as exc:
            error='HTTP_'+str(exc.response.status_code)
            if exc.response.status_code!=429 and exc.response.status_code<500:break
        except (ValueError,httpx.TransportError,llm.LLMError) as exc:error=type(exc).__name__
        if attempt<3:await asyncio.sleep(2**attempt)
        else:break
    return {**row,'label':None,'confidence':None,'rationale':None,'evidence_fields':[],'security_state':value['security_state'],'meta':{**row['meta'],'label_error':True,'label_error_reason':error},'usage_attempts':usage}

async def run(rows,system,settings,path,manifest,concurrency):
    stamp=path.with_suffix('.manifest.json');lock=path.with_suffix('.lock')
    fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY);os.close(fd)
    try:
        if stamp.exists():
            if json.loads(stamp.read_text(encoding='utf8'))!=manifest:raise StopRun('checkpoint_manifest_mismatch')
        elif path.exists():raise StopRun('checkpoint_missing_manifest')
        else:dump(stamp,manifest)
        existing=read(path);done={r['id']:r for r in existing};wanted={r['id'] for r in rows}
        if len(done)!=len(existing) or not set(done)<=wanted:raise StopRun('invalid_checkpoint_ids')
        todo=[r for r in rows if r['id'] not in done];semaphore=asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(timeout=180) as client:
            async def one(row):
                async with semaphore:return await request(row,system,settings,client,DATA/'labeled_v5.usage.jsonl')
            for start in range(0,len(todo),100):
                tasks=[asyncio.create_task(one(r)) for r in todo[start:start+100]];completed=[]
                try:
                    for task in asyncio.as_completed(tasks):completed.append(await task)
                finally:
                    for task in tasks:
                        if not task.done():task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
                    for item in completed:append(path,item);done[item['id']]=item
                    status('running',checkpoint=path.name,completed=len(done),target=len(rows))
        return [done[r['id']] for r in rows]
    finally:lock.unlink()

def costs():
    records=read(DATA/'labeled_v5.usage.jsonl'); inp=out=cached=0
    for r in records:
        u=r['usage'];inp+=u.get('input_tokens',0);out+=u.get('output_tokens',0);cached+=(u.get('input_tokens_details') or {}).get('cached_tokens',0)
    return dict(input_tokens=inp,cached_input_tokens=cached,output_tokens=out,total_tokens=inp+out,estimated_usd_from_actual_usage=((inp-cached)*.15+cached*.075+out*.6)/1e6,pricing_usd_per_million={'input':.15,'cached_input':.075,'output':.6},pricing_source='https://developers.openai.com/api/docs/models/gpt-4o-mini',billing_invoice=False,api_responses=len(records))

def report(name,result):
    result={**result,'usage':costs()};dump(HERE/(name+'.json'),result)
    baseline='v2.4' if name.startswith('pilot') else 'v2.3 (full v2.4 unavailable)'
    lines=['# '+name,'','```json',json.dumps({k:v for k,v in result.items() if k!='transitions'},ensure_ascii=False,indent=2),'```','','| '+baseline+' / v2.5 | '+' | '.join(LABELS)+' |','|---|'+'---:|'*7]
    for label in LABELS:lines.append('| '+label+' | '+' | '.join(str(result['transitions'][label][b]) for b in LABELS)+' |')
    (HERE/(name+'.md')).write_text('\n'.join(lines)+'\n',encoding='utf8')

def review(rows):
    def cell(x):return str(x).replace('|','\\|').replace('\r','').replace('\n','<br>')
    lines=['# v5 review','','| id | service | method | path | security_state | label | confidence | rationale | description 원문 | 검수 | 검수 사유 |','|---|---|---|---|---|---|---:|---|---|---|---|'];rng=random.Random(42)
    shortages={}
    selected=[]
    for label in LABELS:
        for i,band in enumerate(BINS):
            group=[r for r in rows if r['label']==label and bin_index(r['confidence'])==i]
            selected.extend(rng.sample(group,min(5,len(group))))
            if len(group)<5:shortages[label+' '+band]=5-len(group)
    dump(HERE/'review_sample_v5_shortages.json',shortages)
    for r in selected:lines.append('| '+' | '.join(cell(x) for x in [r['id'],r['service'],r['method'],r['path'],r['security_state'],r['label'],r['confidence'],r['rationale'],payload(r)['description'],'',''])+' |')
    target=HERE/'review_sample_v5.md'
    if not target.exists():target.write_text('\n'.join(lines)+'\n',encoding='utf8')

async def workflow(args):
    from training.data.label import read_env
    read_env(ROOT/'.env');provider=args.provider or os.getenv('BLADE_LABEL_PROVIDER','openai');model=args.model or os.getenv('BLADE_LABEL_MODEL','gpt-4o-mini')
    if provider!='openai' or model not in {'gpt-4o-mini','gpt-4o-mini-2024-07-18'}:raise StopRun('requires_openai_gpt4omini')
    key=os.getenv('OPENAI_API_KEY','').strip()
    if not key:raise StopRun('missing_openai_api_key')
    rows=read(INPUT);old_rows=read(OLD);old={r['id']:r for r in old_rows};by_id={r['id']:r for r in rows}
    if len(rows)!=2027 or len(by_id)!=2027 or set(old)!=set(by_id):raise StopRun('input_id_mismatch')
    ids=json.loads((HERE/'pilot_v4_ids.json').read_text(encoding='utf8'))['ids'];settings=llm.Settings(provider,model,key);system=PROMPT.read_text(encoding='utf8')
    base=dict(v4_prompt_sha256=digest(HERE/'prompts/policy_label_v2.4.md'),v4_pilot_sha256=digest(DATA/'apisguru_v4_openai_pilot.jsonl'),input_sha256=digest(INPUT),v3_sha256=digest(OLD),v23_prompt_sha256=digest(HERE/'prompts/policy_label_v2.3.md'),prompt_sha256=digest(PROMPT),implementation_sha256=digest(Path(__file__)),provider=provider,model=model,prompt_version=VERSION,temperature=0,seed=42,confidence_bins=BINS)
    selection=HERE/'pilot_v5_ids.json';expected={'seed':42,'ids':ids,'v3_sha256':base['v3_sha256']}
    if selection.exists() and json.loads(selection.read_text(encoding='utf8'))!=expected:raise StopRun('pilot_selection_changed')
    dump(selection,expected)
    # Preflight every source before spending API tokens; raw source files are read only.
    for r in rows:payload(r)
    pilotpath=DATA/'apisguru_v5_openai_pilot.jsonl'
    old_manifest=json.loads(pilotpath.with_suffix('.manifest.json').read_text(encoding='utf8'))
    expected={**base,'ids':ids}
    for name,value in expected.items():
        if name!='implementation_sha256' and old_manifest.get(name)!=value:raise StopRun('pilot_reuse_manifest_mismatch_'+name)
    pilot=read(pilotpath)
    if len(pilot)!=200 or {r['id'] for r in pilot}!=set(ids):raise StopRun('pilot_reuse_ids_mismatch')
    migration=dict(authorized_override='continue_full_despite_manual_rate; nonanonymous_mutation_public_flag_only',at=now(),pilot_sha256=digest(pilotpath),pilot_implementation_sha256=old_manifest['implementation_sha256'],current_implementation_sha256=base['implementation_sha256'],prompt_sha256=base['prompt_sha256'])
    migration_path=HERE/'v5_full_resume_provenance.json'
    if not migration_path.exists():dump(migration_path,migration)
    base['pilot_implementation_sha256']=old_manifest['implementation_sha256']
    pilot_old={r['id']:r for r in read(DATA/'apisguru_v4_openai_pilot.jsonl')}
    result=summary(pilot,pilot_old);report('pilot_v5_authorized_resume_report',result)
    if result['stop_reasons']:
        status('pilot_stopped',**result,usage=costs());return
    path=DATA/'apisguru_v5_openai.partial.jsonl';manifest={**base,'ids':[r['id'] for r in rows]}
    if not path.exists() and not path.with_suffix('.manifest.json').exists():
        dump(path.with_suffix('.manifest.json'),manifest)
        for record in pilot:
            record={**record,'meta':{**record['meta'],'flag_review':review_flag(record)}}
            append(path,record)
    result_rows=await run(rows,system,settings,path,manifest,args.concurrency)
    if any(r['meta'].get('label_error') for r in result_rows):raise StopRun('full_label_errors_require_review')
    final=DATA/'apisguru_labeled_v5_openai.jsonl';final.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in result_rows),encoding='utf8')
    report('label_report_v5',summary(result_rows,old))
    dump(DATA/'labeled_v5.manifest.json',{**base,'completed_at':now(),'started_at':read(DATA/'labeled_v5.usage.jsonl')[0]['at'],'returned_models':sorted({r['model_id_returned'] for r in result_rows}),'usage':costs(),'records':len(result_rows),'output_sha256':digest(final)})
    if digest(OLD)!=base['v3_sha256'] or digest(HERE/'prompts/policy_label_v2.3.md')!=base['v23_prompt_sha256'] or digest(HERE/'prompts/policy_label_v2.4.md')!=base['v4_prompt_sha256'] or digest(DATA/'apisguru_v4_openai_pilot.jsonl')!=base['v4_pilot_sha256']:raise StopRun('preserved_source_hash_changed')
    status('complete',records=len(result_rows),training_eligible=sum(r['label']!='manual_review_required' and r['confidence']>=.6 and not r['meta'].get('evidence_invalid') for r in result_rows),usage=costs())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true',required=True);parser.add_argument('--provider');parser.add_argument('--model');parser.add_argument('--concurrency',type=int,default=4);args=parser.parse_args()
    if args.concurrency<1:parser.error('positive concurrency required')
    try:asyncio.run(workflow(args))
    except StopRun as exc:status('stopped',reason=str(exc),usage=costs());raise SystemExit(3)

if __name__=='__main__':main()
