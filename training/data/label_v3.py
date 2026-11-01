"""API-only pattern proposals, invoked through label.py --workflow-v3."""
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random

import httpx
from pydantic import BaseModel, ConfigDict, Field
from common.labels import Label
from pipeline.classifier import llm
from training.data.resignal import erd_columns

ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'training/data'
DATA=ROOT/'datasets/blade/processed'
STATUS=HERE/'LABELING_STATUS.md'
FIELDS={'method','path','path_params','query_params','summary','description','security','schema_fields','owner_cols','tenant_cols'}


class Output(BaseModel):
    model_config=ConfigDict(extra='forbid')
    label: Label
    confidence: float=Field(ge=0,le=1,allow_inf_nan=False,strict=True)
    rationale: str=Field(min_length=1)
    evidence_fields: list[str]=Field(min_length=1)


class StopRun(RuntimeError): pass


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path): return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines() if x.strip()] if path.exists() else []
def dump(path,value): path.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')


def status(state,**values):
    payload={'state':state,'updated_at':datetime.now(timezone.utc).isoformat(),**values}
    STATUS.write_text('# Labeling status\n\n```json\n'+json.dumps(payload,ensure_ascii=False,indent=2)+'\n```\n',encoding='utf-8')
    print(json.dumps(payload,ensure_ascii=False),flush=True)


def payload(row):
    old=json.loads(row['oas_snippet']); enrich=row['enrichment']; op=enrich['operation']
    trees=enrich.get('trees',{}); refs=enrich.get('references',{}); names=[]
    def visit(node,prefix='',active=()):
        if len(names)>=40 or not isinstance(node,dict):return
        ref=node.get('$ref')
        if ref and ref not in active:visit(refs.get(ref,{}),prefix,(*active,ref))
        for name,value in (node.get('properties') or {}).items():
            if len(names)>=40:return
            full=prefix+name
            if full not in names:names.append(full)
            visit(value,full+'.',active)
        visit(node.get('items'),prefix+'[].',active)
        for branch in ('allOf','oneOf','anyOf'):
            for child in node.get(branch,[]):visit(child,prefix,active)
    for code,response in trees.get('responses',{}).items():
        if not str(code).startswith('2'):continue
        if '$ref' in response:response=refs.get(response['$ref'],{})
        visit(response.get('schema'))
        for media in response.get('content',{}).values():visit(media.get('schema'))
    return dict(method=row['method'],path=row['path'],path_params=old.get('path_params') or [],
        query_params=old.get('query_params') or [],summary=op.get('summary') or '',description=op.get('description') or '',
        security=enrich['security']['effective'],schema_fields=names[:40],
        schema_provenance='응답 스키마에서 추출한 필드; 실제 DB ERD 아님',
        owner_cols=row['meta']['owner_cols'],tenant_cols=row['meta']['tenant_cols'])


def quota_error(response):
    try: error=response.json().get('error',{})
    except (ValueError,AttributeError): return None
    if not isinstance(error,dict): return None
    code=str(error.get('code','')); kind=str(error.get('type','')); message=str(error.get('message','')).lower()
    if code in {'insufficient_quota','credit_balance_exhausted','billing_hard_limit_reached'} or kind=='insufficient_quota':
        return code or kind
    if response.status_code==429 and any(s in message for s in ('per day','daily','rpd','tpd')):
        return 'daily_limit_exhausted'
    return None


async def request(row,system,settings,client,version):
    user='Return JSON.\n'+json.dumps(payload(row),ensure_ascii=False)
    error='unknown'
    for attempt in range(4):
        try:
            url,headers,body=llm._request(settings,system,user,Output.model_json_schema())
            if settings.provider=='openai': body['temperature']=0
            else: body['options'].update(seed=42,num_ctx=32768)
            response=await client.post(url,headers=headers,json=body)
            fatal=quota_error(response)
            if fatal: raise StopRun(fatal)
            if response.status_code in (401,403): raise StopRun(f'authentication_or_permission_HTTP_{response.status_code}')
            response.raise_for_status()
            data=response.json(); out=Output.model_validate_json(llm._text(settings.provider,data))
            if not set(out.evidence_fields)<=FIELDS: raise ValueError('Unknown evidence field')
            result={**row,**out.model_dump(mode='json'),'model_id':settings.model,'provider':settings.provider,
                'model_id_returned':data.get('model',settings.model),'prompt_version':version,
                'labeled_at':datetime.now(timezone.utc).isoformat(),
                'lookup_status':'unresolved' if out.label.value in {'owner_match','tenant_match','owner_or_admin'} else 'not_applicable',
                'training_target_fields':['label','rationale'],'usage':data.get('usage'),
                'meta':{**row['meta'],'low_conf':out.confidence<.6,'label_error':False,'label_source':'model_api'}}
            return result
        except httpx.HTTPStatusError as exc:
            error=f'HTTP_{exc.response.status_code}'
            if exc.response.status_code!=429 and exc.response.status_code<500: break
        except (ValueError,httpx.TransportError,llm.LLMError) as exc:
            error=type(exc).__name__
        if attempt<3: await asyncio.sleep(2**attempt)
    return {**row,'label':None,'confidence':None,'rationale':None,'evidence_fields':[],
        'model_id':settings.model,'provider':settings.provider,'prompt_version':version,
        'lookup_status':'unresolved','training_target_fields':['label','rationale'],
        'labeled_at':datetime.now(timezone.utc).isoformat(),
        'meta':{**row['meta'],'label_error':True,'label_error_reason':error,'low_conf':False,'label_source':'model_api'}}


async def run_rows(rows,system,settings,path,manifest,concurrency,version):
    stamp=path.with_suffix('.manifest.json'); lock=path.with_suffix('.lock')
    fd=os.open(lock,os.O_CREAT|os.O_EXCL|os.O_WRONLY);os.close(fd)
    try:
        if stamp.exists():
            if json.loads(stamp.read_text(encoding='utf-8'))!=manifest: raise StopRun('checkpoint_manifest_mismatch')
        elif path.exists(): raise StopRun('checkpoint_missing_manifest')
        else: dump(stamp,manifest)
        existing=read(path); done={r['id']:r for r in existing}; wanted={r['id'] for r in rows}
        if len(done)!=len(existing) or not set(done)<=wanted: raise StopRun('checkpoint_ids_invalid')
        todo=[r for r in rows if r['id'] not in done]
        semaphore=asyncio.Semaphore(concurrency if settings.provider=='openai' else 1)
        async with httpx.AsyncClient(timeout=180) as client:
            async def one(row):
                async with semaphore: return await request(row,system,settings,client,version)
            for start in range(0,len(todo),100):
                tasks=[asyncio.create_task(one(r)) for r in todo[start:start+100]]
                completed=[]
                try:
                    for task in asyncio.as_completed(tasks): completed.append(await task)
                finally:
                    for task in tasks:
                        if not task.done(): task.cancel()
                    await asyncio.gather(*tasks,return_exceptions=True)
                    if completed:
                        with path.open('a',encoding='utf-8',newline='\n') as stream:
                            for item in completed:stream.write(json.dumps(item,ensure_ascii=False)+'\n')
                            stream.flush();os.fsync(stream.fileno())
                        done.update({r['id']:r for r in completed})
                        status('running',provider=settings.provider,checkpoint=path.name,completed=len(done),target=len(rows))
        return [done[r['id']] for r in rows]
    finally: lock.unlink()


def summarize(rows):
    good=[r for r in rows if not r['meta'].get('label_error')];c=Counter(r['label'] for r in good)
    return dict(records=len(rows),successful=len(good),label_error=len(rows)-len(good),
        labels={l.value:c[l.value] for l in Label},manual_review_rate=c['manual_review_required']/len(good) if good else None,
        confidence={'below_0.6':sum(r['confidence']<.6 for r in good),'0.6_to_0.7':sum(.6<=r['confidence']<.7 for r in good),
            '0.7_to_0.9':sum(.7<=r['confidence']<.9 for r in good),'0.9_plus':sum(r['confidence']>=.9 for r in good)})


def reports(rows,provider):
    dump(HERE/f'label_report_v3_{provider}.json',summarize(rows))
    def cell(x):return str(x).replace('|','\\|').replace('\n','<br>').replace('\r','')
    lines=['# v3 review — API generated','', '| id | label | confidence | rationale | description 원문 | 사용 단서 | 검수 |','|---|---|---:|---|---|---|---|']
    rng=random.Random(42)
    for label in Label:
        group=[r for r in rows if r['label']==label.value]
        for r in rng.sample(group,min(20,len(group))):
            data=payload(r); clues={k:data[k] for k in r['evidence_fields']}
            lines.append('| '+' | '.join(map(cell,[r['id'],r['label'],r['confidence'],r['rationale'],data['description'],json.dumps(clues,ensure_ascii=False)]))+' |  |')
    path=HERE/('review_sample_v3.md' if provider=='openai' else 'review_sample_v3_ollama.md')
    if not path.exists():path.write_text('\n'.join(lines)+'\n',encoding='utf-8')
    old=read(DATA/'apisguru_policy_pilot_v2.jsonl'); new={r['id']:r for r in rows}
    lines=['# v2.2 agent vs v2.3 '+provider,'','| id | v2.2 | v2.3 | match |','|---|---|---|---|']
    for r in old:lines.append('| '+' | '.join(map(cell,[r['id'],r['label'],new[r['id']]['label'],r['label']==new[r['id']]['label']]))+' |')
    (HERE/f'pilot_v22_vs_v23_{provider}.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')


async def workflow(args):
    from training.data.label import read_env
    read_env(ROOT/'.env')
    key=os.getenv('OPENAI_API_KEY','').strip()
    available=[]
    if key:available.append(llm.Settings('openai',args.model,key))
    ollama=os.getenv('BLADE_OLLAMA_URL','http://127.0.0.1:11434').rstrip('/')
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r=await client.get(ollama+'/api/tags');r.raise_for_status()
            if any(m.get('name')=='gemma2:9b' for m in r.json().get('models',[])):
                available.append(llm.Settings('ollama','gemma2:9b',ollama_url=ollama))
    except (httpx.HTTPError,ValueError):pass
    if not available:raise StopRun('no_openai_key_or_installed_gemma2_9b')
    rows=read(DATA/'apisguru_enriched_v2.jsonl'); by_id={r['id']:r for r in rows}
    pool=json.loads((HERE/'pilot_v2_ids.json').read_text(encoding='utf-8'))['ids']
    ids=random.Random(42).sample(pool,50)
    selection=HERE/'pilot_v3_ids.json'
    expected={'seed':42,'ids':ids,'input_sha256':digest(DATA/'apisguru_enriched_v2.jsonl')}
    if selection.exists() and json.loads(selection.read_text(encoding='utf-8'))!=expected:raise StopRun('pilot_selection_changed')
    if not selection.exists():dump(selection,expected)
    pilots={}; passed={}
    for settings in available:
        for revision in range(2):
            version='policy-label-v2.3'+('-retry1' if revision else '')
            prompt=HERE/'prompts'/('policy_label_v2.3_retry1.md' if revision else 'policy_label_v2.3.md')
            if revision and not prompt.exists():
                prompt.write_text((HERE/'prompts/policy_label_v2.3.md').read_text(encoding='utf-8')+'\n추가 단서 보강: 객체 ID와 사용자 스코프는 소유 제안, 조직/프로젝트 스코프는 tenant 제안에 충분한 구조 단서다. lookup 부재는 모순이 아니다. 서로 조합 가능한 역할과 소유 단서는 owner_or_admin으로 검토한다. 낮은 confidence로 최선의 제안을 유지하되 실제 모순은 숨기지 않는다.\n',encoding='utf-8')
            system=prompt.read_text(encoding='utf-8')
            base=dict(provider=settings.provider,model=settings.model,prompt_sha256=digest(prompt),prompt_version=version,
                input_sha256=expected['input_sha256'],implementation_sha256=digest(Path(__file__)),temperature=0,training_target=['label','rationale'])
            path=DATA/f'apisguru_v3_{settings.provider}_pilot_r{revision}.jsonl'
            result=await run_rows([by_id[i] for i in ids],system,settings,path,{**base,'ids':ids},args.concurrency,version)
            summary=summarize(result);dump(HERE/f'pilot_v3_{settings.provider}_r{revision}.json',summary)
            status('pilot_result',provider=settings.provider,revision=revision,**summary)
            if summary['label_error']:raise StopRun('pilot_label_errors_require_inspection')
            if summary['manual_review_rate']<=.4:
                pilots[settings.provider]=result;passed[settings.provider]=(settings,system,base,version,path);break
            if revision:raise StopRun('manual_review_above_40_percent_after_retry')
    if len(pilots)==2:
        a={r['id']:r['label'] for r in pilots['openai']};b={r['id']:r['label'] for r in pilots['ollama']}
        dump(HERE/'pilot_v3_agreement.json',{'records':50,'matches':sum(a[k]==b[k] for k in ids),'agreement':sum(a[k]==b[k] for k in ids)/50})
    for provider,(settings,system,base,version,pilotpath) in passed.items():
        path=DATA/f'apisguru_v3_{provider}.partial.jsonl';manifest={**base,'ids':[r['id'] for r in rows]}
        if not path.exists() and not path.with_suffix('.manifest.json').exists():
            dump(path.with_suffix('.manifest.json'),manifest)
            path.write_bytes(pilotpath.read_bytes())
        result=await run_rows(rows,system,settings,path,manifest,args.concurrency,version)
        final=DATA/f'apisguru_labeled_v3_{provider}.jsonl'
        final.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in result),encoding='utf-8')
        reports(result,provider)
        status('provider_complete',provider=provider,**summarize(result))
    status('complete',providers=list(passed),records=len(rows),agreement_available=len(pilots)==2)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--model',default='gpt-4o-mini')
    parser.add_argument('--concurrency',type=int,default=4)
    args=parser.parse_args()
    if 'qwen' in args.model.lower() or args.concurrency<1:parser.error('Qwen forbidden; positive concurrency required')
    try:asyncio.run(workflow(args))
    except StopRun as exc:
        status('stopped',reason=str(exc));raise SystemExit(3)


if __name__=='__main__':main()
