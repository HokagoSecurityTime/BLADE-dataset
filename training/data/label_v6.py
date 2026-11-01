"""Human-correction v2.6 experiment; API-only labels and held-out pilot gate."""
import argparse, asyncio, json, os
from pathlib import Path
from training.data import label_v5 as core

# Reuse the audited transport without changing any v5 source/output.
# Its path constants are isolated in a private module namespace.
import types
engine=types.ModuleType('v6_transport')
engine.__dict__['__file__']=__file__
code=Path(core.__file__).read_text(encoding='utf8').split('async def workflow(args):')[0]
code=code.replace('v2.5','v2.6').replace('v5','v6').replace('V5','V6')
exec(compile(code,'v6_transport','exec'),engine.__dict__)
HERE=core.HERE; DATA=core.DATA

async def workflow(args):
    from training.data.label import read_env
    read_env(core.ROOT/'.env')
    provider=os.getenv('BLADE_LABEL_PROVIDER','openai');model=os.getenv('BLADE_LABEL_MODEL','gpt-4o-mini')
    if provider!='openai' or model not in {'gpt-4o-mini','gpt-4o-mini-2024-07-18'}:raise core.StopRun('requires_openai_gpt4omini')
    key=os.getenv('OPENAI_API_KEY','').strip()
    if not key:raise core.StopRun('missing_openai_api_key')
    rows=core.read(core.INPUT);byid={r['id']:r for r in rows}
    old={r['id']:r for r in core.read(DATA/'apisguru_labeled_v5_openai.jsonl')}
    selection=json.loads((HERE/'pilot_v6_ids.json').read_text(encoding='utf8'))
    corrections={r['id']:r for r in core.read(HERE/'human_corrections_v5.jsonl')}
    assert len(rows)==2027 and len(selection['ids'])==200
    assert not set(selection['fewshot_ids'])&set(selection['ids'])
    system=engine.PROMPT.read_text(encoding='utf8');settings=core.llm.Settings(provider,model,key)
    base=dict(input_sha256=core.digest(core.INPUT),v5_sha256=core.digest(DATA/'apisguru_labeled_v5_openai.jsonl'),prompt_sha256=core.digest(engine.PROMPT),implementation_sha256=core.digest(Path(__file__)),transport_sha256=core.digest(Path(core.__file__)),corrections_sha256=core.digest(HERE/'human_corrections_v5.jsonl'),selection_sha256=core.digest(HERE/'pilot_v6_ids.json'),provider=provider,model=model,prompt_version=engine.VERSION,seed=42,temperature=0,confidence_bins=core.BINS)
    pilot=await engine.run([byid[i] for i in selection['ids']],system,settings,DATA/'apisguru_v6_openai_pilot.jsonl',{**base,'ids':selection['ids']},args.concurrency)
    held=[r for r in pilot if r['id'] in selection['validation_ids']]
    correct=sum(r['label']==corrections[r['id']]['corrected_label'] for r in held)
    result=engine.summary(pilot,old)
    result.update(validation_records=31,validation_correct=correct,validation_accuracy=correct/31,v5_validation_accuracy=0,validation_comparison=[dict(id=r['id'],v5=corrections[r['id']]['original_label'],human=corrections[r['id']]['corrected_label'],v6=r['label'],correct=r['label']==corrections[r['id']]['corrected_label']) for r in held])
    result['stop_reasons']=['heldout_accuracy_below_60_percent'] if correct/31<.6 else []
    if result['label_errors']:result['stop_reasons'].append('label_errors')
    engine.report('pilot_v6_report',result)
    if result['stop_reasons']:
        engine.status('pilot_stopped',**result,usage=engine.costs());return
    path=DATA/'apisguru_v6_openai.partial.jsonl';manifest={**base,'ids':[r['id'] for r in rows]}
    if not path.exists() and not path.with_suffix('.manifest.json').exists():
        core.dump(path.with_suffix('.manifest.json'),manifest)
        for row in pilot:engine.append(path,row)
    finalrows=await engine.run(rows,system,settings,path,manifest,args.concurrency)
    if any(r['meta'].get('label_error') for r in finalrows):raise core.StopRun('full_label_errors')
    output=DATA/'apisguru_labeled_v6_openai.jsonl'
    output.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in finalrows),encoding='utf8')
    engine.report('label_report_v6',engine.summary(finalrows,old))
    core.dump(DATA/'labeled_v6.manifest.json',{**base,'records':len(finalrows),'output_sha256':core.digest(output),'completed_at':core.now(),'usage':engine.costs(),'returned_models':sorted({r['model_id_returned'] for r in finalrows})})
    from training.data.build_train import build
    report=build(6);core.dump(HERE/'build_train_v6_report.json',report)
    engine.status('complete',records=len(finalrows),usage=engine.costs())

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--execute',required=True,action='store_true');parser.add_argument('--concurrency',type=int,default=4);args=parser.parse_args()
    try:asyncio.run(workflow(args))
    except core.StopRun as exc:engine.status('stopped',reason=str(exc),usage=engine.costs());raise SystemExit(3)
if __name__=='__main__':main()
