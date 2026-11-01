"""Build audited service-isolated train/val only; never open test source data."""
from __future__ import annotations
import argparse
import ast
from collections import Counter
import hashlib
import json
import random
import re
from pathlib import Path
from typing import Any
import yaml
from common.labels import Label
from pipeline.parsers.controller import parse_controller

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'training/data'
DATA = ROOT / 'datasets/blade/processed'
LABELS = [x.value for x in Label]
MANUAL = 'manual_review_required'
REQUIRED = ('id','service','method','path','oas_snippet','erd_snippet','controller_signals','label','rationale')
BINS = ('[0,0.5]','(0.5,0.7)','[0.7,0.9)','[0.9,1]')

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding='utf8').splitlines() if x.strip()]

def dump(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf8')

def write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in rows),encoding='utf8')

def bin_name(confidence: float) -> str:
    return BINS[0 if confidence <= .5 else 1 if confidence < .7 else 2 if confidence < .9 else 3]

def pattern(path: str) -> str:
    return re.sub(r'\{[^}]+\}|:[A-Za-z_]\w*','{}',path).rstrip('/') or '/'

def synthetic_rows(partition: dict[str, Any]) -> tuple[list[dict[str, Any]],dict[str,str]]:
    """Only the three preselected directories are touched, never a root glob."""
    rows, hashes = [], {}
    for name in partition['train_services']:
        base = ROOT/'datasets/blade/raw/synthetic'/name
        intended_path, oas_path, ddl_path = (base/x for x in ('intended_labels.yaml','openapi.json','schema.sql'))
        intended = yaml.safe_load(intended_path.read_text(encoding='utf8'))
        oas = json.loads(oas_path.read_text(encoding='utf8'))
        ddl = ddl_path.read_text(encoding='utf8')
        source_path = base/({'orbit_tickets':'app.py','copper_wallet':'app.js','campus_records':'src/main/java/fixture/App.java'}[name])
        text = source_path.read_text(encoding='utf8')
        parsed = parse_controller(text,source_path.suffix.lstrip('.')) if source_path.suffix != '.java' else {}
        for p in (intended_path,oas_path,ddl_path,source_path): hashes[str(p.relative_to(ROOT))] = digest(p)
        python_handlers = {n.name: ast.get_source_segment(text,n) for n in ast.walk(ast.parse(text)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))} if source_path.suffix == '.py' else {}
        for ep in intended['endpoints']:
            op = oas['paths'][ep['path']][ep['method'].lower()]
            if source_path.suffix == '.py': snippet = python_handlers[ep['id']]
            else:
                match = re.search(r'\b'+re.escape(ep['id'])+r'\s*\(',text)
                if not match: raise ValueError('Missing synthetic handler '+ep['id'])
                start = text.index('{',match.end()); depth=1; end=start+1
                while depth and end<len(text):
                    depth += (text[end]=='{')-(text[end]=='}'); end+=1
                snippet=text[match.start():end]
            hints = dict(parsed.get(f"{ep['method']} {ep['path']}",{}))
            # Supplemental static hints for generated Python/JS/Java comparison syntax.
            hints.update(has_auth_check=bool(re.search(r'401|UNAUTHORIZED|principal\s+is\s+None|!principal',snippet)),
                         owner_filter=bool(re.search(r'if[^\n]*(?:owner_id)',snippet)),
                         tenant_check=bool(re.search(r'if[^\n]*(?:tenant_id)',snippet)),
                         admin_bypass=bool(re.search(r'if[^\n]*owner_id[^\n]*admin',snippet)),
                         raw_snippet=snippet)
            rows.append(dict(id=ep['id'],service=name,method=ep['method'],path=ep['path'],
                oas_snippet=json.dumps({'paths':{ep['path']:{ep['method'].lower():op}}},ensure_ascii=False),
                erd_snippet=ddl,controller_signals=hints,label=ep['label'],rationale=ep['reason'],confidence=1.0,
                description=op.get('description',ep['reason']),security_state='unknown',
                meta=dict(source='synthetic',label_source='intended_labels',human_confirmed=False,
                          evidence_invalid=False,flag_review=False,known_vulnerable=ep['vulnerable'],
                          confidence_provenance='design_intent_not_model_probability',source_file=str(source_path.relative_to(ROOT))),
                training_target_fields=['label','rationale']))
    return rows,hashes

def machine_reasons(row: dict[str,Any], error_rates: dict[str,float] | None = None) -> list[str]:
    if row.get('meta',{}).get('source')=='synthetic': return []
    reasons=[]
    if row['label']=='public' and row.get('security_state')=='declared': reasons.append('public_declared')
    if row['label']=='membership_required' and row['confidence']<.9: reasons.append('membership_below_0.9')
    if row['label']=='owner_or_admin': reasons.append('api_owner_or_admin')
    if (error_rates or {}).get(row['label'],0)>.2 and .5<row['confidence']<.7: reasons.append('human_error_above_20_percent_low_band')
    return reasons

def prepare(api: list[dict[str, Any]], synthetic: list[dict[str, Any]], demo: set[tuple[str,str]], error_rates: dict[str,float] | None = None) -> tuple[list[dict[str, Any]],list[dict[str, Any]],Counter]:
    candidates, lowconf, reasons = [], [], Counter()
    for row in api+synthetic:
        if row['label'] not in LABELS: raise ValueError('Unknown label')
        row = {**row,'controller_signals':row.get('controller_signals') or {},'meta':dict(row.get('meta',{})), 'training_target_fields':['label','rationale']}
        row['meta'].setdefault('source','apisguru')
        if (row['method'].upper(),pattern(row['path'])) in demo:
            reasons['demo_path_overlap']+=1; continue
        if row['meta'].get('source')=='synthetic': candidates.append(row); continue
        blocked=machine_reasons(row,error_rates)
        if blocked:
            reasons.update(blocked); continue
        # Preserve every low-confidence concrete row, even if another quality flag is present.
        if row['label']!=MANUAL and row['confidence']<.6:
            lowconf.append(row); reasons['concrete_confidence_below_0.6']+=1; continue
        if row['meta'].get('evidence_invalid',False): reasons['evidence_invalid']+=1; continue
        if row['meta'].get('flag_review',False): reasons['flag_review']+=1; continue
        candidates.append(row)
    return candidates,lowconf,reasons

def split_rows(candidates: list[dict[str, Any]], seed: int = 42) -> tuple[list[dict[str, Any]],list[dict[str, Any]],dict[str,Any]]:
    services=sorted({r['service'] for r in candidates}); random.Random(seed).shuffle(services)
    val_services=set(services[:max(1,round(len(services)*.1))])
    outputs=[]; details={}
    for index,name in enumerate(('train','val')):
        group=[r for r in candidates if (r['service'] in val_services)==(name=='val')]
        concrete=[r for r in group if r['label']!=MANUAL]
        fixed=[r for r in group if r['label']==MANUAL and r['meta']['source']=='synthetic']
        pool=sorted([r for r in group if r['label']==MANUAL and r['meta']['source']=='apisguru'],key=lambda r:r['id'])
        random.Random(seed).shuffle(pool)
        desired=max(0,int(len(concrete)/3-len(fixed)+.5))
        selected=concrete+fixed+pool[:desired]; selected.sort(key=lambda r:(r['service'],r['id']))
        outputs.append(selected)
        details[name]=dict(concrete=len(concrete),synthetic_manual=len(fixed),requested_api_manual=desired,
            selected_api_manual=min(desired,len(pool)),available_api_manual=len(pool),
            actual_manual_ratio=sum(r['label']==MANUAL for r in selected)/len(selected) if selected else 0,
            assigned_services=sorted({r['service'] for r in group}),actual_services=sorted({r['service'] for r in selected}))
    details['policy']='Service assignment first: shuffled sorted services, nearest 10% val. Within each split M=round_half_up(C/3-S), capped by available API manual; C=concrete, S=mandatory synthetic manual. Val uses same independent 25% target; seed 42 for both samplings.'
    return outputs[0],outputs[1],details

def validate(train: list[dict[str,Any]], val: list[dict[str,Any]], partition: dict[str,Any]) -> None:
    assert not ({r['service'] for r in train}&{r['service'] for r in val})
    forbidden=set(partition['test_services']+partition['test_vuln_services'])
    for r in train+val:
        assert r['label'] in LABELS and r['service'] not in forbidden
        assert all(k in r and r[k] is not None for k in REQUIRED)
        assert all(bool(r[k]) for k in REQUIRED if k!='controller_signals')
        assert isinstance(r['controller_signals'],dict)

def review(rows: list[dict[str,Any]], path: Path) -> None:
    rng=random.Random(42); chosen=[]
    for label in LABELS:
        pool=[r for r in rows if r['label']==label]; picked=[]
        for bucket in reversed(BINS):
            group=sorted([r for r in pool if bin_name(r['confidence'])==bucket],key=lambda r:r['id'])
            picked.extend(rng.sample(group,min(5,len(group))))
        remaining=[r for r in pool if r['id'] not in {x['id'] for x in picked}]
        picked.extend(rng.sample(remaining,min(max(0,20-len(picked)),len(remaining)))); chosen+=picked
    def cell(value: Any) -> str: return str(value).replace('|','&#124;').replace('\n','<br>').replace('\r','')
    lines=['# Train-only v2.5 review sample','', 'Each label: up to 5 per confidence bin; unavailable bins backfilled from remaining train records. Review cells intentionally blank.','', '| id | service | method | path | security_state | label | confidence | rationale | description 원문 | 검수 | 검수 사유 |','|---|---|---|---|---|---|---|---|---|---|---|']
    for r in chosen:
        desc=r.get('description',r.get('enrichment',{}).get('operation',{}).get('description',''))
        lines.append('| '+' | '.join(cell(r.get(k,'')) for k in ('id','service','method','path','security_state','label','confidence','rationale'))+' | '+cell(desc)+' | | |')
    path.write_text('\n'.join(lines)+'\n',encoding='utf8')

def review_v6(rows: list[dict[str,Any]], excluded_ids: set[str]) -> None:
    rng=random.Random(42);chosen=[]
    for label in LABELS:
        bins=[[r for r in rows if r['label']==label and r['id'] not in excluded_ids and bin_name(r['confidence'])==b] for b in BINS]
        for group in bins:group.sort(key=lambda r:r['id']);rng.shuffle(group)
        picked=[]
        while len(picked)<15 and any(bins):
            for group in reversed(bins):
                if group and len(picked)<15:picked.append(group.pop())
        chosen.extend(picked)
    assert not {r['id'] for r in chosen}&excluded_ids
    def cell(x):return str(x).replace('|','&#124;').replace('\r','').replace('\n','<br>')
    lines=['# v2.6 new train review sample','','| id | service | method | path | security_state | label | confidence | rationale | description 원문 | 검수 | 검수 사유 |','|---|---|---|---|---|---|---|---|---|---|---|']
    for r in chosen:
        desc=r.get('description',r.get('enrichment',{}).get('operation',{}).get('description',''))
        lines.append('| '+' | '.join(cell(r.get(k,'')) for k in ('id','service','method','path','security_state','label','confidence','rationale'))+' | '+cell(desc)+' | | |')
    (HERE/'review_sample_v6.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    dump(HERE/'review_sample_v6_manifest.json',dict(ids=[r['id'] for r in chosen],excluded_v5_review_ids=sorted(excluded_ids),labels=dict(Counter(r['label'] for r in chosen))))

def build(version: int = 5) -> dict[str,Any]:
    source=DATA/f'apisguru_labeled_v{version}_openai.jsonl'; manifest_path=DATA/f'labeled_v{version}.manifest.json'
    manifest=json.loads(manifest_path.read_text(encoding='utf8')); api=read(source)
    if manifest.get('records')!=2027 or len(api)!=2027 or manifest.get('output_sha256')!=digest(source): raise ValueError('Full v5 completion/hash mismatch')
    if len({r['id'] for r in api})!=2027: raise ValueError('Duplicate API ids')
    partition=json.loads((HERE/'synthetic_partition.json').read_text(encoding='utf8'))
    synthetic,hashes=synthetic_rows(partition)
    oas=json.loads((ROOT/'demo_backend/openapi.json').read_text(encoding='utf8'))
    demo={(m.upper(),pattern(p)) for p,ops in oas['paths'].items() for m in ops if m.lower() in {'get','post','put','patch','delete','head','options'}}
    human_path=HERE/'human_corrections_v5_split.json'
    human=json.loads(human_path.read_text(encoding='utf8')) if human_path.exists() else {}
    rates={k:v['error_rate'] for k,v in human.get('label_errors',{}).items()}
    candidates,lowconf,reasons=prepare(api,synthetic,demo,rates)
    train,val,split=split_rows(candidates); validate(train,val,partition)
    used={r['id'] for r in train+val}; manual=[r for r in api if r['label']==MANUAL and r['id'] not in used]
    correction_pool=[{**r,'meta':{**r.get('meta',{}),'correction_pool_reasons':machine_reasons(r,rates)}} for r in api if machine_reasons(r,rates)]
    paths={'train':train,'val':val,'apisguru_manual_pool':manual,'apisguru_lowconf_pool':lowconf,'apisguru_correction_pool':correction_pool}
    for name,rows in paths.items(): write_rows(DATA/(name+'.jsonl'),rows)
    if version==6: review_v6(train,set(human.get('reviewed_ids',[])))
    else: review(train,HERE/'review_sample_v5_filtered.md')
    def stats(rows: list[dict[str,Any]]) -> dict[str,Any]:
        n=sum(r.get('meta',{}).get('source')=='synthetic' for r in rows)
        return dict(records=len(rows),label_distribution={label:sum(r['label']==label for r in rows) for label in LABELS},confidence_bins=dict(Counter(bin_name(r['confidence']) for r in rows)),services=len({r['service'] for r in rows}),synthetic_records=n,synthetic_ratio=n/len(rows) if rows else 0)
    report=dict(seed=42,input_records=len(api),synthetic_records=len(synthetic),input_sha256=digest(source),synthetic_input_sha256=hashes,
        partition=partition,split_policy=split,train=stats(train),val=stats(val),excluded=dict(reasons),manual_pool=len(manual),lowconf_pool=len(lowconf),
        manual_quality_policy='Exclude evidence_invalid and flag_review from sampling; no confidence floor for manual. All unselected API manual preserved in manual pool.',
        manual_pool_reasons=dict(Counter('evidence_invalid' if r.get('meta',{}).get('evidence_invalid') else 'flag_review' if r.get('meta',{}).get('flag_review') else 'demo_overlap' if (r['method'],pattern(r['path'])) in demo else 'manual_quota' for r in manual)),
        outputs_sha256={name:digest(DATA/(name+'.jsonl')) for name in paths},human_reviewed_records=human.get('reviewed',0),
        label_version=version,correction_pool=len(correction_pool),human_label_error_rates=rates,
        held_out_test_sources_read=False,synthetic_labels_human_confirmed=False)
    dump(HERE/'build_train_report.json',report)
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--version',type=int,choices=[5,6],default=5);args=parser.parse_args()
    print(json.dumps(build(args.version),ensure_ascii=False,indent=2))
