"""Build train_v30 / val_v30 from the prompt v3.0.1 full labels. New files only; never overwrites train.jsonl/val.jsonl.
Human corrections are not used. Test-only synthetic and vulnerable API sources are never opened."""
import argparse, json, random
from collections import Counter
from pathlib import Path
from training.data import build_train as bt
from training.data import label_v30 as m

HERE=bt.HERE; DATA=bt.DATA; LABELS=bt.LABELS; MANUAL=bt.MANUAL
OUTPUTS={'train':'train_v30.jsonl','val':'val_v30.jsonl','manual_pool':'apisguru_manual_pool_v30.jsonl','lowconf_pool':'apisguru_lowconf_pool_v30.jsonl','excluded':'apisguru_excluded_v30.jsonl'}

def machine_reasons_v30(row):
    """v3.0 eligibility: public with declared security is excluded (prompt forbids it; keeps the approved filter).
    The v2.6-era membership<0.9 and owner_or_admin exclusions came from human review of v2.5 semantics and are NOT applied; counts are reported."""
    if row['meta'].get('source')=='synthetic':return []
    return ['public_declared'] if row['label']=='public' and row.get('security_state')=='declared' else []

def legacy_filter_counts(api):
    return dict(membership_below_0_9=sum(r['label']=='membership_required' and r['confidence']<.9 for r in api),api_owner_or_admin=sum(r['label']=='owner_or_admin' for r in api))

def prepare(api,synthetic,demo):
    candidates,lowconf,excluded,reasons=[],[],[],Counter()
    for row in api+synthetic:
        if row['label'] not in LABELS:raise ValueError('Unknown label')
        row={**row,'controller_signals':row.get('controller_signals') or {},'meta':dict(row.get('meta',{})),'training_target_fields':['label','rationale']}
        row['meta'].setdefault('source','apisguru')
        if (row['method'].upper(),bt.pattern(row['path'])) in demo:reasons['demo_path_overlap']+=1;excluded.append({**row,'exclusion':'demo_path_overlap'});continue
        if row['meta'].get('source')=='synthetic':
            if row['label']=='membership_required' and row['rationale'].lower().startswith('a premium plan'):
                # User decision 2026-10-21: keep the record, relabel to manual under v3.0 (subscription tier is not group membership).
                row['meta']['v30_relabel_reason']='intended membership_required means premium plan (subscription tier); v3.0 defines membership_required as target group/team membership, so the record is manual_review_required'
                row['meta']['intended_label_original']=row['label']; row['label']=MANUAL
                reasons['synthetic_subscription_relabelled_manual']+=1
            candidates.append(row);continue
        # User decision 2026-10-21: declared-security public and non-anonymous mutation public are kept as manual (override), not dropped.
        if row['label']=='public' and (row.get('security_state')=='declared' or row['meta'].get('flag_review')):
            trig=[c for c,ok in (('security_declared',row.get('security_state')=='declared'),('nonanonymous_mutation_public',bool(row['meta'].get('flag_review')))) if ok]
            row['meta'].update(v30_override_reason='security_declared_public',v30_override_trigger=trig,label_before_override='public'); row['label']=MANUAL
            reasons['override_security_declared_public']+=1
            for c in trig:reasons['override_trigger_'+c]+=1
        blocked=machine_reasons_v30(row)
        if blocked:reasons.update(blocked);excluded.append({**row,'exclusion':blocked[0]});continue
        if row['label']!=MANUAL and row['confidence']<.6:lowconf.append(row);reasons['concrete_confidence_below_0.6']+=1;continue
        if row['meta'].get('evidence_invalid',False):reasons['evidence_invalid']+=1;excluded.append({**row,'exclusion':'evidence_invalid'});continue
        if row['meta'].get('flag_review',False) and 'v30_override_reason' not in row['meta']:reasons['flag_review']+=1;excluded.append({**row,'exclusion':'flag_review'});continue
        candidates.append(row)
    return candidates,lowconf,excluded,reasons

def review_sample(api_rows,candidates,train,val,path,prompt_text):
    """Priority review: all membership_required, all owner_or_admin, 15 tenant_match, 20 overridden declared-public; 15 per remaining label from train_v30."""
    rng=random.Random(42); split={**{r['id']:'val' for r in val},**{r['id']:'train' for r in train}}
    by_id={r['id']:r for r in candidates}
    def pick(pool,n):
        pool=sorted(pool,key=lambda r:r['id']); return pool if n is None or len(pool)<=n else rng.sample(pool,n)
    api_lab={r['id']:r for r in api_rows}
    groups=[('membership_required 전수',[r for r in api_rows if r['label']=='membership_required'],None),
            ('owner_or_admin 전수',[r for r in api_rows if r['label']=='owner_or_admin'],None),
            ('tenant_match 15',[r for r in api_rows if r['label']=='tenant_match'],15),
            ('override declared-public 20',[r for r in candidates if r['meta'].get('v30_override_reason')],20)]
    chosen=[]; seen=set()
    for name,pool,n in groups:
        for r in pick(pool,n):
            if r['id'] in seen:continue
            seen.add(r['id']); chosen.append((name,by_id.get(r['id'],r)))
    for label in ('public','role_required','owner_match','manual_review_required'):
        pool=[r for r in train if r['label']==label and r['id'] not in seen and not r['meta'].get('v30_override_reason')]
        bins=[[r for r in pool if bt.bin_name(r['confidence'])==b] for b in bt.BINS]
        for g in bins:g.sort(key=lambda r:r['id']);rng.shuffle(g)
        picked=[]
        while len(picked)<15 and any(bins):
            for g in reversed(bins):
                if g and len(picked)<15:picked.append(g.pop())
        for r in picked:seen.add(r['id']);chosen.append((label+' 15',r))
    # Operation descriptions come from the labeling input (read only).
    desc={}
    for r in bt.read(DATA/'apisguru_enriched_v2.jsonl'):
        op=r['enrichment']['operation']; desc[r['id']]=(op.get('description') or '')+(' | summary: '+op['summary'] if op.get('summary') else '')
    def cell(x):return str(x).replace('|','&#124;').replace('\r','').replace('\n','<br>')
    defs=prompt_text.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
    lines=['# review_sample_v30 — 사람 검수용 표본 (seed 42)','','검수 열은 비워 두었다. 라벨 기준은 아래 v3.0.1 정의를 따른다. 사람 교정 61건은 이 표본·프롬프트·train 어디에도 사용하지 않았다.',
        '우선 검수: membership_required 전수, owner_or_admin 전수, tenant_match 15, override된 declared-public 20(원래 label은 public, train에는 manual로 포함; 진짜 label 확인용). 나머지 label은 train_v30에서 15건씩.',
        '`split` 열: train_v30 / val_v30 / pool(쿼터 미선택 manual) / excluded.','','## v3.0.1 라벨 정의(프롬프트 원문 발췌)','',defs,'','## 표본','',
        '| 그룹 | id | service | method | path | security_state | label | label_before_override | split | confidence | rationale | description 원문 | 검수 | 검수 사유 |','|---|---|---|---|---|---|---|---|---|---|---|---|---|---|']
    for name,r in chosen:
        lines.append('| '+cell(name)+' | '+' | '.join(cell(r.get(k,'')) for k in ('id','service','method','path','security_state','label'))+' | '+cell(r['meta'].get('label_before_override',''))+' | '+split.get(r['id'],'pool' if r['label']==MANUAL else 'excluded')+' | '+cell(r.get('confidence',''))+' | '+cell(r.get('rationale',''))+' | '+cell(desc.get(r['id'],r.get('description','')))+' | | |')
    path.write_text('\n'.join(lines)+'\n',encoding='utf8')
    return dict(ids=[r['id'] for _,r in chosen],groups=dict(Counter(n for n,_ in chosen)),labels=dict(Counter(r['label'] for _,r in chosen)))

def build(tag='v301'):
    m.configure(tag); source=m.FULL_FINAL; manifest=json.loads((DATA/f'labeled_{tag}.manifest.json').read_text(encoding='utf8')); api=bt.read(source)
    if manifest.get('records')!=2027 or len(api)!=2027 or manifest.get('output_sha256')!=bt.digest(source):raise ValueError('Full completion/hash mismatch')
    if len({r['id'] for r in api})!=2027:raise ValueError('Duplicate API ids')
    manual_ratio=sum(r['label']==MANUAL for r in api)/len(api)
    # 2026-10-21: user accepted the 75.48% manual ratio for this build (70% rule reported, not enforced here).
    guard={p:bt.digest(p) for p in (DATA/'train.jsonl',DATA/'val.jsonl',DATA/'test.jsonl')}
    base_partition=json.loads((HERE/'synthetic_partition.json').read_text(encoding='utf8'))
    partition=json.loads((HERE/'synthetic_partition_v30.json').read_text(encoding='utf8'))  # adds relay_forum (train) / summit_club (test)
    synthetic,hashes=bt.synthetic_rows(base_partition)
    from training.data.sources import synthetic_v30 as s30
    synthetic+=s30.train_records('relay_forum'); hashes.update(s30.file_hashes('relay_forum'))
    oas=json.loads((bt.ROOT/'demo_backend/openapi.json').read_text(encoding='utf8'))
    demo={(mm.upper(),bt.pattern(p)) for p,ops in oas['paths'].items() for mm in ops if mm.lower() in {'get','post','put','patch','delete','head','options'}}
    candidates,lowconf,excluded,reasons=prepare(api,synthetic,demo)
    train,val,split=bt.split_rows(candidates); bt.validate(train,val,partition)
    used={r['id'] for r in train+val}; manual=[r for r in api if r['label']==MANUAL and r['id'] not in used and not machine_reasons_v30(r)]
    outputs={'train':train,'val':val,'manual_pool':manual,'lowconf_pool':lowconf,'excluded':excluded}
    for name,rows in outputs.items():bt.write_rows(DATA/OUTPUTS[name],rows)
    sample=review_sample(api,candidates+lowconf+excluded,train,val,HERE/'review_sample_v30.md',m.PROMPT.read_text(encoding='utf8'))
    def stats(rows):
        n=sum(r['meta'].get('source')=='synthetic' for r in rows)
        return dict(records=len(rows),label_distribution={l:sum(r['label']==l for r in rows) for l in LABELS},
            label_by_source={l:dict(apisguru=sum(r['label']==l and r['meta'].get('source')=='apisguru' for r in rows),synthetic=sum(r['label']==l and r['meta'].get('source')=='synthetic' for r in rows)) for l in LABELS},
            overrides=sum(bool(r['meta'].get('v30_override_reason')) for r in rows),synthetic_relabelled=sum(bool(r['meta'].get('v30_relabel_reason')) for r in rows),
            confidence_bins=dict(Counter(bt.bin_name(r['confidence']) for r in rows)),services=len({r['service'] for r in rows}),synthetic_records=n,synthetic_ratio=round(n/len(rows),4) if rows else 0,manual_ratio=round(sum(r['label']==MANUAL for r in rows)/len(rows),4) if rows else 0)
    assert guard=={p:bt.digest(p) for p in guard},'existing train/val/test changed'
    tr=stats(train); warnings=[l for l in LABELS if tr['label_distribution'][l]<30]
    report=dict(seed=42,prompt_version=m.VERSION,prompt_sha256=manifest['prompt_sha256'],input_records=len(api),input_sha256=bt.digest(source),synthetic_records=len(synthetic),synthetic_input_sha256=hashes,
        partition=partition,split_policy=split,train=tr,val=stats(val),labels_below_30_in_train=warnings,excluded=dict(reasons),legacy_filters_not_applied=legacy_filter_counts(api),
        override_policy='public with security_state=declared or non-anonymous mutation public -> manual_review_required, meta.v30_override_reason=security_declared_public (original label kept in meta.label_before_override); apisguru_labeled_v301.jsonl itself unchanged',
        manual_pool=len(manual),lowconf_pool=len(lowconf),outputs_sha256={OUTPUTS[k]:bt.digest(DATA/OUTPUTS[k]) for k in OUTPUTS},review_sample=sample,
        human_corrections_used=False,held_out_test_sources_read=False,existing_train_val_test_unchanged=True,api_manual_ratio=round(manual_ratio,4),
        service_overlap_with_test_partition=sorted(({r['service'] for r in train+val})&set(partition['test_services']+partition['test_vuln_services'])))
    bt.dump(HERE/'build_train_v30_report.json',report); return report

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--tag',default='v301');a=ap.parse_args();print(json.dumps(build(a.tag),ensure_ascii=False,indent=2)[:6000])
