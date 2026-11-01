"""Import the authorized human corrections without reading held-out test data."""
import json, random
from collections import Counter
from pathlib import Path
from training.data.xlsx_review import sheets
from training.data import label_v5 as v5

WORKBOOK=Path('<USERPROFILE>/Downloads/review/review_sample_v5.xlsx')
def prepare():
    old={r['id']:r for r in v5.read(v5.DATA/'apisguru_labeled_v5_openai.jsonl')}
    records=[r for rs in sheets(WORKBOOK).values() for r in rs if r.get('F') in v5.LABELS and r.get('A') not in ('id','---')]
    corrections=[]
    for r in records:
        if r.get('J') in v5.LABELS and r['J']!=r['F']:
            assert old[r['A']]['label']==r['F']
            corrections.append(dict(id=r['A'],original_label=r['F'],corrected_label=r['J'],reason=r.get('K','')))
    assert len(records)==137 and len(corrections)==61
    path=v5.HERE/'human_corrections_v5.jsonl'
    path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in corrections),encoding='utf8')
    ordered=sorted(corrections,key=lambda r:r['id']);random.Random(42).shuffle(ordered)
    shots,held=ordered[:30],ordered[30:]
    counts=Counter(r['F'] for r in records); errors=Counter(r['original_label'] for r in corrections)
    report=dict(reviewed=137,corrected=61,workbook_sha256=v5.digest(WORKBOOK),seed=42,fewshot_ids=[r['id'] for r in shots],validation_ids=[r['id'] for r in held],reviewed_ids=[r['A'] for r in records],label_errors={k:dict(reviewed=counts[k],corrected=errors[k],error_rate=errors[k]/counts[k] if counts[k] else 0) for k in v5.LABELS})
    v5.dump(v5.HERE/'human_corrections_v5_split.json',report)
    titles=['security 선언됨 → public 아님','계정/회사 스코프 → tenant','admin 명시 없음 → owner','plan 언급만으로 membership 아님','사용자 스코프 있으면 보류 말고 owner','기타 사람 교정']
    groups={k:[] for k in titles}
    for r in shots:
        a,b=r['original_label'],r['corrected_label']
        key=titles[1] if b=='tenant_match' else titles[2] if a=='owner_or_admin' else titles[3] if a=='membership_required' else titles[4] if a=='manual_review_required' and b=='owner_match' else titles[0] if a=='public' else titles[5]
        groups[key].append(r)
    text=v5.PROMPT.read_text(encoding='utf8'); start=text.index('Few-shot ');end=text.index('JSON 객체',start)
    examples=['Few-shot: 사람 교정 30건 (원 label → 수정 label → 사유). 실제 현재 입력만 판단하고 예시의 필드를 현재 입력 근거로 인용하지 않는다.']
    for name,rows in groups.items():
        if not rows:continue
        examples+=['','### '+name]
        for r in rows:
            value=v5.payload(old[r['id']])
            examples+=['입력: '+json.dumps(value,ensure_ascii=False),'교정: '+r['original_label']+' → '+r['corrected_label']+' → '+r['reason']]
    target=v5.HERE/'prompts/policy_label_v2.6.md'
    target.write_text(text[:start]+'\n'.join(examples)+'\n\n'+text[end:],encoding='utf8')
    assert target.read_text(encoding='utf8').split('Few-shot:')[0]==text[:start]
    assert target.read_text(encoding='utf8').split('JSON 객체',1)[1]==text.split('JSON 객체',1)[1]
    # Match each held-out (old label, confidence bin) stratum proportionally.
    strata=Counter((old[r['id']]['label'],v5.bin_index(old[r['id']]['confidence'])) for r in held)
    banned={r['id'] for r in corrections}; rng=random.Random(42);extra=[]
    allocation={k:int(169*n/31) for k,n in strata.items()}
    for k in sorted(strata,key=lambda k:(-(169*strata[k]/31-allocation[k]),k))[:169-sum(allocation.values())]:allocation[k]+=1
    shortages={}
    for k,n in sorted(allocation.items()):
        pool=sorted([r['id'] for r in old.values() if r['id'] not in banned and (r['label'],v5.bin_index(r['confidence']))==k])
        take=min(n,len(pool));extra+=rng.sample(pool,take)
        if take<n:shortages[str(k)]=n-take
    # Sparse strata redistribute only within the held-out label/bin strata.
    pool=sorted([r['id'] for r in old.values() if r['id'] not in banned|set(extra) and (r['label'],v5.bin_index(r['confidence'])) in strata])
    extra+=rng.sample(pool,169-len(extra))
    v5.dump(v5.HERE/'pilot_v6_ids.json',dict(seed=42,ids=[r['id'] for r in held]+extra,validation_ids=[r['id'] for r in held],fewshot_ids=[r['id'] for r in shots],stratum_shortages=shortages))
    return report
if __name__=='__main__':print(json.dumps(prepare(),ensure_ascii=True,indent=2))
