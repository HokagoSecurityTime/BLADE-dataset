"""Validate authored policy-only decisions and publish the 100-record pilot."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from common.labels import Label

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'training/data'
DATA = ROOT / 'datasets/blade/processed'
OBJECT = {'owner_match', 'owner_or_admin', 'tenant_match'}


def read(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def validate(row, decision):
    required = {'id','label','confidence','rationale','policy_status','evidence_strength',
        'object_param','owner_lookup','lookup_status','lookup_reason','roles','allowed_membership','evidence'}
    if not required <= decision.keys():
        raise ValueError('Missing decision fields: '+str(required-decision.keys()))
    if row['id'] != decision['id'] or decision['label'] not in {item.value for item in Label}:
        raise ValueError('Invalid ID/label')
    if type(decision['confidence']) not in (int,float) or not 0 <= decision['confidence'] <= 1:
        raise ValueError('Invalid confidence')
    if decision['policy_status'] not in {'supported','ambiguous','insufficient_evidence','conflict'}:
        raise ValueError('Invalid policy status')
    if decision['evidence_strength'] not in {'explicit','corroborated','heuristic_only','absent'}:
        raise ValueError('Invalid evidence strength')
    if not decision['rationale'].strip() or not decision['lookup_reason'].strip():
        raise ValueError('Missing rationale/reason')
    facts = {fact['json_pointer']:fact['text'] for fact in row['enrichment'].get('facts',[])}
    for evidence in decision['evidence']:
        if not evidence['quote'] or evidence['quote'] not in facts.get(evidence['pointer'],''):
            raise ValueError('Citation mismatch: '+str(evidence))
    if decision['label'] != 'manual_review_required':
        if decision['policy_status'] != 'supported' or decision['evidence_strength'] not in {'explicit','corroborated'} or not decision['evidence']:
            raise ValueError('Concrete label lacks supporting evidence')
    elif decision['policy_status'] == 'supported':
        raise ValueError('Manual label must state ambiguity/conflict/missing evidence')
    # This corpus contains no independently verified database mappings.
    if decision['owner_lookup'] is not None:
        raise ValueError('Unverified lookup forbidden in this pilot')
    expected = 'unresolved' if decision['label'] in OBJECT else 'not_applicable'
    if decision['lookup_status'] != expected:
        raise ValueError('Lookup status inconsistent with policy')
    if decision['object_param'] is not None:
        import re
        oas = json.loads(row['oas_snippet'])
        params = set(oas.get('path_params') or []) | set(oas.get('query_params') or [])
        params.update(re.findall(r'\{([^{}]+)\}',row['path']))
        if decision['object_param'] not in params:
            raise ValueError('Invented request parameter')
    if decision['label'] not in OBJECT and decision['object_param'] is not None:
        raise ValueError('Non-object label has object parameter')
    for field in ('roles','allowed_membership'):
        if not isinstance(decision[field],list) or any(not isinstance(v,str) or not v for v in decision[field]):
            raise ValueError('Invalid policy conditions')
    if decision['label'] in {'role_required','owner_or_admin'} and not decision['roles']:
        raise ValueError('Missing roles')
    if decision['label'] == 'membership_required' and not decision['allowed_membership']:
        raise ValueError('Missing membership condition')


def main():
    destinations = [DATA/'apisguru_policy_pilot_v2.jsonl',OUT/'review_sample_v2.md',OUT/'pilot_comparison_v2.md',OUT/'pilot_comparison_v2.json']
    if any(path.exists() for path in destinations):
        raise ValueError('Refuse overwrite of pilot/review outputs')
    manifest = json.loads((OUT/'pilot_v2_ids.json').read_text(encoding='utf-8'))
    ids = manifest['ids']
    rows = {r['id']:r for r in read(DATA/'apisguru_enriched_v2.jsonl')}
    decisions = {}
    for shard in range(3):
        values=read(OUT/f'policy_pilot_decisions/shard{shard}.jsonl')
        if {v['id'] for v in values} != set(ids[shard::3]) or len(values)!=len(ids[shard::3]):
            raise ValueError('Shard coverage mismatch')
        for value in values:
            validate(rows[value['id']],value)
            decisions[value['id']]=value
    now=datetime.now(timezone.utc).isoformat()
    prompt_hash=hashlib.sha256((OUT/'prompts/policy_label_v2.2.md').read_bytes()).hexdigest()
    results=[]
    for id_ in ids:
        row=rows[id_]
        decision=decisions[id_]
        record={**row,**decision,'model_id':'codex-agent-unreported','prompt_version':'policy-label-v2.2',
            'labeled_at':now,'training_eligibility':'pending_review','human_review':{'status':'pending'},
            'label_source':'interactive_codex_agent','prompt_sha256':prompt_hash}
        record['meta']={**row['meta'],'low_conf':decision['confidence']<.6,'label_error':False,
            'confidence_calibrated':False,'exact_api_prompt_replay':False}
        record['evidence']=[{**e,'source_file':row['enrichment']['source_file'],
            'source_sha256':row['enrichment']['source_sha256']} for e in decision['evidence']]
        results.append(record)
    old={r['id']:r for r in read(DATA/'apisguru_agent_labeled.jsonl')}
    counts=Counter(r['label'] for r in results)
    transitions=Counter((old[r['id']]['label'],r['label']) for r in results)
    promoted=sum(old[r['id']]['label']=='manual_review_required' and r['label']!='manual_review_required' for r in results)
    report={'records':len(results),'labels':{label.value:counts[label.value] for label in Label},
        'transitions':[{'old':a,'new':b,'count':n} for (a,b),n in sorted(transitions.items())],
        'previous_manual':sum(old[r['id']]['label']=='manual_review_required' for r in results),
        'agent_proposed_promotions':promoted,'human_confirmed_promotions':None,'human_error_rate':None,
        'lookup_unresolved':sum(r['lookup_status']=='unresolved' for r in results),
        'low_conf':sum(r['meta']['low_conf'] for r in results),'api_calls':0,'human_reviewed':0,
        'selection_bias':'21 prior concrete labels plus 79 stratified prior manual, including mandatory BigOven cases; not population-random'}
    destinations[0].write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in results),encoding='utf-8')
    def cell(value):return str(value).replace('|','\\|').replace('\n','<br>').replace('\r','')
    lines=['# v2 pilot human review — 100 records','',
        'All labels are agent proposals. Review source quotations. Fill corrected label and reason; blank does not mean confirmed. Existing v1 review is untouched.','',
        '| id | service | method | path | label | status | confidence | lookup_status | source evidence | rationale | 검수 라벨 | 검수 사유 |',
        '|---|---|---|---|---|---|---:|---|---|---|---|---|']
    for r in results:
        evidence='; '.join(e['source_file']+' '+e['pointer']+' → '+e['quote'] for e in r['evidence']) or '(No sufficient explicit policy evidence)'
        vals=[r['id'],r['service'],r['method'],r['path'],r['label'],r['policy_status'],r['confidence'],r['lookup_status'],evidence,r['rationale']]
        lines.append('| '+' | '.join(map(cell,vals))+' |  |  |')
    destinations[1].write_text('\n'.join(lines)+'\n',encoding='utf-8')
    destinations[3].write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    text=['# v2 파일럿 재라벨링 결과','',f'100건 검토, 외부 API 호출 0회. 기존 보류 79건 중 구체 정책 제안 {promoted}건. **사람 확인 전이며 정확도·오라벨률은 미측정**.','',
        '| label | count |','|---|---:|',*[f'| {k} | {v} |' for k,v in report['labels'].items()], '',
        f'lookup unresolved: {report["lookup_unresolved"]}; low_conf: {report["low_conf"]}. 모든 레코드는 pending_review이며 실행 정책·학습·분할에 사용하지 않았다.','',
        '정책 라벨과 물리 조회 설정을 분리했다. 객체 정책이 있어도 검증된 DB 관계가 없어 owner_lookup은 null이며, 이는 새 데이터 계약에서 의도된 상태다. 런타임 계약은 변경하지 않았다.','',
        '21건의 기존 구체 라벨 + 신호별 보류 79건(명시적 BigOven 사례 우선 포함)으로 선정한 의도적 파일럿이다. 보류 감소를 모집단 정확도 상승으로 해석하지 않는다. 원문 인용 일치는 기계적으로 검사했지만 의미 해석은 사람 검수가 필요하다.','',
        'review_sample_v2.md 100건 검수 후 전체 확대를 결정한다. 기존 결과와 비교한 상세 전이는 pilot_comparison_v2.json에 있다. 기존 원본·라벨·검수표·런타임 프롬프트는 보존한다.']
    destinations[2].write_text('\n'.join(text)+'\n',encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False,indent=2))


if __name__=='__main__':main()
