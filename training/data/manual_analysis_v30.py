"""Offline analysis of prompt v3.0.1 full-run outputs: manual rationale types, security/description coverage, declared-public origin. No API calls."""
import json, re
from collections import Counter
from training.data import label_v30 as m

TYPES=[  # (name, regex) — first match wins; evaluated in this order
    ('구독·플랜·등급 조건',r'구독|플랜|등급|premium|subscription|tier'),
    ('복합 조건(AND)·단일 라벨 불가',r'복합|결합|단일 라벨|독립 (필수 )?조건|AND'),
    ('코드·의도 충돌',r'충돌'),
    ('설명 없음·비어 있음',r'설명이 (비어|없)|summary.{0,6}description 없음|description 없음|설명 없음|설명이 제공되지'),
    ('API 키만 요구',r'api.?key|API 키|apikey'),
    ('인증만 확인·인가 조건 없음',r'인증(만|은|이|을)[^;]{0,40}(인가|관계|조건)|인증이 필요하(지만|나)|인증은 선언'),
    ('security·인증 정보 없음',r'security[^;]{0,20}(없|unknown)|인증 (선언|정보)가? 없|인증 방식이 명시되지'),
    ('객체 ID만 있음',r'객체 ID만|ID만 있고|path_params[^;]*;\s*판단: (객체|요청자)'),
    ('역할·권한 조건 불명확',r'역할[^;]{0,30}(명시되지|불명확|확인할 수 없)|권한[^;]{0,20}(명시되지|불명확)'),
    ('요청자-객체 관계 미확인',r'관계[^;]{0,40}(명시되지|확인할 수 없|불확실|확정할 수 없|명확하지|불명확|부족)|관계를 확정'),
    ('접근 조건 미명시(일반)',r'접근 조건[^;]{0,30}(명시되지|명확하지|확정|불확실|부족)|조건이 (명시되지|명확하지)'),
]

def classify(text):
    t=text or ''
    for name,rx in TYPES:
        if re.search(rx,t,re.I):return name
    return '기타'

def main():
    m.configure('v301'); rows=m.read(m.FULL_FINAL); enriched={r['id']:r for r in m.read(m.INPUT)}
    manual=[r for r in rows if r['label']=='manual_review_required']
    primary=Counter(classify(r['rationale']) for r in manual)
    multi=Counter();
    for r in manual:
        for name,rx in TYPES:
            if re.search(rx,r['rationale'] or '',re.I):multi[name]+=1
    unknown=[r for r in rows if r['security_state']=='unknown']
    def desc_empty(r):
        op=enriched[r['id']]['enrichment']['operation']; return not (op.get('description') or '').strip()
    def desc_and_summary_empty(r):
        op=enriched[r['id']]['enrichment']['operation']; return not (op.get('description') or '').strip() and not (op.get('summary') or '').strip()
    unk_desc_empty=sum(desc_empty(r) for r in unknown); unk_both_empty=sum(desc_and_summary_empty(r) for r in unknown)
    unk_manual=sum(r['label']=='manual_review_required' for r in unknown)
    declared=[r for r in rows if r['security_state']=='declared']; dec_desc_empty=sum(desc_empty(r) for r in declared)
    by_state_desc={s:dict(records=sum(r['security_state']==s for r in rows),description_empty=sum(r['security_state']==s and desc_empty(r) for r in rows),
        manual=sum(r['security_state']==s and r['label']=='manual_review_required' for r in rows),
        manual_when_description_empty=sum(r['security_state']==s and desc_empty(r) and r['label']=='manual_review_required' for r in rows),
        manual_when_description_present=sum(r['security_state']==s and not desc_empty(r) and r['label']=='manual_review_required' for r in rows)) for s in ('declared','unknown','explicitly_anonymous')}
    dp=[r for r in rows if r['label']=='public' and r['security_state']=='declared']
    origin=Counter(enriched[r['id']]['enrichment']['security']['origin'] for r in dp)
    origin_all_declared=Counter(enriched[r['id']]['enrichment']['security']['origin'] for r in declared)
    dp_anon_alt=sum(bool(enriched[r['id']]['enrichment']['security'].get('anonymous_alternative')) for r in dp)
    dp_desc_empty=sum(desc_empty(r) for r in dp)
    dp_rationale=Counter(classify_public(r['rationale']) for r in dp)
    out=dict(manual_records=len(manual),primary_types=primary.most_common(),multi_label_type_counts=multi.most_common(),
        security_unknown=dict(records=len(unknown),description_empty=unk_desc_empty,description_empty_ratio=round(unk_desc_empty/len(unknown),4),description_and_summary_empty=unk_both_empty,manual=unk_manual),
        security_declared=dict(records=len(declared),description_empty=dec_desc_empty),by_security_state_description=by_state_desc,
        declared_public=dict(records=len(dp),security_origin=dict(origin),origin_distribution_all_declared=dict(origin_all_declared),anonymous_alternative=dp_anon_alt,description_empty=dp_desc_empty,rationale_types=dp_rationale.most_common()))
    (m.FOUT/'manual_analysis.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf8')
    t='# manual_review_required 원인 분석 — 프롬프트 v3.0.1 전체 2,027건 (API 호출 없음)\n\n'
    t+=f'rationale 문장을 정규식 규칙으로 유형화했다(첫 일치 유형을 주 유형으로 집계, 규칙 순서는 스크립트 TYPES). 모델이 쓴 문장 기반이므로 근사치다. manual {len(manual)}건.\n\n## 1. manual rationale 상위 유형 (주 유형)\n\n| 순위 | 유형 | 건수 | 비율 |\n|---:|---|---:|---:|\n'
    for i,(k,v) in enumerate(primary.most_common(10),1):t+=f'| {i} | {k} | {v} | {v/len(manual):.1%} |\n'
    t+='\n중복 허용 집계(한 rationale이 여러 유형에 해당 가능):\n\n| 유형 | 건수 |\n|---|---:|\n'+''.join(f'| {k} | {v} |\n' for k,v in multi.most_common())
    t+=f"\n## 2. security_state=unknown {len(unknown)}건\n\n- operation description 비어 있음: {unk_desc_empty}건 ({unk_desc_empty/len(unknown):.1%}); description·summary 모두 비어 있음: {unk_both_empty}건.\n- manual 판정: {unk_manual}건 ({unk_manual/len(unknown):.1%}).\n\n"
    t+='security_state × description 유무별 manual:\n\n| security_state | 건수 | description 없음 | manual(설명 없음 중) | manual(설명 있음 중) |\n|---|---:|---:|---:|---:|\n'
    for s,d in by_state_desc.items():
        pres=d['records']-d['description_empty']
        t+=f"| {s} | {d['records']} | {d['description_empty']} | {d['manual_when_description_empty']}/{d['description_empty']} | {d['manual_when_description_present']}/{pres} |\n"
    t+=f"\n## 3. declared public {len(dp)}건의 security 출처\n\n| security.origin | 건수 |\n|---|---:|\n"+''.join(f'| {k} | {v} |\n' for k,v in origin.most_common())
    t+=f"\n참고: declared 전체 {len(declared)}건의 origin 분포 {dict(origin_all_declared)}. declared public 중 anonymous_alternative=true {dp_anon_alt}건, description 비어 있음 {dp_desc_empty}건.\n\n"
    t+='declared public rationale 유형:\n\n| 유형 | 건수 |\n|---|---:|\n'+''.join(f'| {k} | {v} |\n' for k,v in dp_rationale.most_common())
    t+=f"\n해석: origin=global({origin.get('global',0)}건, {origin.get('global',0)/len(dp):.1%})은 spec 전역 security만 있고 operation 레벨 선언이 없는 경우로, 모델이 전역 선언을 해당 operation의 인증 요구로 반영하지 않은 사례다. origin=operation({origin.get('operation',0)}건)은 operation 자체에 security가 있는데도 public을 고른 명백한 규칙 위반이다. rationale 유형을 보면 {dp_rationale.most_common(1)[0][1]}건이 '공개·누구나' 류의 설명 문구를 근거로 삼았다. 두 경우 모두 train_v30에서는 override(manual)로 처리했다.\n\n원자료: manual_analysis.json, apisguru_labeled_v301.jsonl, apisguru_enriched_v2.jsonl(enrichment.security.origin, operation.description).\n"
    (m.FOUT/'manual_analysis.md').write_text(t,encoding='utf8'); print(t)

PUBLIC_TYPES=[('공개 문서·카탈로그 설명 근거',r'공개|public|누구나|anonymous|익명'),('인증 불필요로 해석',r'인증(이|은)? (필요 ?없|요구되지|불필요)|without auth'),('security 배열 비어 있음·없음 근거',r'security[^;]{0,20}(비어|없|empty|\[\])'),('조회·목록 성격 근거',r'조회|목록|list|read')]
def classify_public(text):
    for name,rx in PUBLIC_TYPES:
        if re.search(rx,text or '',re.I):return name
    return '기타'

if __name__=='__main__':main()
