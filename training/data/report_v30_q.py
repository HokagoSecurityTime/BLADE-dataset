"""Build the Q-stage report for prompt v3.0 from saved metrics/predictions. No API calls."""
import json
from pathlib import Path
from training.data import label_v30 as m

OUT=m.QOUT; LABELS=m.LABELS

def table(rows,header):
    return '| '+' | '.join(header)+' |\n|'+'|'.join('---' if i==0 else '---:' for i in range(len(header)))+'|\n'+''.join('| '+' | '.join(str(c) for c in r)+' |\n' for r in rows)

def prf_table(block):
    return table([[l,v['support'],v['precision'],v['recall'],v['f1']] for l,v in block['per_label'].items()],['label','support','P','R','F1'])+f"\nmacro-F1(support 있는 {len(block['supported_labels'])}종: {', '.join(block['supported_labels'])}) = {block['macro_f1_supported']}\n"

def confusion(block):
    cols=LABELS+['output_error']
    return '| 정답 \\ 예측 | '+' | '.join(cols)+' |\n|---|'+'---:|'*len(cols)+'\n'+''.join('| '+a+' | '+' | '.join(str(block['confusion'][a][b]) for b in cols)+' |\n' for a in LABELS)

def compare_section(cur_tag,base_tag):
    """Side-by-side Q comparison of two prompt versions on the identical 42 x 2 inputs."""
    rows=[]; data={}
    for tag in (base_tag,cur_tag):
        d=m.ROOT/f'reports/eval/classification_quality/prompt_{tag}_q'; met=json.loads((d/'metrics.json').read_text(encoding='utf8'))
        preds=m.read(d/'predictions_oas_code.jsonl'); data[tag]=(met,preds)
    base_inputs=m.digest(m.ROOT/f'reports/eval/classification_quality/prompt_{base_tag}_q/inputs.jsonl'); cur_inputs=m.digest(m.ROOT/f'reports/eval/classification_quality/prompt_{cur_tag}_q/inputs.jsonl')
    for tag,(met,preds) in data.items():
        for c in m.CONDITIONS:
            x=met[c]; ps=m.read(m.ROOT/f'reports/eval/classification_quality/prompt_{tag}_q'/f'predictions_{c}.jsonl')
            vuln_public=sum(p['vulnerable'] and p['label']=='public' for p in ps); normal_ok=sum((not p['vulnerable']) and p['label']==p['expected_v30'] for p in ps); normal_n=sum(not p['vulnerable'] for p in ps)
            rows.append([f'{m.TAGS[tag]} / {c}',f"{x['agreement_expected_v30']:.1%}",f"{x['agreement_expected_v30_code']:.1%}",vuln_public,f'{normal_ok}/{normal_n}',f"{x['manual_ratio']:.1%}",x['vs_expected_v30']['macro_f1_supported']])
    t='## v3.0 대비 비교 (같은 42건 × 2조건)\n\n'
    t+=f'입력 동일성: v3.0 inputs SHA `{base_inputs}` / 현재 inputs SHA `{cur_inputs}` → {"동일" if base_inputs==cur_inputs else "상이"}.\n\n'
    t+=table(rows,['버전 / 조건','v3.0 보정 일치','구현 기준 일치','취약 변형 15건 public 오판','정상 구현 27건 일치','manual 비율','macro-F1(보정)'])
    cur=data[cur_tag][1]; base={p['id']:p for p in data[base_tag][1]}
    changed=[(p['id'],base[p['id']]['label'],p['label'],p['expected_v30']) for p in cur if base[p['id']]['label']!=p['label']]
    t+=f'\noas_code 라벨이 바뀐 건 {len(changed)}건:\n\n'+table(changed,['id','v3.0','현재','expected_v30']) if changed else '\noas_code 라벨 변화 없음.\n'
    return t+'\n'

def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument('--tag',choices=sorted(m.TAGS),default='v30'); ap.add_argument('--compare'); a=ap.parse_args()
    m.configure(a.tag); global OUT; OUT=m.QOUT
    metrics=json.loads((OUT/'metrics.json').read_text(encoding='utf8')); manifest=json.loads((OUT/'manifest.json').read_text(encoding='utf8'))
    preds={c:m.read(OUT/f'predictions_{c}.jsonl') for c in m.CONDITIONS}
    u=metrics['usage']
    t=f'# 프롬프트 {m.TAGS[a.tag]} 품질 확인(Q) — 사람 라벨 없는 합성 train 전용 셋\n\n'
    if a.compare:t+=compare_section(a.tag,a.compare)
    t+=f"실행 {manifest['started_at'][:19]}Z, 모델 {manifest['model']}, temperature 0. 프롬프트 SHA `{manifest['prompt_sha256']}`, 입력 SHA `{manifest['inputs_sha256']}`, 검증기 v1 SHA `{manifest['guard_sha256']}`. 사람 교정 미사용, test.jsonl·test 전용 합성 미접근.\n\n"
    t+=f"API 응답 {u['api_responses']}회, 입력 {u['input_tokens']:,}토큰(캐시 {u['cached_input_tokens']:,}), 출력 {u['output_tokens']:,}토큰, 사용량 기준 추정 ${u['estimated_usd']} (청구서 아님).\n\n"
    t+='## 확인용 셋\n\ntrain 전용 합성 3개 서비스(orbit_tickets·copper_wallet·campus_records) 42건. 전 건 intended_labels와 핸들러 코드 보유. 두 입력 조건: `oas`(명세만), `oas_code`(명세 + 핸들러 원문을 description에 포함).\n\n'
    t+='기대 라벨 세 가지를 구분한다.\n- **intended**: intended_labels.yaml 원본.\n- **expected_v30**: v3.0 정의 보정 — subscription(premium plan) 6건은 manual_review_required.\n- **expected_v30_code**: 구현 기준 — archive 변형 15건(vulnerable=true)은 인증만 하고 인가 검사가 없어 코드만으로는 manual_review_required가 v3.0 정답.\n\n'
    t+='## 요약\n\n'
    rows=[]
    for c in m.CONDITIONS:
        x=metrics[c]; rows.append([c,f"{x['agreement_intended']:.1%}",f"{x['agreement_expected_v30']:.1%}",f"{x['agreement_expected_v30_code']:.1%}",f"{x['manual_ratio']:.1%}",x['mean_inference_ms'],x['label_errors'],x['evidence_invalid']])
    t+=table(rows,['조건','intended 일치','expected_v30 일치','expected_v30_code 일치','manual 비율','평균 ms','출력 오류','evidence 오류'])
    g=metrics['gate']; t+=f"\n중단 기준(60%): oas_code의 expected_v30 일치율 {metrics['oas_code']['agreement_expected_v30']:.1%} → **{'통과' if g['passed'] else '미달'}**. 기준 선택 근거: {g['basis']}\n\n"
    x=metrics['oas_code']['agreement_expected_v30_by_vulnerable']; t+=f"oas_code expected_v30 일치율을 변형별로 보면 정상 구현 27건 {x['False']:.1%}, 취약 변형 15건 {x['True']:.1%}.\n\n"
    for c in m.CONDITIONS:
        x=metrics[c]
        t+=f'## {c}: label별 P/R/F1 (기준 expected_v30)\n\n'+prf_table(x['vs_expected_v30'])+'\n혼동행렬:\n\n'+confusion(x['vs_expected_v30'])+'\n'
        if c=='oas_code':
            t+='### oas_code: 기준 expected_v30_code(구현 기준)\n\n'+prf_table(x['vs_expected_v30_code'])+'\n'
        t+=f"confidence 구간: {x['confidence_bins']}\n\n"
    gd=metrics['oas_code']['guard']
    t+='## 적용 검증기 v1 (oas_code 결과에 적용)\n\n'
    t+=table([[k,v] for k,v in gd['reasons'].items()],['검증기 판정','건수'])+'\n'
    t+=table([[k,v] for k,v in gd['bridge_reasons'].items()],['코드→fixture 변환 상태','건수'])+'\n'
    t+=f"올바른 구체 라벨(구현 기준) {gd['correct_concrete']}건 중 차단 {gd['correct_concrete_blocked']}건, 틀린 구체 라벨 통과 {gd['wrong_concrete_passed']}건.\n\n"
    t+='한계: (1) 검증기 v1 fixture 문법에는 "인증만" 상태가 없어 취약 변형 15건은 평가 불가(보류). (2) v1은 role_required를 operator 역할 원자에 고정하므로 admin 역할을 요구하는 audit 건은 올바른 role_required도 차단으로 표시된다. 변환기(bridge)는 합성 세 템플릿 전용이며 검증기 코드는 수정하지 않았다.\n\n'
    vuln_public=sum(p['vulnerable'] and p['label']=='public' for p in preds['oas_code']); vuln_n=sum(p['vulnerable'] for p in preds['oas_code'])
    t+=f'## 알려진 한계 (사용자 확인 2026-10-21)\n\n코드 입력 시 인증만 있고 인가 검사 없는 핸들러를 public으로 오판({vuln_public}/{vuln_n}). 인증이 핸들러 밖(데코레이터·의존성)에 있을 때 발생 추정. 이번 단계에서는 허용하며 프롬프트는 v3.0.1로 고정한다.\n\n'
    t+='## 전체 결과\n\n| id | vulnerable | intended | expected_v30 | expected_v30_code | oas | oas_code | conf(oas_code) | 검증기 |\n|---|---|---|---|---|---|---|---:|---|\n'
    oas={p['id']:p for p in preds['oas']}
    for p in preds['oas_code']:
        o=oas[p['id']]; t+=f"| {p['id']} | {p['vulnerable']} | {p['intended_label']} | {p['expected_v30']} | {p['expected_v30_code']} | {o['label']} | {p['label']} | {p['confidence']} | {p['guard']['reason']} |\n"
    t+='\n## 불일치 근거(oas_code, expected_v30 기준)\n\n'
    for p in preds['oas_code']:
        if p['label']!=p['expected_v30']:t+=f"- **{p['id']}** 기대 {p['expected_v30']} / 출력 {p['label']} ({p['confidence']}): {p['rationale']}\n"
    t+='\n원자료: inputs.jsonl, predictions_oas.jsonl, predictions_oas_code.jsonl, raw_responses.jsonl, usage.jsonl, metrics.json, manifest.json, estimate.json.\n'
    (OUT/'report.md').write_text(t,encoding='utf8'); print('written',OUT/'report.md')

if __name__=='__main__':main()
