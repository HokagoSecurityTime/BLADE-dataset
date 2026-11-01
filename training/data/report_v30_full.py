"""Build the full-stage (F) report for a prompt v3.x run from saved outputs. No API calls."""
import json
from training.data import label_v30 as m

LABELS=m.LABELS

def table(rows,header):
    return '| '+' | '.join(header)+' |\n|'+'|'.join('---' if i==0 else '---:' for i in range(len(header)))+'|\n'+''.join('| '+' | '.join(str(c) for c in r)+' |\n' for r in rows)

def main():
    import argparse
    ap=argparse.ArgumentParser(); ap.add_argument('--tag',choices=sorted(m.TAGS),default='v301'); a=ap.parse_args(); m.configure(a.tag)
    rep=json.loads((m.HERE/f'label_report_{a.tag}.json').read_text(encoding='utf8')); man=json.loads((m.DATA/f'labeled_{a.tag}.manifest.json').read_text(encoding='utf8'))
    rows=m.read(m.FULL_FINAL); n=len(rows); u=rep['usage']
    t=f"# 전체 재라벨링(F) — 프롬프트 {m.TAGS[a.tag]}, APIs.guru 2,027건\n\n"
    t+=f"실행 완료 {man['completed_at'][:19]}Z. 모델 {man['model']}, temperature 0. 프롬프트 SHA `{man['prompt_sha256']}`, 입력 SHA `{man['input_sha256']}` (apisguru_enriched_v2.jsonl, v2.5와 동일 입력), 출력 `{m.FULL_FINAL.name}` SHA `{man['output_sha256']}`, 레코드 {man['records']}. 사람 교정 미사용, test.jsonl 미접근.\n\n"
    t+=f"API 응답 {u['api_responses']}회, 입력 {u['input_tokens']:,}토큰(캐시 {u['cached_input_tokens']:,}), 출력 {u['output_tokens']:,}토큰, 사용량 기준 추정 ${u['estimated_usd']} (청구서 아님). 평균 추론 {rep['mean_inference_ms']} ms. 출력 오류 {rep['label_errors']}건, evidence 참조 오류 {rep['evidence_invalid']}건, 비익명 mutation public(flag_review) {rep['flag_review']}건.\n\n"
    t+='## label 분포\n\n'+table([[l,c,f'{c/n:.1%}'] for l,c in rep['labels'].items()],['label','건수','비율'])
    t+=f"\n**manual_review_required 비율 {rep['manual_ratio']:.2%}** → 70% 기준 {'초과: train_v30 생성 보류' if rep['train_build_blocked_manual_ratio_above_70_percent'] else '이하: train_v30 생성 가능'}.\n\n"
    t+='## security 선언 여부별 label 분포\n\n'
    states=list(rep['by_security_state'].keys())
    t+='| security_state | 건수 | '+' | '.join(LABELS)+' | manual 비율 |\n|---|---:|'+'---:|'*len(LABELS)+'---:|\n'
    for s in states:
        d=rep['by_security_state'][s]; tot=sum(d.values())
        t+=f'| {s} | {tot} | '+' | '.join(str(d[l]) for l in LABELS)+f" | {d['manual_review_required']/tot:.1%} |\n"
    t+=f"\n**public으로 판정된 건 중 security_state=declared: {rep['public_with_security_declared']}건** (public 전체 {rep['labels']['public']}건).\n"
    if rep['public_with_security_declared_ids']:t+='\n'+'\n'.join('- '+i for i in rep['public_with_security_declared_ids'][:50])+('\n- …' if len(rep['public_with_security_declared_ids'])>50 else '')+'\n'
    t+='\n## confidence 구간\n\n'+table([[k,v,f'{v/n:.1%}'] for k,v in rep['confidence'].items()],['구간','건수','비율'])
    t+='\n## v2.5 → 현재 라벨 전이 (행=v2.5, 열=현재)\n\n| v2.5 \\ 현재 | '+' | '.join(LABELS)+' |\n|---|'+'---:|'*7+'\n'
    for a_ in LABELS:t+='| '+a_+' | '+' | '.join(str(rep['transitions'][a_][b]) for b in LABELS)+' |\n'
    t+='\n## 알려진 한계 (사용자 확인 2026-10-21)\n\n- 코드 입력 시 인증만 있고 인가 검사 없는 핸들러를 public으로 오판(Q 재실행 6/15). 인증이 핸들러 밖(데코레이터·의존성)에 있을 때 발생 추정. 프롬프트는 v3.0.1로 고정.\n'
    t+=f"- 프롬프트 v3.0.1은 security 선언 시 public을 금지하지만, 위와 같이 security_state=declared인 public 판정이 {rep['public_with_security_declared']}건 남았다. spec 전역 security 선언을 모델이 해당 operation의 인증 요구로 반영하지 않은 것으로 보이며, train 구성 시 기계 필터(public_declared)로 제외 대상이다.\n"
    t+='\n## 참고 중단 조건(v2.5 파일럿 규칙, 보고만)\n\n'+(', '.join(rep['stop_reasons']) if rep['stop_reasons'] else '해당 없음')+'\n'
    t+='\n원자료: '+m.FULL_FINAL.name+', labeled_'+a.tag+'.manifest.json, training/data/label_report_'+a.tag+'.{json,md}, reports/eval/classification_quality/prompt_'+a.tag+'_full/{raw_responses,usage}.jsonl.\n'
    out=m.FOUT/'report.md'; out.write_text(t,encoding='utf8'); print('written',out)

if __name__=='__main__':main()
