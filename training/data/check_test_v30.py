"""T. Read-only check of frozen test.jsonl membership_required / tenant_match records against the v3.0 definitions.
Never writes to test.jsonl. Not imported by any train-building code."""
import hashlib, json, re
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[2]; TEST=ROOT/'datasets/blade/processed/test.jsonl'
FROZEN='bd22c2580c2ddc2154974f76aa9e7aa2ca30bc6f8434e4960f3d3966093977fa'
OUT=ROOT/'reports/eval/classification_quality/test_v30_check'
SUBSCRIPTION=re.compile(r'premium|plan|subscription|tier|paid',re.I); GROUP=re.compile(r'member|group|team|roster',re.I); TENANT=re.compile(r'tenant|organi[sz]ation|org\b',re.I)

def main():
    data=TEST.read_bytes(); assert hashlib.sha256(data).hexdigest()==FROZEN,'test.jsonl hash mismatch'
    rows=[json.loads(x) for x in data.decode('utf8').splitlines() if x.strip()]
    targets=[r for r in rows if r['label'] in ('membership_required','tenant_match')]
    intended={}
    for svc in sorted({r['service'] for r in targets}):
        p=ROOT/'datasets/blade/raw/synthetic'/svc/'intended_labels.yaml'
        if p.exists():
            for ep in yaml.safe_load(p.read_text(encoding='utf8'))['endpoints']:intended[ep['id']]=ep
    findings=[]
    for r in targets:
        ep=intended.get(r['id'],{}); reason=ep.get('reason') or r.get('rationale') or ''
        code=(r.get('controller_signals') or {}).get('raw_snippet','')
        if r['label']=='membership_required':
            if SUBSCRIPTION.search(reason) or re.search(r'plan|premium|subscription',code,re.I):
                verdict,v30='불일치','manual_review_required'; why='구독·플랜 조건(v3.0: 그룹 구성원 관계가 아니므로 보류)'
            elif GROUP.search(reason) or re.search(r'member|group',code,re.I):verdict,v30='일치','membership_required';why='그룹 구성원 관계'
            else:verdict,v30='미확정','?';why='근거에 그룹 구성원 관계가 명시되지 않음'
        else:
            if TENANT.search(reason) or re.search(r'tenant',code,re.I):verdict,v30='일치','tenant_match';why='요청자·객체 tenant 일치'
            else:verdict,v30='미확정','?';why='근거에 tenant 일치가 명시되지 않음'
        findings.append(dict(id=r['id'],service=r['service'],method=r['method'],path=r['path'],test_label=r['label'],source=r.get('meta',{}).get('source'),
            intended_reason=reason,code_guard=next((l.strip() for l in code.splitlines() if re.search(r'403|FORBIDDEN',l)),''),verdict=verdict,v30_label=v30,why=why))
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'findings.json').write_text(json.dumps(dict(test_sha256=FROZEN,records_checked=len(findings),findings=findings),ensure_ascii=False,indent=2),encoding='utf8')
    n_mis=sum(f['verdict']=='불일치' for f in findings); n_ok=sum(f['verdict']=='일치' for f in findings); n_un=len(findings)-n_mis-n_ok
    t='# T. frozen test.jsonl의 membership_required·tenant_match를 v3.0 정의와 대조 (읽기 전용)\n\n'
    t+=f"test.jsonl SHA-256 `{FROZEN}` 확인. 대상 {len(findings)}건(membership_required {sum(f['test_label']=='membership_required' for f in findings)}, tenant_match {sum(f['test_label']=='tenant_match' for f in findings)}). 전부 test 전용 합성 서비스이며 intended_labels.yaml의 reason과 핸들러 코드의 403 조건으로 대조했다. test.jsonl은 수정하지 않았다.\n\n"
    t+=f'결과: 일치 {n_ok}, 불일치 {n_mis}, 미확정 {n_un}. (test 레코드에는 핸들러 원문이 없어 intended reason 기준으로 판정했다.)\n\n| id | service | test label | intended reason | 판정 | v3.0 기준 라벨 | 근거 |\n|---|---|---|---|---|---|---|\n'
    for f in findings:t+=f"| {f['id']} | {f['service']} | {f['test_label']} | {f['intended_reason']} | {f['verdict']} | {f['v30_label']} | {f['why']} |\n"
    if n_mis:
        t+=f'\n## test_v30.jsonl 별도 생성 계획(제안만, 미실행)\n\n- test.jsonl은 그대로 둔다(해시 고정).\n- `datasets/blade/processed/test_v30.jsonl`을 새로 만들되, 위 불일치 {n_mis}건만 label을 v3.0 기준(manual_review_required)으로 바꾸고 `meta.v30_relabel_reason`에 사유를 기록한다. 나머지 {len(findings)-n_mis}건과 다른 레코드는 바이트 동일.\n- 결과: test_v30에서 membership_required support가 {sum(f["test_label"]=="membership_required" and f["verdict"]!="불일치" for f in findings)}건으로 줄어 해당 label 점수는 측정 불가(N/A)가 된다. 그룹 구성원 의미의 membership 테스트 사례는 별도 확보가 필요하다.\n- 사람 확정이 필요하므로 사용자 승인 후에만 생성한다. 생성 시 새 SHA-256을 AGENTS.md에 test.jsonl과 별도 항목으로 기록한다.\n'
    (OUT/'report.md').write_text(t,encoding='utf8'); print(t)

if __name__=='__main__':main()
