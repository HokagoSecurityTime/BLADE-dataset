"""Read-only offline audit of 28 held-out disagreements; no model calls."""
import hashlib
import json
from collections import Counter
from pathlib import Path
from training.data.label_v3 import payload

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'training/data'
DATA = ROOT / 'datasets/blade/processed'

# Manually assessed after reading each stored input and human correction.
# Category is an audit hypothesis, not a changed training label.
DECISIONS = [
('deutschebahn.com', '输入', '입력에는 rental object 설명과 provider 후보만 있고 공개 open data라는 근거는 없다. unknown은 공개 증거가 아니다.', '서비스 공개 접근 문서 또는 OAS info 설명을 별도 근거로 확보. manual 선택도 최신 제한 규칙에는 부합하지 않아 보조적으로 모델 지침 불이행이 있다.'),
('illumidesk.com', '模型', '경로 /teams/{team}/billing/invoices는 조직 단서인데 모델은 customer 컬럼만 근거로 개인 소유를 골랐다.', '조직 경로와 응답 customer 속성의 우선순위 오류를 검증. tenant가 구조적 제안이라는 뜻이지 실제 정책 증명은 아니다.'),
('zoom.us', '规则', 'description에 account:read:admin과 Pro 이상 prerequisite가 동시에 명시돼 있다. 역할과 구독의 동시 조건 중 단일 label 우선순위가 불명확하다.', '역할+요금제 복합 조건에서 대표 label 선택 규약을 사람이 확정. membership을 근거 없는 환각으로 보기는 어렵다.'),
('gerermesaffaires.com', '规则', '실제 scope에 collaborator/owner/robot가 있다. 사람은 주체 불명확을 보류했지만 프롬프트는 단서 부족만으로 보류하지 말라고 한다.', 'scope의 권한명/역할 구분과 모순의 정의를 명시. 사람 라벨이 틀렸다고 확정하지 않는다.'),
('billingo.hu', '模型', 'tenant_cols=organization 및 organization.address 등 응답 필드를 인용하면서 membership을 출력했다. plan/tier 요구는 없다.', '라벨과 rationale의 의미 정합성 검사 대상으로 우선 활용.'),
('nebl.io', '输入', '블록체인 형태의 txid/blockhash 필드는 있지만 공개 접근이라는 명시는 입력에 없다. 사람 사유의 공개 체인 맥락이 입력 밖이다.', '공개 참조 데이터로 허용하는 도메인 기준 또는 접근 문서 보강. unknown만으로 public을 강제하지 않는다.'),
('trakt.tv', '模型', '/users/{id}/lists와 OAuth Required만 있는데 role_required를 선택했다. 프롬프트는 OAuth와 역할 요구를 분리한다.', '인증과 역할 혼동의 명확한 진단 사례. 실제 소유자 제한 증명과 구조적 owner 제안은 구분.'),
('openbanking.org.uk', '模型', '/accounts/{AccountId}, PSUOAuth2Security scope accounts, 응답 AccountId가 있는데 전무/모순 설명 없이 confidence=0 보류.', 'account 스코프 인식 누락. PSU 동의의 세부 근거는 미제공이므로 사람 사유 전체가 입력에 있다고 주장하지 않는다.'),
('microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/image', '规则', '사람은 prediction key의 7종 매핑 불명확을 보류한다. 프롬프트는 project를 tenant 단서로 규정하고 단서 부족 보류를 금지한다. 모델 membership에도 plan 근거가 없다.', '서비스 키/프로젝트 권한의 taxonomy를 먼저 합의. membership 출력은 별도의 모델 정합성 오류.'),
('velopayments.com', '模型', 'description에 given payor, query payorId, 응답 payorId가 있으며 OAuth 선언도 있다. 모델은 GET·path만으로 public을 출력했다.', '공개 근거 없는 public 선택을 오류로 진단. payor가 조직이라는 해석은 별도 도메인 지식임도 표시.'),
('bitbucket.org', '规则', '사람 membership은 workspace/repository 구성원 쓰기 권한을 뜻하지만 프롬프트 membership은 plan/premium/subscription/tier 중심이다. 경로 workspace는 tenant 단서다.', '구성원 관계와 구독 등급 중 membership 의미를 통일. 실제 write 권한은 현재 description에 명시돼 있지 않다.'),
('slmonitor.com', '模型', 'companies/{companyId}, tenant_cols=company, 응답 company가 일치하는데 membership 선택. plan/tier 요구는 없다.', 'tenant 단서를 membership으로 오해한 사례. CompanyMonitor scope와 개인 사용자 중첩도 함께 검토.'),
('vtex.local', '输入', 'description은 subcollection SKU 위치 변경과 CMS 모듈만 설명한다. 사람 사유의 License Manager 역할은 입력에 없다.', '역할 요구 문서를 확보. /pvt/ 약어만으로 특정 역할을 증명하지 않는다.'),
('amazonaws.com', '模型', '/workspaces/{workspaceId}가 프롬프트 tenant 단서에 명시되지만 모델은 짧은 description만 인용해 보류했다.', '경로 단서를 누락한 사례. AWS 계정 소유라는 상세 배경까지 검증한 것은 아니다.'),
('hetzner.cloud', '输入', 'datacenter 위치·server_types 필드는 카탈로그 해석을 지지하지만 공개 접근 여부는 명시돼 있지 않다.', '공개 카탈로그의 인가 대상 아님 정의를 합의하고 접근 문서로 확인.'),
('netboxdemo.com', '输入', 'description 공란과 Bearer만으로 NetBox change 권한을 알 수 없다. site 후보는 실제로 물리적 장소일 수 있다.', '모델 권한 문서 보강 및 site→tenant 탐지의 오탐 검토.'),
('api2cart.com', '模型', '/account.cart.list.json이라는 개인 계정 단서를 단순 세그먼트가 아니라 점 구분 경로에서도 읽어야 한다. 모델은 설명만 보고 보류했다.', '비 REST 스타일 account 경로 신호의 인식 실패. 실제 계정 소유 정책 확인은 별도.'),
('microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/url', '规则', 'image 변형과 동일하게 project/키 기반 정책의 인간 보류와 강제 6종 제안 규칙이 충돌한다. membership 근거도 없다.', 'image/url 두 행은 같은 원인군이며 독립 오류 유형으로 과대 집계하지 않는다.'),
('rebilly.com', '输入', '사람은 merchant 조직을 근거로 하지만 입력은 SecretApiKey/JWT, customerId/username뿐이다. merchant 스코프가 전달되지 않았다.', '조직 스코프 문서 보강. 모델이 API key를 역할로 읽은 것은 별도 명확한 오류.'),
('appcenter.ms', '规则', '사람은 app collaborator를 membership으로 매핑하지만 입력에는 APIToken과 Cancels a build만 있다. collaborator는 입력 밖이고 구독형 membership 정의와도 다르다.', '협업자 membership 정의와 근거 문서 정리. API token→role 해석도 오류.'),
('visma.net', '输入', 'SalesOrders와 read scope는 있지만 회사/tenant 연결은 입력에 없다. ERP 회사 단위라는 사람 사유는 서비스 맥락이다.', '회사 식별 헤더/조직 설명을 입력에 보강. 모델 owner 선택 역시 현재 입력으로 강하게 지지되지 않는다.'),
('appwrite.io:put:/teams/{teamId}', '模型', 'Only team owners have write access라고 명시되는데 모델은 같은 문장을 인용해 role_required를 출력했다.', '리소스 소유자와 전역 역할 구분을 평가. 팀 소유권은 프로젝트 tenant 소유와 다른 관계일 수 있다.'),
('circuitsandbox.net', '规则', 'WRITE_CONVERSATIONS/MANAGE_CONVERSATIONS는 OAuth 작업 권한이고 description에 구성원/관리자 관계는 없다. 사람 membership은 구독 중심 정의와 다르다.', '작업 scope·객체 구성원·전역 역할을 분리하는 기준과 추가 정책 근거가 필요.'),
('clicksend.com', '输入', '설명은 전화/팩스/email 중 필수 입력 조건일 뿐 계정 소유나 역할 조건이 아니다. 사람 사유의 본인 list 관계는 입력 밖이다.', '계정별 list 소유 근거 보강. 필드 필수 조건→역할 요구는 모델의 별도 오류.'),
('configcat.com', '输入', '환경/설정 ID와 Basic 인증만 있고 organization/product 관계는 전달되지 않았다.', '조직·제품 리소스 연결 문서나 상위 스코프 보강. model manual도 강제 제안 규칙과는 불일치.'),
('shutterstock.com', '复核', '응답에 role_assignments.roles.editors/owners/viewers가 함께 있다. customer_accessCode와 collections.edit만으로 수정 권한을 owner 단독으로 확정할 수 없다.', '사람 owner_match를 객체별 ACL로 읽은 것인지 재검토. 모델 role도 전역 역할인지 객체 역할인지 확인 전 정답으로 채택하지 않는다.'),
('appwrite.io:put:/storage/files/{fileId}', '复核', 'Only users with write permissions와 $permissions.write는 ACL이다. ACL 쓰기 권한 보유자는 소유자와 동치가 아니다.', 'owner_match가 ACL을 포함하는지 라벨 정의를 재확인. 기존 사람 라벨은 변경하지 않으며 7종 밖 관계의 처리 방침 필요.'),
('parliament.uk', '输入', 'Bill 뉴스 목록과 기사 필드만 전달돼 의회 공개 데이터라는 서비스 수준 설명은 없다.', '공개 데이터 성격/접근 근거를 보강. summary는 입력에 있으므로 description 공란만으로 입력 전체가 없다고 보지 않는다.'),
]
CATEGORIES = {'输入':'입력 근거 부족', '模型':'모델 판단 오류', '规则':'규칙·라벨 기준 충돌', '复核':'사람 라벨 재확인'}


def main():
    report = json.loads((HERE/'pilot_v6_report.json').read_text(encoding='utf8'))
    rows = {r['id']:r for r in map(json.loads,(DATA/'apisguru_v6_openai_pilot.jsonl').read_text(encoding='utf8').splitlines())}
    corrections = {r['id']:r for r in map(json.loads,(HERE/'human_corrections_v5.jsonl').read_text(encoding='utf8').splitlines())}
    errors = [x for x in report['validation_comparison'] if not x['correct']]
    assert len(errors) == len(DECISIONS) == 28
    audited = []
    for item, (key, kind, diagnosis, action) in zip(errors, DECISIONS):
        assert key in item['id'], (key,item['id'])
        row = rows[item['id']]
        model_input = payload(row)
        model_input.update(security_state=row['security_state'],schema_provenance='Fields extracted from API response schema; not a verified database ERD')
        audited.append(dict(id=item['id'],category=CATEGORIES[kind],human_label=item['human'],model_label=item['v6'],
                            confidence=row['confidence'],human_reason=corrections[item['id']]['reason'],
                            model_rationale=row['rationale'],evidence_fields=row['evidence_fields'],
                            evidence_invalid=row['meta'].get('evidence_invalid'),
                            diagnosis=diagnosis,recommended_action=action,reconstructed_input=model_input))
    counts = dict(Counter(x['category'] for x in audited))
    files = ['training/data/pilot_v6_report.json','training/data/human_corrections_v5.jsonl',
             'training/data/prompts/policy_label_v2.6.md','datasets/blade/processed/apisguru_v6_openai_pilot.jsonl']
    result = dict(scope='28 disagreements from 31 held-out human corrections; not a population error estimate',
                  api_calls=0,labels_modified=False,primary_category_counts=counts,
                  source_sha256={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in files},records=audited)
    (HERE/'v6_error_analysis.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    lines = ['# v2.6 검증 실패 28건 분석','',
             '검증 31건 중 일치 3건, 불일치 28건. API 호출·라벨 변경·프롬프트 수정 없음. 아래 분류는 저장된 입력과 출력에 대한 진단 가설이며 원인의 실험적 증명이나 새로운 정답이 아니다.',
             '', '| 주원인 | 건수 |','|---|---:|']
    lines += [f'| {k} | {v} |' for k,v in counts.items()]
    lines += ['', '각 행은 주원인 하나로 집계했지만 보조 원인이 겹친다. 특히 입력 부족 행에도 모델의 근거 없는 역할 판정 또는 보류 규칙 위반이 있을 수 있다.',
              '', '## 공통 발견', '',
              '- role_required를 API key/OAuth/필드 필수 조건과 혼동한 출력이 있다. organization/company/project를 인용하면서 membership을 낸 출력도 있어 rationale와 label의 의미가 불일치한다.',
              '- membership의 프롬프트 정의는 plan/premium/subscription/tier 중심인데 사람 검수는 repository/app/community 구성원 권한도 포함한다. 팀 소유자·객체 ACL·전역 역할 구분도 일관된 정책이 필요하다.',
              '- role과 유료 plan이 함께 필요한 Zoom처럼 복합 정책의 단일 라벨 우선순위가 명확하지 않은 사례가 있다.',
              '- 강제 6종 제안 규칙과 불명확하면 보류한 사람 교정 사례가 충돌한다. 가상 예시를 교체했지만 본문에 이전 예시 7·9·11을 참조하는 문장은 남아 있다. 이 참조 오류가 성능 하락의 원인이라고 입증한 것은 아니다.',
              '- evidence_fields 존재 검사는 인용한 필드가 있다는 것만 확인한다. 그 필드가 해당 label을 정당화하는지는 검사하지 못한다. 따라서 evidence_invalid=false는 정책 추론이 옳다는 뜻이 아니다.',
              '- 서비스명·OAS info·security scheme 상세 설명은 현재 입력에 포함되지 않는다. 계좌 동의·회사 스코프·공개 데이터라는 사람 사유가 operation 설명에 없을 때 입력 비대칭이 생긴다.',
              '', '## 행별 진단', '']
    for i,r in enumerate(audited,1):
        p=r['reconstructed_input']
        lines += [f"### {i}. {r['id']}",'',f"- 주원인: **{r['category']}**",f"- 사람: `{r['human_label']}` / 모델: `{r['model_label']}` / confidence: {r['confidence']}",
                  '- 사람 수정 사유: '+r['human_reason'],'- 모델 rationale: '+r['model_rationale'],
                  '- 진단: '+r['diagnosis'],'- 다음 조치: '+r['recommended_action'],'', '실행 입력 재구성:', '```json',json.dumps(p,ensure_ascii=False,indent=2),'```','']
    lines += ['## 다음 작업의 우선순위','',
              '1. 구성원/구독, 객체 ACL/소유권, 조직/개인 계정, 복합 정책의 단일 라벨 선택 기준을 사람과 합의한다. 현재 라벨은 유지한다.',
              '2. 입력 근거 부족 10건은 사람 사유에 필요한 맥락이 로컬 원본 OAS의 info/securitySchemes/상위 설명에 있는지 확인한다. 없다면 별도 출처 확인이 필요하다.',
              '3. 모델 판단 오류 9건은 충분한 구조 단서를 가진 진단 표본으로 사용한다. 단순 API key=역할, 조직=membership 오류를 우선 분리한다.',
              '4. 위 결정 후 새로운 사람 검수 표본으로 평가한다. 이 31건은 이미 분석에 사용됐으므로 독립적인 최종 성능 평가 자료로 계속 재사용하지 않는다.',
              '', '## 재현성과 한계','',
              '입력은 저장된 pilot 레코드에 label_v3.payload의 실제 조립 함수를 적용하고 실행 당시 저장된 security_state와 v2.6 transport의 schema_provenance 문자열을 결합해 재구성했다. 전송 원문 로그는 없으므로 네트워크 캡처와 동일하다고 주장하지 않는다. 전체 입력은 v6_error_analysis.json에도 보존했다. 외부 서비스 문서의 현재 정책은 조회하거나 검증하지 않았다. 사람이 제공한 공개/조직/ACL 해석의 사실성은 별도 검증 대상이다.',
              '이 검증 표본은 v5에서 이미 틀린 사례만 골랐으므로 9.68%는 전체 데이터 정확도가 아니다. Microsoft image/url 두 건은 동일 유형으로 상관돼 있다.']
    (HERE/'v6_error_analysis.md').write_text('\n'.join(lines)+'\n',encoding='utf8')
    print(json.dumps(dict(records=len(audited),categories=counts),ensure_ascii=False))


if __name__ == '__main__':
    main()
