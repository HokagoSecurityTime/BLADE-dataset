# 3-2. 추가 공개 취약 API 후보 조사 (수집 전 확인만, 2026-10-21)

기존 test_v30 취약 API 5종: VAmPI(erev0s, MIT, Flask) · crAPI(OWASP, Apache-2.0, Java/Go/Python) · Juice Shop(juice-shop, MIT, TypeScript) · Pixi(DevSlop, Apache-2.0, Node/MEAN) · DVWS-node(snoopysecurity, GPL-3.0, Node). 겹침 판정 기준: 원작자(owner) 동일, 코드 계보(fork·포팅), 엔드포인트 집합 유사. 메타데이터는 GitHub API로 2026-10-21 조회.

## 후보 (겹치지 않음 → 제안)

| 후보 | 원작자 | 라이선스 | 스택 | 최근 push | ★ | OAS/스펙 출처 | 기존 5종과 겹침 | 제안 |
|---|---|---|---|---|---:|---|---|---|
| roottusk/vapi | roottusk | GPL-3.0 | PHP Laravel | 2025-01 | 1,354 | Postman 컬렉션(OAS 없음, 라우트 파일에서 투영) | 없음 | **1순위**: OWASP API Top10 2019 구성(api1 BOLA 등 10 영역), Laravel 미들웨어·컨트롤러 구조가 train 프레임워크 다양화에 도움 |
| theowni/Damn-Vulnerable-RESTaurant-API-Game | theowni | GPL-3.0 | Python FastAPI | 2026-07 | 940 | FastAPI 런타임 /openapi.json(저장소 파일 없음 → 데코레이터 정적 투영) | 없음 | **1순위**: FastAPI 의존성 기반 인증·역할(Depends) 사례, 2023 Top10 |
| Checkmarx/capital | Checkmarx | AGPL-3.0 | Python FastAPI + React | 2026-06 | 339 | Postman 컬렉션 + FastAPI 투영 | 없음 | **2순위**: 블로그 도메인(JWT), AGPL이라 발췌 재배포 범위 확인 필요(정적 분석·발췌 인용은 가능) |
| payatu/Tiredful-API | payatu | GPL-3.0 | Django REST | 2021-06 | 583 | DRF 라우트(urls.py)에서 투영 | 없음 | 2순위: Django 사례 보강, 오래됨(2021) |
| appsecco/dvcsharp-api | appsecco | MIT | C# ASP.NET Core | 2024-07 | 86 | Postman 컬렉션 + Swagger(런타임) | 없음 | 3순위: C# 다양화 |
| Aif4thah/VulnerableLightApp | Aif4thah | GPL-3.0 | C# | 2026-02 | 62 | 소규모(27 파일) | 없음 | 3순위: 소규모 |
| bnematzadeh/vulnerable-rest-api | bnematzadeh | MIT | Node/React | 2023-11 | 64 | 라우트 파일 투영 | 없음 | 3순위 |

## 제외

| 후보 | 사유 |
|---|---|
| snoopysecurity/dvws (PHP 원본) | DVWS-node와 **원작자 동일·계보 동일** → 겹침 |
| InsiderPhD/Generic-University | 라이선스 파일 없음(재배포·발췌 인용 근거 없음) |
| payatu/DVAPI | 라이선스 없음 |
| dolevf/Damn-Vulnerable-GraphQL-Application | GraphQL(REST OAS 없음, 현재 스키마 계약과 불일치) |
| cr0hn/vulnerable-node | 라이선스 NOASSERTION(비표준) → 확인 전 보류 |
| Erdemstar/VulnerableApp4APISecurity 등 라이선스 없는 소규모 레포 | 라이선스 없음 |

## 수집 시 유의

- 정적 분석만 수행(실행·수정 금지), 클론은 `datasets/blade/raw/vuln_apis/`에 두고 git 미추적, 커밋 해시만 기록.
- 라벨은 사람 확정 전 후보로 두고 test/train 어느 쪽에 넣을지는 held-out 정책(3-3 10번)과 함께 결정한다. 공개 취약 API는 현재 규약상 test 전용이다.
- 수집은 사용자 승인 후에만 진행한다.

출처: GitHub API 메타데이터(2026-10-21), [vAPI 소개](https://portswigger.net/daily-swig/introducing-vapi-an-open-source-lab-environment-to-learn-about-api-security), [Damn Vulnerable RESTaurant](https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game), [c{api}tal](https://checkmarx.com/blog/how-we-created-an-api-security-ctf), [Tiredful API](https://github.com/payatu/Tiredful-API).
