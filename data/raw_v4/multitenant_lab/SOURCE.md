# multitenant_lab — 출처

- 저장소: https://github.com/RimaBenJaballah/cloud-security-multitenant-lab
- 브랜치: main (기본), 고정 커밋 `a428c4f85d479c932f49323ebc9b8c5e7e47f8fc`, 태그 없음
- clone 위치: `datasets/blade/raw/opensource/RimaBenJaballah_cloud-security-multitenant-lab` (`--depth 1 --filter=blob:none`)
- 라이선스: **선언 없음** (GitHub API `license: null`, 저장소에 LICENSE 파일 없음, README에 라이선스 문구 없음). 레코드에는 `NOASSERTION`으로 기록. 재배포 권리 불명이므로 **평가 전용(test_v31_supp)**, 학습·재배포 금지.
- 성격: 의도적 취약 교육용 랩(멀티 테넌트 XML/SVG 수집 API, Flask on ECS Fargate). 저장소에 `application/vulnerable`과 `application/hardened`가 함께 있다.

## 추출 범위

- 입력 코드: `application/vulnerable/app.py` (Flask 라우트 6개 전부).
- OAS: 저장소 명세 없음 → Flask 라우트에서 생성(`oas_status=generated`). securityScheme `ApiKeyAuth`(header `X-API-Key`)는 데코레이터 구현에서 도출.
- 의도 정책 근거로만 사용(후보로 추가하지 않음): `application/hardened/app.py`(16-21행 lab 라우트 삭제, 430·506행 테넌트 범위 주석), `application/vulnerable/README.md`(85-110행 엔드포인트 설명, 287행 수정 지침 `s3_key.startswith(g.tenant_id + "/")`), `docs/remediation.md:58`.

## 인증·인가 구조

- `require_api_key` 데코레이터(app.py 232-250): `X-API-Key`를 Secrets Manager의 `tenant-{a,b,c}/api-key`와 대조(`_identify_tenant`), `g.tenant_id` 설정. 401(키 없음)/403(불일치).
- 인가 함수·정책 클래스 없음. 테넌트 범위는 핸들러가 `g.tenant_id`를 S3 prefix·SQL `WHERE tenant_id = %s`에 직접 쓰는 방식.
- 역할(관리자) 개념 없음. `/admin/all-objects`는 이름만 admin이고 검사 없음.
- 취약점(VULN-2): `/files/<s3_key>`는 테넌트 prefix 검사 누락, `/admin/all-objects`는 관리자 검사 누락, `/lab/secrets-dump`는 모든 테넌트 키 노출. hardened 버전은 세 라우트를 삭제.

## 제외

- `application/hardened` 라우트(같은 엔드포인트의 수정판 — 별도 후보로 넣지 않음).
- 인프라(Terraform), IAM JSON, 스크립트, Lambda forwarder: HTTP API 아님.

## 건수

6건: public 1, tenant_match 3, role_required 1, manual_review_required 1. known_vulnerable=true 3건.
