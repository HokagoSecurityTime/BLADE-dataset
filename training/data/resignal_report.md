# A2 소유권 신호 재탐지

입력 4,333건 → 출력 4,333건. 원본 SHA-256 `0bdf3b5b6a82063e4aba32e53cd149d263c2bcf070dcb5243a4a769debba1bcb` 보존 확인.

ERD 테이블명만 수정한 레코드: 38건. 기존 meta 값과 기타 필드·순서·중복은 보존.

## signal_class × has_security

| signal_class | has_security | 건수 |
| --- | --- | --- |
| owner | False | 170 |
| owner | True | 258 |
| tenant | False | 53 |
| tenant | True | 115 |
| both | False | 88 |
| both | True | 155 |
| path_only | False | 115 |
| path_only | True | 289 |
| none | False | 1277 |
| none | True | 1813 |

## owner_cols 상위 30

| 원본 컬럼명 | 레코드 수 |
| --- | --- |
| user | 105 |
| username | 81 |
| account | 63 |
| owner | 60 |
| createdBy | 55 |
| author | 48 |
| user_id | 46 |
| accountId | 34 |
| userId | 34 |
| customerId | 29 |
| created_by | 28 |
| customer | 26 |
| userName | 22 |
| ownerId | 16 |
| userEmail | 15 |
| account_id | 14 |
| creator | 12 |
| creatorId | 11 |
| UserID | 10 |
| owner_id | 9 |
| userid | 9 |
| UserName | 8 |
| creator_id | 8 |
| customer_id | 8 |
| ownerName | 8 |
| accountName | 7 |
| CustomerId | 6 |
| authorName | 6 |
| created_by_id | 6 |
| CreatedById | 5 |

## tenant_cols 상위 30

| 원본 컬럼명 | 레코드 수 |
| --- | --- |
| account | 63 |
| accountId | 34 |
| company | 27 |
| project | 27 |
| provider | 23 |
| organization | 22 |
| organizationId | 20 |
| site | 20 |
| companyName | 15 |
| account_id | 14 |
| team | 14 |
| organization_id | 13 |
| Team | 10 |
| TeamID | 10 |
| projectId | 10 |
| teamId | 10 |
| Company | 8 |
| tenant | 8 |
| accountName | 7 |
| companyId | 7 |
| company_id | 7 |
| company_name | 7 |
| site_id | 7 |
| CompanyName | 6 |
| siteid | 6 |
| orgID | 5 |
| orgId | 5 |
| org_id | 5 |
| organization_name | 5 |
| Project | 4 |

## path_only 샘플 10건 (path만)

- `/accounts/{accountId}/statements/{statementId}`
- `/2010-04-01/Accounts/{AccountSid}/AuthorizedConnectApps.json`
- `/cloud/accounts/{accountid}/snapshots`
- `/api/v2/AuthorizationCategories/{id}/Users/{userID}`
- `/api/v1/users/me/abuses`
- `/accounts/{id}`
- `/accounts/{accountId}/phone/sip_trunk/trunks/{sipTrunkId}`
- `/v2/companies/{companyId}/codes/{codeResource}`
- `/accounts/{accountId}/managed_domains`
- `/{username}/dashboards/{dashboard_id}/blocks/{id}`

## 정보 부족 후보

ERD 컬럼 ≤2인 957건 중 signal_class != none: 126건.

## 판정 규칙·제한

- 대소문자와 underscore를 제거한 전체 이름을 비교하며 부분 문자열은 매칭하지 않는다. 기본명 뒤 id/uuid/name/email 변형을 포함한다.
- 컬럼 빈도는 원래 표기를 유지한 레코드 단위다. 예: userId와 user_id는 탐지 시 같게 취급하지만 빈도표에서는 구분한다.
- ERD 양쪽 목록이 모두 비고 경로 신호만 있으면 path_only를 우선한다. 그 외 ERD·경로의 owner/tenant 신호를 합쳐 both/owner/tenant/none을 정한다.
- account 컬럼·파라미터는 owner/tenant 양쪽에 표시한다. 경로 패턴은 지정된 복수 리소스와 me를 인식한다.
- path_resource_depth는 리소스 세그먼트 바로 뒤의 {파라미터} 쌍 수다. /a/{x}/b/{y}=2, /a/{x}/b=1.
- 기존 has_owner_col/has_tenant_col/has_security는 보존한다. 확장 결과는 새 목록과 signal_class를 사용한다.
- admin/write/manage는 scope 문자열의 대소문자 무시 포함 검사다. 실제 관리자 권한이나 소유권을 확정하는 라벨이 아니다.
- 원본 후보 파일과 oas_snippet은 수정하지 않았다. 필터링·라벨링·분할은 실행하지 않았다.
