# Untitled

#### 1. 크롤링 대상 소스

| 소스 | 형태 | 역할 |
| --- | --- | --- |
| NVD CVE | REST API | BOLA 관련 CVE 수집, CVSS/CWE 공식 수치 포함 |
| OWASP API Security | HTML/MD | API1:2023 BOLA 공식 정의 및 패턴 |
| CAPEC | XML/JSON | 공격 패턴 분류 체계 |
| CISA KEV | JSON Feed | 실제로 악용된 BOLA/IDOR CVE만 골라 우선순위 부여 |

| 소스 | 역할 |
| --- | --- |
| HackerOne 공개 리포트 | 실제 버그 바운티 IDOR 사례 |
| PortSwigger Web Academy | IDOR Lab 해설, 공격 시나리오 |
| OWASP Juice Shop 소스 | 의도적 취약점 → Negative Sample |
| Conduit (RealWorld) / Airbyte | OAS + 백엔드 코드 세트 → 역공학용 |
| Vulnerable-Flask-App | Python 기반, IDOR 시나리오 다수 |

**전형적인 백엔드 비지니스 로직 구조**

**비지니스 로직 취약점 사례**

| 소스 | 내용 | 형태 |
| --- | --- | --- |
| PortSwigger Web Academy | IDOR/Business Logic Labs 해설 | HTML |
| HackerOne Hacktivity | 실제 버그 바운티 리포트 (공개된 것) | HTML |
| OWASP Testing Guide | WSTG-ATHZ-01~04 | MD |
| PentesterLand writeups | 실제 공격시나리오 | HTML |
| ASVS (Application Security Verification Standard) | 소유권 검증 요구사항 목록 | MD/PDF |

**학습 데이터에 들어가야 하는 비지니스 로직 Feature**

| Feature | 예시 | BOLA 관련성 |
| --- | --- | --- |
| ID 식별자 패턴 | `{orderId}`, `{userId}` | 소유권 결정 핵심 요소 |
| 리소스 계층 구조 | `/users/{userId}/orders/{orderId}` | 상위-하위 종속 관계 |
| 상태 변경 흐름 | ORDER_PENDING → ORDER_CONFIRMED | 상태 변경 권한 소유자 확인 |
| DB 트랜잭션 조건 | `WHERE id=? AND owner_id=?` | 조건절 소유권 컬럼 유무 |
| 외부 API 의존성 | 결제 API 호출 전 소유권 검증 | 의존 체인에서의 권한 누락 |
| 예외 처리 흐름 | `role=admin`이면 bypass | 예외가 취약점이 되는 경우 |

**도메인 별 소유권 구조 합성 예시**
OAS를 보고 소유권 컬럼을 추론하게 하는 훈련 데이터

**소유권 유형 분류**

| 유형 | 설명 | 예시 |
| --- | --- | --- |
| Private | 본인만 접근 가능 | `/my-page`, `/settings` |
| Shared | 읽기 전체, 수정은 작성자만 | `/posts/{id}` |
| Admin | 관리자 권한 전체 조회 | `/admin/users` |
| Delegated | 위임/공유 접근 (예외 케이스) | 공유 계좌, 팀 프로젝트, 대리인 |

#### 2. 임베딩 모델

| 모델 | 용도 | 벡터 차원 | 추천 여부 |
| --- | --- | --- | --- |
| llama3.1 | 텍스트 생성(정책 생성) | - | 생성용, 임베딩 부적합 |
| **nomic-embed-text** | 임베딩 전용 | 768 | 임베딩용 |
| mxbai-embed-large | 임베딩 전용, 성능 더 좋음 | 1024 | 임베딩용 |
| all-MiniLM-L6-v2 | sentence-transformers, 경량 | 384 | 서버 없을 때 대안 |

#### 3. 데이터셋 구성 스키마

```scheme
{
  "id":       "nvd-CVE-2021-27886",       # 중복 방지용 고유 ID

  "document": "CVE-2021-27886: Nested resource path BOLA. "
              "API endpoint /users/{userId}/posts/{postId} "
              "does not validate parent ownership. CWE-285.",

  "metadata": {
    "source":        "nvd",               # nvd / owasp_api / capec / hackerone / cisa / wstg / github
    "cve_id":        "CVE-2021-27886",
    "cwe_id":        "CWE-285",
    "severity":      "HIGH",              # NVD 공식 수치 (주관적 아님)
    "cvss_score":    "8.1",              # NVD 공식 수치
    "attack_vector": "NETWORK",
    "bola_pattern":  "nested_resource_idor",
    "updated_at":    "2025-04-28"
  }
}
```

`bola_pattern` 분류 정의

| 패턴 ID | 설명 | 예시 |
| --- | --- | --- |
| `integer_id_enumeration` | 정수 ID 순열거 | `GET /orders/1001 → /1002` |
| `nested_resource_idor` | 중첩 리소스 상위 ID 미검증 | `GET /users/{id}/orders/{id}` |
| `mass_assignment` | 바디에 ownerId 포함 | `PUT /orders/1 {ownerId: 2}` |
| `filter_param_bypass` | 쿼리 파라미터 userId 직접 지정 | `GET /list?userId=999` |
| `batch_unvalidated` | 배치 요청 개별 소유권 미검증 | `POST /bulk {ids:[1,2,999]}` |
| `admin_path_exposure` | 관리자 경로 권한 없이 접근 | `DELETE /admin/users/100` |
| `uuid_idor` | UUID도 소유권 검증 누락 | `GET /docs/{uuid}` |

#### 4. JSON 정책 포맷

```json
{
  "policy_version": "1.0",
  "generated_at":   "2025-04-28T09:00:00Z",
  "endpoint":       "GET /accounts/{accountId}",
  "method":         "GET",
  "path_pattern":   "/accounts/{accountId}",
  "risk_level":     "HIGH",
  "confidence":     0.91,
  "matched_cves":   ["CVE-2021-27886", "OWASP-API1-2023"],
  "bola_pattern":   "integer_id_enumeration",
  "rules": [
    {
      "rule_id":      "R001",
      "type":         "jwt_ownership",
      "extract":      "path.accountId",
      "compare_with": "jwt.sub",
      "on_mismatch":  "block",
      "status_code":  403,
      "log":          true
    },
    {
      "rule_id":      "R002",
      "type":         "rate_limit",
      "max_requests": 20,
      "window_sec":   60,
      "on_exceed":    "block"
    }
  ],
  "status":       "PENDING",
  "review_note":  "",
  "review_hint":  "accountId가 JWT sub와 1:1 매핑인지 확인 필요. 공유 계좌 등 예외 케이스 검토 권장."
}
```

### Rule Type 목록

| Rule Type | 설명 | 대응 패턴 |
| --- | --- | --- |
| `jwt_ownership` | JWT sub와 path param 비교 | integer_id, nested_resource |
| `block_path` | `/admin/*` 경로 차단 | admin_path_exposure |
| `strip_body_field` | ownerId 등 필드 제거 | mass_assignment |
| `rate_limit` | ID 열거 방어 | integer_id_enumeration |
| `batch_size_limit` | 배치 요청 크기 제한 | batch_unvalidated |
| `query_param_override` | userId 쿼리파라미터 → JWT값 교체 | filter_param_bypass |

#### **5. 신뢰도 산출 방식**

`최종 신뢰도 = RAG 점수 × 0.6 + LLM 자기평가 × 0.4`

**RAG 점수 (객관적):**

- ChromaDB L2 distance → 0~1 변환
- score = 1 - (L2_distance / max_distance)
- 유사 CVE가 많이 걸릴수록 신뢰도 상승

**LLM 자기평가 (주관적):**

- 프롬프트에 "이 판단의 확신도를 0.0~1.0으로 출력하라" 지시
- LLM이 불확실할 때 스스로 낮은 수치 출력

구간 기준

| 구간 | 상태 | 처리 |
| --- | --- | --- |
| 0.85 이상 | ACTIVE | 자동 승인, 즉시 프록시 적용 |
| 0.65 ~ 0.84 | PENDING | 관리자 검토 필요 |
| 0.65 미만 | DRAFT | LLM 재추론 또는 수동 작성 |

#### 6. 관리자 PENDING 리뷰 제도

**화면에 표시할 정보**

- 엔드포인트 + 탐지된 `bola_pattern`
- 신뢰도 % + **신뢰도가 낮은 이유** (LLM 자동 생성)
- 매핑된 CVE ID + 요약
- 생성된 Rule Type + 비교 로직 상세
- 비즈니스 로직 확인 권고 메시지
- 승인 / 수정 후 승인 / 거절 + `review_note` 입력란
    
    ```
    프롬프트 추가:
    신뢰도가 낮은 경우, 관리자에게 확인을 권고할 
    비즈니스 로직 케이스를 1~2줄로 함께 출력하라.
    
    출력 예시:
    "review_hint": "accountId가 JWT sub와 1:1 매핑인지 확인 필요.
    공유 계좌, 법인 계좌, 대리인 접근 등 예외 케이스가 있으면
    jwt_ownership 룰보다 role 기반 검증이 적합할 수 있음."
    ```