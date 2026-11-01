# APIs.guru 후보 샘플 — 단계 A

입력 SHA-256: `0bdf3b5b6a82063e4aba32e53cd149d263c2bcf070dcb5243a4a769debba1bcb`. seed=42. 중복 키 제거 후 서로 다른 service에서 10건.

method는 전체 5종이므로 10건 모두 다른 method로 추출할 수 없다. 가능한 method를 모두 포함한 다음 사용 횟수가 적은 method부터 선택했다. 대표성 추정용 무작위 표본은 아니다.

oas_snippet·erd_snippet은 원문 전문이며 축약·JSON 재정렬을 하지 않았다.

## 1. daniweb.com — PATCH /conversations/{ID}/statuses

id: `apisguru:daniweb.com:patch:/conversations/{ID}/statuses`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | True | 17 |

### oas_snippet

```json
{"summary": "Archive or unarchive a conversation that is with a user who exists within the same bubble.", "operationId": null, "tags": ["conversations"], "security": [{"explicit_flow": ["conversations_read", "conversations_write"]}, {"implicit_flow": ["conversations_read", "conversations_write"]}], "path_params": ["ID"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE statuses (
  data TEXT,
  archived_status BOOLEAN,
  conversation TEXT,
  first_message TEXT,
  author TEXT,
  timestamp TEXT,
  id NUMERIC,
  latest_message TEXT,
  last_seen TEXT,
  text TEXT,
  user_a TEXT,
  business_card TEXT,
  community_persona TEXT,
  profile TEXT,
  usage TEXT,
  user_b TEXT,
  success BOOLEAN
);
```

## 2. telnyx.com — DELETE /authentication_providers/{id}

id: `apisguru:telnyx.com:delete:/authentication_providers/{id}`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | True | True | 17 |

### oas_snippet

```json
{"summary": "Deletes an authentication provider", "operationId": "DeleteAuthenticationProvider", "tags": ["Authentication Providers"], "security": [{"BearerAuth": []}], "path_params": ["id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE authentication_providers (
  data TEXT,
  active BOOLEAN,
  created_at TEXT,
  id TEXT,
  name TEXT,
  organization_id TEXT -- tenant candidate,
  record_type TEXT,
  settings TEXT,
  assertion_consumer_service_url TEXT,
  idp_cert_fingerprint TEXT,
  idp_cert_fingerprint_algorithm TEXT,
  idp_entity_id TEXT,
  idp_sso_target_url TEXT,
  name_identifier_format TEXT,
  service_provider_entity_id TEXT,
  short_name TEXT,
  updated_at TEXT
);
```

## 3. netbox.dev — PUT /circuits/circuits/{id}/

id: `apisguru:netbox.dev:put:/circuits/circuits/{id}/`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | True | 29 |

### oas_snippet

```json
{"summary": "", "operationId": "circuits_circuits_update", "tags": ["circuits"], "security": [{"Bearer": []}], "path_params": ["id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE circuits (
  cid TEXT,
  comments TEXT,
  commit_rate INTEGER,
  created TEXT,
  custom_fields TEXT,
  description TEXT,
  display TEXT,
  id INTEGER,
  install_date TEXT,
  last_updated TEXT,
  provider TEXT,
  circuit_count INTEGER,
  name TEXT,
  slug TEXT,
  url TEXT,
  status TEXT,
  label TEXT,
  value TEXT,
  tags TEXT,
  tenant TEXT,
  termination_a TEXT,
  port_speed INTEGER,
  provider_network TEXT,
  site TEXT,
  upstream_speed INTEGER,
  xconnect_id TEXT,
  termination_date TEXT,
  termination_z TEXT,
  type TEXT
);
```

## 4. ritc.io — POST /channels/{channel_id}/functions

id: `apisguru:ritc.io:post:/channels/{channel_id}/functions`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | True | 9 |

### oas_snippet

```json
{"summary": "Create a channel function", "operationId": "addChannelFunction", "tags": ["Channels"], "security": [{"Authorization": []}], "path_params": ["channel_id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE functions (
  apiType TEXT,
  description TEXT,
  endpoint TEXT,
  httpMethod TEXT,
  id TEXT,
  name TEXT,
  requestParameters TEXT,
  responseFormat TEXT,
  type TEXT
);
```

## 5. tokenjay.app — GET /mosaik/tokenburn/get/{uuid}

id: `apisguru:tokenjay.app:get:/mosaik/tokenburn/get/{uuid}`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | False | 7 |

### oas_snippet

```json
{"summary": "", "operationId": "getBurningTransaction", "tags": ["token-burn-controller"], "security": null, "path_params": ["uuid"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE get (
  address TEXT,
  addresses TEXT,
  message TEXT,
  messageSeverity TEXT,
  reducedTx TEXT,
  reducedTxList TEXT,
  replyTo TEXT
);
```

## 6. visagecloud.com — GET /rest/v1.1/analysis/retrieve

id: `apisguru:visagecloud.com:get:/rest/v1.1/analysis/retrieve`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | False | 3 |

### oas_snippet

```json
{"summary": "Retrieve a complete analysis object including both detection and recognition information", "operationId": "retrieveAnalysisUsingGET", "tags": ["Analysis"], "security": null, "path_params": [], "query_params": ["accessKey", "secretKey", "analysisId"]}
```

### erd_snippet

```sql
CREATE TABLE retrieve (
  message TEXT,
  payload TEXT,
  status TEXT
);
```

## 7. clicksend.com — PUT /lists/{list_id}/contacts/{contact_id}

id: `apisguru:clicksend.com:put:/lists/{list_id}/contacts/{contact_id}`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | True | 16 |

### oas_snippet

```json
{"summary": "Update a specific contact", "operationId": "Update a specific contact", "tags": ["Contacts"], "security": [{"basic": []}], "path_params": ["list_id", "contact_id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE contacts (
  address_city TEXT,
  address_country TEXT,
  address_line_1 TEXT,
  address_line_2 TEXT,
  address_postal_code TEXT,
  address_state TEXT,
  custom_1 TEXT,
  custom_2 TEXT,
  custom_3 TEXT,
  custom_4 TEXT,
  email TEXT,
  fax_number TEXT,
  first_name TEXT,
  last_name TEXT,
  organization_name TEXT,
  phone_number TEXT
);
```

## 8. klarna.com — POST /payments/v1/sessions/{session_id}

id: `apisguru:klarna.com:post:/payments/v1/sessions/{session_id}`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | False | 56 |

### oas_snippet

```json
{"summary": "Update an existing payment session", "operationId": "updateCreditSession", "tags": ["sessions"], "security": null, "path_params": ["session_id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE sessions (
  acquiring_channel TEXT,
  attachment TEXT,
  body TEXT,
  content_type TEXT,
  authorization_token TEXT,
  billing_address TEXT,
  attention TEXT,
  city TEXT,
  country TEXT,
  email TEXT,
  family_name TEXT,
  given_name TEXT,
  organization_name TEXT,
  phone TEXT,
  postal_code TEXT,
  region TEXT,
  street_address TEXT,
  street_address2 TEXT,
  title TEXT,
  client_token TEXT,
  custom_payment_method_ids TEXT,
  customer TEXT,
  date_of_birth TEXT,
  gender TEXT,
  last_four_ssn TEXT,
  national_identification_number TEXT,
  organization_entity_type TEXT,
  organization_registration_id TEXT,
  type TEXT,
  vat_id TEXT,
  design TEXT,
  expires_at TEXT,
  intent TEXT,
  locale TEXT,
  merchant_data TEXT,
  merchant_reference1 TEXT,
  merchant_reference2 TEXT,
  merchant_urls TEXT,
  authorization TEXT,
  confirmation TEXT,
  notification TEXT,
  push TEXT,
  options TEXT,
  color_border TEXT,
  color_border_selected TEXT,
  color_details TEXT,
  color_text TEXT,
  radius_border TEXT,
  order_amount INTEGER,
  order_lines TEXT,
  order_tax_amount INTEGER,
  payment_method_categories TEXT,
  purchase_country TEXT,
  purchase_currency TEXT,
  shipping_address TEXT,
  status TEXT
);
```

## 9. github.com — DELETE /applications/{client_id}/token

id: `apisguru:github.com:delete:/applications/{client_id}/token`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | False | 1 |

### oas_snippet

```json
{"summary": "Delete an app token", "operationId": "apps/delete-token", "tags": ["apps"], "security": null, "path_params": ["client_id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE token (
  access_token TEXT
);
```

## 10. appcenter.ms — PATCH /v0.1/apps/{owner_name}/{app_name}/builds/{build_id}

id: `apisguru:appcenter.ms:patch:/v0.1/apps/{owner_name}/{app_name}/builds/{build_id}`

| has_owner_col | has_tenant_col | has_security | ERD columns |
| --- | --- | --- | --- |
| False | False | True | 10 |

### oas_snippet

```json
{"summary": "Cancels a build", "operationId": "builds_update", "tags": ["build"], "security": [{"APIToken": []}], "path_params": ["owner_name", "app_name", "build_id"], "query_params": []}
```

### erd_snippet

```sql
CREATE TABLE builds (
  buildNumber TEXT,
  finishTime TEXT,
  id INTEGER,
  lastChangedDate TEXT,
  queueTime TEXT,
  result TEXT,
  sourceBranch TEXT,
  sourceVersion TEXT,
  startTime TEXT,
  status TEXT
);
```
