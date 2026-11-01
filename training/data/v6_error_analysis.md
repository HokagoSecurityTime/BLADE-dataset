# v2.6 검증 실패 28건 분석

검증 31건 중 일치 3건, 불일치 28건. API 호출·라벨 변경·프롬프트 수정 없음. 아래 분류는 저장된 입력과 출력에 대한 진단 가설이며 원인의 실험적 증명이나 새로운 정답이 아니다.

| 주원인 | 건수 |
|---|---:|
| 입력 근거 부족 | 10 |
| 모델 판단 오류 | 9 |
| 규칙·라벨 기준 충돌 | 7 |
| 사람 라벨 재확인 | 2 |

각 행은 주원인 하나로 집계했지만 보조 원인이 겹친다. 특히 입력 부족 행에도 모델의 근거 없는 역할 판정 또는 보류 규칙 위반이 있을 수 있다.

## 공통 발견

- role_required를 API key/OAuth/필드 필수 조건과 혼동한 출력이 있다. organization/company/project를 인용하면서 membership을 낸 출력도 있어 rationale와 label의 의미가 불일치한다.
- membership의 프롬프트 정의는 plan/premium/subscription/tier 중심인데 사람 검수는 repository/app/community 구성원 권한도 포함한다. 팀 소유자·객체 ACL·전역 역할 구분도 일관된 정책이 필요하다.
- role과 유료 plan이 함께 필요한 Zoom처럼 복합 정책의 단일 라벨 우선순위가 명확하지 않은 사례가 있다.
- 강제 6종 제안 규칙과 불명확하면 보류한 사람 교정 사례가 충돌한다. 가상 예시를 교체했지만 본문에 이전 예시 7·9·11을 참조하는 문장은 남아 있다. 이 참조 오류가 성능 하락의 원인이라고 입증한 것은 아니다.
- evidence_fields 존재 검사는 인용한 필드가 있다는 것만 확인한다. 그 필드가 해당 label을 정당화하는지는 검사하지 못한다. 따라서 evidence_invalid=false는 정책 추론이 옳다는 뜻이 아니다.
- 서비스명·OAS info·security scheme 상세 설명은 현재 입력에 포함되지 않는다. 계좌 동의·회사 스코프·공개 데이터라는 사람 사유가 operation 설명에 없을 때 입력 비대칭이 생긴다.

## 행별 진단

### 1. apisguru:deutschebahn.com:get:/providernetworks/{providernetworkUID}/rentalobjects/{rentalObjectUID}

- 주원인: **입력 근거 부족**
- 사람: `public` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: 공개 open data 조회
- 모델 rationale: path: /providernetworks/{providernetworkUID}/rentalobjects/{rentalObjectUID}; security_state: unknown
- 진단: 입력에는 rental object 설명과 provider 후보만 있고 공개 open data라는 근거는 없다. unknown은 공개 증거가 아니다.
- 다음 조치: 서비스 공개 접근 문서 또는 OAS info 설명을 별도 근거로 확보. manual 선택도 최신 제한 규칙에는 부합하지 않아 보조적으로 모델 지침 불이행이 있다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/providernetworks/{providernetworkUID}/rentalobjects/{rentalObjectUID}",
  "path_params": [
    "providernetworkUID",
    "rentalObjectUID"
  ],
  "query_params": [
    "expand"
  ],
  "summary": "Get information about the RentalObject.",
  "description": "Get information about the Rental Object.\n",
  "security": null,
  "schema_fields": [
    "_links",
    "_links.[].href",
    "_links.[].rel",
    "_links.[].verb",
    "attributes",
    "category",
    "category._links",
    "category._links.[].href",
    "category._links.[].rel",
    "category._links.[].verb",
    "category.attributes",
    "category.description",
    "category.expand",
    "category.href",
    "category.name",
    "category.price",
    "category.price.[]._links",
    "category.price.[]._links.[].href",
    "category.price.[]._links.[].rel",
    "category.price.[]._links.[].verb",
    "category.price.[].attributes",
    "category.price.[].currency",
    "category.price.[].description",
    "category.price.[].expand",
    "category.price.[].grossamount",
    "category.price.[].href",
    "category.price.[].interval",
    "category.price.[].name",
    "category.price.[].preferredprice",
    "category.price.[].taxrate",
    "category.price.[].type",
    "category.price.[].uid",
    "category.uid",
    "description",
    "expand",
    "href",
    "name",
    "provider",
    "provider._links",
    "provider._links.[].href"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "provider"
  ],
  "security_state": "unknown"
}
```

### 2. apisguru:illumidesk.com:get:/v1/teams/{team}/billing/invoices/{id}/

- 주원인: **모델 판단 오류**
- 사람: `tenant_match` / 모델: `owner_match` / confidence: 0.6
- 사람 수정 사유: team 단위 billing invoice, customer는 소유자 신호 아님
- 모델 rationale: path: /v1/teams/{team}/billing/invoices/{id}; owner_cols: customer; security_state: declared
- 진단: 경로 /teams/{team}/billing/invoices는 조직 단서인데 모델은 customer 컬럼만 근거로 개인 소유를 골랐다.
- 다음 조치: 조직 경로와 응답 customer 속성의 우선순위 오류를 검증. tenant가 구조적 제안이라는 뜻이지 실제 정책 증명은 아니다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/v1/teams/{team}/billing/invoices/{id}/",
  "path_params": [
    "team",
    "id"
  ],
  "query_params": [],
  "summary": "Get an invoice",
  "description": "",
  "security": [
    {
      "jwt": []
    }
  ],
  "schema_fields": [
    "amount_due",
    "application_fee",
    "attempt_count",
    "attempted",
    "closed",
    "created",
    "currency",
    "customer",
    "description",
    "id",
    "invoice_date",
    "livemode",
    "metadata",
    "next_payment_attempt",
    "paid",
    "period_end",
    "period_start",
    "reciept_number",
    "starting_balance",
    "statement_descriptor",
    "stripe_id",
    "subscription",
    "subtotal",
    "tax",
    "total"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [
    "customer"
  ],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 3. apisguru:zoom.us:get:/accounts/{accountId}/lock_settings

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `role_required` / 모델: `membership_required` / confidence: 0.6
- 사람 수정 사유: scope account:read:admin, 관리자 전용. Pro plan은 부가 조건
- 모델 rationale: path: /accounts/{accountId}/lock_settings; description: account:read:admin; security_state: declared
- 진단: description에 account:read:admin과 Pro 이상 prerequisite가 동시에 명시돼 있다. 역할과 구독의 동시 조건 중 단일 label 우선순위가 불명확하다.
- 다음 조치: 역할+요금제 복합 조건에서 대표 label 선택 규약을 사람이 확정. membership을 근거 없는 환각으로 보기는 어렵다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/accounts/{accountId}/lock_settings",
  "path_params": [
    "accountId"
  ],
  "query_params": [
    "option",
    "custom_query_fields"
  ],
  "summary": "Get locked settings",
  "description": "[Account Locked Settings](https://support.zoom.us/hc/en-us/articles/115005269866) allow you turn settings on or off for all users in your account. No user except the account admin or account owner can change these settings. With lock settings, you force the settings on for all users.\nUse this API to retrieve an account's locked settings. \n\n**Note:** This API can be used by Zoom Accounts that are on a Pro or a higher plan as well accounts that have master and sub accounts options enabled. <br><br>\n**Prerequisites:**\n* Pro or a higher paid account. <br>\n\n**Scope**: `account:read:admin`.\n<br> **[Rate Limit Label](https://marketplace.zoom.us/docs/api-reference/rate-limits#rate-limits):** `Medium`<br>\n\n\n\n\n\n**Scope:** account:read:admin",
  "security": [
    {
      "OAuth": []
    }
  ],
  "schema_fields": [
    "email_notification",
    "email_notification.alternative_host_reminder",
    "email_notification.cancel_meeting_reminder",
    "email_notification.cloud_recording_available_reminder",
    "email_notification.jbh_reminder",
    "email_notification.schedule_for_host_reminder",
    "in_meeting",
    "in_meeting.alert_guest_join",
    "in_meeting.allow_show_zoom_windows",
    "in_meeting.annotation",
    "in_meeting.anonymous_question_answer",
    "in_meeting.attendee_on_hold",
    "in_meeting.auto_answer",
    "in_meeting.auto_saving_chat",
    "in_meeting.breakout_room",
    "in_meeting.chat",
    "in_meeting.closed_caption",
    "in_meeting.co_host",
    "in_meeting.custom_data_center_regions",
    "in_meeting.dscp_marking",
    "in_meeting.e2e_encryption",
    "in_meeting.entry_exit_chime",
    "in_meeting.far_end_camera_control",
    "in_meeting.feedback",
    "in_meeting.file_transfer",
    "in_meeting.group_hd",
    "in_meeting.original_audio",
    "in_meeting.polling",
    "in_meeting.post_meeting_feedback",
    "in_meeting.private_chat",
    "in_meeting.remote_control",
    "in_meeting.request_permission_to_unmute",
    "in_meeting.screen_sharing",
    "in_meeting.sending_default_email_invites",
    "in_meeting.show_meeting_control_toolbar",
    "in_meeting.stereo_audio",
    "in_meeting.use_html_format_email",
    "in_meeting.virtual_background",
    "in_meeting.webinar_question_answer",
    "in_meeting.whiteboard"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 4. apisguru:gerermesaffaires.com:patch:/spaces/{id}

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `manual_review_required` / 모델: `role_required` / confidence: 0.6
- 사람 수정 사유: space 수정 주체(소유자·그룹 관리자) 불명확
- 모델 rationale: security: [{"gma_auth": ["collaborator", "owner", "robot"]}]; security_state: declared
- 진단: 실제 scope에 collaborator/owner/robot가 있다. 사람은 주체 불명확을 보류했지만 프롬프트는 단서 부족만으로 보류하지 말라고 한다.
- 다음 조치: scope의 권한명/역할 구분과 모순의 정의를 명시. 사람 라벨이 틀렸다고 확정하지 않는다.

실행 입력 재구성:
```json
{
  "method": "PATCH",
  "path": "/spaces/{id}",
  "path_params": [
    "id"
  ],
  "query_params": [],
  "summary": "",
  "description": "Modify a Space (except private)",
  "security": [
    {
      "gma_auth": [
        "collaborator",
        "owner",
        "robot"
      ]
    }
  ],
  "schema_fields": [],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 5. apisguru:billingo.hu:post:/documents/{id}/create-from-proforma

- 주원인: **모델 판단 오류**
- 사람: `tenant_match` / 모델: `membership_required` / confidence: 0.6
- 사람 수정 사유: 조직 단위 문서 생성
- 모델 rationale: tenant_cols: organization; security_state: declared
- 진단: tenant_cols=organization 및 organization.address 등 응답 필드를 인용하면서 membership을 출력했다. plan/tier 요구는 없다.
- 다음 조치: 라벨과 rationale의 의미 정합성 검사 대상으로 우선 활용.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/documents/{id}/create-from-proforma",
  "path_params": [
    "id"
  ],
  "query_params": [],
  "summary": "Create a document from proforma.",
  "description": "Create a new document from proforma. Returns a document object if the create is succeded.",
  "security": [
    {
      "api_key": []
    }
  ],
  "schema_fields": [
    "block_id",
    "cancelled",
    "comment",
    "conversion_rate",
    "currency",
    "due_date",
    "electronic",
    "fulfillment_date",
    "gross_total",
    "id",
    "invoice_date",
    "invoice_number",
    "items",
    "items.[].gross_amount",
    "items.[].name",
    "items.[].net_amount",
    "items.[].net_unit_amount",
    "items.[].product_id",
    "items.[].quantity",
    "items.[].vat",
    "items.[].vat_amount",
    "language",
    "notification_status",
    "organization",
    "organization.address",
    "organization.address.address",
    "organization.address.city",
    "organization.address.country_code",
    "organization.address.post_code",
    "organization.bank_account",
    "organization.bank_account.account_number",
    "organization.bank_account.account_number_iban",
    "organization.bank_account.id",
    "organization.bank_account.name",
    "organization.bank_account.swift",
    "organization.cash_settled",
    "organization.eu_tax_number",
    "organization.ev_number",
    "organization.name",
    "organization.small_taxpayer"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "organization"
  ],
  "security_state": "declared"
}
```

### 6. apisguru:nebl.io:get:/ntp1/transactioninfo/{txid}

- 주원인: **입력 근거 부족**
- 사람: `public` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: 블록체인 공개 트랜잭션
- 모델 rationale: security_state: unknown; path: /ntp1/transactioninfo/{txid}; description: Returns detailed information regarding an NTP1 transaction.
- 진단: 블록체인 형태의 txid/blockhash 필드는 있지만 공개 접근이라는 명시는 입력에 없다. 사람 사유의 공개 체인 맥락이 입력 밖이다.
- 다음 조치: 공개 참조 데이터로 허용하는 도메인 기준 또는 접근 문서 보강. unknown만으로 public을 강제하지 않는다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/ntp1/transactioninfo/{txid}",
  "path_params": [
    "txid"
  ],
  "query_params": [],
  "summary": "Information On an NTP1 Transaction",
  "description": "Returns detailed information regarding an NTP1 transaction.\n",
  "security": null,
  "schema_fields": [
    "blockhash",
    "blockheight",
    "blocktime",
    "confirmations",
    "fee",
    "hex",
    "locktime",
    "time",
    "totalsent",
    "txid",
    "version",
    "vin",
    "vin.[].previousOutput",
    "vin.[].previousOutput.addresses",
    "vin.[].previousOutput.asm",
    "vin.[].previousOutput.hex",
    "vin.[].previousOutput.reqSigs",
    "vin.[].previousOutput.type",
    "vin.[].scriptSig",
    "vin.[].scriptSig.asm",
    "vin.[].scriptSig.hex",
    "vin.[].sequence",
    "vin.[].tokens",
    "vin.[].tokens.[].aggregationPolicy",
    "vin.[].tokens.[].amount",
    "vin.[].tokens.[].divisibility",
    "vin.[].tokens.[].issueTxid",
    "vin.[].tokens.[].lockStatus",
    "vin.[].tokens.[].tokenId",
    "vin.[].txid",
    "vin.[].value",
    "vin.[].vout",
    "vout",
    "vout.[].blockheight",
    "vout.[].n",
    "vout.[].scriptPubKey",
    "vout.[].scriptPubKey.addresses",
    "vout.[].scriptPubKey.asm",
    "vout.[].scriptPubKey.hex",
    "vout.[].scriptPubKey.reqSigs"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "unknown"
}
```

### 7. apisguru:trakt.tv:post:/users/{id}/lists/{list_id}/items/reorder

- 주원인: **모델 판단 오류**
- 사람: `owner_match` / 모델: `role_required` / confidence: 0.6
- 사람 수정 사유: OAuth는 인증. /users/{id}/lists = 본인 리스트
- 모델 rationale: path: /users/{id}/lists/{list_id}/items/reorder; description: OAuth Required; security_state: declared
- 진단: /users/{id}/lists와 OAuth Required만 있는데 role_required를 선택했다. 프롬프트는 OAuth와 역할 요구를 분리한다.
- 다음 조치: 인증과 역할 혼동의 명확한 진단 사례. 실제 소유자 제한 증명과 구조적 owner 제안은 구분.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/users/{id}/lists/{list_id}/items/reorder",
  "path_params": [
    "id",
    "list_id"
  ],
  "query_params": [],
  "summary": "Reorder items on a list",
  "description": "#### &#128274; OAuth Required\n\nReorder all items on a list by sending the updated `rank` of list item ids. Use the [**/users/:id/lists/:list_id/items**](#reference/users/list-items) method to get all list item ids.",
  "security": [
    {
      "oauth2": []
    }
  ],
  "schema_fields": [],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 8. apisguru:openbanking.org.uk:get:/accounts/{AccountId}/product

- 주원인: **모델 판단 오류**
- 사람: `owner_match` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: PSU 본인 계좌(동의 기반)
- 모델 rationale: security_state: declared; path: /accounts/{AccountId}/product; description: 
- 진단: /accounts/{AccountId}, PSUOAuth2Security scope accounts, 응답 AccountId가 있는데 전무/모순 설명 없이 confidence=0 보류.
- 다음 조치: account 스코프 인식 누락. PSU 동의의 세부 근거는 미제공이므로 사람 사유 전체가 입력에 있다고 주장하지 않는다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/accounts/{AccountId}/product",
  "path_params": [
    "AccountId"
  ],
  "query_params": [],
  "summary": "Get Products",
  "description": "",
  "security": [
    {
      "PSUOAuth2Security": [
        "accounts"
      ]
    }
  ],
  "schema_fields": [
    "Data",
    "Data.Product",
    "Data.Product.[].AccountId",
    "Data.Product.[].BCA",
    "Data.Product.[].BCA.CreditInterest",
    "Data.Product.[].BCA.CreditInterest.TierBandSet",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].CalculationMethod",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].Destination",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].Notes",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].AER",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].ApplicationFrequency",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].BankInterestRate",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].BankInterestRateType",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].CalculationFrequency",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].DepositInterestAppliedCoverage",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].FixedVariableInterestRateType",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].Identification",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].Notes",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherApplicationFrequency",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherApplicationFrequency.Code",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherApplicationFrequency.Description",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherApplicationFrequency.Name",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherBankInterestType",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherBankInterestType.Code",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherBankInterestType.Description",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherBankInterestType.Name",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherCalculationFrequency",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherCalculationFrequency.Code",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherCalculationFrequency.Description",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].OtherCalculationFrequency.Name",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].TierValueMaximum",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBand.[].TierValueMinimum",
    "Data.Product.[].BCA.CreditInterest.TierBandSet.[].TierBandMethod",
    "Data.Product.[].BCA.OtherFeesCharges",
    "Data.Product.[].BCA.OtherFeesCharges.[].FeeChargeCap",
    "Data.Product.[].BCA.OtherFeesCharges.[].FeeChargeCap.[].CappingPeriod",
    "Data.Product.[].BCA.OtherFeesCharges.[].FeeChargeCap.[].FeeCapAmount",
    "Data.Product.[].BCA.OtherFeesCharges.[].FeeChargeCap.[].FeeCapOccurrence",
    "Data.Product.[].BCA.OtherFeesCharges.[].FeeChargeCap.[].FeeType"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 9. apisguru:microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/image

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `manual_review_required` / 모델: `membership_required` / confidence: 0.4
- 사람 수정 사유: description 없음, 프로젝트 prediction key 기반이라 7종 매핑 불명확
- 모델 rationale: path: /{projectId}/classify/iterations/{publishedName}/image; tenant_cols: project; security_state: declared
- 진단: 사람은 prediction key의 7종 매핑 불명확을 보류한다. 프롬프트는 project를 tenant 단서로 규정하고 단서 부족 보류를 금지한다. 모델 membership에도 plan 근거가 없다.
- 다음 조치: 서비스 키/프로젝트 권한의 taxonomy를 먼저 합의. membership 출력은 별도의 모델 정합성 오류.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/{projectId}/classify/iterations/{publishedName}/image",
  "path_params": [
    "projectId",
    "publishedName"
  ],
  "query_params": [
    "application"
  ],
  "summary": "Classify an image and saves the result.",
  "description": "",
  "security": [
    {
      "apim_key": []
    }
  ],
  "schema_fields": [
    "created",
    "id",
    "iteration",
    "predictions",
    "predictions.[].boundingBox",
    "predictions.[].boundingBox.height",
    "predictions.[].boundingBox.left",
    "predictions.[].boundingBox.top",
    "predictions.[].boundingBox.width",
    "predictions.[].probability",
    "predictions.[].tagId",
    "predictions.[].tagName",
    "project"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "project"
  ],
  "security_state": "declared"
}
```

### 10. apisguru:velopayments.com:get:/v1/webhooks

- 주원인: **모델 판단 오류**
- 사람: `tenant_match` / 모델: `public` / confidence: 0.4
- 사람 수정 사유: payor(조직) 단위 webhook 설정
- 모델 rationale: method: GET; path: /v1/webhooks; security_state: declared
- 진단: description에 given payor, query payorId, 응답 payorId가 있으며 OAuth 선언도 있다. 모델은 GET·path만으로 public을 출력했다.
- 다음 조치: 공개 근거 없는 public 선택을 오류로 진단. payor가 조직이라는 해석은 별도 도메인 지식임도 표시.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/v1/webhooks",
  "path_params": [],
  "query_params": [
    "page",
    "pageSize",
    "payorId"
  ],
  "summary": "List the details about the webhooks for the given payor.",
  "description": "List the details about the webhooks for the given payor.",
  "security": [
    {
      "OAuth2": []
    }
  ],
  "schema_fields": [
    "content",
    "content.[].authorizationHeader",
    "content.[].categories",
    "content.[].enabled",
    "content.[].id",
    "content.[].payorId",
    "content.[].webhookUrl",
    "links",
    "links.[].href",
    "links.[].rel",
    "page",
    "page.numberOfElements",
    "page.page",
    "page.pageSize",
    "page.totalElements",
    "page.totalPages"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 11. apisguru:bitbucket.org:put:/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{reportId}/annotations/{annotationId}

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `membership_required` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: repository 쓰기 권한(workspace·repo 구성원)
- 모델 rationale: path: /repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{reportId}/annotations/{annotationId}; security_state: unknown
- 진단: 사람 membership은 workspace/repository 구성원 쓰기 권한을 뜻하지만 프롬프트 membership은 plan/premium/subscription/tier 중심이다. 경로 workspace는 tenant 단서다.
- 다음 조치: 구성원 관계와 구독 등급 중 membership 의미를 통일. 실제 write 권한은 현재 description에 명시돼 있지 않다.

실행 입력 재구성:
```json
{
  "method": "PUT",
  "path": "/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{reportId}/annotations/{annotationId}",
  "path_params": [
    "workspace",
    "repo_slug",
    "commit",
    "reportId",
    "annotationId"
  ],
  "query_params": [],
  "summary": "Create or update an annotation",
  "description": "Creates or updates an individual annotation for the specified report.\nAnnotations are individual findings that have been identified as part of a report, for example, a line of code that represents a vulnerability. These annotations can be attached to a specific file and even a specific line in that file, however, that is optional. Annotations are not mandatory and a report can contain up to 1000 annotations.\n\nJust as reports, annotation needs to be uploaded with a unique ID that can later be used to identify the report as an alternative to the generated [UUID](https://developer.atlassian.com/bitbucket/api/2/reference/meta/uri-uuid#uuid). If you want to use an existing id from your own system, we recommend prefixing it with your system's name to avoid collisions, for example, mySystem-annotation001.\n\n### Sample cURL request:\n```\ncurl --request PUT 'https://api.bitbucket.org/2.0/repositories/<username>/<reposity-name>/commit/<commit-hash>/reports/mySystem-001/annotations/mysystem-annotation001' \\\n--header 'Content-Type: application/json' \\\n--data-raw '{\n    \"title\": \"Security scan report\",\n    \"annotation_type\": \"VULNERABILITY\",\n    \"summary\": \"This line represents a security thread.\",\n    \"severity\": \"HIGH\",\n    \"path\": \"my-service/src/main/java/com/myCompany/mysystem/logic/Main.java\",\n    \"line\": 42\n}'\n```\n\n### Possible field values:\nannotation_type: VULNERABILITY, CODE_SMELL, BUG\nresult: PASSED, FAILED, IGNORED, SKIPPED\nseverity: HIGH, MEDIUM, LOW, CRITICAL\n\nPlease refer to the [Code Insights documentation](https://confluence.atlassian.com/bitbucket/code-insights-994316785.html) for more information.\n",
  "security": null,
  "schema_fields": [
    "type",
    "annotation_type",
    "created_on",
    "details",
    "external_id",
    "line",
    "link",
    "path",
    "result",
    "severity",
    "summary",
    "updated_on",
    "uuid"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "unknown"
}
```

### 12. apisguru:slmonitor.com:post:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin-audio

- 주원인: **모델 판단 오류**
- 사람: `tenant_match` / 모델: `membership_required` / confidence: 0.6
- 사람 수정 사유: companyId 단위 worker 데이터, 동일 서비스 81행과 일치
- 모델 rationale: path: /api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin-audio; description: This operation checks the worker in for a default time or a custom time if the optional interval is provided, and includes an audio attachment.; security_state: declared
- 진단: companies/{companyId}, tenant_cols=company, 응답 company가 일치하는데 membership 선택. plan/tier 요구는 없다.
- 다음 조치: tenant 단서를 membership으로 오해한 사례. CompanyMonitor scope와 개인 사용자 중첩도 함께 검토.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin-audio",
  "path_params": [
    "companyId",
    "uniqueUserId"
  ],
  "query_params": [
    "interval",
    "deviceType"
  ],
  "summary": "Check in with an audio recording",
  "description": "This operation checks the worker in for a default time or a custom time if the optional interval is provided, and includes an audio attachment.",
  "security": [
    {
      "EmailLogin": [
        "CompanyMonitor"
      ]
    },
    {
      "MicrosoftLogin": [
        "CompanyMonitor"
      ]
    },
    {
      "Pin": []
    }
  ],
  "schema_fields": [
    "address",
    "cell",
    "comments",
    "company",
    "company.login",
    "company.name",
    "firstName",
    "fullName",
    "group",
    "group.name",
    "language",
    "lastName",
    "notificationEmails",
    "notificationPhones",
    "notificationPhones.[].order",
    "notificationPhones.[].phoneNumber",
    "phone",
    "priveleges",
    "satelliteDeviceId",
    "uniqueUserId",
    "vehicle",
    "vehicle.color",
    "vehicle.plate",
    "vehicle.type",
    "workerInformation",
    "workerInformation.actions",
    "workerInformation.actions.[].instructions",
    "workerInformation.actions.[].order",
    "workerInformation.itinerary",
    "workerInformation.lastLocation",
    "workerInformation.lastLocation.accuracy",
    "workerInformation.lastLocation.address",
    "workerInformation.lastLocation.altitude",
    "workerInformation.lastLocation.altitudeAccuracy",
    "workerInformation.lastLocation.battery",
    "workerInformation.lastLocation.device",
    "workerInformation.lastLocation.deviceName",
    "workerInformation.lastLocation.heading",
    "workerInformation.lastLocation.latitude",
    "workerInformation.lastLocation.longitude"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "company"
  ],
  "security_state": "declared"
}
```

### 13. apisguru:vtex.local:post:/api/catalog/pvt/collection/{collectionId}/position

- 주원인: **입력 근거 부족**
- 사람: `role_required` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: pvt catalog 관리 API, License Manager 역할
- 모델 rationale: security_state: declared; description: There are two ways to configure collections, through Legacy CMS Portal or using the Beta Collection module.
- 진단: description은 subcollection SKU 위치 변경과 CMS 모듈만 설명한다. 사람 사유의 License Manager 역할은 입력에 없다.
- 다음 조치: 역할 요구 문서를 확보. /pvt/ 약어만으로 특정 역할을 증명하지 않는다.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/api/catalog/pvt/collection/{collectionId}/position",
  "path_params": [
    "collectionId"
  ],
  "query_params": [],
  "summary": "Reposition SKU on the Subcollection",
  "description": " >⚠️ There are two ways to configure collections, through Legacy CMS Portal or using the Beta Collection module. This endpoint is compatible with [collections configured through the Legacy CMS Portal](https://help.vtex.com/en/tutorial/adding-collections-cms--2YBy6P6X0NFRpkD2ZBxF6L).\n\nEdits the position of an SKU that already exists in the Subcollection,  which is a [Group](https://help.vtex.com/en/tutorial/adding-collections-cms--2YBy6P6X0NFRpkD2ZBxF6L#group-types) within a  Collection.\r\n## Request body example\r\n\r\n```json\r\n{\r\n     \"skuId\": 1,\r\n     \"position\": 1,\r\n     \"subCollectionId\": 17\r\n}\r\n```",
  "security": [
    {
      "appKey": [],
      "appToken": []
    }
  ],
  "schema_fields": [],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 14. apisguru:amazonaws.com:get:/workspaces/{workspaceId}/alertmanager/definition

- 주원인: **모델 판단 오류**
- 사람: `tenant_match` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: AWS 계정 소유 workspace 리소스
- 모델 rationale: security_state: declared; description: Describes an alert manager definition.
- 진단: /workspaces/{workspaceId}가 프롬프트 tenant 단서에 명시되지만 모델은 짧은 description만 인용해 보류했다.
- 다음 조치: 경로 단서를 누락한 사례. AWS 계정 소유라는 상세 배경까지 검증한 것은 아니다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/workspaces/{workspaceId}/alertmanager/definition",
  "path_params": [
    "workspaceId"
  ],
  "query_params": [],
  "summary": "",
  "description": "Describes an alert manager definition.",
  "security": [
    {
      "hmac": []
    }
  ],
  "schema_fields": [
    "alertManagerDefinition",
    "alertManagerDefinition.status",
    "alertManagerDefinition.status.statusCode",
    "alertManagerDefinition.status.statusReason",
    "alertManagerDefinition.data",
    "alertManagerDefinition.createdAt",
    "alertManagerDefinition.modifiedAt"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 15. apisguru:hetzner.cloud:get:/datacenters/{id}

- 주원인: **입력 근거 부족**
- 사람: `public` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: 공개 datacenter 카탈로그
- 모델 rationale: security_state: unknown; path: /datacenters/{id}; description: Returns a specific Datacenter object.
- 진단: datacenter 위치·server_types 필드는 카탈로그 해석을 지지하지만 공개 접근 여부는 명시돼 있지 않다.
- 다음 조치: 공개 카탈로그의 인가 대상 아님 정의를 합의하고 접근 문서로 확인.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/datacenters/{id}",
  "path_params": [
    "id"
  ],
  "query_params": [],
  "summary": "Get a Datacenter",
  "description": "Returns a specific Datacenter object.",
  "security": null,
  "schema_fields": [
    "datacenter",
    "datacenter.description",
    "datacenter.id",
    "datacenter.location",
    "datacenter.location.city",
    "datacenter.location.country",
    "datacenter.location.description",
    "datacenter.location.id",
    "datacenter.location.latitude",
    "datacenter.location.longitude",
    "datacenter.location.name",
    "datacenter.location.network_zone",
    "datacenter.name",
    "datacenter.server_types",
    "datacenter.server_types.available",
    "datacenter.server_types.available_for_migration",
    "datacenter.server_types.supported"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "unknown"
}
```

### 16. apisguru:netboxdemo.com:put:/circuits/circuit-terminations/{id}/

- 주원인: **입력 근거 부족**
- 사람: `role_required` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: NetBox 모델 change 권한 기반, site는 tenant 신호 아님
- 모델 rationale: security_state: declared; path: /circuits/circuit-terminations/{id}/; tenant_cols: site
- 진단: description 공란과 Bearer만으로 NetBox change 권한을 알 수 없다. site 후보는 실제로 물리적 장소일 수 있다.
- 다음 조치: 모델 권한 문서 보강 및 site→tenant 탐지의 오탐 검토.

실행 입력 재구성:
```json
{
  "method": "PUT",
  "path": "/circuits/circuit-terminations/{id}/",
  "path_params": [
    "id"
  ],
  "query_params": [],
  "summary": "",
  "description": "",
  "security": [
    {
      "Bearer": []
    }
  ],
  "schema_fields": [
    "circuit",
    "circuit.cid",
    "circuit.id",
    "circuit.url",
    "id",
    "interface",
    "interface.device",
    "interface.device.display_name",
    "interface.device.id",
    "interface.device.name",
    "interface.device.url",
    "interface.id",
    "interface.is_connected",
    "interface.name",
    "interface.url",
    "port_speed",
    "pp_info",
    "site",
    "site.id",
    "site.name",
    "site.slug",
    "site.url",
    "term_side",
    "upstream_speed",
    "xconnect_id"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "site"
  ],
  "security_state": "declared"
}
```

### 17. apisguru:api2cart.com:get:/account.cart.list.json

- 주원인: **모델 판단 오류**
- 사람: `owner_match` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: API 계정 본인의 cart 목록
- 모델 rationale: security_state: declared; description: Get list of carts.
- 진단: /account.cart.list.json이라는 개인 계정 단서를 단순 세그먼트가 아니라 점 구분 경로에서도 읽어야 한다. 모델은 설명만 보고 보류했다.
- 다음 조치: 비 REST 스타일 account 경로 신호의 인식 실패. 실제 계정 소유 정책 확인은 별도.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/account.cart.list.json",
  "path_params": [],
  "query_params": [
    "params",
    "exclude",
    "request_from_date",
    "request_to_date",
    "store_url",
    "store_key"
  ],
  "summary": "",
  "description": "Get list of carts.",
  "security": [
    {
      "api_key": []
    }
  ],
  "schema_fields": [
    "result",
    "result.carts",
    "result.carts.[].cart_id",
    "result.carts.[].id",
    "result.carts.[].store_key",
    "result.carts.[].total_calls",
    "result.carts.[].url",
    "result.carts_count",
    "return_code",
    "return_message"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 18. apisguru:microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/url

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `manual_review_required` / 모델: `membership_required` / confidence: 0.4
- 사람 수정 사유: description 없음, 프로젝트 prediction key 기반이라 7종 매핑 불명확
- 모델 rationale: path: /{projectId}/classify/iterations/{publishedName}/url; security_state: declared; tenant_cols: project
- 진단: image 변형과 동일하게 project/키 기반 정책의 인간 보류와 강제 6종 제안 규칙이 충돌한다. membership 근거도 없다.
- 다음 조치: image/url 두 행은 같은 원인군이며 독립 오류 유형으로 과대 집계하지 않는다.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/{projectId}/classify/iterations/{publishedName}/url",
  "path_params": [
    "projectId",
    "publishedName"
  ],
  "query_params": [
    "application"
  ],
  "summary": "Classify an image url and saves the result.",
  "description": "",
  "security": [
    {
      "apim_key": []
    }
  ],
  "schema_fields": [
    "created",
    "id",
    "iteration",
    "predictions",
    "predictions.[].boundingBox",
    "predictions.[].boundingBox.height",
    "predictions.[].boundingBox.left",
    "predictions.[].boundingBox.top",
    "predictions.[].boundingBox.width",
    "predictions.[].probability",
    "predictions.[].tagId",
    "predictions.[].tagName",
    "project"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "project"
  ],
  "security_state": "declared"
}
```

### 19. apisguru:rebilly.com:get:/credentials/{id}

- 주원인: **입력 근거 부족**
- 사람: `tenant_match` / 모델: `role_required` / confidence: 0.6
- 사람 수정 사유: merchant 조직 단위 credential, 45행과 일치
- 모델 rationale: security: [{"SecretApiKey": []}, {"JWT": []}]; owner_cols: ["customerId", "username"]
- 진단: 사람은 merchant 조직을 근거로 하지만 입력은 SecretApiKey/JWT, customerId/username뿐이다. merchant 스코프가 전달되지 않았다.
- 다음 조치: 조직 스코프 문서 보강. 모델이 API key를 역할로 읽은 것은 별도 명확한 오류.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/credentials/{id}",
  "path_params": [
    "id"
  ],
  "query_params": [],
  "summary": "Retrieve a credential",
  "description": "Retrieve a credential with specified identifier string.\n",
  "security": [
    {
      "SecretApiKey": []
    },
    {
      "JWT": []
    }
  ],
  "schema_fields": [
    "_links",
    "_links.[].rel",
    "_links.[].href",
    "customerId",
    "expiredTime",
    "id",
    "password",
    "username"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [
    "customerId",
    "username"
  ],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 20. apisguru:appcenter.ms:patch:/v0.1/apps/{owner_name}/{app_name}/builds/{build_id}

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `membership_required` / 모델: `role_required` / confidence: 0.6
- 사람 수정 사유: app collaborator 권한
- 모델 rationale: security: [{"APIToken": []}]; security_state: declared
- 진단: 사람은 app collaborator를 membership으로 매핑하지만 입력에는 APIToken과 Cancels a build만 있다. collaborator는 입력 밖이고 구독형 membership 정의와도 다르다.
- 다음 조치: 협업자 membership 정의와 근거 문서 정리. API token→role 해석도 오류.

실행 입력 재구성:
```json
{
  "method": "PATCH",
  "path": "/v0.1/apps/{owner_name}/{app_name}/builds/{build_id}",
  "path_params": [
    "owner_name",
    "app_name",
    "build_id"
  ],
  "query_params": [],
  "summary": "",
  "description": "Cancels a build",
  "security": [
    {
      "APIToken": []
    }
  ],
  "schema_fields": [
    "buildNumber",
    "finishTime",
    "id",
    "lastChangedDate",
    "queueTime",
    "result",
    "sourceBranch",
    "sourceVersion",
    "startTime",
    "status"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 21. apisguru:visma.net:get:/api/v3/SalesOrders/{type}/{orderId}/discounts

- 주원인: **입력 근거 부족**
- 사람: `tenant_match` / 모델: `owner_match` / confidence: 0.6
- 사람 수정 사유: ERP 회사 단위 판매주문 데이터, 공개 아님
- 모델 rationale: path: /api/v3/SalesOrders/{type}/{orderId}/discounts; description: Gets discount details information for a single sales order; security_state: declared
- 진단: SalesOrders와 read scope는 있지만 회사/tenant 연결은 입력에 없다. ERP 회사 단위라는 사람 사유는 서비스 맥락이다.
- 다음 조치: 회사 식별 헤더/조직 설명을 입력에 보강. 모델 owner 선택 역시 현재 입력으로 강하게 지지되지 않는다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/api/v3/SalesOrders/{type}/{orderId}/discounts",
  "path_params": [
    "type",
    "orderId"
  ],
  "query_params": [],
  "summary": "Gets discount details information for a single sales order",
  "description": "Sample request:\r\n            \r\n`GET /salesorders/SO/000101/discounts`",
  "security": [
    {
      "oauth2": [
        "read"
      ]
    }
  ],
  "schema_fields": [
    "[].discountAmount",
    "[].discountId",
    "[].discountPercent",
    "[].discountSequenceId",
    "[].discountableAmount",
    "[].discountableQuantity",
    "[].freeItem",
    "[].freeItem.description",
    "[].freeItem.id",
    "[].freeItemQuantity",
    "[].isManual",
    "[].manualOrderIndex",
    "[].skipDiscount",
    "[].type"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 22. apisguru:appwrite.io:put:/teams/{teamId}

- 주원인: **모델 판단 오류**
- 사람: `owner_match` / 모델: `role_required` / confidence: 0.9
- 사람 수정 사유: "Only team owners", admin 언급 없음
- 모델 rationale: description: Only team owners have write access for this resource; security_state: declared
- 진단: Only team owners have write access라고 명시되는데 모델은 같은 문장을 인용해 role_required를 출력했다.
- 다음 조치: 리소스 소유자와 전역 역할 구분을 평가. 팀 소유권은 프로젝트 tenant 소유와 다른 관계일 수 있다.

실행 입력 재구성:
```json
{
  "method": "PUT",
  "path": "/teams/{teamId}",
  "path_params": [
    "teamId"
  ],
  "query_params": [],
  "summary": "Update Team",
  "description": "Update a team by its unique ID. Only team owners have write access for this resource.",
  "security": [
    {
      "JWT": [],
      "Project": []
    }
  ],
  "schema_fields": [
    "$id",
    "dateCreated",
    "name",
    "sum"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 23. apisguru:circuitsandbox.net:put:/conversations/community/{convId}

- 주원인: **규칙·라벨 기준 충돌**
- 사람: `membership_required` / 모델: `role_required` / confidence: 0.75
- 사람 수정 사유: scope는 역할 아님. community 구성원·관리자 수정
- 모델 rationale: path: /conversations/community/{convId}; description: OauthScopes: WRITE_CONVERSATIONS, MANAGE_CONVERSATIONS; security_state: declared
- 진단: WRITE_CONVERSATIONS/MANAGE_CONVERSATIONS는 OAuth 작업 권한이고 description에 구성원/관리자 관계는 없다. 사람 membership은 구독 중심 정의와 다르다.
- 다음 조치: 작업 scope·객체 구성원·전역 역할을 분리하는 기준과 추가 정책 근거가 필요.

실행 입력 재구성:
```json
{
  "method": "PUT",
  "path": "/conversations/community/{convId}",
  "path_params": [
    "convId"
  ],
  "query_params": [],
  "summary": "Updates the information of a community",
  "description": "Updates the information of the given community.\nOauthScopes: WRITE_CONVERSATIONS, MANAGE_CONVERSATIONS",
  "security": [
    {
      "oauth": [
        "ALL",
        "WRITE_CONVERSATIONS",
        "MANAGE_CONVERSATIONS"
      ]
    }
  ],
  "schema_fields": [
    "avatar",
    "avatarLarge",
    "convId",
    "creationTime",
    "creatorId",
    "creatorTenantId",
    "description",
    "isGuestAccessDisabled",
    "isModerated",
    "modificationTime",
    "participants",
    "topic",
    "topicPlaceholder",
    "type"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [
    "creatorId"
  ],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 24. apisguru:clicksend.com:post:/lists/{list_id}/contacts

- 주원인: **입력 근거 부족**
- 사람: `owner_match` / 모델: `role_required` / confidence: 0.6
- 사람 수정 사유: rationale이 필드 검증 문구로 잘못 추출. 계정 본인 list
- 모델 rationale: path: /lists/{list_id}/contacts; description: at least one of them must be specified; security_state: declared
- 진단: 설명은 전화/팩스/email 중 필수 입력 조건일 뿐 계정 소유나 역할 조건이 아니다. 사람 사유의 본인 list 관계는 입력 밖이다.
- 다음 조치: 계정별 list 소유 근거 보강. 필드 필수 조건→역할 요구는 모델의 별도 오류.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/lists/{list_id}/contacts",
  "path_params": [
    "list_id"
  ],
  "query_params": [],
  "summary": "Create a new contact",
  "description": "Note that the fields `phone_number`, `fax_number` and email` are all optional; however at least one of them must be specified, otherwise the API call will fail.",
  "security": [
    {
      "basic": []
    }
  ],
  "schema_fields": [],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [
    "organization_name"
  ],
  "security_state": "declared"
}
```

### 25. apisguru:configcat.com:post:/v1/environments/{environmentId}/settings/{settingId}/integrationLinks/{integrationLinkType}/{key}

- 주원인: **입력 근거 부족**
- 사람: `tenant_match` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: organization·product 단위 환경 설정
- 모델 rationale: path: /v1/environments/{environmentId}/settings/{settingId}/integrationLinks/{integrationLinkType}/{key}; security_state: declared
- 진단: 환경/설정 ID와 Basic 인증만 있고 organization/product 관계는 전달되지 않았다.
- 다음 조치: 조직·제품 리소스 연결 문서나 상위 스코프 보강. model manual도 강제 제안 규칙과는 불일치.

실행 입력 재구성:
```json
{
  "method": "POST",
  "path": "/v1/environments/{environmentId}/settings/{settingId}/integrationLinks/{integrationLinkType}/{key}",
  "path_params": [
    "environmentId",
    "settingId",
    "integrationLinkType",
    "key"
  ],
  "query_params": [],
  "summary": "Add or update Integration link",
  "description": "",
  "security": [
    {
      "Basic": []
    }
  ],
  "schema_fields": [
    "description",
    "integrationLinkType",
    "key",
    "url"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 26. apisguru:shutterstock.com:patch:/v2/catalog/collections/{collection_id}

- 주원인: **사람 라벨 재확인**
- 사람: `owner_match` / 모델: `role_required` / confidence: 0.75
- 사람 수정 사유: 사용자 본인 catalog collection 수정
- 모델 rationale: security: [{"customer_accessCode": ["collections.view", "collections.edit"]}]; security_state: declared
- 진단: 응답에 role_assignments.roles.editors/owners/viewers가 함께 있다. customer_accessCode와 collections.edit만으로 수정 권한을 owner 단독으로 확정할 수 없다.
- 다음 조치: 사람 owner_match를 객체별 ACL로 읽은 것인지 재검토. 모델 role도 전역 역할인지 객체 역할인지 확인 전 정답으로 채택하지 않는다.

실행 입력 재구성:
```json
{
  "method": "PATCH",
  "path": "/v2/catalog/collections/{collection_id}",
  "path_params": [
    "collection_id"
  ],
  "query_params": [],
  "summary": "Update collection metadata",
  "description": "This endpoint updates the metadata of a catalog collection.",
  "security": [
    {
      "customer_accessCode": [
        "collections.view",
        "collections.edit"
      ]
    }
  ],
  "schema_fields": [
    "cover_asset",
    "cover_asset.asset",
    "cover_asset.asset.id",
    "cover_asset.asset.name",
    "cover_asset.asset.type",
    "cover_asset.collection_ids",
    "cover_asset.created_time",
    "cover_asset.id",
    "created_time",
    "id",
    "name",
    "role_assignments",
    "role_assignments.collection_id",
    "role_assignments.roles",
    "role_assignments.roles.editors",
    "role_assignments.roles.editors.[].email",
    "role_assignments.roles.editors.[].id",
    "role_assignments.roles.editors.[].type",
    "role_assignments.roles.owners",
    "role_assignments.roles.owners.[].email",
    "role_assignments.roles.owners.[].id",
    "role_assignments.roles.owners.[].type",
    "role_assignments.roles.viewers",
    "role_assignments.roles.viewers.[].email",
    "role_assignments.roles.viewers.[].id",
    "role_assignments.roles.viewers.[].type",
    "total_item_count",
    "updated_time",
    "visibility"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 27. apisguru:appwrite.io:put:/storage/files/{fileId}

- 주원인: **사람 라벨 재확인**
- 사람: `owner_match` / 모델: `role_required` / confidence: 0.75
- 사람 수정 사유: 객체별 write 권한(ACL) 기반, 전역 역할 아님
- 모델 rationale: description: Only users with write permissions have access to update this resource; security_state: declared
- 진단: Only users with write permissions와 $permissions.write는 ACL이다. ACL 쓰기 권한 보유자는 소유자와 동치가 아니다.
- 다음 조치: owner_match가 ACL을 포함하는지 라벨 정의를 재확인. 기존 사람 라벨은 변경하지 않으며 7종 밖 관계의 처리 방침 필요.

실행 입력 재구성:
```json
{
  "method": "PUT",
  "path": "/storage/files/{fileId}",
  "path_params": [
    "fileId"
  ],
  "query_params": [],
  "summary": "Update File",
  "description": "Update a file by its unique ID. Only users with write permissions have access to update this resource.",
  "security": [
    {
      "JWT": [],
      "Project": []
    }
  ],
  "schema_fields": [
    "$id",
    "$permissions",
    "$permissions.[].read",
    "$permissions.[].write",
    "dateCreated",
    "mimeType",
    "name",
    "signature",
    "sizeOriginal"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "declared"
}
```

### 28. apisguru:parliament.uk:get:/api/v1/Bills/{billId}/NewsArticles

- 주원인: **입력 근거 부족**
- 사람: `public` / 모델: `manual_review_required` / confidence: 0.0
- 사람 수정 사유: 의회 공개 데이터
- 모델 rationale: security_state: unknown; path: /api/v1/Bills/{billId}/NewsArticles; description: 
- 진단: Bill 뉴스 목록과 기사 필드만 전달돼 의회 공개 데이터라는 서비스 수준 설명은 없다.
- 다음 조치: 공개 데이터 성격/접근 근거를 보강. summary는 입력에 있으므로 description 공란만으로 입력 전체가 없다고 보지 않는다.

실행 입력 재구성:
```json
{
  "method": "GET",
  "path": "/api/v1/Bills/{billId}/NewsArticles",
  "path_params": [
    "billId"
  ],
  "query_params": [
    "Skip",
    "Take"
  ],
  "summary": "Returns a list of news articles for a Bill.",
  "description": "",
  "security": null,
  "schema_fields": [
    "items",
    "items.[].content",
    "items.[].displayDate",
    "items.[].id",
    "items.[].title",
    "itemsPerPage",
    "totalResults"
  ],
  "schema_provenance": "Fields extracted from API response schema; not a verified database ERD",
  "owner_cols": [],
  "tenant_cols": [],
  "security_state": "unknown"
}
```

## 다음 작업의 우선순위

1. 구성원/구독, 객체 ACL/소유권, 조직/개인 계정, 복합 정책의 단일 라벨 선택 기준을 사람과 합의한다. 현재 라벨은 유지한다.
2. 입력 근거 부족 10건은 사람 사유에 필요한 맥락이 로컬 원본 OAS의 info/securitySchemes/상위 설명에 있는지 확인한다. 없다면 별도 출처 확인이 필요하다.
3. 모델 판단 오류 9건은 충분한 구조 단서를 가진 진단 표본으로 사용한다. 단순 API key=역할, 조직=membership 오류를 우선 분리한다.
4. 위 결정 후 새로운 사람 검수 표본으로 평가한다. 이 31건은 이미 분석에 사용됐으므로 독립적인 최종 성능 평가 자료로 계속 재사용하지 않는다.

## 재현성과 한계

입력은 저장된 pilot 레코드에 label_v3.payload의 실제 조립 함수를 적용하고 실행 당시 저장된 security_state와 v2.6 transport의 schema_provenance 문자열을 결합해 재구성했다. 전송 원문 로그는 없으므로 네트워크 캡처와 동일하다고 주장하지 않는다. 전체 입력은 v6_error_analysis.json에도 보존했다. 외부 서비스 문서의 현재 정책은 조회하거나 검증하지 않았다. 사람이 제공한 공개/조직/ACL 해석의 사실성은 별도 검증 대상이다.
이 검증 표본은 v5에서 이미 틀린 사례만 골랐으므로 9.68%는 전체 데이터 정확도가 아니다. Microsoft image/url 두 건은 동일 유형으로 상관돼 있다.
