# v2.6 status

```json
{
  "version": "policy-label-v2.6",
  "state": "pilot_stopped",
  "updated_at": "2026-10-19T15:24:02.513372+00:00",
  "records": 200,
  "labels": {
    "public": 2,
    "role_required": 45,
    "membership_required": 12,
    "tenant_match": 2,
    "owner_match": 25,
    "owner_or_admin": 2,
    "manual_review_required": 112
  },
  "confidence": {
    "[0,0.5]": 115,
    "(0.5,0.7)": 56,
    "[0.7,0.9)": 15,
    "[0.9,1]": 14
  },
  "evidence_invalid": 1,
  "mutation_public": 0,
  "flag_review": 0,
  "label_errors": 0,
  "transitions": {
    "public": {
      "public": 2,
      "role_required": 2,
      "membership_required": 0,
      "tenant_match": 1,
      "owner_match": 7,
      "owner_or_admin": 0,
      "manual_review_required": 15
    },
    "role_required": {
      "public": 0,
      "role_required": 20,
      "membership_required": 2,
      "tenant_match": 0,
      "owner_match": 2,
      "owner_or_admin": 0,
      "manual_review_required": 3
    },
    "membership_required": {
      "public": 0,
      "role_required": 6,
      "membership_required": 10,
      "tenant_match": 0,
      "owner_match": 2,
      "owner_or_admin": 0,
      "manual_review_required": 7
    },
    "tenant_match": {
      "public": 0,
      "role_required": 0,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 0,
      "owner_or_admin": 0,
      "manual_review_required": 0
    },
    "owner_match": {
      "public": 0,
      "role_required": 5,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 9,
      "owner_or_admin": 1,
      "manual_review_required": 1
    },
    "owner_or_admin": {
      "public": 0,
      "role_required": 5,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 0,
      "owner_or_admin": 1,
      "manual_review_required": 0
    },
    "manual_review_required": {
      "public": 0,
      "role_required": 7,
      "membership_required": 0,
      "tenant_match": 1,
      "owner_match": 5,
      "owner_or_admin": 0,
      "manual_review_required": 86
    }
  },
  "stop_reasons": [
    "heldout_accuracy_below_60_percent"
  ],
  "validation_records": 31,
  "validation_correct": 3,
  "validation_accuracy": 0.0967741935483871,
  "v5_validation_accuracy": 0,
  "validation_comparison": [
    {
      "id": "apisguru:deutschebahn.com:get:/providernetworks/{providernetworkUID}/rentalobjects/{rentalObjectUID}",
      "v5": "manual_review_required",
      "human": "public",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:illumidesk.com:get:/v1/teams/{team}/billing/invoices/{id}/",
      "v5": "owner_match",
      "human": "tenant_match",
      "v6": "owner_match",
      "correct": false
    },
    {
      "id": "apisguru:zoom.us:get:/accounts/{accountId}/lock_settings",
      "v5": "membership_required",
      "human": "role_required",
      "v6": "membership_required",
      "correct": false
    },
    {
      "id": "apisguru:gerermesaffaires.com:patch:/spaces/{id}",
      "v5": "owner_or_admin",
      "human": "manual_review_required",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:slack.com:get:/admin.conversations.getConversationPrefs",
      "v5": "public",
      "human": "role_required",
      "v6": "role_required",
      "correct": true
    },
    {
      "id": "apisguru:billingo.hu:post:/documents/{id}/create-from-proforma",
      "v5": "membership_required",
      "human": "tenant_match",
      "v6": "membership_required",
      "correct": false
    },
    {
      "id": "apisguru:nebl.io:get:/ntp1/transactioninfo/{txid}",
      "v5": "manual_review_required",
      "human": "public",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:trakt.tv:post:/users/{id}/lists/{list_id}/items/reorder",
      "v5": "role_required",
      "human": "owner_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:openbanking.org.uk:get:/accounts/{AccountId}/product",
      "v5": "manual_review_required",
      "human": "owner_match",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/image",
      "v5": "membership_required",
      "human": "manual_review_required",
      "v6": "membership_required",
      "correct": false
    },
    {
      "id": "apisguru:velopayments.com:get:/v1/webhooks",
      "v5": "public",
      "human": "tenant_match",
      "v6": "public",
      "correct": false
    },
    {
      "id": "apisguru:bitbucket.org:put:/repositories/{workspace}/{repo_slug}/commit/{commit}/reports/{reportId}/annotations/{annotationId}",
      "v5": "manual_review_required",
      "human": "membership_required",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:slmonitor.com:post:/api/v2.1/companies/{companyId}/users/{uniqueUserId}/checkin-audio",
      "v5": "membership_required",
      "human": "tenant_match",
      "v6": "membership_required",
      "correct": false
    },
    {
      "id": "apisguru:vtex.local:post:/api/catalog/pvt/collection/{collectionId}/position",
      "v5": "manual_review_required",
      "human": "role_required",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:amazonaws.com:get:/workspaces/{workspaceId}/alertmanager/definition",
      "v5": "public",
      "human": "tenant_match",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:hetzner.cloud:get:/datacenters/{id}",
      "v5": "manual_review_required",
      "human": "public",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:netboxdemo.com:put:/circuits/circuit-terminations/{id}/",
      "v5": "membership_required",
      "human": "role_required",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:api2cart.com:get:/account.cart.list.json",
      "v5": "public",
      "human": "owner_match",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:microsoft.com:post:/{projectId}/classify/iterations/{publishedName}/url",
      "v5": "membership_required",
      "human": "manual_review_required",
      "v6": "membership_required",
      "correct": false
    },
    {
      "id": "apisguru:twinehealth.com:get:/oauth/token/{id}/groups",
      "v5": "public",
      "human": "manual_review_required",
      "v6": "manual_review_required",
      "correct": true
    },
    {
      "id": "apisguru:rebilly.com:get:/credentials/{id}",
      "v5": "owner_match",
      "human": "tenant_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:appcenter.ms:patch:/v0.1/apps/{owner_name}/{app_name}/builds/{build_id}",
      "v5": "manual_review_required",
      "human": "membership_required",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:visma.net:get:/api/v3/SalesOrders/{type}/{orderId}/discounts",
      "v5": "public",
      "human": "tenant_match",
      "v6": "owner_match",
      "correct": false
    },
    {
      "id": "apisguru:appwrite.io:put:/teams/{teamId}",
      "v5": "owner_or_admin",
      "human": "owner_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:circuitsandbox.net:put:/conversations/community/{convId}",
      "v5": "role_required",
      "human": "membership_required",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:clicksend.com:post:/lists/{list_id}/contacts",
      "v5": "membership_required",
      "human": "owner_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:configcat.com:post:/v1/environments/{environmentId}/settings/{settingId}/integrationLinks/{integrationLinkType}/{key}",
      "v5": "manual_review_required",
      "human": "tenant_match",
      "v6": "manual_review_required",
      "correct": false
    },
    {
      "id": "apisguru:shutterstock.com:patch:/v2/catalog/collections/{collection_id}",
      "v5": "role_required",
      "human": "owner_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:aiception.com:get:/face/{taskId}",
      "v5": "public",
      "human": "owner_match",
      "v6": "owner_match",
      "correct": true
    },
    {
      "id": "apisguru:appwrite.io:put:/storage/files/{fileId}",
      "v5": "role_required",
      "human": "owner_match",
      "v6": "role_required",
      "correct": false
    },
    {
      "id": "apisguru:parliament.uk:get:/api/v1/Bills/{billId}/NewsArticles",
      "v5": "manual_review_required",
      "human": "public",
      "v6": "manual_review_required",
      "correct": false
    }
  ],
  "usage": {
    "input_tokens": 2251629,
    "cached_input_tokens": 1484032,
    "output_tokens": 12261,
    "total_tokens": 2263890,
    "estimated_usd_from_actual_usage": 0.23379855000000002,
    "pricing_usd_per_million": {
      "input": 0.15,
      "cached_input": 0.075,
      "output": 0.6
    },
    "pricing_source": "https://developers.openai.com/api/docs/models/gpt-4o-mini",
    "billing_invoice": false,
    "api_responses": 209
  }
}
```
