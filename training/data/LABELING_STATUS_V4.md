# v2.4 status

```json
{
  "version": "policy-label-v2.4",
  "state": "pilot_stopped",
  "updated_at": "2026-10-19T06:45:47.909967+00:00",
  "records": 200,
  "labels": {
    "public": 2,
    "role_required": 5,
    "membership_required": 13,
    "tenant_match": 5,
    "owner_match": 20,
    "owner_or_admin": 1,
    "manual_review_required": 154
  },
  "confidence": {
    "[0,0.5]": 154,
    "(0.5,0.7)": 0,
    "[0.7,0.9)": 25,
    "[0.9,1]": 21
  },
  "evidence_invalid": 3,
  "mutation_public": 1,
  "label_errors": 0,
  "transitions": {
    "public": {
      "public": 2,
      "role_required": 0,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 0,
      "owner_or_admin": 0,
      "manual_review_required": 28
    },
    "role_required": {
      "public": 0,
      "role_required": 3,
      "membership_required": 3,
      "tenant_match": 0,
      "owner_match": 2,
      "owner_or_admin": 1,
      "manual_review_required": 21
    },
    "membership_required": {
      "public": 0,
      "role_required": 0,
      "membership_required": 7,
      "tenant_match": 0,
      "owner_match": 2,
      "owner_or_admin": 0,
      "manual_review_required": 11
    },
    "tenant_match": {
      "public": 0,
      "role_required": 0,
      "membership_required": 2,
      "tenant_match": 5,
      "owner_match": 0,
      "owner_or_admin": 0,
      "manual_review_required": 23
    },
    "owner_match": {
      "public": 0,
      "role_required": 0,
      "membership_required": 1,
      "tenant_match": 0,
      "owner_match": 7,
      "owner_or_admin": 0,
      "manual_review_required": 22
    },
    "owner_or_admin": {
      "public": 0,
      "role_required": 1,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 8,
      "owner_or_admin": 0,
      "manual_review_required": 21
    },
    "manual_review_required": {
      "public": 0,
      "role_required": 1,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 1,
      "owner_or_admin": 0,
      "manual_review_required": 28
    }
  },
  "stop_reasons": [
    "mutation_public_present",
    "manual_review_above_40_percent",
    "confidence_bin_at_least_70_percent"
  ],
  "usage": {
    "input_tokens": 399890,
    "cached_input_tokens": 27648,
    "output_tokens": 9777,
    "total_tokens": 409667,
    "estimated_usd_from_actual_usage": 0.06377609999999999,
    "pricing_usd_per_million": {
      "input": 0.15,
      "cached_input": 0.075,
      "output": 0.6
    },
    "pricing_source": "https://developers.openai.com/api/docs/models/gpt-4o-mini",
    "billing_invoice": false,
    "api_responses": 212
  }
}
```
