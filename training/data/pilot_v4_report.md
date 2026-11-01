# pilot_v4_report

```json
{
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

| v3 / v2.4 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|
| public | 2 | 0 | 0 | 0 | 0 | 0 | 28 |
| role_required | 0 | 3 | 3 | 0 | 2 | 1 | 21 |
| membership_required | 0 | 0 | 7 | 0 | 2 | 0 | 11 |
| tenant_match | 0 | 0 | 2 | 5 | 0 | 0 | 23 |
| owner_match | 0 | 0 | 1 | 0 | 7 | 0 | 22 |
| owner_or_admin | 0 | 1 | 0 | 0 | 8 | 0 | 21 |
| manual_review_required | 0 | 1 | 0 | 0 | 1 | 0 | 28 |
