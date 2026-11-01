# pilot_v5_authorized_resume_report

```json
{
  "records": 200,
  "labels": {
    "public": 10,
    "role_required": 6,
    "membership_required": 15,
    "tenant_match": 10,
    "owner_match": 24,
    "owner_or_admin": 1,
    "manual_review_required": 134
  },
  "confidence": {
    "[0,0.5]": 134,
    "(0.5,0.7)": 8,
    "[0.7,0.9)": 30,
    "[0.9,1]": 28
  },
  "evidence_invalid": 3,
  "mutation_public": 1,
  "flag_review": 1,
  "label_errors": 0,
  "stop_reasons": [],
  "usage": {
    "input_tokens": 481785,
    "cached_input_tokens": 282240,
    "output_tokens": 9533,
    "total_tokens": 491318,
    "estimated_usd_from_actual_usage": 0.05681955,
    "pricing_usd_per_million": {
      "input": 0.15,
      "cached_input": 0.075,
      "output": 0.6
    },
    "pricing_source": "https://developers.openai.com/api/docs/models/gpt-4o-mini",
    "billing_invoice": false,
    "api_responses": 207
  }
}
```

| v2.4 / v2.5 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|
| public | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| role_required | 0 | 5 | 0 | 0 | 0 | 0 | 0 |
| membership_required | 0 | 0 | 8 | 4 | 0 | 0 | 1 |
| tenant_match | 0 | 0 | 0 | 4 | 0 | 0 | 1 |
| owner_match | 0 | 0 | 1 | 1 | 17 | 0 | 1 |
| owner_or_admin | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| manual_review_required | 8 | 1 | 6 | 1 | 7 | 0 | 131 |
