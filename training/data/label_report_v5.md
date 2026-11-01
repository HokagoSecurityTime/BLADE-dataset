# label_report_v5

```json
{
  "records": 2027,
  "labels": {
    "public": 162,
    "role_required": 63,
    "membership_required": 88,
    "tenant_match": 90,
    "owner_match": 228,
    "owner_or_admin": 12,
    "manual_review_required": 1384
  },
  "confidence": {
    "[0,0.5]": 1384,
    "(0.5,0.7)": 82,
    "[0.7,0.9)": 278,
    "[0.9,1]": 283
  },
  "evidence_invalid": 24,
  "mutation_public": 22,
  "flag_review": 22,
  "label_errors": 0,
  "stop_reasons": [],
  "usage": {
    "input_tokens": 4934620,
    "cached_input_tokens": 3766016,
    "output_tokens": 95518,
    "total_tokens": 5030138,
    "estimated_usd_from_actual_usage": 0.5150526000000001,
    "pricing_usd_per_million": {
      "input": 0.15,
      "cached_input": 0.075,
      "output": 0.6
    },
    "pricing_source": "https://developers.openai.com/api/docs/models/gpt-4o-mini",
    "billing_invoice": false,
    "api_responses": 2103
  }
}
```

| v2.3 (full v2.4 unavailable) / v2.5 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|
| public | 75 | 0 | 1 | 0 | 2 | 0 | 466 |
| role_required | 26 | 50 | 41 | 2 | 14 | 4 | 173 |
| membership_required | 3 | 0 | 18 | 1 | 0 | 0 | 13 |
| tenant_match | 23 | 0 | 17 | 83 | 13 | 0 | 183 |
| owner_match | 24 | 3 | 10 | 4 | 161 | 2 | 318 |
| owner_or_admin | 5 | 8 | 1 | 0 | 35 | 6 | 74 |
| manual_review_required | 6 | 2 | 0 | 0 | 3 | 0 | 157 |
