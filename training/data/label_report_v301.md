# label_report_v301 (prompt policy-label-v3.0.1, full 2,027)

```json
{
  "records": 2027,
  "labels": {
    "public": 173,
    "role_required": 124,
    "membership_required": 26,
    "tenant_match": 35,
    "owner_match": 138,
    "owner_or_admin": 1,
    "manual_review_required": 1530
  },
  "confidence": {
    "[0,0.5]": 0,
    "(0.5,0.7)": 0,
    "[0.7,0.9)": 1549,
    "[0.9,1]": 478
  },
  "evidence_invalid": 2,
  "mutation_public": 5,
  "flag_review": 5,
  "label_errors": 0,
  "stop_reasons": [
    "confidence_bin_at_least_70_percent"
  ],
  "usage": {
    "api_responses": 2043,
    "input_tokens": 5573661,
    "cached_input_tokens": 4342528,
    "output_tokens": 137031,
    "estimated_usd": 0.59258,
    "billing_invoice": false
  },
  "mean_inference_ms": 1521.8,
  "manual_ratio": 0.7548,
  "by_security_state": {
    "declared": {
      "public": 150,
      "role_required": 120,
      "membership_required": 26,
      "tenant_match": 35,
      "owner_match": 134,
      "owner_or_admin": 1,
      "manual_review_required": 801
    },
    "explicitly_anonymous": {
      "public": 6,
      "role_required": 0,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 0,
      "owner_or_admin": 0,
      "manual_review_required": 0
    },
    "unknown": {
      "public": 17,
      "role_required": 4,
      "membership_required": 0,
      "tenant_match": 0,
      "owner_match": 4,
      "owner_or_admin": 0,
      "manual_review_required": 729
    }
  },
  "public_with_security_declared": 150,
  "train_build_blocked_manual_ratio_above_70_percent": true,
  "prompt_version": "policy-label-v3.0.1",
  "prompt_sha256": "d0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef"
}
```

| v2.5 \ policy-label-v3.0.1 | public | role_required | membership_required | tenant_match | owner_match | owner_or_admin | manual_review_required |
|---|---:|---:|---:|---:|---:|---:|---:|
| public | 84 | 16 | 0 | 0 | 3 | 0 | 59 |
| role_required | 0 | 39 | 0 | 0 | 2 | 0 | 22 |
| membership_required | 1 | 19 | 14 | 7 | 2 | 0 | 45 |
| tenant_match | 5 | 3 | 6 | 28 | 8 | 0 | 40 |
| owner_match | 3 | 8 | 4 | 0 | 102 | 0 | 111 |
| owner_or_admin | 0 | 1 | 0 | 0 | 6 | 1 | 4 |
| manual_review_required | 80 | 38 | 2 | 0 | 15 | 0 | 1249 |
