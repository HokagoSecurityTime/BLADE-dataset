# D — Agent labeling report

Records: 2,027; API calls in this agent run: 0; label_error: 0.

| label | count |
|---|---:|
| public | 9 |
| role_required | 9 |
| membership_required | 3 |
| tenant_match | 0 |
| owner_match | 0 |
| owner_or_admin | 0 |
| manual_review_required | 2006 |

low_conf (<0.6): 2,011 (99.21%).
Review sample: 41; labels below 20: public, role_required, membership_required, tenant_match, owner_match, owner_or_admin.

## Provenance and limitations

The user authorized interactive agent labeling instead of the blocked paid API run. Three agents read disjoint record sets and authored decisions. The merger validates IDs, fields and lookup names; it never assigns a missing label.

- Exact underlying agent model/configuration not exposed; not gpt-4o-mini.
- v2.1 used as review instructions, not an exact isolated API prompt per record.
- Confidence is an uncalibrated agent judgment, not measured probability.
- API response pseudo-DDL is not verified database schema; controllers absent.
- No human review or training split has occurred.

manual_review_required is a completed uncertainty decision, not a failed request. label_error=0 does not mean correct labels or verified policies. A heavily concentrated distribution is unsuitable for balanced seven-class training without additional evidence and human review.

Source and prompt hashes plus individual shard hashes are in agent_label_report.json. Per-record authorship files are in agent_labels/. The API checkpoint remains separate. No train/val/test split or training was performed.

Input limitations: 136 records lack summary; 754 have unknown security; 14 explicitly specify empty security; none retains operation.description; all 2,027 lack controller signals.

Next: human review_sample.md review. Add full OAS authorization descriptions and verified schema/controller evidence before promoting uncertain records to concrete policies. Do not manufacture missing labels to balance the classes.
