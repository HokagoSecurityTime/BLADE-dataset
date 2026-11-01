# Shard 2 inspection audit

Assigned: input zero-based index modulo 3 equals 2, indices 2 through 2024, 675 records.
Input: `datasets/blade/processed/apisguru_filtered.jsonl`.
Policy reference: `AGENT.md` Phase 3 and `prompts/v2.1.md`.

Every assigned OAS and ERD was read by the conversation agent. The first batch was
printed in full; a truncated region (104–161) was re-read in full. Subsequent batches
used `shard2_read.py`, which preserves all OAS text and ERD column names, compressing
only whitespace and SQL type/comment spellings. Its legend is TEXT=~T,
INTEGER=~I, NUMERIC=~N, BOOLEAN=~B, owner-candidate comment=~O,
tenant-candidate comment=~E. No field-name truncation or keyword-only summaries
were used. Inspection batches ended at 224, 371, 524, 674, 824, 974, 1124,
1274, 1424, 1574, 1724, 1874, and 2024. The cp949 rendering failure at 374 was
resolved by UTF-8 output and that record was read in the next successful batch.

`shard2_notes.tsv` contains one individually authored evidence/uncertainty sentence
for each of the 675 records. `shard2_serialize.py` serializes those decisions and
asserts complete exact coverage; it is not a keyword classifier. Its seven explicit
positive decisions record the independently reconsidered labels and rationales.
No external API, local model, web request, or paid labeling script was called.
No actual model identifier such as gpt-4o-mini is claimed. These are conversation
agent annotations requiring human review, not gold labels.

Confidence is subjective and uncalibrated. Manual-review decisions use 0.55 to
communicate weak evidence for a usable authorization policy, rather than a calibrated
probability that abstention is correct. The five inferential role/membership positives
use 0.58 and should remain low_conf. The two explicit Public-tag positives use 0.65.
No output owner_lookup was invented from response-derived pseudo-DDL; all are null.
OAuth admin/write/user scopes were not converted to caller roles. Scope-free or
missing security was never sufficient evidence of public access. Publicly-accessible
network exposure tags on private checkout or pool mutation were treated cautiously.
Tyk health usage/quotas metrics were distinguished from a simple liveness probe.

Final decisions: manual_review_required 668, role_required 3, public 2,
membership_required 2. No owner_match, owner_or_admin, or tenant_match claims were
supported by usable non-invented lookup evidence in this shard. Explicit owner prose
in BigOven and subuser assignment in smart-me were recorded as manual review because
the flattened ERD cannot resolve a trustworthy lookup binding. Do not manufacture
positive examples to balance the label distribution.

Positive review indices: 146 (tier descriptor), 404/407/521 (inferred admin role),
488/494 (explicit Public tag), 1709 (donation requirement; donor canonical name unknown).
Parent agent will independently spot-check positives and may revise them before merge.
