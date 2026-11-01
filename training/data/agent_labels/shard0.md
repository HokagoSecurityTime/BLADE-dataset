# Shard 0 agent inspection audit

Inspected and individually authored 676 decisions for input indices divisible by 3 (0 through 2025) in `datasets/blade/processed/apisguru_filtered.jsonl`.

Read the v2.1 decision tree and security rules and the AGENT.md Phase 3 requirements. Each assigned OAS snippet and full inferred ERD was displayed and inspected in batches. One oversized initial display was truncated; the omitted portion was subsequently re-read. A later console encoding failure was recovered with UTF-8 and the affected records were re-read before decisions. No API, local Qwen or network calls were used. Raw records were not modified.

Authored decisions were persisted in batches, with explicit per-index rationales; the helper only serializes authored decisions and does not classify or fill unreviewed rows. The output JSONL is authoritative: root-review corrections changed page-details public to manual, preserved the literal Analyst Plan Or Greater descriptor, and assigned both admin/editor roles to the directly documented device-tag operation. Intermediate authoring text retains original decisions for traceability.

Distribution: manual_review_required 665; public 5; role_required 5; membership_required 1; owner_match 0; owner_or_admin 0; tenant_match 0. Total 676.

Manual-review confidence 0.55 is an uncalibrated expression of insufficient confidence in a concrete policy, not a measured probability that manual review itself is correct. Positive confidences are also uncalibrated. This is direct agent annotation, not an exact replay of an API-model prompt, not human ground truth, and not gpt-4o-mini provenance.

Most snippets contain response properties flattened into pseudo-tables, opaque relations, no verified lookup binding, and short summaries that omit authorization semantics. Customer/account fields frequently refer to business counterparties; team fields sometimes refer to sports teams; user fields often represent content authors rather than exclusive authorized readers. OAuth scope names were not promoted to roles. No ownership or tenant lookup was invented to improve label balance. Explicit Public tags supported four content-read labels; explicit anonymous authentication bootstrap supported one public label. Explicit Admin operation tags and the admins/editors sentence supported role labels. The Analyst Plan Or Greater tag supported the membership label.

This extreme manual-review concentration makes this shard unsuitable as a balanced seven-class policy-training dataset without additional controller/schema/authorization evidence and human review. It must not be represented as successful coverage of all seven classes.
