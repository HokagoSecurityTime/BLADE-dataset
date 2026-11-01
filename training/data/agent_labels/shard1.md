# Shard 1 inspection audit

All 676 assigned filtered indices (index modulo 3 = 1) were individually inspected from their complete OAS and ERD snippets. No API, local-model, or network labeling was used. Decisions were explicitly authored in TSV batches, not inferred by serialization code or populated using defaults for uninspected records.

Read batches: indices 1–148, 151–298, 301–448, 451–598, 601–748, 751–898, 901–1048, 1051–1198, 1201–1348, 1351–1498, 1501–1648, 1651–1798, 1801–1948, 1951–2026 (modulo-3 assignment throughout). The 151–298 display had truncated middle content; indices 178–199 were reread separately in full. Some displays abbreviated SQL type spelling losslessly (T=TEXT, I=INTEGER, B=BOOLEAN, N=NUMERIC), preserving every column and OAS field.

AGENT.md and prompts/v2.1.md rules were followed conservatively. Inferred response columns are not verified SQL keys; scope strings are not application roles. Null security is unknown. Explicit affirmative public evidence was accepted for published dev.to articles (397) and character public information (1669). Explicit admin-only summary supports role_required at 1699. Explicit recipe ownership restriction at 178 is retained in rationale but needs review because the required database lookup cannot be verified from flattened Poster/UserID data.

Confidence is subjective and uncalibrated; manual rows at 0.50 or 0.55 record limited certainty about the underlying policy, not a measured probability. They should not be mistaken for validated training truth. Output has 673 manual_review_required, 2 public, 1 role_required. Other four classes have no justified examples in this shard. Human review and source enrichment remain necessary.

Tool writes were interrupted twice by automatic approval-review usage limits; failed writes were resumed only following the user's continuation instruction. Original dataset files were not modified. compile_shard1.py only serializes explicit per-index decisions and checks completeness; it performs no classification.
