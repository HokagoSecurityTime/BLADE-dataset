# Public-release copies (2026-11-01)

Frozen originals (hashes in AGENTS.md / DATA_CARD.md) are never modified. These copies withhold code excerpts whose redistribution is not covered by a permissive license:

| reason | records | sources |
|---|---:|---|
| GPL-3.0 — snoopysecurity/dvws-node `eb6e2886` | 25 | test.jsonl, test_v30.jsonl (+ test_v30_inputs oas_code_user) |
| no license declared — 5 RealWorld repositories (data-v3 code pairs) | 28 | train_v3a/v3b/v31b/v4/v5, pairs_train_v3s1/v3s1b |
| GPL-3.0 — NodeBB `c3d8dc51` (data-v5 policy: links only) | 109 | train_v5, val_v5 |

- `*_public.jsonl`: same records and labels as the original; withheld records have `controller_text: ""`, `meta.code_withheld` (reason) and `meta.code_ref` (repository, commit, license, SHA-256 of the withheld text, pinned permalinks). All other lines are byte-identical to the original.
- `withheld_manifest.json`: per-record provenance and a **code-free** reconstruction recipe (line ranges, whitespace transform, ellipsis marker, or for check-removed variants the original line indices and indentation), plus SHA-256 of originals and copies.
- `../../../../training/lora/public/`: SFT copies with the withheld rows dropped (ids listed in the manifest `sft_dropped`) and test_v30_inputs copies with the 25 DVWS `oas_code_user` fields set to null.
- `PUBLIC_EXCLUDE.txt`: original files that must not be included in a public export.
- Rebuild: `python -X utf8 scripts/rebuild_from_public.py` with the clones at the recorded commits restores the 10 original files byte-for-byte (verified 2026-11-01, 162/162 records). Builder: `scripts/build_public_copies.py`.
