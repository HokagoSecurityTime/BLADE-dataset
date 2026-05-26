"""raw items 를 enrich 해 통합 데이터셋(bola_dataset.json) 생성.

- data/raw/*.json 모두 로드
- _preclassified 가 있으면 그대로 사용 (CAPEC/OWASP/WSTG/Sheets)
- 없으면 enrich.rules.classify (규칙 기반)
- 규칙도 None 이면 enrich.llm.classify (LLM, 옵션)
- 결과를 schema.Record 로 변환 → data/processed/bola_dataset.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from blade import config
from blade.enrich import llm as enrich_llm
from blade.enrich import rules as enrich_rules
from blade.schema import Metadata, Record, build_document_text, dump_records


RAW_FILES = [
    config.RAW_NVD,
    config.RAW_HACKERONE,
    config.RAW_GITHUB,
    config.RAW_CISA,
    config.RAW_OWASP_API,
    config.RAW_WSTG,
    config.RAW_CAPEC,
    config.RAW_SHEETS,
]


def _load_raw(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _dedupe(items: Iterable[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for it in items:
        key = it.get("id", "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out


def _build_record(item: dict, extra: dict) -> Record:
    md = Metadata(
        source=item.get("source", ""),
        source_type=config.SOURCE_TO_TYPE.get(item.get("source", ""), ""),
        source_id=item["id"],
        cve_id=item.get("cve_id", "") or "",
        url=item.get("url", "") or "",
        title=item.get("title", "") or "",
        updated_at=item.get("updated_at", "") or "",

        cwe_id=item.get("cwe_id", "") or "",
        severity=item.get("severity", "") or "",
        cvss_score=float(item.get("cvss_score") or 0.0),
        attack_vector=item.get("attack_vector", "") or "",

        bola_pattern=extra.get("bola_pattern", ""),

        endpoint_pattern=extra.get("endpoint_pattern", ""),
        http_method=extra.get("http_method", ""),
        id_type=extra.get("id_type", ""),
        id_format=extra.get("id_format", ""),
        ownership_type=extra.get("ownership_type", ""),
        ownership_check_missing=extra.get("ownership_check_missing", ""),
        attack_method=extra.get("attack_method", ""),

        rule_type=extra.get("rule_type", ""),
        rule_based_detectable=bool(extra.get("rule_based_detectable", False)),
        inference_required=bool(extra.get("inference_required", True)),
        business_logic_complexity=int(extra.get("business_logic_complexity") or 0),
        domain=extra.get("domain", ""),
        owasp_mapping=extra.get("owasp_mapping", ""),

        policy_template_hint=extra.get("policy_template_hint", ""),

        enrichment_method=extra.get("enrichment_method", ""),
        reason=extra.get("reason", ""),
    )
    document = build_document_text(md, description=item.get("description", "") or "")
    return Record(id=item["id"], document=document, metadata=md)


def run(*, use_llm: bool = True, output_path: Path | None = None) -> list[Record]:
    output_path = output_path or config.DATASET_PATH

    print("=== build_dataset ===")
    raw: list[dict] = []
    for path in RAW_FILES:
        items = _load_raw(path)
        if items:
            print(f"  loaded {len(items)} items from {path.name}")
        raw.extend(items)

    print(f"\n  total raw: {len(raw)}")
    deduped = _dedupe(raw)
    print(f"  after dedupe (by id): {len(deduped)}")

    llm_alive = enrich_llm.warmup() if use_llm else False
    if use_llm and not llm_alive:
        print("  [warn] LLM unreachable — items needing inference will be skipped")

    pre_count = rule_count = llm_count = skipped = 0
    records: list[Record] = []
    for idx, item in enumerate(deduped, 1):
        prefix = f"  [{idx}/{len(deduped)}] {item.get('id')}"
        try:
            extra = enrich_rules.classify(item)
            if extra is None:
                if llm_alive:
                    extra = enrich_llm.classify(item)
                    if extra is None:
                        skipped += 1
                        print(f"{prefix} -> skipped (LLM gave no JSON)")
                        continue
                    llm_count += 1
                else:
                    skipped += 1
                    print(f"{prefix} -> skipped (no rule match, no LLM)")
                    continue
            else:
                if extra.get("enrichment_method") == "preclassified":
                    pre_count += 1
                else:
                    rule_count += 1

            records.append(_build_record(item, extra))
        except Exception as exc:
            skipped += 1
            print(f"{prefix} -> error: {exc}")

    print(
        f"\n  enrichment: preclassified={pre_count}  rule={rule_count}  "
        f"llm={llm_count}  skipped={skipped}"
    )

    dump_records(records, output_path)
    print(f"  wrote {len(records)} records → {output_path}")
    return records


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Build unified bola_dataset.json")
    p.add_argument("--no-llm", action="store_true", help="skip LLM enrichment")
    args = p.parse_args()
    run(use_llm=not args.no_llm)
