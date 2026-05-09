"""모든 source fetcher 를 호출해 raw 데이터를 data/raw/*.json 으로 저장."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from blade import config
from blade.sources import (
    capec,
    cisa_kev,
    github_advisory,
    google_sheets,
    hackerone,
    nvd,
    owasp_api,
    owasp_wstg,
)


SOURCES: list[tuple[str, Path, Callable[[], list]]] = [
    ("nvd",        config.RAW_NVD,        lambda: nvd.fetch(mode="cwe")),
    ("hackerone",  config.RAW_HACKERONE,  hackerone.fetch),
    ("github",     config.RAW_GITHUB,     github_advisory.fetch),
    ("cisa",       config.RAW_CISA,       cisa_kev.fetch),
    ("owasp_api",  config.RAW_OWASP_API,  owasp_api.fetch),
    ("wstg",       config.RAW_WSTG,       owasp_wstg.fetch),
    ("capec",      config.RAW_CAPEC,      capec.fetch),
    ("sheets",     config.RAW_SHEETS,     google_sheets.fetch),
]


def _save(items: list, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def run(*, only: list[str] | None = None, skip: list[str] | None = None) -> dict[str, int]:
    """source 별로 fetch → data/raw/*.json. 카운트 dict 반환."""
    only_set = set(only) if only else None
    skip_set = set(skip) if skip else set()

    counts: dict[str, int] = {}
    for name, path, fetcher in SOURCES:
        if only_set and name not in only_set:
            continue
        if name in skip_set:
            continue
        print(f"\n=== fetch: {name} -> {path.name} ===")
        try:
            items = fetcher()
        except Exception as exc:
            print(f"  [error] fetcher {name} failed: {exc}")
            continue
        _save(items, path)
        counts[name] = len(items)
        print(f"  saved {len(items)} items to {path}")
    return counts


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Fetch all data sources to data/raw/")
    p.add_argument("--only", nargs="+", help="run only these sources")
    p.add_argument("--skip", nargs="+", help="skip these sources")
    args = p.parse_args()
    counts = run(only=args.only, skip=args.skip)
    print("\n=== summary ===")
    for name, n in counts.items():
        print(f"  {name:<12} {n}")
