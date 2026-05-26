"""모든 source fetcher 를 호출 → data/raw/*.json"""

import argparse

import _bootstrap  # noqa: F401

from blade.pipeline import fetch


def main() -> None:
    p = argparse.ArgumentParser(description="Fetch all data sources to data/raw/")
    p.add_argument("--only", nargs="+", help="run only these sources (e.g. nvd capec)")
    p.add_argument("--skip", nargs="+", help="skip these sources (e.g. hackerone)")
    args = p.parse_args()
    counts = fetch.run(only=args.only, skip=args.skip)
    print("\n=== summary ===")
    for name, n in counts.items():
        print(f"  {name:<12} {n}")


if __name__ == "__main__":
    main()
