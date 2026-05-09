"""raw → enrich → data/processed/bola_dataset.json"""

import argparse

import _bootstrap  # noqa: F401

from blade.pipeline import build_dataset


def main() -> None:
    p = argparse.ArgumentParser(description="Enrich raw items into unified dataset")
    p.add_argument("--no-llm", action="store_true", help="skip LLM enrichment")
    args = p.parse_args()
    build_dataset.run(use_llm=not args.no_llm)


if __name__ == "__main__":
    main()
