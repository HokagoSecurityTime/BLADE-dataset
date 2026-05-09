"""ChromaDB 검색 sanity check."""

import _bootstrap  # noqa: F401

from blade.pipeline import search_test

if __name__ == "__main__":
    search_test.run()
