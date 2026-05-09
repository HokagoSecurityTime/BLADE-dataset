"""bola_dataset.json → ChromaDB"""

import _bootstrap  # noqa: F401

from blade.pipeline import load_chroma

if __name__ == "__main__":
    load_chroma.run()
