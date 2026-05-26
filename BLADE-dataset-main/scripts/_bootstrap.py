"""scripts/* 가 src/blade 패키지를 import 할 수 있게 sys.path 보정.

`pip install -e .` 를 안 한 환경에서도 `python scripts/01_fetch_all.py` 가 동작하도록.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
