"""test_v6 inference/scoring guard (AGENTS.md 작업 S0).

test_v6 is the final hold-out for S9. Until then no model (base, LoRA v4/v5, Ollama, HF) may be run on
test_v6 inputs, and no scorer may read test_v6 predictions. Every script that touches test_v6 must call
`assert_allowed(<what>)` first. It passes only when
  1. the frozen manifest datasets/blade/processed/data_v6/test_v6_manifest.json exists and
  2. every file it lists still has the recorded SHA-256 and
  3. the environment variable BLADE_TESTV6_STAGE is exactly "S9".
Otherwise it raises SystemExit with the reason. `verify_manifest()` (hash gate only) is used by scorers.
Usage: `from scripts.testv6_guard import assert_allowed; assert_allowed('inference')`.
"""
from __future__ import annotations
import hashlib, json, os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'datasets/blade/processed/data_v6/test_v6_manifest.json'
STAGE_VAR, STAGE_OK = 'BLADE_TESTV6_STAGE', 'S9'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def verify_manifest(manifest: Path = MANIFEST) -> dict:
    """Hash gate: return the manifest if every listed file matches; raise SystemExit on absence/mismatch."""
    if not manifest.exists(): raise SystemExit(f'test_v6 is not frozen: {manifest} missing; scoring/inference refused')
    man = json.loads(manifest.read_text(encoding='utf-8'))
    for rel, h in man.get('sha256', {}).items():
        p = ROOT / rel
        if not p.exists(): raise SystemExit(f'test_v6 frozen file missing: {rel}')
        if sha(p) != h: raise SystemExit(f'test_v6 frozen file changed: {rel} (manifest {h[:12]}…, actual {sha(p)[:12]}…); refused')
    return man


def assert_allowed(what: str = 'inference') -> dict:
    """Full guard for inference and prediction reading: hash gate + S9 stage flag."""
    man = verify_manifest()
    if os.environ.get(STAGE_VAR) != STAGE_OK:
        raise SystemExit(f'test_v6 {what} is forbidden before S9 (set {STAGE_VAR}={STAGE_OK} only when the user has approved the S9 run). AGENTS.md 작업 S0.')
    return man


if __name__ == '__main__':
    try: verify_manifest(); print('manifest OK'); assert_allowed(sys.argv[1] if len(sys.argv) > 1 else 'inference'); print('stage OK (S9)')
    except SystemExit as e: print('REFUSED:', e); sys.exit(2)
