"""data-v1 hash guard shared by read-only analysis scripts: assert before and after work. Raises if any frozen file changed."""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {'datasets/blade/processed/train_v30.jsonl': 'a99d30da2d29907e8e3fc2d1b8ef313c3d2aa24b1539251130bd08cf96b829e2',
         'datasets/blade/processed/val_v30.jsonl': '62bdadb29cae7aaf814007ad8adec40115e8612d70f2911693219399c82b595c',
         'datasets/blade/processed/test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2',
         'training/data/prompts/policy_label_v3.0.1.md': 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'}

def assert_data_v1(stage='start'):
    agents = (ROOT / 'AGENTS.md').read_text(encoding='utf-8')
    for rel, h in FILES.items():
        actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert actual == h, f'[{stage}] {rel} hash {actual[:16]} != data-v1 {h[:16]}'
        assert h in agents, f'[{stage}] {rel} hash not in AGENTS.md'
    return {rel: h[:16] + '…' for rel, h in FILES.items()}
