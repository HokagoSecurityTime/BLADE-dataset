"""data-v2 hash guard shared by read-only analysis scripts: assert before and after work. Raises if any frozen data-v2 file changed.
Use together with data_v1_guard.assert_data_v1 (test_v30 and prompt are in both)."""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = {'datasets/blade/processed/train_v2.jsonl': 'f26c368d051e1ec2683a1f70ed52162808740d9b06540bbad1fe94988ed47ada',
         'datasets/blade/processed/val_v2.jsonl': 'd0e216dd1267ba7f46eb08e5db955473b11bbd049d875e33eb8032504c0f3ac0',
         'datasets/blade/processed/train_v2_manual_pool.jsonl': '32e23716422f43dcb77b97bed03acdca5ec1fff9ece93c7794934d987798b32a',
         'datasets/blade/processed/test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2',
         'training/data/prompts/policy_label_v3.0.1.md': 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'}

def assert_data_v2(stage='start'):
    agents = (ROOT / 'AGENTS.md').read_text(encoding='utf-8')
    for rel, h in FILES.items():
        actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert actual == h, f'[{stage}] {rel} hash {actual[:16]} != data-v2 {h[:16]}'
        assert h in agents, f'[{stage}] {rel} hash not in AGENTS.md'
    return {rel: h[:16] + '…' for rel, h in FILES.items()}

if __name__ == '__main__':
    print(assert_data_v2('check'))
