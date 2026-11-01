"""Stage C offline estimation and an explicitly opted-in future labeling runner.

Default invocation does not execute labeling. --dry-run never calls an LLM.
Runtime modules are imported, never modified. Versioned prompt and tokenizer
artifacts must exist locally; this script never downloads them implicitly.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
from statistics import mean
from typing import Any, Callable, Iterator

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field

from common.labels import Label
from common.schema import OwnerLookup
from pipeline.classifier import llm
from pipeline.classifier.prompt import build_user_prompt, system_prompt
from pipeline.classifier.security import security_context
from pipeline.classifier.prompt_store import prompt_bundle, prompt_path
from pipeline.parsers.erd import TableInfo
from pipeline.parsers.oas import Endpoint
from training.data.analyze_candidates import ROOT, load
from training.data.resignal import CLASSES, erd_columns, normalize


def read_env(path: Path) -> None:
    """Read literal dotenv assignments without shell expansion or secret logging."""
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        name, value = line.removeprefix('export ').split('=', 1)
        name, value = name.strip(), value.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        else:
            value = value.split(' #', 1)[0].rstrip()
        os.environ.setdefault(name, value)


@contextmanager
def features_off() -> Iterator[None]:
    names = ('BLADE_RAG_ENABLED', 'BLADE_CONTROLLER_ENABLED', 'BLADE_PROMPT_VERSION')
    previous = {name: os.environ.get(name) for name in names}
    os.environ.update({name: 'false' for name in names})
    os.environ['BLADE_PROMPT_VERSION'] = 'v2.1'
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def prompt_version(path: Path) -> tuple[str, str]:
    """A named version must be a real, reviewable artifact, not a fabricated tag."""
    if path.resolve() != prompt_path('v2.1').resolve():
        raise ValueError('Labeling must use the shared root prompts/v2.1.md')
    prompt_bundle('v2.1')  # Verify the data checksum before use.
    with features_off():
        system = system_prompt(rag=False)
    builder_hash = hashlib.sha256((ROOT / 'pipeline/classifier/prompt.py').read_bytes()).hexdigest()
    return system, builder_hash


def assemble(row: dict[str, Any], truncate: bool = False) -> tuple[str, bool]:
    """Adapt extractor pseudo-DDL to TableInfo, without inventing PK/FK facts.

    The extractor places some delimiters inside SQL comments and emits unquoted
    JSON field names. Parse its line format, not execute or silently repair SQL.
    Effective OAS security is passed separately through the shared v2.1 template.
    """
    oas = json.loads(row['oas_snippet'])
    columns = erd_columns(row['erd_snippet'])
    table_match = re.match(r'CREATE TABLE (.*?) \(', row['erd_snippet'])
    if not table_match:
        raise ValueError('Missing pseudo-DDL table name')
    candidates = set(row['meta']['owner_cols'] + row['meta']['tenant_cols'])
    keep = set(columns[:30]) | candidates | {name for name in columns if normalize(name) == 'id'}
    selected = [name for name in columns if name in keep] if truncate else columns
    changed = selected != columns
    # Candidate metadata is heuristic, not a trusted SQL ownership declaration.
    owner_hints = [name for name in selected if name in row['meta']['owner_cols']]
    tenant_hints = [name for name in selected if name in row['meta']['tenant_cols']]
    info = TableInfo(pk=[], columns=selected,
                     owner_col=owner_hints[0] if len(owner_hints) == 1 else None,
                     tenant_col=tenant_hints[0] if len(tenant_hints) == 1 else None, fks=[])
    endpoint = Endpoint(method=row['method'], path=row['path'],
                        path_params=oas.get('path_params') or re.findall(r'\{([^{}]+)\}', row['path']),
                        query_params=[p for p in (oas.get('query_params') or []) if isinstance(p, str)],
                        operation_id=oas.get('operationId'), tags=oas.get('tags') or [], summary=oas.get('summary'))
    with features_off():
        payload = json.loads(build_user_prompt(endpoint, {table_match.group(1): info}, None, [], security_context={**security_context(oas.get('security')), 'erd_provenance': 'API response schema inferred pseudo-DDL; PK/FK and ownership unverified'}))
    return json.dumps(payload, ensure_ascii=False), changed


def tokenizer(model: str, provider: str, local_path: Path | None) -> tuple[Callable[[str, str], int], str]:
    if local_path is not None:
        from transformers import AutoTokenizer
        instance = AutoTokenizer.from_pretrained(str(local_path), local_files_only=True, trust_remote_code=False)
        def count(system: str, user: str) -> int:
            if instance.chat_template:
                return len(instance.apply_chat_template([{'role': 'system', 'content': system},
                    {'role': 'user', 'content': user}], tokenize=True, add_generation_prompt=True))
            return len(instance.encode(system, add_special_tokens=False)) + len(instance.encode(user, add_special_tokens=False))
        return count, f'local provider tokenizer: {local_path}; chat template if available'
    if provider == 'openai':
        import tiktoken
        encoding = tiktoken.encoding_for_model(model)  # Unknown models fail; no guessed fallback.
        return lambda system, user: len(encoding.encode(system, disallowed_special=())) + len(encoding.encode(user, disallowed_special=())), \
            f'tiktoken/{encoding.name}; system+user content tokens, provider envelope overhead excluded'
    raise ValueError(f'Local matching tokenizer required for provider={provider}, model={model}; no token counts invented')


def estimate(rows: list[dict[str, Any]], system: str, count: Callable[[str, str], int], concurrency: int) -> dict[str, Any]:
    rng = random.Random(42)
    sample = []
    for kind in CLASSES:
        group = [index for index, row in enumerate(rows) if row['meta']['signal_class'] == kind]
        if len(group) < 10:
            raise ValueError(f'{kind} has fewer than 10 rows; cannot construct requested 50-record sample')
        sample.extend(rng.sample(group, 10))
    normal_counts, truncated_counts, shortened = [], [], []
    for row in rows:
        user, _ = assemble(row)
        tokens = count(system, user)
        normal_counts.append(tokens)
        # --truncate-erd is conditional: only prompts above the requested threshold.
        changed = False
        if tokens > 8000:
            user, changed = assemble(row, truncate=True)
        truncated_counts.append(count(system, user))
        shortened.append(changed)
    average = mean(normal_counts[index] for index in sample)
    truncated_average = mean(truncated_counts[index] for index in sample)
    output_tokens = 150 * len(rows)
    return dict(api_calls=0, records=len(rows), sample_size=len(sample), seed=42,
                sample_ids=[rows[index]['id'] for index in sample],
                sample_input_mean=average, sample_input_max=max(normal_counts[index] for index in sample),
                all_input_max=max(normal_counts), over_8000=sum(value > 8000 for value in normal_counts),
                over_8000_ids=[row['id'] for row, value in zip(rows, normal_counts) if value > 8000],
                estimated_input_tokens=math.ceil(average * len(rows)), estimated_output_tokens=output_tokens,
                estimated_total_tokens=math.ceil(average * len(rows)) + output_tokens,
                exact_content_input_sum=sum(normal_counts),
                truncate_sample_input_mean=truncated_average,
                truncate_estimated_total_tokens=math.ceil(truncated_average * len(rows)) + output_tokens,
                truncate_exact_content_input_sum=sum(truncated_counts),
                truncated_records=sum(shortened), remaining_over_8000=sum(value > 8000 for value in truncated_counts),
                concurrency=concurrency, seconds_per_record_assumption=3,
                estimated_seconds=3 * len(rows) / concurrency,
                note='50-record mean is signal-class balanced, not population-weighted; full-corpus sums are also provided. Output length/latency are assumptions, not API measurements.')


class ModelOutput(BaseModel):
    """Validate output without runtime's <0.7 automatic label remapping."""
    model_config = ConfigDict(extra='forbid')
    label: Label
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)
    evidence: str = Field(min_length=1)
    object_param: str | None
    owner_lookup: OwnerLookup | None
    roles: list[str]
    allowed_membership: list[str]


class LabelQuotaExhausted(RuntimeError):
    pass


async def label_one(row, system, settings, session, truncate, count):
    user, _ = assemble(row)
    changed = False
    if truncate and count(system, user) > 8000:
        user, changed = assemble(row, truncate=True)
    result = dict(row, model_id=settings.model, prompt_version='v2.1', labeled_at=datetime.now(timezone.utc).isoformat())
    result['meta'] = dict(row['meta'], erd_truncated=changed, low_conf=False, label_error=False)
    error = 'unknown'
    for attempt in range(4):
        try:
            url, headers, body = llm._request(settings, system, user)
            response = await session.post(url, headers=headers, json=body)
            if response.status_code == 429:
                try:
                    provider_error = response.json().get('error', {})
                except (ValueError, AttributeError):
                    provider_error = {}
                if isinstance(provider_error, dict) and (provider_error.get('type') == 'insufficient_quota' or provider_error.get('code') in {'insufficient_quota', 'credit_balance_exhausted'}):
                    raise LabelQuotaExhausted('API credit balance exhausted; fund the account before resuming')
            response.raise_for_status()
            output = ModelOutput.model_validate_json(llm._text(settings.provider, response.json()))
            result.update(label=output.label.value, confidence=output.confidence, rationale=output.evidence,
                          object_param=output.object_param,
                          owner_lookup=output.owner_lookup.model_dump() if output.owner_lookup else None)
            result['meta']['low_conf'] = output.confidence < .6
            return result
        except httpx.HTTPStatusError as exc:
            error = f'HTTP {exc.response.status_code}'
            if exc.response.status_code != 429 and exc.response.status_code < 500:
                break
        except (httpx.TransportError, ValueError, llm.LLMError):
            error = 'transport_or_invalid_output'
        if attempt < 3:
            await asyncio.sleep(2 ** attempt)
    result.update(label=None, confidence=None, rationale=None, object_param=None, owner_lookup=None)
    result['meta'].update(label_error=True, label_error_reason=error)
    return result


async def execute(rows: list[dict[str, Any]], system: str, count: Callable[[str, str], int],
                  output: Path, manifest: dict[str, Any], concurrency: int, truncate: bool,
                  settings: llm.Settings) -> None:
    if settings.provider not in {'openai', 'anthropic'}:
        raise ValueError('Stage D requires an explicitly selected API provider/model')
    output.parent.mkdir(parents=True, exist_ok=True)
    lock = output.with_suffix(output.suffix + '.lock')
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(descriptor)
    try:
        stamp = output.with_suffix(output.suffix + '.manifest.json')
        completed: dict[str, dict[str, Any]] = {}
        if output.exists():
            if not stamp.exists() or json.loads(stamp.read_text(encoding='utf-8')) != manifest:
                raise ValueError('Checkpoint input/model/prompt mismatch; refusing to mix runs')
            for line in output.read_text(encoding='utf-8').splitlines():
                row = json.loads(line)  # Partial/corrupt lines fail closed; no silent truncation.
                if row['id'] in completed:
                    raise ValueError('Duplicate checkpoint id')
                completed[row['id']] = row
            if not set(completed) <= {row['id'] for row in rows}:
                raise ValueError('Unknown checkpoint IDs')
        else:
            stamp.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding='utf-8')
        pending = [row for row in rows if row['id'] not in completed]
        semaphore = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(timeout=60) as session:
            async def worker(row: dict[str, Any]) -> dict[str, Any]:
                async with semaphore:
                    return await label_one(row, system, settings, session, truncate, count)
            # Bound each checkpoint to 100 records; appends are serialized, flushed
            # and fsynced. A crash can require repeating at most 100 uncommitted rows.
            for start in range(0, len(pending), 100):
                batch = await asyncio.gather(*(worker(row) for row in pending[start:start + 100]))
                with output.open('a', encoding='utf-8', newline='\n') as stream:
                    stream.write(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in batch))
                    stream.flush()
                    os.fsync(stream.fileno())
    finally:
        lock.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--dry-run', action='store_true')
    mode.add_argument('--execute', action='store_true', help='Stage D only, after explicit user approval')
    parser.add_argument('--input', type=Path, default=ROOT / 'datasets/blade/processed/apisguru_filtered.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'datasets/blade/processed/apisguru_labeled.partial.jsonl')
    parser.add_argument('--prompt-file', type=Path, default=ROOT / 'prompts/v2.1.md')
    parser.add_argument('--provider', choices=['openai', 'anthropic'])
    parser.add_argument('--model')
    parser.add_argument('--tokenizer-path', type=Path)
    parser.add_argument('--truncate-erd', action='store_true')
    parser.add_argument('--concurrency', type=int, default=4)
    args = parser.parse_args()
    if args.concurrency <= 0:
        parser.error('concurrency must be positive')
    read_env(ROOT / '.env')
    provider = args.provider or os.getenv('BLADE_LABEL_PROVIDER', 'openai')
    model = args.model or os.getenv('BLADE_LABEL_MODEL') or {'openai': 'gpt-4o-mini', 'anthropic': 'claude-sonnet-4-5'}.get(provider, '')
    if provider not in {'openai', 'anthropic'} or not model or 'qwen' in model.casefold():
        parser.error('Use a separate API labeling model, never the Qwen baseline model')
    rows, digest = load(args.input)
    if len({row['id'] for row in rows}) != len(rows):
        parser.error('Input IDs must be unique')
    try:
        system, builder_hash = prompt_version(args.prompt_file)
        counter, tokenizer_name = tokenizer(model, provider, args.tokenizer_path)
    except (ValueError, OSError, ImportError) as exc:
        if not args.dry_run:
            raise
        blocked = dict(stage='C', status='blocked', api_calls=0, provider=provider, model=model,
                       reason=str(exc), input_sha256=digest, records=len(rows),
                       input_tokens=None, estimated_total_tokens=None,
                       estimated_output_tokens=150 * len(rows),
                       estimated_seconds=3 * len(rows) / args.concurrency, concurrency=args.concurrency)
        (Path(__file__).parent / 'label_dry_run.json').write_text(json.dumps(blocked, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(blocked, ensure_ascii=False, indent=2))
        parser.exit(2)
    manifest = dict(input_sha256=digest, provider=provider, model=model, prompt_version='v2.1',
                    prompt_file_sha256=hashlib.sha256(args.prompt_file.read_bytes()).hexdigest(),
                    system_sha256=hashlib.sha256(system.encode()).hexdigest(), builder_sha256=builder_hash,
                    adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    truncate_erd=args.truncate_erd, tokenizer=tokenizer_name)
    if args.dry_run:
        report = estimate(rows, system, counter, args.concurrency)
        pricing = yaml.safe_load((ROOT / 'training/configs/pricing.yaml').read_text(encoding='utf-8'))
        rates = pricing.get('models', {}).get(model, {})
        report.update(stage='C', status='complete', provider=provider, model=model, manifest=manifest, cost=None)
        if rates.get('provider') == provider and all(isinstance(rates.get(key), (float, int)) for key in ('input_per_million', 'output_per_million')):
            report['cost'] = dict(currency=pricing['currency'],
                estimated=(report['estimated_input_tokens'] * rates['input_per_million'] + report['estimated_output_tokens'] * rates['output_per_million']) / 1e6)
        (Path(__file__).parent / 'label_dry_run.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        key_name = {'openai': 'OPENAI_API_KEY', 'anthropic': 'ANTHROPIC_API_KEY'}[provider]
        key = os.getenv(key_name, '').strip()
        if not key:
            parser.error(f'Set {key_name} before approved Stage D execution')
        settings = llm.Settings(provider=provider, model=model, api_key=key)
        try:
            asyncio.run(execute(rows, system, counter, args.output, manifest, args.concurrency, args.truncate_erd, settings))
        except LabelQuotaExhausted as exc:
            parser.exit(3, str(exc) + '\n')


if __name__ == '__main__':
    import sys
    if '--workflow-v5' in sys.argv:
        sys.argv.remove('--workflow-v5')
        from training.data.label_v5 import main as v5_main
        v5_main()
    elif '--workflow-v4' in sys.argv:
        sys.argv.remove('--workflow-v4')
        from training.data.label_v4 import main as v4_main
        v4_main()
    elif '--workflow-v3' in sys.argv:
        sys.argv.remove('--workflow-v3')
        from training.data.label_v3 import main as v3_main
        v3_main()
    else:
        main()
