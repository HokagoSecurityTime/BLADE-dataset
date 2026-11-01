"""Stage B: fixed-seed filtering; never labels records or modifies its input."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
from typing import Any

from training.data.analyze_candidates import ROOT, load, table
from training.data.resignal import CLASSES, erd_columns


def endpoint_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return row['service'], row['method'], row['path']


def select(rows: list[dict[str, Any]], quotas: dict[bool, int], seed: int = 42) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if any(row['meta'].get('signal_class') not in CLASSES for row in rows):
        raise ValueError('Missing or invalid A2 signal_class')
    selected = {i for i, row in enumerate(rows) if row['meta']['signal_class'] != 'none'}
    signal_count = len(selected)
    eligible = {flag: [] for flag in (True, False)}
    excluded_small = 0
    for i, row in enumerate(rows):
        if row['meta']['signal_class'] != 'none':
            continue
        if len(erd_columns(row['erd_snippet'])) <= 2:
            excluded_small += 1
        else:
            eligible[row['meta']['has_security']].append(i)
    rng = random.Random(seed)
    service_counts: Counter[str] = Counter()
    sampled: Counter[bool] = Counter()
    # Security=true first, then false; cap=4 is shared across BOTH none groups.
    for flag in (True, False):
        rng.shuffle(eligible[flag])
        for index in eligible[flag]:
            if sampled[flag] >= quotas[flag]:
                break
            service = rows[index]['service']
            if service_counts[service] >= 4:
                continue
            selected.add(index)
            sampled[flag] += 1
            service_counts[service] += 1
    output, seen, duplicates = [], set(), []
    for index in sorted(selected):
        row = rows[index]
        key = endpoint_key(row)
        if key in seen:
            duplicates.append(dict(source_line=index + 1, id=row['id'], service=row['service'], method=row['method'], path=row['path']))
            continue
        seen.add(key)
        result = dict(row)
        result['meta'] = dict(row['meta'], incomplete=len(erd_columns(row['erd_snippet'])) <= 2)
        output.append(result)
    return output, dict(signal_before_dedup=signal_count, none_small_excluded=excluded_small,
                        none_eligible={str(flag).lower(): len(values) for flag, values in eligible.items()},
                        none_quotas={str(flag).lower(): quotas[flag] for flag in (True, False)},
                        none_selected_before_dedup={str(flag).lower(): sampled[flag] for flag in (True, False)},
                        selected_before_dedup=len(selected), selected_duplicates_removed=len(duplicates),
                        removed_duplicates=duplicates)


def run(source: Path, destination: Path, reports: Path) -> dict[str, Any]:
    if source.resolve() == destination.resolve():
        raise ValueError('Input cannot be overwritten')
    rows, digest = load(source)
    quotas = {True: 450, False: 350}
    attempts = []
    output, stats = select(rows, quotas)
    attempts.append(dict(quotas=dict(stats['none_quotas']), final_count=len(output)))
    # Change only none quotas if needed. Never relax signals, column rule or service cap.
    for _ in range(10):
        if 1950 <= len(output) <= 2100:
            break
        gap = 2025 - len(output)
        previous = len(output)
        quotas[True] = max(0, quotas[True] + round(gap * 450 / 800))
        quotas[False] = max(0, quotas[False] + gap - round(gap * 450 / 800))
        output, stats = select(rows, quotas)
        attempts.append(dict(quotas=dict(stats['none_quotas']), final_count=len(output)))
        if len(output) == previous:
            break
    if not 1950 <= len(output) <= 2100:
        raise ValueError(f'Cannot meet target with none quota adjustments alone: {attempts}')
    services = Counter(row['service'] for row in output)
    none_services = Counter(row['service'] for row in output if row['meta']['signal_class'] == 'none')
    combos = Counter((row['meta']['signal_class'], row['meta']['has_security']) for row in output)
    assert max(none_services.values(), default=0) <= 4
    assert len({endpoint_key(row) for row in output}) == len(output)
    assert {endpoint_key(row) for row in rows if row['meta']['signal_class'] != 'none'} <= {endpoint_key(row) for row in output}
    payload = ''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in output).encode('utf-8')
    report = dict(stage='B', seed=42, input_sha256=digest, output_sha256=hashlib.sha256(payload).hexdigest(),
                  input_records=len(rows), final_records=len(output), service_count=len(services),
                  service_records_max=max(services.values()), none_services_at_cap4=sum(n == 4 for n in none_services.values()),
                  services_at_source_cap15=sum(n == 15 for n in services.values()),
                  incomplete=sum(row['meta']['incomplete'] for row in output),
                  raw_signal_incomplete=sum(row['meta']['signal_class'] != 'none' and len(erd_columns(row['erd_snippet'])) <= 2 for row in rows),
                  source_duplicate_keys=len(rows) - len({endpoint_key(row) for row in rows}),
                  combinations=[dict(signal_class=kind, has_security=flag, count=combos[kind, flag]) for kind in CLASSES for flag in (False, True)],
                  methods=dict(sorted(Counter(row['method'] for row in output).items())),
                  quota_attempts=attempts, **stats)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix('.jsonl.tmp')
    temporary.write_bytes(payload)
    temporary.replace(destination)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / 'filter_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    text = ['# B 필터 결과', '', f'최종 {len(output):,}건 / {len(services)} services / seed 42.', '',
            table(['signal_class', 'has_security', 'count'], [[r['signal_class'], r['has_security'], r['count']] for r in report['combinations']]), '',
            table(['method', 'count'], list(map(list, report['methods'].items()))), '',
            f'none 쿼터: {report["none_quotas"]}. 조정 시도: {attempts}.', '',
            f'none service당 공유 상한 4에 도달: {report["none_services_at_cap4"]}개. 전체 service당 최대 {report["service_records_max"]}건; 원본 상한 15건 도달 {report["services_at_source_cap15"]}개.', '',
            f'incomplete: 신호 그룹 원본 {report["raw_signal_incomplete"]}건 → 최종 {report["incomplete"]}건.', '',
            f'입력 전체 중복 키 초과분 {report["source_duplicate_keys"]}건 중 선택된 집합에서 {report["selected_duplicates_removed"]}건 제거. 나머지는 앞선 제외/표본 선택에서 탈락했다.', '',
            '규칙 순서: 신호 전량 유지 → none 저정보 제외 → true/false 순서의 무작위 추출(두 그룹 공유 service 상한 4) → incomplete 표시 → 선택된 레코드 중 입력 순서상 첫 endpoint 키 유지.', '',
            '원본·A2 입력을 수정하지 않았으며 라벨링·학습·분할은 실행하지 않았다.', '']
    (reports / 'filter_report.md').write_text('\n'.join(text), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'datasets/blade/processed/apisguru_resignaled.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'datasets/blade/processed/apisguru_filtered.jsonl')
    parser.add_argument('--report-dir', type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    print(json.dumps(run(args.input, args.output, args.report_dir), ensure_ascii=False, indent=2))
