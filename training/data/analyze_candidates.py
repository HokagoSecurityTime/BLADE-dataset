"""Stage A only: inspect candidates without filtering, labeling or splitting."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from itertools import product
import json
from pathlib import Path
import random
import re
from statistics import median
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ('has_owner_col', 'has_tenant_col', 'has_security')


def column_count(ddl: str) -> int:
    """Count the one-column-per-line pseudo-DDL emitted by sources/apisguru.py.

    Do not execute SQL or split on commas: candidate comments can contain commas.
    Reject other formats instead of presenting an unverified column count.
    """
    if not ddl.strip():
        return 0
    lines = ddl.strip().splitlines()
    if len(lines) < 2 or not lines[0].startswith('CREATE TABLE ') or lines[-1].strip() != ');':
        raise ValueError('Unexpected ERD format; expected APIs.guru extractor pseudo-DDL')
    columns = [line for line in lines[1:-1] if line.strip()]
    for line in columns:
        declaration = line.split('--', 1)[0].strip().rstrip(',').rstrip()
        if not re.fullmatch(r'.+\s+(INTEGER|NUMERIC|BOOLEAN|TEXT)', declaration):
            raise ValueError(f'Unrecognized column declaration: {line!r}')
    return len(columns)


def load(path: Path) -> tuple[list[dict[str, Any]], str]:
    contents = path.read_bytes()
    rows = []
    for number, line in enumerate(contents.decode('utf-8-sig').splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError(f'Line {number}: record is not an object')
        for name in ('id', 'service', 'method', 'path'):
            if not isinstance(row.get(name), str) or not row[name].strip():
                raise ValueError(f'Line {number}: missing/invalid {name}')
        for name in ('oas_snippet', 'erd_snippet'):
            if not isinstance(row.get(name), str):
                raise ValueError(f'Line {number}: {name} must be a string')
        for name in FLAGS:
            if type(row.get('meta', {}).get(name)) is not bool:
                raise ValueError(f'Line {number}: meta.{name} must be boolean')
        rows.append(row)
    if not rows:
        raise ValueError('Candidate file is empty')
    return rows, hashlib.sha256(contents).hexdigest()


def unique_endpoints(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {}
    for row in rows:
        unique.setdefault((row['service'], row['method'], row['path']), row)
    return list(unique.values())


def samples(rows: list[dict[str, Any]], seed: int = 42, count: int = 10) -> list[dict[str, Any]]:
    """Distinct services, maximum method coverage, then balanced method counts."""
    shuffled = list(rows)
    random.Random(seed).shuffle(shuffled)
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for row in shuffled:
        pairs.setdefault((row['service'], row['method']), row)
    methods = sorted({row['method'] for row in rows})
    by_method = {method: [service for service, m in pairs if m == method] for method in methods}
    matching: dict[str, str] = {}

    def assign(method: str, seen: set[str]) -> bool:
        for service in by_method[method]:
            if service in seen:
                continue
            seen.add(service)
            if service not in matching or assign(matching[service], seen):
                matching[service] = method
                return True
        return False

    for method in sorted(methods, key=lambda m: (len(by_method[m]), m)):
        if len(matching) >= count:
            break
        assign(method, set())
    chosen = [pairs[(service, method)] for service, method in matching.items()]
    used = set(matching)
    while len(chosen) < count:
        frequencies = Counter(row['method'] for row in chosen)
        eligible = [row for row in shuffled if row['service'] not in used]
        if not eligible:
            break
        row = min(eligible, key=lambda r: frequencies[r['method']])
        chosen.append(row)
        used.add(row['service'])
    return chosen


def table(headers: list[str], rows: list[list[Any]]) -> str:
    def escape(value: Any) -> str:
        return str(value).replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')
    return '\n'.join(['| ' + ' | '.join(headers) + ' |', '| ' + ' | '.join('---' for _ in headers) + ' |']
                     + ['| ' + ' | '.join(escape(value) for value in row) + ' |' for row in rows])


def fenced(text: str, language: str) -> str:
    fence = '`' * max(3, 1 + max((len(m.group()) for m in re.finditer(r'`+', text)), default=0))
    return f'{fence}{language}\n{text}\n{fence}'


def analyze(path: Path, output: Path, seed: int = 42) -> dict[str, Any]:
    rows, digest = load(path)
    services = Counter(row['service'] for row in rows)
    methods = Counter(row['method'] for row in rows)
    combos = Counter(tuple(row['meta'][name] for name in FLAGS) for row in rows)
    columns = Counter(column_count(row['erd_snippet']) for row in rows)
    unique = unique_endpoints(rows)
    chosen = samples(unique, seed)
    service_sizes = Counter(services.values())
    report = dict(stage='A', source=str(path.resolve()), source_sha256=digest, seed=seed,
                  total_records=len(rows), service_count=len(services),
                  service_records_max=max(services.values()), service_records_median=median(services.values()),
                  service_size_distribution=dict(sorted(service_sizes.items())),
                  records_by_service=dict(sorted(services.items())), method_distribution=dict(sorted(methods.items())),
                  flag_combinations=[dict(zip(FLAGS, flags), count=combos[flags])
                                     for flags in product((False, True), repeat=3)],
                  erd_column_distribution=dict(sorted(columns.items())),
                  erd_columns_min=min(columns), erd_columns_max=max(columns),
                  erd_columns_median=median([n for n, count in columns.items() for _ in range(count)]),
                  information_poor_records=sum(columns[n] for n in (0, 1, 2)),
                  unique_endpoint_records=len(unique), duplicate_endpoint_records=len(rows) - len(unique),
                  sample_ids=[row['id'] for row in chosen], sample_service_count=len({r['service'] for r in chosen}),
                  sample_method_distribution=dict(sorted(Counter(r['method'] for r in chosen).items())),
                  missing_label_records=sum(row.get('label') is None for row in rows))
    output.mkdir(parents=True, exist_ok=True)
    sample = ['# APIs.guru 후보 샘플 — 단계 A', '',
              f'입력 SHA-256: `{digest}`. seed={seed}. 중복 키 제거 후 서로 다른 service에서 {len(chosen)}건.', '',
              f'method는 전체 {len(methods)}종이므로 10건 모두 다른 method로 추출할 수 없다. '
              '가능한 method를 모두 포함한 다음 사용 횟수가 적은 method부터 선택했다. 대표성 추정용 무작위 표본은 아니다.', '',
              'oas_snippet·erd_snippet은 원문 전문이며 축약·JSON 재정렬을 하지 않았다.', '']
    for index, row in enumerate(chosen, 1):
        sample += [f'## {index}. {row["service"]} — {row["method"]} {row["path"]}', '',
                   f'id: `{row["id"]}`', '',
                   table([*FLAGS, 'ERD columns'], [[*[row['meta'][name] for name in FLAGS], column_count(row['erd_snippet'])]]), '',
                   '### oas_snippet', '', fenced(row['oas_snippet'], 'json'), '',
                   '### erd_snippet', '', fenced(row['erd_snippet'], 'sql'), '']
    (output / 'candidates_sample.md').write_text('\n'.join(sample), encoding='utf-8')
    summary = ['# APIs.guru 후보 분석 — 단계 A', '', f'입력: `{path}`', '', f'SHA-256: `{digest}`', '',
               table(['항목', '값'], [['총 건수', len(rows)], ['service 수', len(services)],
                     ['service당 최대', report['service_records_max']], ['service당 중앙값', report['service_records_median']],
                     ['키 중복 제거 후', len(unique)], ['키 중복 제거 대상', len(rows)-len(unique)],
                     ['ERD 컬럼 0~2개', report['information_poor_records']]]), '',
               '## Method', '', table(['method', '건수'], [[m, n] for m, n in sorted(methods.items())]), '',
               '## Meta 조합 (원본 전체)', '', table(list(FLAGS) + ['건수'],
                   [[*[item[name] for name in FLAGS], item['count']] for item in report['flag_combinations']]), '',
               '## Service별 건수 분포', '', table(['service당 건수', 'service 수'], [[n,c] for n,c in sorted(service_sizes.items())]), '',
               '## ERD 컬럼 수 분포', '',
               f'최소 {min(columns)}, 중앙값 {report["erd_columns_median"]}, 최대 {max(columns)}.', '',
               table(['컬럼 수', '레코드 수'], [[n,c] for n,c in sorted(columns.items())]), '',
               '## 해석 제한', '',
               '- 중복은 요청한 (service, method, path) 키의 동일성이다. 키가 같아도 스니펫 본문까지 같다는 뜻은 아니다. 실제 원본은 변경하지 않았다.',
               '- 제공된 추출기는 service당 15건 상한을 이미 적용하며, 파일·경로 순서로 먼저 발견한 후보를 선택한다.',
               '- service는 APIs 디렉터리의 첫 경로 요소다. 한 제공자의 여러 제품·버전이 합쳐질 수 있다.',
               '- ERD는 응답/요청 JSON 스키마 필드로 만든 의사 DDL이다. 실제 DB 테이블·FK·소유권 검증의 증거가 아니다. 중첩 필드가 평탄화되고 동명 필드는 합쳐진다.',
               '- meta 플래그는 추출기의 이름 정규식 및 security 선언 존재 여부다. 실제 인가 정책의 정답 라벨이 아니다.',
               '- security 미선언은 public의 확정 근거가 아니다. has_security=false에는 보안 메타데이터 부재도 포함된다.',
               '- 단계 A만 실행했다. 필터·라벨링·분할은 실행하지 않았다.', '']
    (output / 'candidates_analysis.md').write_text('\n'.join(summary), encoding='utf-8')
    (output / 'candidates_analysis.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    assert path.read_bytes() and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert sum(services.values()) == sum(methods.values()) == sum(columns.values()) == len(rows)
    assert sum(item['count'] for item in report['flag_combinations']) == len(rows)
    assert len({row['service'] for row in chosen}) == len(chosen)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'datasets/blade/raw/apisguru_candidates.jsonl')
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    report = analyze(args.input, args.output_dir)
    print(json.dumps({key: value for key, value in report.items()
                      if key not in ('records_by_service', 'sample_ids', 'erd_column_distribution')}, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
