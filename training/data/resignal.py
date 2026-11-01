"""A2 only: preserve candidates, add heuristic metadata and repair table names."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
from typing import Any

from training.data.analyze_candidates import ROOT, load, table
from training.data.sources.naming import resource_name

OWNER_ROOTS = {'user', 'owner', 'createdby', 'author', 'account', 'customer', 'member',
               'creator', 'usera', 'userb', 'assignee', 'reporter', 'uploadedby', 'submittedby', 'requester'}
TENANT_ROOTS = {'tenant', 'organization', 'org', 'company', 'workspace', 'team', 'project',
                'merchant', 'provider', 'site', 'account'}
SUFFIXES = ('', 'id', 'uuid', 'name', 'email')
OWNER_SEGMENTS = {'users', 'accounts', 'customers', 'members'}
TENANT_SEGMENTS = {'orgs', 'organizations', 'tenants', 'teams', 'workspaces', 'projects', 'companies', 'merchants'}
CLASSES = ('owner', 'tenant', 'both', 'path_only', 'none')


def normalize(name: str) -> str:
    return name.replace('_', '').casefold()


def matches(name: str, roots: set[str]) -> bool:
    normalized = normalize(name)
    return any(normalized == root + suffix for root in roots for suffix in SUFFIXES)


def erd_columns(ddl: str) -> list[str]:
    if not ddl.strip():
        return []
    lines = ddl.splitlines()
    if not lines[0].startswith('CREATE TABLE ') or lines[-1].strip() != ');':
        raise ValueError('Unexpected pseudo-DDL format')
    columns = []
    for line in lines[1:-1]:
        if not line.strip():
            continue
        match = re.fullmatch(r'  (.+) (?:INTEGER|NUMERIC|BOOLEAN|TEXT)(?:,| -- (?:owner|tenant) candidate,?)?', line)
        if not match:
            raise ValueError(f'Unrecognized column: {line!r}')
        columns.append(match.group(1))
    return columns


def path_signals(path: str, params: list[str]) -> tuple[bool, bool, int]:
    segments = [segment for segment in path.split('/') if segment]
    parameter = re.compile(r'^\{[^{}]+\}(?:\.[A-Za-z0-9]+)?$')
    resource_segments = [segments[i - 1].casefold() for i in range(1, len(segments))
                         if parameter.fullmatch(segments[i]) and not parameter.fullmatch(segments[i - 1])]
    all_params = list(dict.fromkeys(params + re.findall(r'\{([^{}]+)\}', path)))
    owner = ('me' in [segment.casefold() for segment in segments]
             or bool(OWNER_SEGMENTS.intersection(resource_segments))
             or any(matches(param, OWNER_ROOTS) for param in all_params))
    tenant = (bool(TENANT_SEGMENTS.intersection(resource_segments))
              or any(matches(param, TENANT_ROOTS) for param in all_params))
    return owner, tenant, len(resource_segments)


def reclassify(row: dict[str, Any]) -> dict[str, Any]:
    columns = erd_columns(row['erd_snippet'])
    owner_cols = [name for name in columns if matches(name, OWNER_ROOTS)]
    tenant_cols = [name for name in columns if matches(name, TENANT_ROOTS)]
    oas = json.loads(row['oas_snippet'])
    params = oas.get('path_params') or []
    if not isinstance(params, list) or any(not isinstance(param, str) for param in params):
        raise ValueError(f'Invalid path_params in {row["id"]}')
    path_owner, path_tenant, depth = path_signals(row['path'], params)
    scopes = []
    security = oas.get('security') or []
    if not isinstance(security, list):
        raise ValueError(f'Invalid security array in {row["id"]}')
    for requirement in security:
        if not isinstance(requirement, dict):
            raise ValueError(f'Invalid security requirement in {row["id"]}')
        for values in requirement.values():
            if not isinstance(values, list) or any(not isinstance(scope, str) for scope in values):
                raise ValueError(f'Invalid security scopes in {row["id"]}')
            scopes.extend(values)
    scopes = sorted(set(scopes))
    owner, tenant = bool(owner_cols) or path_owner, bool(tenant_cols) or path_tenant
    if not owner_cols and not tenant_cols and (path_owner or path_tenant):
        signal_class = 'path_only'
    elif owner and tenant:
        signal_class = 'both'
    elif owner:
        signal_class = 'owner'
    elif tenant:
        signal_class = 'tenant'
    else:
        signal_class = 'none'
    result = dict(row)
    result['meta'] = dict(row['meta'], owner_cols=owner_cols, tenant_cols=tenant_cols,
                         path_owner_signal=path_owner, path_tenant_signal=path_tenant,
                         path_resource_depth=depth, security_scopes=scopes,
                         has_admin_scope=any(word in scope.casefold() for scope in scopes
                                             for word in ('admin', 'write', 'manage')),
                         signal_class=signal_class)
    if row['erd_snippet'].strip():
        # Replace the first-line table identifier only; preserve columns/comments/newlines.
        result['erd_snippet'], count = re.subn(r'\ACREATE TABLE (.*?) \(',
            lambda _: 'CREATE TABLE ' + resource_name(row['path']) + ' (', row['erd_snippet'], count=1)
        if count != 1:
            raise ValueError(f'Cannot locate table name: {row["id"]}')
    return result


def run(source: Path, destination: Path, report_dir: Path) -> dict[str, Any]:
    if source.resolve() == destination.resolve():
        raise ValueError('Output must differ from raw input')
    rows, raw_hash = load(source)
    converted = [reclassify(row) for row in rows]
    changes = []
    for index, (before, after) in enumerate(zip(rows, converted), 1):
        assert all(before[key] == after[key] for key in before if key not in {'meta', 'erd_snippet'})
        assert all(after['meta'][key] == value for key, value in before['meta'].items())
        assert before['erd_snippet'].partition('\n')[2] == after['erd_snippet'].partition('\n')[2]
        if before['erd_snippet'] != after['erd_snippet']:
            changes.append(dict(line=index, id=before['id'], path=before['path'],
                                before=before['erd_snippet'].splitlines()[0], after=after['erd_snippet'].splitlines()[0]))
    combinations = Counter((row['meta']['signal_class'], row['meta']['has_security']) for row in converted)
    owner_counts = Counter(name for row in converted for name in set(row['meta']['owner_cols']))
    tenant_counts = Counter(name for row in converted for name in set(row['meta']['tenant_cols']))
    poor = [row for row in converted if len(erd_columns(row['erd_snippet'])) <= 2]
    path_only = [row for row in converted if row['meta']['signal_class'] == 'path_only']
    paths = sorted({row['path'] for row in path_only})
    selected_paths = random.Random(42).sample(paths, min(10, len(paths)))
    top = lambda counts: sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:30]
    payload = ''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in converted).encode('utf-8')
    report = dict(stage='A2', source=str(source.resolve()), output=str(destination.resolve()),
                  input_sha256=raw_hash, output_sha256=hashlib.sha256(payload).hexdigest(),
                  records=len(rows), records_preserved=True, raw_unchanged=True,
                  combinations=[dict(signal_class=kind, has_security=security, count=combinations[kind, security])
                                for kind in CLASSES for security in (False, True)],
                  owner_cols_top30=top(owner_counts), tenant_cols_top30=top(tenant_counts),
                  column_frequency_unit='records containing the exact original column name; duplicates retained',
                  information_poor_records=len(poor),
                  information_poor_with_signal=sum(row['meta']['signal_class'] != 'none' for row in poor),
                  path_only_sample_paths=selected_paths, sample_seed=42, table_names_changed=len(changes),
                  table_name_changes=changes)
    assert sum(combinations.values()) == len(rows)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == raw_hash
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + '.tmp')
    temporary.write_bytes(payload)
    temporary.replace(destination)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / 'resignal_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    text = ['# A2 소유권 신호 재탐지', '',
            f'입력 {len(rows):,}건 → 출력 {len(converted):,}건. 원본 SHA-256 `{raw_hash}` 보존 확인.', '',
            f'ERD 테이블명만 수정한 레코드: {len(changes)}건. 기존 meta 값과 기타 필드·순서·중복은 보존.', '',
            '## signal_class × has_security', '',
            table(['signal_class', 'has_security', '건수'],
                  [[r['signal_class'], r['has_security'], r['count']] for r in report['combinations']]), '',
            '## owner_cols 상위 30', '', table(['원본 컬럼명', '레코드 수'], top(owner_counts)), '',
            '## tenant_cols 상위 30', '', table(['원본 컬럼명', '레코드 수'], top(tenant_counts)), '',
            '## path_only 샘플 10건 (path만)', '', *['- `' + path + '`' for path in selected_paths], '',
            '## 정보 부족 후보', '',
            f'ERD 컬럼 ≤2인 {len(poor):,}건 중 signal_class != none: {report["information_poor_with_signal"]:,}건.', '',
            '## 판정 규칙·제한', '',
            '- 대소문자와 underscore를 제거한 전체 이름을 비교하며 부분 문자열은 매칭하지 않는다. 기본명 뒤 id/uuid/name/email 변형을 포함한다.',
            '- 컬럼 빈도는 원래 표기를 유지한 레코드 단위다. 예: userId와 user_id는 탐지 시 같게 취급하지만 빈도표에서는 구분한다.',
            '- ERD 양쪽 목록이 모두 비고 경로 신호만 있으면 path_only를 우선한다. 그 외 ERD·경로의 owner/tenant 신호를 합쳐 both/owner/tenant/none을 정한다.',
            '- account 컬럼·파라미터는 owner/tenant 양쪽에 표시한다. 경로 패턴은 지정된 복수 리소스와 me를 인식한다.',
            '- path_resource_depth는 리소스 세그먼트 바로 뒤의 {파라미터} 쌍 수다. /a/{x}/b/{y}=2, /a/{x}/b=1.',
            '- 기존 has_owner_col/has_tenant_col/has_security는 보존한다. 확장 결과는 새 목록과 signal_class를 사용한다.',
            '- admin/write/manage는 scope 문자열의 대소문자 무시 포함 검사다. 실제 관리자 권한이나 소유권을 확정하는 라벨이 아니다.',
            '- 원본 후보 파일과 oas_snippet은 수정하지 않았다. 필터링·라벨링·분할은 실행하지 않았다.', '']
    (report_dir / 'resignal_report.md').write_text('\n'.join(text), encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'datasets/blade/raw/apisguru_candidates.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'datasets/blade/processed/apisguru_resignaled.jsonl')
    parser.add_argument('--report-dir', type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    result = run(args.input, args.output, args.report_dir)
    print(json.dumps({key: value for key, value in result.items() if key != 'table_name_changes'}, ensure_ascii=False, indent=2))
