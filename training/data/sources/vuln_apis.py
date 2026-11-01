"""Read-only, offline inventory of cloned vulnerable APIs; never executes repo code.

This is a collection preview, not ground truth. Unknown signals remain null and
all proposed/confirmed labels remain null until source review by a human.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
from typing import Any

import yaml
from pipeline.parsers.controller import parse_controller

ROOT = Path(__file__).resolve().parents[3]
REPOS = {
    'VAmPI': 'openapi_specs/openapi3.yml',
    'crAPI': 'openapi-spec/crapi-openapi-spec.json',
    'juice-shop': 'swagger.yml',
    'Pixi': 'app/public/swagger.json',
    'DVWS-node': 'docs/openapi/openapi.json',
}
METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
SIGNALS = ('has_auth_check', 'admin_bypass', 'tenant_check', 'owner_filter')


def read(path: Path) -> str:
    return path.read_text(encoding='utf-8-sig', errors='replace')


def normalize(path: str) -> str:
    return re.sub(r':([A-Za-z_]\w*)', r'{\1}', path).rstrip('/') or '/'


def shape(path: str) -> str:
    return re.sub(r'\{[^}]+\}', '{}', normalize(path))


def commit(repo: Path) -> str | None:
    head = repo / '.git/HEAD'
    if not head.exists():
        return None
    value = read(head).strip()
    if not value.startswith('ref: '):
        return value
    ref = value[5:]
    loose = repo / '.git' / ref
    if loose.exists():
        return read(loose).strip()
    packed = repo / '.git/packed-refs'
    if packed.exists():
        for line in read(packed).splitlines():
            if line.endswith(' ' + ref):
                return line.split()[0]
    return None


def location(file: Path, repo: Path, start: int, end: int, kind: str) -> dict[str, Any]:
    lines = read(file).splitlines()
    end = min(end, start + 29, len(lines))
    return {'file': file.relative_to(repo).as_posix(), 'start_line': start,
            'end_line': end, 'excerpt': '\n'.join(lines[start - 1:end]),
            'file_sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'kind': kind}


def python_handler(repo: Path, operation: str) -> dict[str, Any] | None:
    if not operation or '.' not in operation:
        return None
    module, name = operation.rsplit('.', 1)
    file = repo / (module.replace('.', '/') + '.py')
    if not file.is_file() or not file.resolve().is_relative_to(repo.resolve()):
        return None
    try:
        tree = ast.parse(read(file))
    except SyntaxError:
        return None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return location(file, repo, node.lineno, node.end_lineno or node.lineno, 'handler')
    return None


def python_signals(repo: Path, operation: str, method: str, path: str) -> dict[str, bool] | None:
    mapped = python_handler(repo, operation)
    if not mapped:
        return None
    source = read(repo / mapped['file'])
    name = operation.rsplit('.', 1)[-1]
    for node in ast.parse(source).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            # Text adapter supplies only the OAS route to the existing static parser.
            # The entire original handler body is parsed, not its 30-line excerpt.
            wrapped = f'@app.{method.lower()}({path!r})\n' + ast.get_source_segment(source, node)
            hints = parse_controller(wrapped, 'python').get(f'{method} {path}')
            return {k: hints[k] for k in SIGNALS} if hints else None
    return None


def java_routes(file: Path, repo: Path) -> list[dict[str, Any]]:
    text = read(file)
    # Preserve offsets while removing comments; commented annotations are not routes.
    clean = re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: re.sub(r'[^\n]', ' ', m[0]), text, flags=re.S)
    class_at = re.search(r'\bclass\s+\w+', clean)
    if not class_at:
        return []
    prefix = re.search(r'@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?"([^"]*)"', clean[:class_at.start()])
    root = prefix[1] if prefix else ''
    matches = list(re.finditer(r'@(Get|Post|Put|Patch|Delete|Head|Options)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?"([^"]*)"', clean))
    rows = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(clean)
        start_line = text.count('\n', 0, match.start()) + 1
        rows.append({'method': match[1].upper(), 'path': normalize(root + '/' + match[2].lstrip('/')),
                     'source': location(file, repo, start_line, text.count('\n', 0, end) + 1, 'annotation_handler'),
                     'signals': None})
    return rows


def javascript_routes(file: Path, repo: Path) -> list[dict[str, Any]]:
    from tree_sitter import Language, Parser
    import tree_sitter_typescript
    source = read(file)
    tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(source.encode())
    if tree.root_node.has_error:
        return []
    imports: dict[str, tuple[Path, str | None]] = {}
    for imported in re.finditer(r'''(?:const|let|var)\s+(\w+)\s*=\s*require\(['"](\.[^'"]+)['"]\)''', source):
        imports[imported[1]] = (file.parent / imported[2], None)
    for imported in re.finditer(r'''import\s+\{([^}]+)\}\s+from\s+['"](\.[^'"]+)['"]''', source):
        for name in imported[1].split(','):
            parts = name.strip().split(' as ')
            imports[parts[-1]] = (file.parent / imported[2], parts[0])
    for imported in re.finditer(r'''import\s+\*\s+as\s+(\w+)\s+from\s+['"](\.[^'"]+)['"]''', source):
        imports[imported[1]] = (file.parent / imported[2], None)

    def resolve_handlers(text: str) -> tuple[list[dict[str, Any]], list[str]]:
        found = []
        bodies: list[str] = []
        for alias, (base, exported) in imports.items():
            if exported:
                names = [exported] if re.search(r'\b' + re.escape(alias) + r'\b', text) else []
            else:
                names = re.findall(r'\b' + re.escape(alias) + r'\.(\w+)', text)
            target = next((p for p in [base, base.with_suffix('.ts'), base.with_suffix('.js'), base / 'index.js']
                           if p.is_file() and p.resolve().is_relative_to(repo.resolve())), None)
            if not target or not names:
                continue
            target_source = read(target)
            parsed_tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(target_source.encode())
            def find(node: Any) -> None:
                name = node.child_by_field_name('name')
                if node.type == 'assignment_expression':
                    left = node.child_by_field_name('left')
                    name = left.child_by_field_name('property') if left else None
                if node.type == 'pair':
                    name = node.child_by_field_name('key')
                if node.type in {'function_declaration', 'variable_declarator', 'assignment_expression', 'pair'} and name and name.text.decode() in names:
                    found.append(location(target, repo, node.start_point.row + 1, node.end_point.row + 1, 'referenced_handler_or_middleware'))
                    value = node.child_by_field_name('value') or node.child_by_field_name('right') or node
                    body = value.child_by_field_name('body')
                    if body:
                        bodies.append(body.text.decode())
                for child in node.named_children:
                    find(child)
            find(parsed_tree.root_node)
        return found, bodies
    rows: list[dict[str, Any]] = []
    def walk(node: Any) -> None:
        if node.type == 'call_expression':
            text = node.text.decode()
            match = re.match(r'''[\w.]+\.(get|post|put|patch|delete|head|options)\s*\(\s*(['"])(.*?)\2\s*,''', text, re.S)
            chained = re.match(r'''[\w.]+\.route\s*\(\s*(['"])(.*?)\1\s*\)''', text, re.S)
            fn = node.child_by_field_name('function')
            prop = fn.child_by_field_name('property') if fn else None
            method = prop.text.decode() if prop else ''
            if match:
                method, path = match[1], match[3]
            elif chained and method in METHODS:
                path = chained[2]
            else:
                path = None
            if path is not None and path.startswith('/'):
                key = method.upper() + ' ' + normalize(path)
                # Chained Express registration needs a parser-compatible wrapper.
                args = node.child_by_field_name('arguments')
                wrapped = text if match else f"app.{method}({json.dumps(path)}, {args.text.decode()[1:]}"
                parsed = parse_controller(wrapped, 'typescript').get(key)
                handler_sources, bodies = resolve_handlers(args.text.decode() if args else '')
                for body in bodies:
                    hints = parse_controller(f'app.{method}({json.dumps(path)}, () => {body})', 'typescript').get(key)
                    if hints:
                        parsed = {k: bool((parsed or {}).get(k)) or hints[k] for k in SIGNALS}
                rows.append({'method': method.upper(), 'path': normalize(path),
                             'source': location(file, repo, node.start_point.row + 1, node.end_point.row + 1, 'route_registration'),
                             'handler_sources': handler_sources,
                             'signals': {k: parsed[k] for k in SIGNALS} if parsed else None})
        for child in node.named_children:
            walk(child)
    walk(tree.root_node)
    return rows


def routes(repo: Path) -> list[dict[str, Any]]:
    result = []
    excluded = {'.git', 'node_modules', 'test', 'tests', 'frontend', 'public', 'dist', 'build', 'data', 'cypress'}
    for file in sorted(repo.rglob('*')):
        if not file.is_file() or excluded.intersection(file.relative_to(repo).parts):
            continue
        if file.suffix == '.java':
            result.extend(java_routes(file, repo))
        elif file.suffix in {'.js', '.ts'} and not file.name.endswith(('.min.js', '.test.js', '.spec.ts')):
            result.extend(javascript_routes(file, repo))
    return result


def vulnerability_docs(repo: Path, path: str) -> list[dict[str, Any]]:
    """Only explicit endpoint plus vulnerability words on the same doc line."""
    result = []
    for file in sorted(repo.rglob('*.md')):
        if '.git' in file.parts or not ('readme' in file.name.lower() or any(x.lower() in {'docs', 'doc'} for x in file.parts)):
            continue
        for number, line in enumerate(read(file).splitlines(), 1):
            if path != '/' and path in line and re.search(r'\b(?:BOLA|IDOR|vulnerab\w*|broken object\w*)\b', line, re.I):
                result.append({'file': file.relative_to(repo).as_posix(), 'line': number, 'quote': line})
    return result


def collect(repo: Path) -> list[dict[str, Any]]:
    spec_file = repo / REPOS[repo.name]
    spec = yaml.safe_load(read(spec_file)) if spec_file.exists() else {}
    mappings = routes(repo)
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for path, item in (spec or {}).get('paths', {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() not in METHODS or not isinstance(operation, dict):
                continue
            full = normalize((spec.get('basePath') or '').rstrip('/') + '/' + path.lstrip('/'))
            entries[(method.upper(), full)] = {'operation': operation, 'oas_file': spec_file.relative_to(repo).as_posix(), 'oas_path': path}
    for mapping in mappings:
        key = (mapping['method'], mapping['path'])
        # OAS parameter spelling can differ from source; retain the OAS spelling.
        candidates = [k for k in entries if k[0] == key[0] and shape(k[1]) == shape(key[1])]
        if len(candidates) == 1:
            key = candidates[0]
        entries.setdefault(key, {}).setdefault('mappings', []).append(mapping)
    rows = []
    revision = commit(repo)
    for (method, path), entry in sorted(entries.items()):
        operation = entry.get('operation', {})
        source = python_handler(repo, operation.get('operationId', ''))
        mapped = entry.get('mappings', [])
        sources = ([source] if source else []) + [m['source'] for m in mapped]
        sources += [handler for m in mapped for handler in m.get('handler_sources', [])]
        signals = {k: None for k in SIGNALS}
        supported = [m['signals'] for m in mapped if m['signals'] is not None]
        py_hints = python_signals(repo, operation.get('operationId', ''), method, path) if source else None
        if py_hints is not None:
            supported.append(py_hints)
        if supported:
            signals = {k: any(s[k] for s in supported) for k in SIGNALS}
        docs = vulnerability_docs(repo, path)
        rows.append({'id': hashlib.sha256(f'{repo.name}:{method}:{path}'.encode()).hexdigest()[:20],
                     'source': 'vuln', 'service': repo.name, 'method': method, 'path': path,
                     'path_params': re.findall(r'\{([^}]+)\}', path),
                     'parameters': operation.get('parameters', []),
                     'oas_source': {k: entry[k] for k in ('oas_file', 'oas_path') if k in entry},
                     'operation_id': operation.get('operationId'), 'source_locations': sources,
                     'controller_signals': signals, 'controller_signal_status': 'parsed_hint' if supported else 'unsupported_or_unmapped',
                     'proposed_label': None, 'confirmed_label': None,
                     'meta': {'commit': revision, 'known_vulnerable': bool(docs), 'vulnerability_sources': docs,
                              'needs_source_review': True, 'source_mapped': bool(sources),
                              'limitation': 'Registration signals are partial; absent hints do not prove absence of authorization. No label inferred.'}})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT / 'datasets/blade/raw/vuln_apis')
    parser.add_argument('--output', type=Path, default=ROOT / 'verification/vuln_collection_preview.jsonl')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.name == 'test.jsonl' or output.is_relative_to(args.root.resolve()):
        parser.error('Output must not overwrite cloned sources or create test.jsonl')
    rows = [row for name in REPOS if (args.root / name).is_dir() for row in collect(args.root / name)]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    report = {'total': len(rows), 'services': {name: {'endpoints': sum(r['service'] == name for r in rows),
               'mapped': sum(r['service'] == name and r['meta']['source_mapped'] for r in rows),
               'signals_parsed': sum(r['service'] == name and r['controller_signal_status'] == 'parsed_hint' for r in rows),
               'known_vulnerable': sum(r['service'] == name and r['meta']['known_vulnerable'] for r in rows)} for name in REPOS},
               'labels_generated': 0, 'note': 'Static collection preview only. Handler review and ground-truth confirmation outstanding.'}
    output.with_suffix('.report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
