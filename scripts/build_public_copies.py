"""Build public-release copies of frozen data files with license-restricted code excerpts withheld (2026-11-01, user-approved plan F).

Frozen originals are never modified (SHA-256 asserted before and after). For each withheld record the manifest stores
repository/commit/file:line permalinks, the SHA-256 of the withheld text and a code-free reconstruction recipe so that
scripts/rebuild_from_public.py can restore the byte-identical originals from local clones.

Withheld: (1) DVWS-node (GPL-3.0) handler excerpts in test.jsonl / test_v30.jsonl / test_v30_inputs.jsonl,
          (2) data-v3 pair records from the five repositories with no declared license (code body withheld, records kept),
          (3) NodeBB (GPL-3.0) in data-v5 copies (existing policy: links only).
SFT public copies drop the affected rows (the user message embeds the code).
"""
from __future__ import annotations
import hashlib, json, subprocess, sys, textwrap
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUB = ROOT / 'datasets/blade/processed/public'; PUB_SFT = ROOT / 'training/lora/public'
UND = {  # project (meta.project) -> (clone dir under datasets/blade/raw/opensource, commit)
    'gothinkster/node-express-realworld-example-app': ('gothinkster_node-express-realworld-example-app', '30b68e1e881462b2f4164ea09ab4c4f5699c7b0b'),
    'gothinkster/rails-realworld-example-app': ('gothinkster_rails-realworld-example-app', 'a2ae4fff78b3337683cea988c023281dcb5551b9'),
    'adr1enbe4udou1n/nestjs-realworld-example-app': ('adr1enbe4udou1n_nestjs-realworld-example-app', 'd4ddf3fd9ebd9112f117c0c6b2c5de3a76815c0c'),
    'gothinkster/kotlin-spring-realworld-example-app': ('gothinkster_kotlin-spring-realworld-example-app', '848c29e3abfe1bd72001cc7d7a3227aebec96e9b'),
    'gothinkster/koa-knex-realworld-example': ('gothinkster_koa-knex-realworld-example', '602e234139c453825eb3939cf24bdf00fc164e0e'),
}
DVWS = dict(repository='https://github.com/snoopysecurity/dvws-node', commit='eb6e2886f2206b88bf709fe1fa311adc3ae3c34f', license='GPL-3.0', clone='datasets/blade/raw/vuln_apis/DVWS-node')
NODEBB = dict(repository='https://github.com/NodeBB/NodeBB', commit='c3d8dc512292a376f19e06cb93512bdff2505102', license='GPL-3.0', clone='datasets/blade/raw/opensource/NodeBB_NodeBB')
FROZEN = {  # AGENTS.md / DATA_CARD hashes of the originals
    'datasets/blade/processed/test.jsonl': 'bd22c2580c2ddc2154974f76aa9e7aa2ca30bc6f8434e4960f3d3966093977fa',
    'datasets/blade/processed/test_v30.jsonl': '9bd47216575afc602b03afa20e617308dd9a97476c94e67a117eb17009afd5e2',
    'datasets/blade/processed/train_v3a.jsonl': '1f5d1055ac3d8d407e555c774183acf4c52ceb03ea508391ee5d508484446e66',
    'datasets/blade/processed/train_v3b.jsonl': '723e3b3a784e624033379dce5e46b243c2c3444c34db7efb5032ea2436a696dd',
    'datasets/blade/processed/train_v31b.jsonl': '8ca09e29ec00d7816e933f5b6e6bf92a36743d4c41ac2c72a1f66e8639d26543',
    'datasets/blade/processed/train_v4.jsonl': '1729f79dd1c06408846e4083b2e82fdace113166c0f92fea32e293441791966c',
    'datasets/blade/processed/train_v5.jsonl': '528b36907768de8d6b4253fbcb587254b5009cb33f6d38bb35e79bd3b03c6344',
    'datasets/blade/processed/val_v5.jsonl': '43d53150be7bba9564f21bfddbc225b8ebbd99bcd86a6f30e96ad898f15c81e9',
    'datasets/blade/processed/data_v3_stage1/pairs_train_v3s1.jsonl': 'fddf09bf1b046cea83a2227e98870831f0df58ad0ba3e6011a27cb6d83fb6418',
    'datasets/blade/processed/data_v3_stage1b/pairs_train_v3s1b.jsonl': 'cc34308a149dee2d92998087002e6f63ab771d083cae07f5604d6828fdfab303',
    'training/lora/data_v3/train_sft_v3a.jsonl': 'ff931f5e944e23ef7d9249465d174ab809f32c9a77d79dc93638b4353389e9d1',
    'training/lora/data_v3/train_sft_v3b.jsonl': '85e634a170c83a9bbe209514fa268dc35dc16b9842dbb58dc8aaa0dfac5f92ab',
    'training/lora/data_v31/train_sft_v31b.jsonl': '712efacacbff010fa4d2a10129a345c7cad43e8bcf4ca4633be64d155bbbe0ec',
    'training/lora/data_v4/train_sft_v4.jsonl': '5178c35e7c6bd66e7dfcc44ca603c26bb2319edc85b86abe4679646a3b93a593',
    'training/lora/data_v5/train_sft_v5.jsonl': '2351afe93518f6e29c95ab9305a15b5a1cda7bd6e3c6d18bec7e8e3d45c3216b',
    'training/lora/data_v5/val_sft_v5.jsonl': '0df4642f439c812d4e7b9f5ca968c89fd966703bfc59229d6f7ea7f83115748f',
    'training/lora/data_v4/test_v30_inputs.jsonl': 'd65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a',
    'training/lora/data_v5/test_v30_inputs.jsonl': 'd65f25b966f61131c0ba5a2341798e56dcd2d3b8da73e9f5d03eb3cd6b0f119a',
}
UNHASHED_INPUTS = ['training/lora/data_v3/test_v30_inputs.jsonl', 'training/lora/data_v31/test_v30_inputs.jsonl']  # tracked, no frozen hash recorded
sha = lambda b: hashlib.sha256(b).hexdigest()
fsha = lambda p: sha(Path(p).read_bytes())


def reason_of(r: dict, kind: str) -> str | None:
    meta = r.get('meta') or {}
    if kind == 'test' and r.get('service') == 'DVWS-node':
        return 'GPL-3.0 (snoopysecurity/dvws-node): excerpt withheld in public copy'
    if meta.get('project') in UND:
        return 'no license declared in repository: excerpt withheld in public copy'
    if meta.get('project') == 'nodebb':
        return 'GPL-3.0 (NodeBB): excerpt withheld in public copy (data-v5 policy)'
    return None


def source_of(r: dict) -> dict:
    meta = r.get('meta') or {}
    if r.get('service') == 'DVWS-node':
        return dict(repository=DVWS['repository'], commit=DVWS['commit'], license=DVWS['license'], clone=DVWS['clone'])
    if meta.get('project') in UND:
        d, c = UND[meta['project']]
        assert meta.get('commit') == c, (r['id'], meta.get('commit'))
        return dict(repository='https://github.com/' + meta['project'], commit=c, license='none declared', clone='datasets/blade/raw/opensource/' + d)
    assert meta.get('project') == 'nodebb' and meta.get('commit') == NODEBB['commit']
    return dict(repository=NODEBB['repository'], commit=NODEBB['commit'], license=NODEBB['license'], clone=NODEBB['clone'])


def permalinks(src: dict, locs: list[dict]) -> list[str]:
    return [f"{src['repository']}/blob/{src['commit']}/{l['file'].replace('/../', '/').lstrip('./')}#L{l['start_line']}-L{l['end_line']}" for l in locs]


def clone_ok(src: dict) -> bool:
    p = ROOT / src['clone']
    if not p.exists():
        return False
    head = subprocess.run(['git', '-C', str(p), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    return head == src['commit']


def slice_text(clone: Path, loc: dict) -> str:
    lines = (clone / loc['file']).read_text(encoding='utf-8', errors='replace').splitlines()
    return '\n'.join(lines[loc['start_line'] - 1:loc['end_line']])


TRANSFORMS = {'none': lambda p: p, 'dedent': textwrap.dedent, 'lstrip': str.lstrip, 'strip': str.strip, 'rstrip': str.rstrip}
SUFFIXES = [''] + ['\n' + ws + '...' for ws in ('', '\t', '\t\t', '\t\t\t', '  ', '    ', '      ', '        ')]  # extractors mark cut tails with an indented ellipsis line


def slices_recipe(text: str, clone: Path, locs: list[dict]) -> dict | None:
    """Code-free assembly recipe: per-part whitespace transform + optional ellipsis suffix, parts joined by `join`.
    Also covers whole-text dedent. Returns the first recipe that reproduces `text` exactly (verified by the caller via SHA)."""
    parts = [slice_text(clone, l) for l in locs]
    for join in ('\n\n', '\n'):
        for whole in ('none', 'dedent'):
            pos = 0; per = []; ok = True
            for i, p in enumerate(parts):
                last = i == len(parts) - 1; found = None
                for tname, tf in TRANSFORMS.items():
                    for suf in SUFFIXES:
                        c = tf(p) + suf
                        if last:
                            rest = text[pos:]
                            if whole == 'none' and rest == c: found = (tname, suf, 'none')
                            elif whole == 'none' and rest == c.rstrip(): found = (tname, suf, 'rstrip')
                        elif whole == 'none' and text.startswith(c + join, pos): found = (tname, suf, 'none')
                        if found: break
                    if found: break
                if whole == 'dedent':  # whole-text dedent only as a plain join (rare)
                    break
                if not found: ok = False; break
                per.append(dict(transform=found[0], suffix=found[1])); pos += len(TRANSFORMS[found[0]](p) + found[1]) + (0 if last else len(join))
                final_strip = found[2] if last else 'none'
            if whole == 'dedent':
                if textwrap.dedent(join.join(parts)) == text: return dict(kind='slices', join=join, whole='dedent', parts=[dict(transform='none', suffix='') for _ in parts], final_strip='none')
                if textwrap.dedent(join.join(parts)).rstrip() == text: return dict(kind='slices', join=join, whole='dedent', parts=[dict(transform='none', suffix='') for _ in parts], final_strip='rstrip')
                continue
            if ok:
                return dict(kind='slices', join=join, whole='none', parts=per, final_strip=final_strip)
    return None


def variant_recipe(text: str, original: str) -> dict | None:
    """Variant lines are a subsequence of the original's lines (compared without indentation), re-indented. Store (orig line index, indent)."""
    o = original.split('\n'); v = text.split('\n'); j = 0; lines = []
    for line in v:
        s = line.strip()
        while j < len(o) and o[j].strip() != s:
            j += 1
        if j >= len(o):
            return None
        lines.append([j, line[:len(line) - len(line.lstrip())]])
        j += 1
    rebuilt = '\n'.join(o[i][len(o[i]) - len(o[i].lstrip()):].join([ind, '']) if False else ind + o[i].strip() for i, ind in lines)
    return dict(kind='variant', lines=lines) if rebuilt == text else None


def apply_variant(recipe: dict, original: str) -> str:
    o = original.split('\n')
    return '\n'.join(ind + o[i].strip() for i, ind in recipe['lines'])


def serializer_for(line: str, row: dict) -> str:
    for name, kw in (('ensure_ascii_false', dict(ensure_ascii=False)), ('ensure_ascii_true', dict(ensure_ascii=True))):
        if json.dumps(row, **kw) == line:
            return name
    raise AssertionError('cannot reproduce original serialization')


def main() -> None:
    PUB.mkdir(parents=True, exist_ok=True); PUB_SFT.mkdir(parents=True, exist_ok=True)
    before = {k: fsha(ROOT / k) for k in FROZEN}
    assert before == FROZEN, {k: v for k, v in before.items() if FROZEN[k] != v}
    manifest = dict(built_utc=datetime.now(timezone.utc).isoformat(), builder='scripts/build_public_copies.py', policy='reports/presentation_support/F_license_release_plan.md (approved 2026-11-01)',
                    originals=dict(FROZEN), copies={}, records=[], sft_dropped={}, inputs_withheld={}, clones={})
    rec_index: dict[str, dict] = {}
    rebuilt_texts: dict[tuple[str, str], str] = {}  # (file, id) -> original text (for variant recipes within the same file)

    def withhold_file(rel: str, kind: str, out: Path) -> None:
        data = (ROOT / rel).read_bytes(); newline = '\r\n' if b'\r\n' in data else '\n'
        raw = data.decode('utf-8').split(newline)
        assert raw[-1] == '' and '\r' not in ''.join(raw), rel
        out_lines = []; n = 0; rows = {}
        for line in raw[:-1]:
            r = json.loads(line); rows[r['id']] = r
        for line in raw[:-1]:
            r = json.loads(line); reason = reason_of(r, kind)
            if not reason:
                out_lines.append(line); continue
            n += 1; src = source_of(r); meta = r['meta']; locs = meta.get('source_locations') or []
            text = r['controller_text'] or ''
            entry = rec_index.get(r['id'])
            if entry is None:
                entry = dict(id=r['id'], files=[], reason=reason, label=r.get('label'), method=r.get('method'), path=r.get('path'), project=meta.get('project') or r.get('service'),
                             repository=src['repository'], commit=src['commit'], license=src['license'], source_locations=locs, permalinks=permalinks(src, locs),
                             text_sha256=sha(text.encode('utf-8')), text_len=len(text), recipe=None)
                recipe = None
                if meta.get('pair_role') == 'check_removed' and meta.get('variant_of'):
                    orig = rows.get(meta['variant_of'])
                    recipe = variant_recipe(text, orig['controller_text']) if orig else None
                    if recipe: recipe['variant_of'] = meta['variant_of']
                elif clone_ok(src):
                    manifest['clones'][src['clone']] = src['commit']
                    recipe = slices_recipe(text, ROOT / src['clone'], locs)
                entry['recipe'] = recipe or dict(kind='sha_only')
                manifest['records'].append(entry); rec_index[r['id']] = entry
            entry['files'].append(dict(file=rel, serializer=serializer_for(line, r)))
            r['controller_text'] = ''
            meta['code_withheld'] = reason; meta['code_ref'] = dict(repository=src['repository'], commit=src['commit'], license=src['license'], text_sha256=entry['text_sha256'], permalinks=entry['permalinks'])
            out_lines.append(json.dumps(r, ensure_ascii=False))
        out.write_text('\n'.join(out_lines) + '\n', encoding='utf-8', newline='\n')
        manifest['copies'][str(out.relative_to(ROOT)).replace('\\', '/')] = dict(source=rel, sha256=fsha(out), records=len(raw) - 1, withheld=n, source_newline=newline)

    for rel, kind in [('datasets/blade/processed/test.jsonl', 'test'), ('datasets/blade/processed/test_v30.jsonl', 'test'), ('datasets/blade/processed/train_v3a.jsonl', 'train'),
                      ('datasets/blade/processed/train_v3b.jsonl', 'train'), ('datasets/blade/processed/train_v31b.jsonl', 'train'), ('datasets/blade/processed/train_v4.jsonl', 'train'),
                      ('datasets/blade/processed/train_v5.jsonl', 'train'), ('datasets/blade/processed/val_v5.jsonl', 'train'),
                      ('datasets/blade/processed/data_v3_stage1/pairs_train_v3s1.jsonl', 'train'), ('datasets/blade/processed/data_v3_stage1b/pairs_train_v3s1b.jsonl', 'train')]:
        withhold_file(rel, kind, PUB / (Path(rel).stem + '_public.jsonl'))

    withheld_ids = set(rec_index)
    for rel in ['training/lora/data_v3/train_sft_v3a.jsonl', 'training/lora/data_v3/train_sft_v3b.jsonl', 'training/lora/data_v31/train_sft_v31b.jsonl', 'training/lora/data_v4/train_sft_v4.jsonl',
                'training/lora/data_v5/train_sft_v5.jsonl', 'training/lora/data_v5/val_sft_v5.jsonl']:
        raw = (ROOT / rel).read_text(encoding='utf-8').split('\n'); assert raw[-1] == ''
        keep, dropped = [], []
        for line in raw[:-1]:
            (dropped if json.loads(line)['id'] in withheld_ids else keep).append(line)
        out = PUB_SFT / (Path(rel).parent.name + '_' + Path(rel).stem + '_public.jsonl')
        out.write_text('\n'.join(keep) + '\n', encoding='utf-8', newline='\n')
        ids = [json.loads(l)['id'] for l in dropped]
        manifest['sft_dropped'][rel] = dict(copy=str(out.relative_to(ROOT)).replace('\\', '/'), sha256=fsha(out), kept=len(keep), dropped=len(dropped), dropped_ids=ids,
                                            rebuild='rebuild the record files with scripts/rebuild_from_public.py, then regenerate SFT rows with the data_v* prepare script; dropped rows are the withheld ids')
    for rel in [k for k in FROZEN if k.endswith('test_v30_inputs.jsonl')] + UNHASHED_INPUTS:
        raw = (ROOT / rel).read_text(encoding='utf-8').split('\n'); assert raw[-1] == ''
        out_lines, with_ = [], []
        for line in raw[:-1]:
            r = json.loads(line)
            if r.get('service') == 'DVWS-node':
                with_.append(dict(id=r['id'], oas_code_user_sha256=sha((r.get('oas_code_user') or '').encode('utf-8'))))
                r['oas_code_user'] = None; r['code_withheld'] = 'GPL-3.0 (snoopysecurity/dvws-node): oas_code input withheld; oas input kept'
                out_lines.append(json.dumps(r, ensure_ascii=False))
            else:
                out_lines.append(line)
        out = PUB_SFT / (Path(rel).parent.name + '_' + Path(rel).stem + '_public.jsonl')
        out.write_text('\n'.join(out_lines) + '\n', encoding='utf-8', newline='\n')
        manifest['inputs_withheld'][rel] = dict(copy=str(out.relative_to(ROOT)).replace('\\', '/'), sha256=fsha(out), source_sha256=fsha(ROOT / rel), withheld=with_)

    recipes = {}
    for e in manifest['records']: recipes[e['recipe']['kind']] = recipes.get(e['recipe']['kind'], 0) + 1
    manifest['summary'] = dict(withheld_records=len(manifest['records']), by_reason={}, recipes=recipes)
    for e in manifest['records']: manifest['summary']['by_reason'][e['reason']] = manifest['summary']['by_reason'].get(e['reason'], 0) + 1
    (PUB / 'withheld_manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + '\n', encoding='utf-8', newline='\n')
    excl = ['# Original files that contain license-restricted code excerpts. Exclude from any public export; ship the *_public copies and withheld_manifest.json instead.',
            '# (files already in .gitignore for the same reason are listed too)'] + sorted(set(list(FROZEN) + UNHASHED_INPUTS + ['datasets/blade/processed/data_v5/candidates_train_v5.jsonl', 'datasets/blade/processed/data_v5/train_v5_rule_labeled.jsonl', 'datasets/blade/processed/data_v5/train_v5_selected.jsonl', 'datasets/blade/processed/data_v5/train_v5_pool.jsonl', 'data/raw_v5_train/nodebb/candidates.jsonl', 'reports/data_v3/review_pairs_v3s1.xlsx', 'reports/data_v3/review_pairs_v3s1_reviewed.xlsx', 'reports/data_v3/review_pairs_v3s1b.xlsx', 'reports/data_v3/review_pairs_v3s1b_reviewed.xlsx', 'review/v5_train_review.xlsx', 'review/v5_train_review_reviewed.xlsx']))
    (PUB / 'PUBLIC_EXCLUDE.txt').write_text('\n'.join(excl) + '\n', encoding='utf-8', newline='\n')
    after = {k: fsha(ROOT / k) for k in FROZEN}
    assert after == FROZEN, 'originals changed!'
    print(json.dumps(manifest['summary'], ensure_ascii=False)); print({k: (v['withheld'], v['records']) for k, v in manifest['copies'].items()})
    print({k: (v['kept'], v['dropped']) for k, v in manifest['sft_dropped'].items()})
    print('non-reconstructible:', [e['id'] for e in manifest['records'] if e['recipe']['kind'] == 'sha_only'][:10])


if __name__ == '__main__':
    main()
