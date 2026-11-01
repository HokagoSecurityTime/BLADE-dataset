"""Rebuild the frozen originals from the public copies + withheld_manifest.json + local clones, and verify SHA-256.

Usage: python -X utf8 scripts/rebuild_from_public.py [--out <dir>]   (default out: .cache/rebuild_from_public)
Clones expected at the paths recorded in the manifest (datasets/blade/raw/vuln_apis/DVWS-node, datasets/blade/raw/opensource/<owner_repo>)
checked out at the recorded commit. Records with recipe kind 'sha_only' cannot be rebuilt automatically; the script reports them.
"""
from __future__ import annotations
import argparse, hashlib, json, subprocess, sys, textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sha = lambda b: hashlib.sha256(b).hexdigest()


def slice_text(clone: Path, loc: dict) -> str:
    lines = (clone / loc['file']).read_text(encoding='utf-8', errors='replace').splitlines()
    return '\n'.join(lines[loc['start_line'] - 1:loc['end_line']])


TRANSFORMS = {'none': lambda p: p, 'dedent': textwrap.dedent, 'lstrip': str.lstrip, 'strip': str.strip, 'rstrip': str.rstrip}


def from_slices(recipe: dict, clone: Path, locs: list[dict]) -> str:
    parts = [slice_text(clone, l) for l in locs]; join = recipe['join']
    if recipe.get('whole') == 'dedent':
        text = textwrap.dedent(join.join(parts))
    else:
        text = join.join(TRANSFORMS[pr['transform']](p) + pr['suffix'] for p, pr in zip(parts, recipe['parts']))
    return text.rstrip() if recipe.get('final_strip') == 'rstrip' else text


def apply_variant(recipe: dict, original: str) -> str:
    o = original.split('\n')
    return '\n'.join(ind + o[i].strip() for i, ind in recipe['lines'])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--out', default=str(ROOT / '.cache/rebuild_from_public')); ap.add_argument('--manifest', default=str(ROOT / 'datasets/blade/processed/public/withheld_manifest.json'))
    a = ap.parse_args(); out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    m = json.load(open(a.manifest, encoding='utf-8'))
    clones = {}
    for rel, commit in m['clones'].items():
        p = ROOT / rel; head = subprocess.run(['git', '-C', str(p), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip() if p.exists() else ''
        clones[rel] = p if head == commit else None
        print(f"clone {rel}: {'OK' if clones[rel] else 'MISSING/WRONG COMMIT (' + head[:12] + ')'}")
    texts: dict[str, str] = {}; failed = []
    by_id = {e['id']: e for e in m['records']}
    for e in m['records']:  # originals first (variants depend on them)
        if e['recipe']['kind'] == 'variant': continue
        if e['recipe']['kind'] == 'sha_only':
            failed.append((e['id'], 'sha_only')); continue
        src_clone = None
        for rel, c in clones.items():
            if c and m['clones'][rel] == e['commit']: src_clone = c
        if src_clone is None:
            failed.append((e['id'], 'clone unavailable')); continue
        t = from_slices(e['recipe'], src_clone, e['source_locations'])
        if sha(t.encode('utf-8')) == e['text_sha256']: texts[e['id']] = t
        else: failed.append((e['id'], 'sha mismatch after slice'))
    for e in m['records']:
        if e['recipe']['kind'] != 'variant': continue
        o = texts.get(e['recipe']['variant_of'])
        if o is None: failed.append((e['id'], 'original not rebuilt')); continue
        t = apply_variant(e['recipe'], o)
        if sha(t.encode('utf-8')) == e['text_sha256']: texts[e['id']] = t
        else: failed.append((e['id'], 'sha mismatch after variant'))
    print(f"texts rebuilt: {len(texts)} / {len(m['records'])}; failed: {failed[:10]}")
    results = {}
    for copy_rel, info in m['copies'].items():
        lines = (ROOT / copy_rel).read_text(encoding='utf-8').split('\n'); assert lines[-1] == ''
        rebuilt = []; missing = 0
        for line in lines[:-1]:
            r = json.loads(line)
            if 'code_withheld' not in (r.get('meta') or {}):
                rebuilt.append(line); continue
            e = by_id[r['id']]; t = texts.get(r['id'])
            if t is None:
                missing += 1; rebuilt.append(line); continue
            r['controller_text'] = t; r['meta'].pop('code_withheld'); r['meta'].pop('code_ref')
            ser = next(f['serializer'] for f in e['files'] if f['file'] == info['source'])
            rebuilt.append(json.dumps(r, ensure_ascii=(ser == 'ensure_ascii_true')))
        nl = info.get('source_newline', '\n'); data = (nl.join(rebuilt) + nl).encode('utf-8'); dest = out / Path(info['source']).name; dest.write_bytes(data)
        ok = sha(data) == m['originals'].get(info['source']); results[info['source']] = ('OK' if ok else 'MISMATCH') + (f' ({missing} records not rebuilt)' if missing else '')
        print(f"{info['source']}: {results[info['source']]} -> {dest}")
    sys.exit(0 if all(v == 'OK' for v in results.values()) else 1)


if __name__ == '__main__':
    main()
