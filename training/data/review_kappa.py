"""Cohen's kappa between two reviewers on review_overlap20.md (columns '검수자A label' / '검수자B label'). Usage: python review_kappa.py <md>"""
import sys
from collections import Counter

LABELS = ['public', 'role_required', 'membership_required', 'tenant_match', 'owner_match', 'owner_or_admin', 'manual_review_required']

def parse(path):
    rows = []; header = None
    for line in open(path, encoding='utf-8'):
        if not line.startswith('|'): continue
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if header is None and 'id' in cells: header = cells; continue
        if header and len(cells) == len(header) and not set(cells[0]) <= set('-'): rows.append(dict(zip(header, cells)))
    return rows

def kappa(pairs):
    n = len(pairs); po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[l] * cb[l] for l in LABELS) / (n * n)
    return po, (po - pe) / (1 - pe) if pe < 1 else 1.0

if __name__ == '__main__':
    rows = parse(sys.argv[1]); a, b = '검수자A label', '검수자B label'
    pairs = [(r[a], r[b]) for r in rows if r.get(a) in LABELS and r.get(b) in LABELS]
    if not pairs: raise SystemExit(f'채워진 쌍이 없음 (행 {len(rows)})')
    po, k = kappa(pairs)
    print(f'비교 쌍 {len(pairs)}/{len(rows)}  단순 일치율 {po:.3f}  Cohen kappa {k:.3f}')
    for r in rows:
        if r.get(a) in LABELS and r.get(b) in LABELS and r[a] != r[b]: print('불일치', r['id'], r[a], '/', r[b])
