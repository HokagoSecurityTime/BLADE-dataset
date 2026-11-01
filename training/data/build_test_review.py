"""Merge human-review candidates without creating ground truth or test.jsonl."""
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> list[dict]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding='utf8').splitlines()]


def main() -> None:
    rows = read('datasets/blade/processed/vuln_review_candidates.jsonl')
    partition = json.loads((ROOT / 'training/data/synthetic_partition.json').read_text(encoding='utf8'))
    rows += [r for r in read('verification/synthetic_review_records.jsonl') if r['service'] in partition['test_services']]
    assert len(rows) == 317 and len({r['id'] for r in rows}) == 317
    assert not {r['service'] for r in rows}.intersection(partition['train_services'])
    def cell(value: object) -> str:
        return str(value).replace('|', '&#124;').replace('\r', '').replace('\n', '<br>')
    lines = ['# Test 후보 — 사람 검수용', '',
             '공개 API 275건과 test 전용 합성 42건. train/val 전용 합성 3개 서비스는 제외했습니다. 제안은 확정 정답이 아닙니다. 제외 사유는 근거 열에 표시하며 확정 label과 비고는 비워둡니다.', '',
             '| id | source | service | method | path | 제안 label | 근거(파일:줄 + 코드 1~3줄) | controller 신호 | known_vulnerable | 확정 label | 비고 |',
             '|---|---|---|---|---|---|---|---|---|---|---|']
    for r in rows:
        assert not r.get('confirmed_label')
        refs = r.get('review_evidence', r.get('evidence', []))
        evidence = []
        for ref in refs:
            code = ref.get('excerpt', ref.get('code', ''))
            assert len(code.splitlines()) <= 3
            evidence.append(f"{ref['file']}:{ref.get('start_line', ref.get('line'))}\n{code}")
        evidence.append(r.get('proposal_reason', r.get('rationale', '수동 확인 필요')))
        if r.get('meta', {}).get('code_review_status'):
            evidence.append('코드 확인 상태: ' + r['meta']['code_review_status'])
        for ref in r.get('handler_excerpts_50', []):
            code = ref.get('excerpt', '')
            assert len(code.splitlines()) <= 50
            evidence.append(f"핸들러 {ref['file']}:{ref.get('start_line')}\n{code}")
        for ref in r.get('authorization_evidence', []):
            evidence.append('인가 단서: ' + json.dumps(ref, ensure_ascii=False))
        if r['meta'].get('exclude'):
            evidence.append('EXCLUDE: ' + str(r['meta'].get('exclude_reason', r['meta']['exclude'])))
        values = [r['id'], r['source'], r['service'], r['method'], r.get('effective_path', r['path']),
                  r['proposed_label'], '\n'.join(evidence), json.dumps(r['controller_signals']),
                  r['meta']['known_vulnerable'], '', '']
        lines.append('| ' + ' | '.join(map(cell, values)) + ' |')
    (ROOT / 'training/data/review_test.md').write_text('\n'.join(lines) + '\n', encoding='utf8')
    services = {}
    for name in dict.fromkeys(r['service'] for r in rows):
        group = [r for r in rows if r['service'] == name]
        retained = [r for r in group if not r['meta'].get('exclude')]
        services[name] = {'total': len(group), 'retained': len(retained),
                          'excluded': len(group)-len(retained),
                          'proposed_labels_all': dict(Counter(r['proposed_label'] for r in group)),
                          'known_vulnerable_all': sum(bool(r['meta']['known_vulnerable']) for r in group)}
    report = {'total': len(rows), 'retained': sum(not r['meta'].get('exclude') for r in rows),
              'excluded': sum(bool(r['meta'].get('exclude')) for r in rows), 'services': services,
              'confirmed': 0, 'test_jsonl_created': False}
    retained = [r for r in rows if not r['meta'].get('exclude')]
    grounded = [r for r in retained if r['source'] == 'synthetic' or not r['meta'].get('needs_human_judgment', True)]
    report.update(grounded_proposals=len(grounded), unresolved_retained=len(retained)-len(grounded),
                  grounded_fraction_of_retained=len(grounded)/len(retained),
                  known_vulnerable=sum(bool(r['meta']['known_vulnerable']) for r in retained),
                  target_150_200_met_for_all_retained=150 <= len(retained) <= 200)
    (ROOT / 'verification/test_review_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps(report, ensure_ascii=False))


if __name__ == '__main__':
    main()
