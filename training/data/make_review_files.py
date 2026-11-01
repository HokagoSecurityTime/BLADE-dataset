"""Build / rebuild all human-review files with a common header (prompt v3.0.1 label definitions + manual rules for visibility-dependent / ACL),
the REVIEW_PLAN.md progress table, and the 20-record cross-review overlap set. Read-only on data; writes only review markdown files.
Run after label_reference_v30.py has produced the *_llmref.jsonl files."""
import json, random
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]; P = ROOT / 'datasets/blade/processed'; T = ROOT / 'training/data'
rd = lambda p: [json.loads(l) for l in open(p, encoding='utf-8') if l.strip()] if Path(p).exists() else []
cell = lambda x: str(x if x is not None else '').replace('|', '&#124;').replace('\r', '').replace('\n', '<br>')
PROMPT = (T / 'prompts/policy_label_v3.0.1.md').read_text(encoding='utf-8')
DEFS = PROMPT.split('## 고정 라벨')[1].split('## 판단 절차')[0].strip()
RULES = PROMPT.split('## 보류가 필수인 경우')[1].split('## 판단 절차')[0].strip()

def header(title, purpose, n):
    return [f'# {title}', '', f'용도: {purpose}. 건수 {n}. 검수 열은 비워 두었다. 라벨 기준은 프롬프트 v3.0.1 정의 전문(아래)을 따른다.', '',
            '**추가 기준**: visibility_dependent(저장소·조직·설정의 공개 여부에 따라 접근이 달라지는 조건부 접근)와 ACL(관리자가 배포별로 설정하는 객체 권한·역할 목록)은 원칙적으로 manual_review_required. 인증만 있고 인가 검사가 없으면 manual_review_required. 구독·플랜·등급만 요구하면 manual_review_required.', '',
            '## v3.0.1 라벨 정의(전문)', '', DEFS, '', '## 보류가 필수인 경우(전문)', '', RULES, '', '## 표본', '']

def key_lines(code, pats):
    import re
    return ' / '.join(l.strip()[:120] for l in (code or '').splitlines() if re.search(pats, l))[:600]

def summit_club():
    rows = [r for r in rd(P / 'test_v30.jsonl') if r['service'] == 'summit_club']
    lines = header('review_summit_club — test_v30의 summit_club 16건 (test 정답 확정용)', 'test 정답(설계 라벨 확정)', len(rows)) + ['| id | method | path | 설계 label(제안) | vulnerable | 코드 발췌 | 정답 | 사유 | 검수자 |', '|---|---|---|---|---|---|---|---|---|']
    for r in rows: lines.append('| ' + ' | '.join(cell(x) for x in [r['id'], r['method'], r['path'], r['label'], r['meta'].get('known_vulnerable'), r.get('controller_text', '')]) + ' | | | |')
    (T / 'review_summit_club.md').write_text('\n'.join(lines) + '\n', encoding='utf-8'); return rows

def test_v2_extra():
    rows = rd(P / 'test_v2_extra_candidates_llmref.jsonl') or rd(P / 'test_v2_extra_candidates.jsonl')
    lines = header('review_sample_test_v2_extra — vAPI·Damn Vulnerable RESTaurant 56건 (test 정답 확정용, GPL-3.0 고지 필요)', 'test 정답', len(rows)) + ['| id | 프로젝트 | 인증 방식(발췌) | 역할/미들웨어 | 핵심 코드 줄 | LLM 참고 label | LLM 근거 | 정답 | 사유 | 검수자 |', '|---|---|---|---|---|---|---|---|---|---|']
    for r in rows:
        cs = r['controller_signals']; auth = 'inline CustomHeaderAuth' if cs.get('auth_inline') else ('Depends(get_current_user)/RolesBasedAuthChecker' if cs.get('auth_dependency') else ('middleware ' + ','.join(cs.get('middleware', [])) if cs.get('middleware') else '없음'))
        ref = r.get('llm_reference') or {}
        lines.append('| ' + ' | '.join(cell(x) for x in [r['id'], r['service'], auth, cs.get('required_roles') or cs.get('middleware') or '', key_lines(r['controller_text'], r'403|401|Forbidden|Unauthorized|RolesBasedAuthChecker\(|get_current_user|CustomHeaderAuth\(|where\(\'id\'|find\(|findorFail|filter\('), r.get('llm_reference_label'), ref.get('rationale')]) + ' | | | |')
    (T / 'review_sample_test_v2_extra.md').write_text('\n'.join(lines) + '\n', encoding='utf-8'); return rows

def netbox():
    rows = rd(P / 'opensource/netbox_v4.7.3_heldout185_llmref.jsonl')
    if not rows: return []
    rows.sort(key=lambda r: (r['meta'].get('heldout_priority', 9), r['id']))
    lines = header('review_sample_netbox — NetBox v4.7.3 held-out 185건 (test 정답 확정용, 프로젝트 단위 held-out)', 'test 정답(held-out). 우선순위 1=커스텀 action·permission_classes 오버라이드, 2=users 앱, 3=대표 모델 CRUD. 검수가 다 안 되면 1·2순위만 held-out으로 사용', len(rows)) + ['| 우선순위 | id | viewset | action | permission_override | custom | 핵심 코드 줄 | LLM 참고 label | LLM 근거 | 정답 | 사유 | 검수자 |', '|---|---|---|---|---|---|---|---|---|---|---|---|']
    for r in rows:
        cs = r['controller_signals']; ref = r.get('llm_reference') or {}
        lines.append('| ' + ' | '.join(cell(x) for x in [r['meta'].get('heldout_priority'), r['id'], cs.get('viewset'), cs.get('action'), cs.get('permission_override'), cs.get('custom_action'), key_lines(r['controller_text'], r'permission_classes|restrict\(|get_object_or_404|request\.user|is_superuser|PermissionDenied|IsAuthenticated|IsSuperuser|def (get|post|put|patch|delete)\('), r.get('llm_reference_label'), ref.get('rationale')]) + ' | | | |')
    (T / 'review_sample_netbox.md').write_text('\n'.join(lines) + '\n', encoding='utf-8'); return rows

def overlap(summit, extra, nb):
    rng = random.Random(42); picks = []
    picks += rng.sample(sorted(summit, key=lambda r: r['id']), 3)
    ex_v = sorted([r for r in extra if r['service'] == 'vAPI'], key=lambda r: r['id']); ex_d = sorted([r for r in extra if r['service'] == 'DVRestaurant'], key=lambda r: r['id'])
    picks += rng.sample(ex_v, 4) + rng.sample(ex_d, 3)
    p1 = sorted([r for r in nb if r['meta'].get('heldout_priority') == 1], key=lambda r: r['id']); p2 = sorted([r for r in nb if r['meta'].get('heldout_priority') == 2], key=lambda r: r['id']); p3 = sorted([r for r in nb if r['meta'].get('heldout_priority') == 3], key=lambda r: r['id'])
    picks += rng.sample(p1, min(5, len(p1))) + rng.sample(p2, min(3, len(p2))) + rng.sample(p3, min(2, len(p3)))
    picks = picks[:20]
    lines = header('review_overlap20 — 교차 검수용 겹침 셋 20건 (test 정답 파일에서 층화 추출: summit_club 3, vAPI 4, DVRestaurant 3, NetBox 1순위 5·2순위 3·3순위 2)', '검수자 2명 일치율(Cohen\'s kappa) 측정. 각자 자기 열만 채운다', len(picks)) + ['| id | 출처 | 핵심 코드 줄 | 검수자A label | 검수자A 사유 | 검수자B label | 검수자B 사유 |', '|---|---|---|---|---|---|---|']
    for r in picks: lines.append('| ' + ' | '.join(cell(x) for x in [r['id'], r['service'], key_lines(r.get('controller_text', ''), r'403|401|Forbidden|Unauthorized|permission|principal|current_user|restrict|request\.user|MEMBERSHIPS|owner_id|tenant_id|role')]) + ' | | | | |')
    (T / 'review_overlap20.md').write_text('\n'.join(lines) + '\n', encoding='utf-8'); return picks

def split_gitea_ownadmin():
    """Move the 'owner_or_admin 10' rows out of review_sample_gitea.md into review_gitea_ownadmin10.md (user decision 2026-10-21)."""
    src = T / 'review_sample_gitea.md'; lines = src.read_text(encoding='utf-8').splitlines()
    rows = [l for l in lines if l.startswith('| owner_or_admin 10 |')]
    if not rows: return sum(1 for l in (T / 'review_gitea_ownadmin10.md').read_text(encoding='utf-8').splitlines() if l.startswith('| owner_or_admin 10 |')) if (T / 'review_gitea_ownadmin10.md').exists() else 0
    hdr = next(l for l in lines if l.startswith('| 그룹 |')); sep = lines[lines.index(hdr) + 1]
    out = header('review_gitea_ownadmin10 — Gitea owner_or_admin LLM 라벨 10건 (train 포함 여부 결정용)', 'train 품질. reqAdmin은 저장소 단위 관리자 ACL이라 BLADE owner_or_admin(객체 소유자 OR 시스템 관리자)과 다를 수 있다. 이 10건의 검수 결과로 pool의 owner_or_admin 84건 포함 여부를 재결정한다', len(rows)) + [hdr, sep] + rows
    (T / 'review_gitea_ownadmin10.md').write_text('\n'.join(out) + '\n', encoding='utf-8')
    src.write_text('\n'.join(l for l in lines if not l.startswith('| owner_or_admin 10 |')) + '\n', encoding='utf-8'); return len(rows)

def plan(counts):
    files = [('1', 'training/data/review_overlap20.md', 20, '교차 검수 → review_kappa.py (kappa < 0.6이면 이후 검수 중단, 불일치 목록 보고)', 'A + B', '필수'),
             ('2', 'training/data/review_summit_club.md', counts['summit'], 'test 정답(test_v30 합성 16건, 설계 라벨 확정)', 'A', '필수'),
             ('3', 'training/data/review_gitea_ownadmin10.md', counts['ownadmin'], 'train 품질(Gitea owner_or_admin 10건 → pool 84건 포함 여부 결정)', 'A', '필수'),
             ('4', 'training/data/review_sample_test_v2_extra.md', counts['extra'], 'test 정답(test_v2_extra, GPL 고지)', 'B', '필수'),
             ('5', 'training/data/review_sample_netbox.md (우선순위 1)', counts['nb1'], 'test 정답(held-out NetBox 커스텀 action·permission 오버라이드)', 'A', '필수'),
             ('5', 'training/data/review_sample_netbox.md (우선순위 2)', counts['nb2'], 'test 정답(held-out NetBox users 앱)', 'B', '필수'),
             ('6', 'training/data/review_sample_netbox.md (우선순위 3)', counts['nb3'], 'test 정답(held-out NetBox 대표 CRUD)', '미배정', '완료분만'),
             ('7', 'training/data/review_sample_gitea.md', counts['gitea'], 'train 품질(Gitea 나머지: label별 10·public_candidate 28·visibility 10)', '미배정', '완료분만'),
             ('8', 'training/data/review_sample_v30.md', counts['v30'], 'train 품질(data-v1 APIs.guru 라벨 교정)', '미배정', '완료분만')]
    t = ['# REVIEW_PLAN — 사람 검수 진행표 (2026-10-21 개정)', '',
         '순서: overlap20 → summit_club → gitea owner_or_admin 10 → test_v2_extra → NetBox 1·2순위 → NetBox 3순위 → gitea 나머지 → v30. 모든 파일 상단에 v3.0.1 정의 전문과 visibility_dependent·ACL=manual 기준이 있다. 검수 결과는 파일의 검수/정답 열에만 적고 원본 데이터는 바꾸지 않는다(반영은 apply_reviews_v2.py).', '',
         '**중단 규칙**: review_overlap20의 Cohen\'s kappa가 0.6 미만이면 이후 검수를 멈추고 불일치 목록을 보고한다. 기준 문서를 보강하고 불일치 건을 합의한 뒤 재개한다.', '',
         '**10/26 동결 필수 범위**: overlap20, summit_club, gitea owner_or_admin 10, test_v2_extra, NetBox 1·2순위. 나머지는 완료분만 반영하고 미완료로 기록한다.', '',
         '| 순서 | 파일 | 건수 | 용도 | 검수자 | 동결 범위 | 상태 | 완료일 |', '|---|---|---:|---|---|---|---|---|']
    for p, f, n, u, who, scope in files: t.append(f'| {p} | {f} | {n} | {u} | {who} | {scope} | 미시작 | |')
    t += ['', '## 검수자 배정', '', '- (A): overlap20, summit_club, gitea owner_or_admin 10, NetBox 1순위', '- (B): overlap20, test_v2_extra, NetBox 2순위', '- 미배정: NetBox 3순위, gitea 나머지, v30', '',
          '## 교차 검수', '', '`review_overlap20.md`를 두 검수자가 각자 채운 뒤:', '', '```', '.python\\python.exe -X utf8 training\\data\\review_kappa.py training\\data\\review_overlap20.md', '```', '',
          '## 기입 규칙', '', '- test 정답 파일(summit_club·test_v2_extra·netbox·overlap20): `정답` 열에 7종 label 중 하나, 제외할 건은 `제외`. 비어 있으면 미확정으로 최종 파일에서 빠진다.', '- train 품질 파일(gitea·gitea_ownadmin10·v30): `검수` 열이 비어 있으면 LLM 라벨 유지, label을 적으면 교정(override), `제외`면 train에서 제외.', '',
          '## 반영 경로 (apply_reviews_v2.py)', '', '- summit_club 정답 → test_v30은 불변. 설계 라벨과 다른 확정이 있으면 data-v2 평가용 `test_v30_corrections.json`에 기록.', '- test_v2_extra·NetBox 정답 → `test_v2_extra.jsonl` / `netbox_heldout.jsonl`(정답 채운 건만, 우선순위·support 보고, 해시 기록).', '- gitea·v30 교정 → `train_v2.jsonl` 빌드 시 override 테이블로 반영(원본 라벨 파일 불변). manual 25% 쿼터(data-v1 manual·합성 manual 전량 유지, 남는 자리는 Gitea visibility_dependent manual 층화).', '- 빈 검수 파일로 `--dry-run` 실행하면 반영 건수만 보고하고 파일을 쓰지 않는다.']
    (T / 'REVIEW_PLAN.md').write_text('\n'.join(t) + '\n', encoding='utf-8')

if __name__ == '__main__':
    s = summit_club(); e = test_v2_extra(); n = netbox(); o = overlap(s, e, n); own = split_gitea_ownadmin()
    count = lambda name: sum(1 for l in (T / name).read_text(encoding='utf-8').splitlines() if l.startswith('| ') and not l.startswith('| 그룹') and not l.startswith('|---'))
    gitea = count('review_sample_gitea.md'); v30 = count('review_sample_v30.md')
    plan(dict(summit=len(s), extra=len(e), ownadmin=own, nb1=sum(r['meta'].get('heldout_priority') == 1 for r in n), nb2=sum(r['meta'].get('heldout_priority') == 2 for r in n), nb3=sum(r['meta'].get('heldout_priority') == 3 for r in n), gitea=gitea, v30=v30))
    print(dict(summit=len(s), extra=len(e), netbox=len(n), overlap=len(o), ownadmin=own, gitea=gitea, v30=v30))
