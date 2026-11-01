# REVIEW_PLAN — 사람 검수 진행표 (2026-10-21 개정)

순서: overlap20 → summit_club → gitea owner_or_admin 10 → test_v2_extra → NetBox 1·2순위 → NetBox 3순위 → gitea 나머지 → v30. 모든 파일 상단에 v3.0.1 정의 전문과 visibility_dependent·ACL=manual 기준이 있다. 검수 결과는 파일의 검수/정답 열에만 적고 원본 데이터는 바꾸지 않는다(반영은 apply_reviews_v2.py).

**중단 규칙**: review_overlap20의 Cohen's kappa가 0.6 미만이면 이후 검수를 멈추고 불일치 목록을 보고한다. 기준 문서를 보강하고 불일치 건을 합의한 뒤 재개한다.

**10/26 동결 필수 범위**: overlap20, summit_club, gitea owner_or_admin 10, test_v2_extra, NetBox 1·2순위. 나머지는 완료분만 반영하고 미완료로 기록한다.

| 순서 | 파일 | 건수 | 용도 | 검수자 | 동결 범위 | 상태 | 완료일 |
|---|---|---:|---|---|---|---|---|
| 1 | training/data/review_overlap20.md | 20 | 교차 검수 → review_kappa.py (kappa < 0.6이면 이후 검수 중단, 불일치 목록 보고) | A + B | 필수 | 미시작 | |
| 2 | training/data/review_summit_club.md | 16 | test 정답(test_v30 합성 16건, 설계 라벨 확정) | A | 필수 | 미시작 | |
| 3 | training/data/review_gitea_ownadmin10.md | 10 | train 품질(Gitea owner_or_admin 10건 → pool 84건 포함 여부 결정) | A | 필수 | 미시작 | |
| 4 | training/data/review_sample_test_v2_extra.md | 56 | test 정답(test_v2_extra, GPL 고지) | B | 필수 | 미시작 | |
| 5 | training/data/review_sample_netbox.md (우선순위 1) | 50 | test 정답(held-out NetBox 커스텀 action·permission 오버라이드) | A | 필수 | 미시작 | |
| 5 | training/data/review_sample_netbox.md (우선순위 2) | 54 | test 정답(held-out NetBox users 앱) | B | 필수 | 미시작 | |
| 6 | training/data/review_sample_netbox.md (우선순위 3) | 81 | test 정답(held-out NetBox 대표 CRUD) | 미배정 | 완료분만 | 미시작 | |
| 7 | training/data/review_sample_gitea.md | 86 | train 품질(Gitea 나머지: label별 10·public_candidate 28·visibility 10) | 미배정 | 완료분만 | 미시작 | |
| 8 | training/data/review_sample_v30.md | 122 | train 품질(data-v1 APIs.guru 라벨 교정) | 미배정 | 완료분만 | 미시작 | |

## 검수자 배정

- (A): overlap20, summit_club, gitea owner_or_admin 10, NetBox 1순위
- (B): overlap20, test_v2_extra, NetBox 2순위
- 미배정: NetBox 3순위, gitea 나머지, v30

## 교차 검수

`review_overlap20.md`를 두 검수자가 각자 채운 뒤:

```
.python\python.exe -X utf8 training\data\review_kappa.py training\data\review_overlap20.md
```

## 기입 규칙

- test 정답 파일(summit_club·test_v2_extra·netbox·overlap20): `정답` 열에 7종 label 중 하나, 제외할 건은 `제외`. 비어 있으면 미확정으로 최종 파일에서 빠진다.
- train 품질 파일(gitea·gitea_ownadmin10·v30): `검수` 열이 비어 있으면 LLM 라벨 유지, label을 적으면 교정(override), `제외`면 train에서 제외.

## 반영 경로 (apply_reviews_v2.py)

- summit_club 정답 → test_v30은 불변. 설계 라벨과 다른 확정이 있으면 data-v2 평가용 `test_v30_corrections.json`에 기록.
- test_v2_extra·NetBox 정답 → `test_v2_extra.jsonl` / `netbox_heldout.jsonl`(정답 채운 건만, 우선순위·support 보고, 해시 기록).
- gitea·v30 교정 → `train_v2.jsonl` 빌드 시 override 테이블로 반영(원본 라벨 파일 불변). manual 25% 쿼터(data-v1 manual·합성 manual 전량 유지, 남는 자리는 Gitea visibility_dependent manual 층화).
- 빈 검수 파일로 `--dry-run` 실행하면 반영 건수만 보고하고 파일을 쓰지 않는다.
