# 작업 C 정지 지점 1 — hold-out test_v5 후보·검수 시트 (2026-10-31)

학습·동결은 하지 않았다. 기존 동결본(data-v1~v4, test_v30, test_v31_supp, 프롬프트 v3.0.1)은 빌드 시작·끝에 해시를 대조하고 읽기만 했다. AGENTS.md에 '작업 C' 절(사전 고정 판정 기준, v4 주 수치 유지, 마감, 출처 제외, test_v5 출처의 학습 사용 금지)을 먼저 기록한 뒤 시작했다.

## 1. 후보 프로젝트

| 프로젝트 | 태그 · 커밋 | 라이선스 | 선정 이유 | 추출 |
|---|---|---|---|---:|
| Rocket.Chat | `8.9.0` · `057a927d` | MIT (`apps/meteor/ee/`·`ee/`는 EE 라이선스 → 체크아웃·인용 모두 제외, 0건 유입) | 비공개 그룹·DM·팀 구독 행 확인(membership), 본인 OR edit-other-user-* 권한(owner_or_admin) | 163 |
| Ghost | `v6.73.0` · `5794cfd8` | MIT | Contributor/Author 본인 글만 OR Editor+ 역할(owner_or_admin). 그룹·테넌트 개념 없음 | 73 |
| Umami | `v3.4.1` · `559e3c60` | MIT | `canViewTeam`(admin OR 팀 구성원 행), `canViewUser/canUpdateUser`(admin OR 본인) | 60 |

- 제외 검토: Discourse는 APIs.guru 라벨링 풀에 `discourse.local` 9건(manual pool)이 있어 제외. Mattermost·Plane·Mastodon·Lemmy·Nextcloud·Cal.com 등 AGPL 제외. Gitea 계열(Gogs·Forgejo)은 포크 관계로 제외. Appwrite·GitLab은 APIs.guru train 서비스(appwrite.io, gitlab.com)와 겹쳐 제외.
- 중복 대조: (서비스 정규화, method, 경로 정규화) 키 5,804건(APIs.guru 후보 424개 서비스, data-v1~v4 train/val/pool/rule_labeled, test_v30, test_v31_supp 확정·제외분)과 대조해 **겹침 0건**, 내부 중복 0건, 형식 오류 0건.
- 클론은 `datasets/blade/raw/opensource/`(git 미추적)에 얕게 받았고 읽기만 했다(수정·빌드·실행·LLM API 호출 없음). 추출 스크립트·원자료: `data/raw_v5/<project>/{candidates.jsonl, SOURCE.md, extract_*.py}`.

## 2. 초안 label 분포 (296건, 전 건 사람 확정 대상)

| 초안 label | Rocket.Chat | Ghost | Umami | 합 |
|---|---:|---:|---:|---:|
| membership_required | 26 | 0 | 5 | **31** |
| owner_or_admin | 11 | 10 | 4 | **25** |
| owner_match | 27 | 3 | 12 | 42 |
| role_required | 56 | 44 | 13 | 113 |
| manual_review_required | 37 | 8 | 20 | 65 |
| public | 6 | 8 | 6 | 20 |
| tenant_match | 0 | 0 | 0 | 0 |
| **합** | 163 | 73 | 60 | **296** |

- 목표(owner_or_admin ≥ 20, membership_required ≥ 20)는 초안 기준으로 충족하지만 여유가 작다(25 / 31). 검수에서 경계 건이 제외(G8)되거나 owner_match로 바뀌면 20 아래로 떨어질 수 있으며, 그 경우 실제 수를 보고한다.
- 편중: membership 26/31이 Rocket.Chat, owner_or_admin은 세 프로젝트에 분산(11/10/4). tenant_match는 세 프로젝트 모두 구조상 없다.
- 초안 confidence < 0.6은 6건. security_state는 declared 290, explicitly_anonymous 6.

## 3. 검수자가 일관되게 정해야 할 것 (SOURCE.md '불확실' 절 요약)

1. **Rocket.Chat "지정한 방의 본인 구독"**: channels.close/open, im.close/open, teams.leave, chat.starMessage 등은 (요청자, 방) 구독 행을 확인한 뒤 본인 구독만 바꾼다. 초안은 "구성원 행 조회 → membership_required", "본인 구독 플래그만 변경 → owner_match"로 나눴다. 한 규칙으로 통일할 것.
2. **Rocket.Chat 방 종류 무관 접근(canAccessRoom)**: rooms.info, chat.getMessage, channels.info 등 17건은 공개 채널 권한 OR 구독 OR 팀 구성원 분기라 G6대로 manual. teams.info 등 공개 팀 분기도 manual.
3. **Rocket.Chat integrations.* 4건**: `manage-*-integrations` OR (작성자 AND `manage-own-*-integrations`). 소유자 분기에 기능 권한이 붙어 owner_or_admin(0.6) 초안이며 manual·role_required 대안.
4. **Ghost 글 생성(POST /posts, /pages)**: Contributor/Author는 본인 명의만, Editor+ 무제한 → owner_or_admin(0.6) 초안, role_required 대안. webhooks PUT/DELETE는 소유 주체가 integration이라 manual 대안(0.5).
5. **Ghost 조회 계열**(GET /posts, /users, /tags 등): 모든 역할이 권한을 갖고 본인 필터가 없어 "인증만" → manual(0.6). DELETE /users/{id}는 role_required(0.55), owner_or_admin 대안.
6. **Umami 팀 관리 5건**(canUpdateTeam/canDeleteTeam = 구성원 행의 role): G3대로 role_required 초안. canUpdate/DeleteWebsite는 개인 소유·팀 소유 분기라 manual(0.7) 초안이며 owner_or_admin 대안. logout/verify는 owner_match 초안이나 G6(객체 없는 인증)로 보면 manual.
7. 경계·근거 부족 건은 manual로 넣지 말고 비고에 `EXCLUDE` + 사유(G8).
8. 참고: Rocket.Chat chat.getDeletedMessages는 방 접근 검사 없이 인증만 확인한다(초안 manual 0.8). advisory 확인은 하지 않았고 known_vulnerable로 표시하지 않았다.

## 4. 검수 시트

- `review/test_v5_review.xlsx` — 시트 `test_v5_review` 296행. 열: id, **담당자**(검수자A/B/C — project × 초안 label 층화 후 순환 배정, 각 98·99·99건, label·프로젝트 구성이 거의 같음), project, service, method, path, auth_summary, permission_doc, 초안 label, 초안 confidence, 초안 근거 설명, 근거(코드 줄·문서), controller_text(입력 코드), source permalink(GitHub 고정 커밋 링크), **확정 label**(드롭다운), **확정 근거**, **비고(EXCLUDE + 사유)**. 보조 시트 '라벨 정의'(프롬프트 v3.0.1 발췌), '검수 규약'(AGENTS.md G1~G8 원문).
- 검수 완료본은 `review/test_v5_review_reviewed.xlsx`로 저장한다. 동결은 `scripts/build_test_v5.py freeze`가 '확정 label'·'비고' 열을 읽어 test_v5.jsonl / test_v5_excluded.jsonl / manifest / SFT 입력을 만든다(C-2).
- 레코드 파일: `datasets/blade/processed/data_v5/test_v5_candidates.jsonl`(296, label=None, meta.label_status=draft_pending_human_confirmation), `assemble_report.json`, `sheets_report.json`.

## 5. 라이선스·공개 범위

- 세 프로젝트 모두 MIT이며 Rocket.Chat EE 코드는 들어 있지 않다. 따라서 test_v31_supp와 달리 코드 본문을 .gitignore에 넣을 사유는 현재 없다(동결 시 재확인).

## 6. 일정 메모

- README_runpod_rerun.md 기준으로 C-4(학습·평가 약 4.5~5시간)는 토요일 낮 12:00 전에 시작해야 일요일 18:00 마감을 지킨다. 정지 지점 1 이후 사람 검수(296건, 3인) → 동결(C-2) → 보강분 수집·검수·동결(C-3)이 모두 그 전에 끝나야 한다.
