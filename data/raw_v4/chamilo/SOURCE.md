# chamilo — Chamilo LMS 2.0 (test_v31_supp 후보)

- 저장소: https://github.com/chamilo/chamilo-lms
- 고정 태그: `v2.0.0-RC.2` → 커밋 `296654b9ce0e9b8d466808340a31c2666b9fc042` (2026-03-09)
- 태그 선택 이유: `gh api repos/chamilo/chamilo-lms/tags` 기준 2.0 계열 태그의 커밋 일자는 RC.1(2026-01-18) → RC.2(2026-03-09) → RC.3(2026-04-01) 순이다(alpha/beta 태그는 2024-07~2026-01로 RC보다 앞선다). 따라서 v2.0.0-RC.3 바로 앞 태그는 RC.2다. RC.2는 GHSA-x373(course_rel_users), GHSA-7phx(PUT /api/users/{id}) 등 "<=2.0-RC.2, 패치 RC.3" advisory의 취약 버전이다.
- 로컬 clone: `datasets/blade/raw/opensource/chamilo_chamilo-lms` (`--depth 1 --filter=blob:none --sparse`, sparse `src/`, `config/`, `core.longpaths=true`). 읽기만 했고 빌드·실행·의존성 설치는 하지 않았다.
- 라이선스: GPL-3.0-or-later. `LICENSE`는 GNU GPL v3 전문이고, `license.txt`에 "either version 3 of the License, or (at your option) any later version", `composer.json`은 `"license": "GPL-3.0-or-later"`.

## 추출 범위

- API Platform 리소스(`src/CoreBundle/Entity`, `src/CourseBundle/Entity`의 `#[ApiResource]`). 경로 prefix `/api`(`config/routes/api_platform.yaml`), 경로 이름은 API Platform 기본 underscore 규칙(`CourseRelUser` → `/api/course_rel_users`, `shortName`가 있으면 그 이름). 저장소에 정적 OpenAPI 명세가 없어 모든 operation을 속성에서 생성했다(`oas_status=generated`). `description`에 operation의 security 식을 적었다.
- advisory 수정 커밋이 건드린 Symfony 컨트롤러 `src/CoreBundle/Controller/SocialController.php`(`/social-network/...`, API Platform 아님) 일부 라우트. 메서드 제한이 없는 라우트는 사용 방식에 따라 GET/POST로 표기했다.
- controller_text: operation 속성(security/securityPostDenormalize/provider/processor) + 관련 Voter(`src/CoreBundle/Security/Authorization/Voter/**`) + state provider/processor + Doctrine collection extension(`src/CoreBundle/DataProvider/Extension/**`) 원문 발췌.

## 인증·인가 구조 요약

- 방화벽 `api`(`^/api`, JWT + main context 세션), `main`(`^/`). `access_control`은 로그인·토큰 경로만 PUBLIC_ACCESS로 두고 나머지를 제한하지 않는다 → security가 없는 API Platform operation은 익명 허용.
- `access_decision_manager.strategy: unanimous`. AbstractResource 엔티티는 `ResourceVoter`(RC.2에서 항상 true)와 전용 voter가 함께 투표한다.
- 주요 voter: `UserVoter`(VIEW 본인·친구·친구의 친구·상사·메시지 공유, EDIT 본인, 관리자 전체), `UsergroupVoter`(RC.2: EDIT=그룹 moderator, VIEW 미구현 → 수정 후 VIEW=그룹 구성원), `CourseVoter`(강좌 가시성 + 등록/세션 구성원, `ROLE_CURRENT_COURSE_*` 맥락 역할 부여), `SessionVoter`, `ResourceNodeVoter`(공개 노드·생성자·강좌/세션/그룹 맥락 역할·게시 상태), `MessageVoter`, `MessageRelUserVoter`, `MessageTagVoter`, `SocialPostVoter`, `UserRelUserVoter`, `CCalendarEventVoter`, `TrackEExerciseVoter`.
- 테넌트(다중 포털)는 AccessUrl. `AccessUrlHelper::getCurrent()`(요청 호스트 기준 현재 포털)로 일부 extension·provider가 필터한다(`PageExtension`, `CourseCategoryExtension`, `CourseRelUserExtension`, `UserCourseSubscriptionsStateProvider` 등). 요청자-포털 소속 검사는 RC.2에 거의 없고 이후 커밋(7fc7527, 6e2b271)에서 `AccessUrlScopeHelper`로 추가됐다.

## Advisory와 수정 커밋 (RC.2 취약 코드 = 입력, 수정 커밋 = 의도 정책)

| advisory | 대상 | 수정 커밋 |
|---|---|---|
| GHSA-x373-8j9j-g5pj (CVE-2026-34602) | POST/GET `/api/course_rel_users` | 2a9f060, bd2ba34, c9c30cd (advisory 본문에 명시) |
| GHSA-7phx-w897-4c9x (CVE-2026-40291) | PUT `/api/users/{id}` roles 대량할당 | d3b8838 |
| GHSA-fp2p-fj6c-x3x9 (CVE-2026-33736) | GET `/api/users` | 1739371 |
| GHSA-j2pr-2r5w-jrpj | GET `/api/users/{id}/courses/{courseId}/stats/{metric}` | 792ba05 (2026-03-12, RC.2 태그 이후 → RC.2 취약) |
| GHSA-27x6-c5c7-gpf5 (CVE-2026-33703) | GET `/social-network/personal-data/{userId}` | 6776e78 (2026-06-02; 커밋은 비공개 GHSA-v86g-64fh-5gh2 참조, RC.3·v2.0.0에는 검사 없음) |
| (GHSA-v86g-64fh-5gh2, 공개 조회 404) | `/social-network/*` 그룹·친구 라우트 | 6776e78 |
| GHSA-ch7g-4f23-9hm2 (CVE-2026-61733) | GET `/api/usergroups/{id}/members` | cd50944 (+0b953db UsergroupVoter::VIEW) |
| GHSA-p2pv-9wv4-pw66 (CVE-2026-61537) | GET `/api/messages/by-group/list` | 0b953db |
| GHSA-2fr5-c8p6-5hq6 (CVE-2026-61734) | `/api/push_subscriptions` 4개 | f75dc98 |
| GHSA-65wx-4v4p-xph3 (CVE-2026-61533) | GET `/api/track_e_attempts` | b00ac92 |
| GHSA-99q5-mwrx-jq34 (CVE-2026-54748) | ResourceVoter(CToolIntro), SocialPostVoter, UserRelUserVoter, SessionVoter | acf5786, 1488993, 8601c15, 694394f, b152c3a |
| GHSA-438r-9jh4-mmfc (CVE-2026-61531) | blog API(`c_blogs`, `c_blog_posts`, `c_blog_comments`, `c_blog_rel_users`) | d70bcc2 |
| GHSA-8423-5658-789h (CVE-2026-61530) | POST `/api/c_student_publication_comments/upload` | c4fd4e9 |
| advisory 없음 | POST `/api/session_rel_users` | c372e84 |
| advisory 없음 | POST `/api/access_urls/{id}/user` | 6e2b271 |

2.0.2 이하를 대상으로 하는 advisory(GHSA-ch7g 등)는 해당 코드가 RC.2에도 같은 형태로 있는지 확인한 뒤 포함했다.

## 제외 범위와 이유

- 레거시 PHP(`public/main/**`, sparse checkout 범위 밖)와 그 advisory(SQLi·XSS·RCE·CSRF·SSRF·노트북 IDOR GHSA-fm35, gradebook GHSA-9h22/rqpg 등): REST API가 아니거나 인가 패턴 문제가 아니다.
- 인가와 무관한 advisory(XSS, XXE, 역직렬화, 경로 조작, SSRF, 약한 키 등).
- 관리자 전용 설정성 리소스 다수(ExtraField, Language, Legal, ColorTheme, ThirdParty 등): 대부분 role_required이고 선정 우선순위가 낮아 대표 몇 건만 넣었다.
- ResourceNodeVoter 기반 강좌 자원(CDocument, CLink, CGlossary, CLp 등): 가시성 분기가 같아 중복이 많아 넣지 않았다(블로그·CToolIntro만 advisory 관련으로 포함).

## 건수

- 후보 69건(API Platform 60, SocialController 9). known_vulnerable 36건(advisory 연결 26건, advisory 없이 수정 커밋만 연결 10건).
- draft_label: owner_or_admin 22, manual_review_required 19, role_required 10, membership_required 8, owner_match 7, tenant_match 2, public 1.
