# Gitea 엔드포인트 발췌 규칙 (data-v2, 3-3)

대상: go-gitea/gitea, 태그 v28.2.0, 커밋 `829b49c1ae96015e345f9d2a0eb1ea7acd5f31e1`, 라이선스 MIT(LICENSE 파일 확인). 클론은 `datasets/blade/raw/opensource/gitea/`(git 미추적, `--depth 1 --branch v28.2.0`), 정적 분석만 하며 수정·실행하지 않는다. OAS 출처: 저장소에 포함된 생성 스펙 `templates/swagger/v1-openapi3.generated.json`(SHA-256 `c797dc2a…d278e`), 342 path · 537 operation. 추출기: `training/data/sources/gitea_extract.py`.

## 규칙

- **R1 라우트**: `routers/api/v1/api.go`의 `Routes()` 본문을 괄호·중괄호 매칭으로 파싱한다. `m.Group(prefix, func(){…}, mw…)`의 후행 인자를 그룹 미들웨어로, `m.Get/Post/Put/Patch/Delete(path, mw…, handler)`의 마지막 인자를 핸들러로, `m.Combo(path, mw…).Get(…).Post(…)` 체인을 각 메서드 라우트로 본다. 미들웨어는 바깥 그룹 → 안쪽 그룹 → 라우트 순으로 누적한다.
- **R2 OAS 매칭**: METHOD + 경로(모든 `{param}`과 `*`를 `{}`로 정규화)로 OpenAPI operation과 1:1 매칭한다. api.go의 `{username}/{reponame}`와 OAS의 `{owner}/{repo}` 차이는 정규화로 흡수한다. 매칭된 레코드의 path는 OAS 표기를 쓴다.
- **R3 코드 발췌**(controller_text): (a) 미들웨어 체인의 각 함수 정의를 api.go에서 추출(중복 제거, 함수당 30줄 상한). `context.*` 헬퍼는 고정 주석으로 요약(UserAssignmentAPI, ReferencesGitRepo, RepoAssignment). (b) 핸들러 함수: 시그니처 + 본문 처음 20줄(주석 제외) + 인가 관용구 정규식에 걸리는 모든 줄 ±2줄(구간 병합), 60줄 상한. swagger 주석 블록은 제거한다. 인가 관용구: `ctx.Doer`, `ctx.IsSigned`, `IsAdmin`, `IsOwner`, `IsPoster`, `Forbidden`, `Permission`, `.CanXxx(`, `access_model.`, `perm.Access`, `IsOrgMember`, `HasOrgOrUserVisible`, `unit.Type`, `Collaborator`, `IsPrivate`, `Visibility`, `OwnerID` 등.
- **R4**: `bind(...)` 옵션 바인더와 비인가 미들웨어(`mustEnable*`, `context.ReferencesGitRepo`)는 이름만 기록한다.
- **R5**: 헬퍼 함수로 등록되는 라우트(`addActionsRoutes`의 `act.*` 26개)는 파싱 범위 밖이라 레코드에서 제외하고 manifest의 `unmatched`에 남긴다. OAS에만 있고 api.go 파싱에 잡히지 않은 operation 82개도 이번 수집에서 제외한다(후속 보강 가능).
- **공통 헬퍼 부록**: `services/context/*.go`, `models/perm/access/repo_permission.go`의 `IsUserSiteAdmin/IsUserRepoAdmin/IsUserRepoWriter/CanRead/CanWrite/CanReadIssuesOrPulls/HasAnyUnitAccess` 정의를 `datasets/blade/processed/opensource/gitea_context_helpers.txt`에 한 번만 저장한다(라벨 입력에는 넣지 않고 검수 참고용).
- **입력 금지**: 테스트 코드, 사람 라벨, 검수 메모는 모델 입력에 넣지 않는다. ERD는 없음(erd_status=unknown).

## 결과 (v28.2.0)

| 항목 | 값 |
|---|---|
| 파싱된 라우트 | 481 |
| OAS operation | 537 |
| 매칭 레코드 | 455 (repo 259, user 76, org 50, admin 33, misc 14, packages 9, notify 7, settings 4, token 2, shared 1) |
| 미매칭 라우트 | 26 (전부 addActionsRoutes의 act.*) |
| 핸들러 미해결 | 0 |
| 라우트 미들웨어에 인증(reqToken 등) | 341 |
| 라우트 인가 미들웨어(reqAdmin/reqRepoReader/reqOrgOwnership 등) 보유 | 265 |
| 핸들러 내부 인가 관용구 1줄 이상 | 251 |

출력: `datasets/blade/processed/opensource/gitea_v28.2.0_endpoints.jsonl`(label=null, 라벨 전), `gitea_v28.2.0_manifest.json`. 10건 표본: `gitea_sample10.md`.

## 라벨링 계획 (승인 후)

gpt-4o-mini + 프롬프트 v3.0.1 + oas_code(미들웨어 정의 + 핸들러 발췌를 description에 포함) 455회. 결과는 `datasets/blade/processed/opensource/gitea_v28.2.0_labeled_v301.jsonl`(새 파일), 원시 응답은 git 미추적. 사람 검수 표본 label별 10건 → `training/data/review_sample_gitea.md`.
