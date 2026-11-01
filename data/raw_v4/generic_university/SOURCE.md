# Generic University (InsiderPhD) — test_v31_supp 추출 출처

- 저장소: https://github.com/InsiderPhD/Generic-University
- 브랜치: master (기본), 태그 없음
- 고정 커밋: `50dfa924b3a31d30c6d6c20373bc9f4dced8aac8` (2022-11-14, "fixed some stuff")
- 로컬 clone: `datasets/blade/raw/opensource/InsiderPhD_Generic-University/` (`--depth 1 --filter=blob:none`, git 추적 안 함)
- 라이선스: **없음 (NOASSERTION)**. 저장소에 LICENSE 파일이 없고 GitHub API `license: null`. 재배포·학습 사용 권리가 불분명하므로 **평가 전용**(test_v31_supp)으로만 쓰고 train에 넣지 않는다. 발췌 코드는 평가 레코드 안에만 둔다.
- 성격: OWASP API Top 10(2019) 데모용 의도적 취약 Laravel 7 앱. README가 취약점 목표(1~15)를 공개한다. 정적 분석만 수행(실행·의존성 설치 없음).

## 추출 범위

- `routes/api.php` (RouteServiceProvider가 `/api` prefix + `api` 미들웨어 그룹): `GET /api/user` 1건.
- `routes/web.php`의 `Route::group(['prefix'=>'api'])` 블록(33~45행, web 미들웨어 그룹·세션 인증): grades·users·classes·roles 리소스와 `api/admin` 하위(index, delete, restore, vulnerabilities 리소스). `Route::resource(..., except edit/create)`를 index/store/show/update(PUT·PATCH 각각)/destroy로 전개.
- GraphQL(rebing/graphql-laravel, `config/graphql.php` prefix `graphql`, 미들웨어 없음): `POST /graphql` 1건(GET도 같은 핸들러, 별도 후보 없음).
- 코드 발췌: 라우트 그룹 정의 + 컨트롤러(얇은 서브클래스) + `ApiController` 해당 메서드 + 관련 `AuthApiController` 트레이트(주석 처리된 의도 근거) + 모델 관계. OAS는 라우트에서 생성(`oas_status=generated`), 응답 필드는 마이그레이션 컬럼.

## 인증·인가 구조

- `auth` = `App\Http\Middleware\Authenticate`(세션, web guard), `auth:api` = token guard.
- grades 리소스와 `api/admin` 그룹만 `auth` 적용. users·classes·roles 리소스는 인증 없음.
- `App\Http\Middleware\Admin`(`role->name == "Admin"`)은 정의돼 있으나 커널에 등록되지 않았고 `admin` 웹 그룹(27행)에서 주석 처리, api/admin에는 미적용.
- `AdminController@delete`/`repopulate`만 핸들러에서 `Auth::user()->role_id == 1` 검사.
- `AuthApiController` + 트레이트 `authIndex/authStore/authShow/authUpdate/authDelete`(소유 필드 == `Auth::id()`)가 의도된 소유자 검사이나 UserController·GradeController에서 `//use authIndex;` 등으로 주석 처리돼 사용되지 않음.
- Policy/Gate 없음(AuthServiceProvider 비어 있음). 역할: 1=Admin, 2=Student(기본), 3=Teacher (RoleSeeder).
- 관계: Grade belongsTo User·UniClass, UniClass belongsToMany User(수강 피벗 `uni_class_user`)·teacher belongsTo User(user_id), User belongsTo Role.

## 제외

- `routes/web.php`의 HTML 페이지(`/`, `/home`, `/contact`, `/contact/submit`, `/vulnerability` GET/POST 제보 폼, `/admin`, `/admin/security` 뷰)와 `Auth::routes()`(login/register/password 폼): JSON API가 아님.
- `GET /graphql`: `POST /graphql`과 동일 핸들러(중복).

## 건수

- 후보 35건 (`candidates.jsonl`): role_required 21, owner_match 7, manual_review_required 7. membership_required·tenant_match·owner_or_admin 0(아래 참고).
- known_vulnerable true 28 / false 7.
- 라벨은 의도된 정책 기준 초안(draft)이며 사람 검수 전 확정 아님. 앱에 대상 그룹 구성원 검사·테넌트 개념이 코드·문서에 없어 membership_required/tenant_match는 만들지 않았다(수업 조회만 membership 가능성을 draft_reason에 기록하고 manual로 둠).
