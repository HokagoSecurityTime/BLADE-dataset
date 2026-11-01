"""data-v3 stage 1b: variant-label rule (user-confirmed 2026-10-26), more sources, petclinic cap, review sheet (no training, no API labelling).

Inputs: stage-1 pairs (datasets/blade/processed/data_v3_stage1/pairs_*_v3s1.jsonl, read only — reproducibility re-checked by re-running the
stage-1 builder into .cache/) + new repositories built with the stage-1 machinery (training/data/build_data_v3_pairs.py).
Variant rule: a check-removed variant is kept only when the intended policy is readable from path, method, schema and handler body;
otherwise the variant is dropped and the original kept. Variants are never relabelled to manual. Every original carries
meta.variant_kept / meta.variant_drop_reason / meta.variant_rule. Outputs: datasets/blade/processed/data_v3_stage1b/ (new), reports/data_v3/."""
import hashlib, json, random, re, sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from training.data import build_data_v3_pairs as s1
from scripts.data_v1_guard import assert_data_v1
from scripts.data_v2_guard import assert_data_v2

S1_DIR = ROOT / 'datasets/blade/processed/data_v3_stage1'
OUT_DIR = ROOT / 'datasets/blade/processed/data_v3_stage1b'
REP_DIR = ROOT / 'reports/data_v3'
REVIEWED = REP_DIR / 'review_pairs_v3s1_reviewed.xlsx'
REVIEWED_1B = REP_DIR / 'review_pairs_v3s1b_reviewed.xlsx'
LICENSE_FIX = {'rw_django': 'MIT'}   # stage-1 recorded 'see repository'; GitHub API 2026-10-26 says MIT (stage-1 builder left untouched for reproducibility)
EXCLUDED_REPOS = {'rw_axum': 'launchbadge/realworld-axum-sqlx (AGPL-3.0) — user decision 2026-10-26: excluded'}
SEED = 42
PETCLINIC_CAP = 24          # records (original + variant)
MIN_TRAIN_OOA = 10          # owner_or_admin records in train
S1_HASHES = {'pairs_train_v3s1.jsonl': 'fddf09bf1b046cea83a2227e98870831f0df58ad0ba3e6011a27cb6d83fb6418',
             'pairs_val_v3s1.jsonl': 'b3816655df0d01f6a9c2e248ffc443a48229644eca080b5ef02b1b98c4553265'}

# ---- variant rule (first match wins; a variant no rule covers stops the build) ----
RW_WRITE = re.compile(r'^(/api)?/articles/\{[^}]+\}(/comments/\{[^}]+\})?$')
VARIANT_RULES = [
    ('drop_owner_or_admin', lambda r: r['label'] == 'owner_or_admin', False,
     '소유자 부분은 경로로 보이지만 관리자 우회는 경로·스키마·본문으로 알 수 없음'),
    ('drop_check_in_sql', lambda r: r['meta'].get('variant_technical_drop') is not None, False,
     '검사가 SQL 문자열 안에 있어 줄 단위로 제거할 수 없음'),
    ('keep_realworld_article_comment_write', lambda r: r['service'].startswith('rw_') and r['method'] in ('PUT', 'PATCH', 'DELETE') and RW_WRITE.match(r['path']) and r['label'] == 'owner_match', True,
     'RealWorld 게시글·댓글 수정/삭제: 경로·메서드로 작성자 정책이 드러남'),
    ('keep_reference_data_write', lambda r: r['service'] == 'petclinic_rest' and re.match(r'^/(pettypes|specialties|vets)(/|$)', r['path']) and r['method'] in ('POST', 'PUT', 'DELETE'), True,
     '공용 기준 데이터(pettypes·specialties·vets) 생성/수정/삭제 = 관리 역할'),
    ('drop_reference_data_read', lambda r: r['service'] == 'petclinic_rest' and re.match(r'^/(pettypes|specialties|vets)(/|$)', r['path']) and r['method'] == 'GET', False,
     '기준 데이터 조회는 경로상 일반 조회로 보임'),
    ('drop_owner_pet_visit', lambda r: r['service'] == 'petclinic_rest' and re.match(r'^/(v2/)?(owners|pets|visits)(/|$)', r['path']), False,
     'owners·pets·visits는 소유자 관점(owner_match)으로 읽혀 직원 역할 의도를 알 수 없음'),
    ('keep_user_create_or_list', lambda r: (r['service'], r['method'], r['path']) in {('petclinic_rest', 'POST', '/users'), ('fastapi_tpl', 'POST', '/api/v1/users/'), ('fastapi_tpl', 'GET', '/api/v1/users/')}, True,
     '사용자 생성·전체 목록 = 관리자 기능(가입은 별도 엔드포인트)'),
    ('drop_user_by_id_write', lambda r: re.search(r'/users/\{[^}]+\}$', r['path']) and r['method'] in ('PATCH', 'PUT', 'DELETE'), False,
     '/users/{id} 수정·삭제는 본인 수정·탈퇴로도 읽힘'),
    ('keep_user_self_subresource', lambda r: r['label'] == 'owner_match' and r['meta'].get('rule_id') == 'self_only' and re.search(r'/users/\{[^}]+\}/', r['path']) is not None, True,
     '본인만(관리자 경로 없음) 쓰는 /users/{id} 하위 보안 자원(webhooks·토큰·연동 계정): 경로로 owner_match 의도가 드러남'),
    ('drop_user_subresource', lambda r: r['label'] == 'owner_or_admin' and re.search(r'/users/\{[^}]+\}/', r['path']) is not None, False,
     '/users/{id} 하위 자원의 관리자 우회(self_or_admin)는 경로로 알 수 없음'),
    ('drop_utility_endpoint', lambda r: r['service'] == 'fastapi_tpl' and re.search(r'/utils/|password-recovery-html-content', r['path']), False,
     '유틸 엔드포인트는 경로로 관리자 의도를 알 수 없음'),
]


def variant_decision(orig):
    for key, pred, keep, why in VARIANT_RULES:
        if pred(orig): return key, keep, why
    raise AssertionError(f"no variant rule covers {orig['service']} {orig['method']} {orig['path']} {orig['label']}")


# ---- new repositories (commit = clone HEAD on 2026-10-26; stars/license from the GitHub API that day) ----
NEW_REPOS = {
    'rw_nest': dict(repo='adr1enbe4udou1n/nestjs-realworld-example-app', dir='adr1enbe4udou1n_nestjs-realworld-example-app', commit='d4ddf3fd9ebd9112f117c0c6b2c5de3a76815c0c',
                    lang='typescript', framework='NestJS', license='none declared', stars=24, split='train', oas='generated',
                    why='RealWorld NestJS: first by stars with explicit owner checks (lujakob 3364, mikro-orm 344, mutoe 44, neo4j-examples 48: no check in update/delete)'),
    'rw_laravel': dict(repo='gothinkster/laravel-realworld-example-app', dir='gothinkster_laravel-realworld-example-app', commit='e45c37c8a5f57131c9d239f1fc104c227e66b6ee',
                       lang='php', framework='Laravel', license='MIT', stars=1200, split='train', oas='generated', why='RealWorld Laravel, most stars (FormRequest::authorize owner check)'),
    'rw_aspnet': dict(repo='realworld-apps/aspnetcore-realworld-example-app', dir='realworld-apps_aspnetcore-realworld-example-app', commit='8aa617abed5dd645f8f9d99578a3e07b4e2e52e7',
                      lang='csharp', framework='ASP.NET Core', license='MIT', stars=2094, split='val', oas='generated', why='RealWorld ASP.NET Core, most stars; val (C#)'),
    'rw_kotlin': dict(repo='gothinkster/kotlin-spring-realworld-example-app', dir='gothinkster_kotlin-spring-realworld-example-app', commit='848c29e3abfe1bd72001cc7d7a3227aebec96e9b',
                      lang='kotlin', framework='Spring Boot (Kotlin)', license='none declared', stars=476, split='train', oas='generated', why='RealWorld Kotlin Spring, most stars'),
    'rw_koa': dict(repo='gothinkster/koa-knex-realworld-example', dir='gothinkster_koa-knex-realworld-example', commit='602e234139c453825eb3939cf24bdf00fc164e0e',
                   lang='javascript', framework='Koa', license='none declared', stars=232, split='train', oas='generated', why='RealWorld Koa, most stars (comment delete has no check)'),
    'rw_fastify': dict(repo='avanelli/fastify-realworld-example-app', dir='avanelli_fastify-realworld-example-app', commit='bdb8ce4e130916a76970d8df1bf1a3291d0f5227',
                       lang='javascript', framework='Fastify', license='MIT', stars=25, split='val', oas='generated', why='RealWorld Fastify, most stars; val (JS)'),
    'rw_fastapi': dict(repo='nsidnev/fastapi-realworld-example-app', dir='nsidnev_fastapi-realworld-example-app', commit='029eb7781c60d5f563ee8990a0cbfb79b244538c',
                       lang='python', framework='FastAPI', license='MIT', stars=3100, split='train', oas='generated', why='RealWorld FastAPI, most stars (permission dependency)'),
    'memos': dict(repo='usememos/memos', dir='usememos_memos', commit='6387991fdd1d1ae491b8435708357fa334e19f3a', lang='go', framework='Connect/gRPC-gateway', license='MIT', stars=64084,
                  split='train', oas='repository_spec', oas_file='proto/gen/openapi.yaml', why='owner_or_admin source: "self or admin" checks on user resources, reaction "creator or admin"'),
    'kutt': dict(repo='thedevs-network/kutt', dir='thedevs-network_kutt', commit='029da42b2459693681886665589fd9512d6b473c', lang='javascript', framework='Express', license='MIT', stars=11172,
                 split='train', oas='generated', why='owner_or_admin source: link lookup scoped to the requester unless admin'),
}
NEW_RULES = {'owner_filter_unless_admin': ('owner_or_admin', 'lookup filtered by requester as owner unless the requester is admin'),
             'self_or_admin': ('owner_or_admin', 'requester must be the target user or an instance admin, else PermissionDenied'),
             'owner_or_instance_admin': ('owner_or_admin', 'requester must be the creator of the object or an instance admin, else PermissionDenied'),
             'self_only': ('owner_match', 'requester must be the target user (admin not allowed), else PermissionDenied'),
             'form_request_owner': ('owner_match', 'Laravel FormRequest::authorize compares the object owner with the requester; false -> 403')}
CHECK_RE_1B = re.compile(r'403|[Ff]orbidden|FORBIDDEN|author\.id !==|authorId !==|author\.id != |PersonId != |user_id != auth_user|user_id == auth\(\)|RoleAdmin|IsInstanceAdmin|'
                         r'authorizeUserResourceAccess|!req\.user\.admin|!user\.admin|_modification_permissions|check_user_can_modify|\.where\(\'author\', userid\)|\.where\(\{ author: userId \}\)|'
                         r'author\.username !== |PermissionDenied')
NS, NC = 'src/articles/articles.service.ts', 'src/articles/comments/comments.service.ts'
ASP = 'src/Conduit/Features/'
KT = 'src/main/kotlin/io/realworld/web/ArticleHandler.kt'
KOA = 'src/controllers/articles-controller.js'
FAR, FAM = 'lib/routes/articles/index.js', 'lib/models/articles.js'
NSI = 'app/api/routes/'
NSI_HELP = [('app/api/dependencies/articles.py', 'check_article_modification_permissions'), ('app/services/articles.py', 'check_user_can_modify_article')]
NSI_CHELP = [('app/api/dependencies/comments.py', 'check_comment_modification_permissions'), ('app/services/comments.py', 'check_user_can_modify_comment')]
MU = 'server/api/'
MU_HELP = [(MU + 'user_service_settings.go', 'authorizeUserResourceAccess')]
LV = 'app/Http/Requests/Api/'
NEW_HANDLERS = [
    # NestJS: controller method + service method (check in the service)
    dict(repo='rw_nest', file='src/articles/articles.controller.ts', symbol='update', service=(NS, 'update'), rule='owner_compare',
         route=('PUT', '/api/articles/{slug}', [('src/main.ts', r"setGlobalPrefix\('api'\)"), ('src/articles/articles.controller.ts', r"@Controller\('articles'\)"), ('src/articles/articles.controller.ts', r"@Put\(':slug'\)")]),
         ops=[dict(op='drop_stmt', match=r'if \(article\.author\.id !== currentUser\.id\)', target='service')]),
    dict(repo='rw_nest', file='src/articles/articles.controller.ts', symbol='delete', service=(NS, 'delete'), rule='owner_compare',
         route=('DELETE', '/api/articles/{slug}', [('src/main.ts', r"setGlobalPrefix\('api'\)"), ('src/articles/articles.controller.ts', r"@Delete\(':slug'\)")]),
         ops=[dict(op='drop_stmt', match=r'if \(article\.author\.id !== currentUser\.id\)', target='service')]),
    dict(repo='rw_nest', file='src/articles/comments/comments.controller.ts', symbol='delete', service=(NC, 'delete'), rule='owner_or_parent_owner',
         route=('DELETE', '/api/articles/{slug}/comments/{commentId}', [('src/articles/comments/comments.controller.ts', r"@Controller\('articles/:slug/comments'\)"), ('src/articles/comments/comments.controller.ts', r"@Delete\(':commentId'\)")]),
         ops=[dict(op='drop_stmt', match=r'^\s*article\.authorId !== currentUser\.id &&$', row_offset=-1, target='service')]),
    # Laravel: controller action + FormRequest::authorize (check); the variant's authorize no longer compares owners
    *[dict(repo='rw_laravel', file=f'app/Http/Controllers/Api/{c}.php', symbol=m, service=(LV + req + '.php', 'authorize'), service_called=False, rule='form_request_owner',
           route=(meth, path, [('app/Providers/RouteServiceProvider.php', r"Route::prefix\('api'\)"), ('routes/api.php', ev), ('app/Article.php', r"return 'slug';")]),
           ops=[dict(op='sub', match=r"\$(article|comment) = \$this->route\('(article|comment)'\);\n\n        return \$(article|comment)->user_id == auth\(\)->id\(\);", repl='return true;', count=1, target='service')])
      for c, m, req, meth, path, ev in [('ArticleController', 'update', 'UpdateArticle', 'PUT', '/api/articles/{article}', r"Route::resource\('articles', 'ArticleController'"),
                                       ('ArticleController', 'destroy', 'DeleteArticle', 'DELETE', '/api/articles/{article}', r"Route::resource\('articles', 'ArticleController'"),
                                       ('CommentController', 'destroy', 'DeleteComment', 'DELETE', '/api/articles/{article}/comments/{comment}', r"Route::resource\('articles/\{article\}/comments', 'CommentController'")]],
    # ASP.NET Core: controller action (MediatR) + command handler (check)
    dict(repo='rw_aspnet', file=ASP + 'Articles/ArticlesController.cs', symbol='Edit', service=(ASP + 'Articles/Edit.cs', 'Handle'), service_called=False, rule='owner_compare',
         route=('PUT', '/api/articles/{slug}', [('src/Conduit/Program.cs', r'ApiRoutePrefixConvention\(builder\.Configuration\["ApiPrefix"\] \?\? "api"\)'), (ASP + 'Articles/ArticlesController.cs', r'\[Route\("articles"\)\]'), (ASP + 'Articles/ArticlesController.cs', r'\[HttpPut\("\{slug\}"\)\]')]),
         ops=[dict(op='drop_stmt', match=r'if \(article\.Author\?\.PersonId != currentUserAccessor\.GetCurrentPersonId\(\)\)', target='service')]),
    dict(repo='rw_aspnet', file=ASP + 'Articles/ArticlesController.cs', symbol='Delete', service=(ASP + 'Articles/Delete.cs', 'Handle'), service_called=False, rule='owner_compare',
         route=('DELETE', '/api/articles/{slug}', [(ASP + 'Articles/ArticlesController.cs', r'\[HttpDelete\("\{slug\}"\)\]')]),
         ops=[dict(op='drop_stmt', match=r'if \(article\.Author\?\.PersonId != currentUserAccessor\.GetCurrentPersonId\(\)\)', target='service')]),
    dict(repo='rw_aspnet', file=ASP + 'Comments/CommentsController.cs', symbol='Delete', service=(ASP + 'Comments/Delete.cs', 'Handle'), service_called=False, rule='owner_compare',
         route=('DELETE', '/api/articles/{slug}/comments/{id}', [(ASP + 'Comments/CommentsController.cs', r'\[HttpDelete\("\{slug\}/comments/\{id\}"\)\]')]),
         ops=[dict(op='drop_stmt', match=r'if \(comment\.Author\?\.PersonId != currentUserAccessor\.GetCurrentPersonId\(\)\)', target='service')]),
    # Kotlin Spring
    dict(repo='rw_kotlin', file=KT, symbol='updateArticle', rule='owner_compare', route=('PUT', '/api/articles/{slug}', [(KT, r'@PutMapping\("/api/articles/\{slug\}"\)')]),
         ops=[dict(op='drop_stmt', match=r'if \(it\.author\.id != currentUser\.id\)')]),
    dict(repo='rw_kotlin', file=KT, symbol='deleteArticle', rule='owner_compare', route=('DELETE', '/api/articles/{slug}', [(KT, r'@DeleteMapping\("/api/articles/\{slug\}"\)')]),
         ops=[dict(op='drop_stmt', match=r'if \(it\.author\.id != userService\.currentUser\(\)\.id\)')]),
    dict(repo='rw_kotlin', file=KT, symbol='deleteComment', rule='owner_compare', route=('DELETE', '/api/articles/{slug}/comments/{id}', [(KT, r'@DeleteMapping\("/api/articles/\{slug\}/comments/\{id\}"\)')]),
         ops=[dict(op='drop_stmt', match=r'if \(comment\.author\.id != currentUser\.id\)')], allow_residual=r'^\s*throw ForbiddenRequestException\(\)$'),   # comment-belongs-to-article integrity check stays
    # Koa: top-level controller methods (the same names exist in nested objects)
    *[dict(repo='rw_koa', file=KOA, symbol=m, anchor=r'^  async ' + m + r'\(ctx\)', rule='owner_compare',
           route=(meth, '/api/articles/{slug}', [('src/routes/index.js', r'router\.use\("/api", api\.routes\(\)\)'), ('src/routes/articles-router.js', r'router\.' + m + r'\("/articles/:slug", auth, ctrl\.' + m + r'\)')]),
           ops=[dict(op='drop_stmt', match=r'^\s*article\.author\.id === ctx\.state\.user\.id,$', row_offset=-1)]) for m, meth in (('put', 'PUT'), ('del', 'DELETE'))],
    # Fastify: route handler + model function (owner filter in the query)
    dict(repo='rw_fastify', file=FAR, symbol='onUpdateArticle', service=(FAM, 'updateArticle'), rule='owner_filter',
         route=('PUT', '/api/articles/{slug}', [('.env.sample', r'^API_PREFIX=/api$'), (FAR, r"method: 'PUT',\n    path: options\.prefix \+ 'articles/:slug',\n    onRequest: \[server\.authenticate\],\n    schema: schema\.update,\n    handler: onUpdateArticle")]),
         ops=[dict(op='drop_lines', match=r"^\s*\.where\('author', userid\)$", count=1, target='service')]),
    dict(repo='rw_fastify', file=FAR, symbol='onDeleteArticle', service=(FAM, 'deleteArticle'), rule='owner_filter',
         route=('DELETE', '/api/articles/{slug}', [(FAR, r"method: 'DELETE',\n    path: options\.prefix \+ 'articles/:slug',\n    onRequest: \[server\.authenticate\],\n    schema: schema\.remove,\n    handler: onDeleteArticle")]),
         ops=[dict(op='drop_lines', match=r"^\s*\.where\('author', userid\)$", count=1, target='service')]),
    dict(repo='rw_fastify', file='lib/routes/comments/index.js', symbol='onDeleteComment', service=('lib/models/comments.js', 'deleteComment'), rule='owner_compare',
         route=('DELETE', '/api/articles/{slug}/comments/{id}', [('lib/routes/comments/index.js', r"method: 'DELETE',\n    path: options\.prefix \+ 'articles/:slug/comments/:id',\n    onRequest: \[server\.authenticate\]")]),
         ops=[dict(op='drop_lines', match=r"^\s*if \(comment\.author\.username !== req\.user\.username\) throw createError\(403", count=1),
              dict(op='drop_lines', match=r"^\s*\.where\(\{ author: userId \}\)$", count=2, target='service')]),
    # FastAPI (nsidnev): permission dependency on the route
    *[dict(repo='rw_fastapi', file=NSI + f, symbol=sym, helpers=hp, rule='owner_compare',
           route=(meth, path, [('app/core/settings/app.py', r'api_prefix: str = "/api"'), *ev]),
           ops=[dict(op='drop_lines', match=r'^\s*dependencies=\[Depends\(check_(article|comment)_modification_permissions\)\],\s*$', count=1)])
      for f, sym, hp, meth, path, ev in [
          ('articles/articles_resource.py', 'update_article_by_slug', NSI_HELP, 'PUT', '/api/articles/{slug}', [(NSI + 'articles/api.py', r'include_router\(articles_resource\.router, prefix="/articles"\)'), (NSI + 'articles/articles_resource.py', r'@router\.put\(\n    "/\{slug\}"')]),
          ('articles/articles_resource.py', 'delete_article_by_slug', NSI_HELP, 'DELETE', '/api/articles/{slug}', [(NSI + 'articles/articles_resource.py', r'@router\.delete\(\n    "/\{slug\}"')]),
          ('comments.py', 'delete_comment_from_article', NSI_CHELP, 'DELETE', '/api/articles/{slug}/comments/{comment_id}', [(NSI + 'api.py', r'prefix="/articles/\{slug\}/comments"'), (NSI + 'comments.py', r'@router\.delete\(\n    "/\{comment_id\}"')])]],
    # memos: Connect handlers; route = openapi.yaml operationId. owner_or_admin variants are dropped by rule; self_only variants drop the self check
    *[dict(repo='memos', file=MU + f, symbol=sym, op_id=op, rule=rule, helpers=MU_HELP if helper else [],
           ops=[] if rule != 'self_only' else [dict(op='drop_stmt', match=r'if _, err := s\.authorizeUserResourceAccess\(ctx, userID, false\); err != nil \{' if helper
                                                    else r'if currentUser\.ID != (userID|user\.ID) \{')])
      for f, sym, op, rule, helper in [
        ('user_service.go', 'UpdateUser', 'UserService_UpdateUser', 'self_or_admin', False),
        ('user_service.go', 'DeleteUser', 'UserService_DeleteUser', 'self_or_admin', False),
        ('user_service_usage.go', 'GetUserUsage', 'UserService_GetUserUsage', 'self_or_admin', False),
        ('reaction_service.go', 'DeleteMemoReaction', 'MemoService_DeleteMemoReaction', 'owner_or_instance_admin', False),
        ('user_service_access_tokens.go', 'ListPersonalAccessTokens', 'UserService_ListPersonalAccessTokens', 'self_or_admin', True),
        ('user_service_identities.go', 'ListLinkedIdentities', 'UserService_ListLinkedIdentities', 'self_or_admin', True),
        ('user_service_identities.go', 'GetLinkedIdentity', 'UserService_GetLinkedIdentity', 'self_or_admin', True),
        ('user_service_identities.go', 'DeleteLinkedIdentity', 'UserService_DeleteLinkedIdentity', 'self_or_admin', True),
        ('user_service_access_tokens.go', 'CreatePersonalAccessToken', 'UserService_CreatePersonalAccessToken', 'self_only', True),
        ('user_service_access_tokens.go', 'DeletePersonalAccessToken', 'UserService_DeletePersonalAccessToken', 'self_only', True),
        ('user_service_webhooks.go', 'GetUserWebhookSigningSecret', 'UserService_GetUserWebhookSigningSecret', 'self_only', True),
        ('user_service_identities.go', 'CreateLinkedIdentity', 'UserService_CreateLinkedIdentity', 'self_only', False),
        *[('user_service_webhooks.go', m, 'UserService_' + m, 'self_only', False) for m in ('ListUserWebhooks', 'CreateUserWebhook', 'UpdateUserWebhook', 'DeleteUserWebhook')]]],
    # kutt: link handlers; variants dropped by rule (owner_or_admin)
    *[dict(repo='kutt', file='server/handlers/links.handler.js', symbol=sym, anchor=r'^async function ' + sym + r'\(', rule='owner_filter_unless_admin', ops=[],
           route=(meth, '/api/links' + p, [('server/server.js', r'app\.use\("/api", routes\.api\)'), ('server/routes/routes.js', r'apiRouter\.use\("/links", link\)'),
                                           ('server/routes/link.routes.js', r'router\.' + meth.lower() + r'\(\n  "' + re.escape(p) + r'",[\s\S]{0,200}?asyncHandler\(auth\.jwt\),[\s\S]{0,120}?asyncHandler\(link\.' + sym + r'\)')]))
      for sym, meth, p in (('edit', 'PATCH', '/:id'), ('remove', 'DELETE', '/:id'), ('stats', 'GET', '/:id/stats'))],
]
SCAN_1B = {'rw_nest': ['src/articles/articles.controller.ts', NS, 'src/articles/comments/comments.controller.ts', NC],
           'rw_laravel': ['app/Http/Controllers/Api/ArticleController.php', 'app/Http/Controllers/Api/CommentController.php', LV + 'UpdateArticle.php', LV + 'DeleteArticle.php', LV + 'DeleteComment.php'],
           'rw_aspnet': [ASP + 'Articles/ArticlesController.cs', ASP + 'Articles/Edit.cs', ASP + 'Articles/Delete.cs', ASP + 'Comments/CommentsController.cs', ASP + 'Comments/Delete.cs'],
           'rw_kotlin': [KT], 'rw_koa': [KOA, 'src/routes/articles-router.js'], 'rw_fastify': [FAR, FAM, 'lib/routes/comments/index.js', 'lib/models/comments.js'],
           'rw_fastapi': [NSI + 'articles/articles_resource.py', NSI + 'comments.py', 'app/api/dependencies/articles.py', 'app/api/dependencies/comments.py'],
           'memos': [MU + f for f in ('user_service.go', 'user_service_usage.go', 'reaction_service.go', 'user_service_access_tokens.go', 'user_service_identities.go', 'user_service_webhooks.go')],
           'kutt': ['server/handlers/links.handler.js']}
EXCLUDE_1B = [
    ('rw_nest', NC, r"article\.id !== comment\.articleId", 'comment-belongs-to-article integrity check, not authorization'),
    ('rw_fastapi', None, r'^from |^\s+check_(article|comment)_modification_permissions,$|^\s+check_user_can_modify_(article|comment),$|^import ', 'import line'),
    ('rw_aspnet', None, r'^using ', 'using line'),
    ('rw_kotlin', KT, r'^import ', 'import line'),
    ('memos', MU + 'user_service.go', r'.', 'other user_service handlers (admin-only create/list/role change, self-delete flags): not selected in this stage'),
    ('memos', MU + 'user_service_access_tokens.go', r'authorizeUserResourceAccess\(ctx, userID, (true|false)\)|PermissionDenied', 'helper call / denial inside an adopted handler span is counted there; outside spans none'),
    ('memos', None, r'^import |^\s+"google\.golang\.org/grpc/codes"$', 'import line'),
    ('memos', MU + 'reaction_service.go', r'ErrReactionPermissionDenied|codes\.PermissionDenied, "permission denied"\)$', 'mapReactionMutationError: store error -> status mapping, not a check'),
    ('kutt', 'server/handlers/links.handler.js', r'.', 'other link handlers (admin table, ban, report, create): not selected in this stage'),
]


def sha(b): return hashlib.sha256(b).hexdigest()
def jl(p): return [json.loads(l) for l in p.read_text(encoding='utf-8').splitlines() if l.strip()]


def stage1_reproducible():
    """Re-run the (extended) stage-1 builder into .cache/ and require byte-identical pair files."""
    tmp = ROOT / '.cache/v3s1_repro'; out, rep = s1.OUT_DIR, s1.REP_DIR
    s1.OUT_DIR, s1.REP_DIR = tmp / 'processed', tmp / 'reports'
    try: s1.build()
    finally: s1.OUT_DIR, s1.REP_DIR = out, rep
    got = {n: sha((tmp / 'processed' / n).read_bytes()) for n in S1_HASHES}
    assert got == S1_HASHES, ('stage-1 builder no longer reproduces v3s1', got)
    assert {n: sha((S1_DIR / n).read_bytes()) for n in S1_HASHES} == S1_HASHES, 'stage-1 outputs changed'
    return got


def verify_route(repo, evidence):
    for f, rx in evidence:
        assert re.search(rx, s1.read_text(s1.OS_DIR / s1.REPOS[repo]['dir'] / f), re.M), (repo, f, rx)
    return ' + '.join(f for f, _ in evidence)


def build_new(memos_spec):
    """Build originals (and variants where the rule keeps them) for NEW_HANDLERS with the stage-1 machinery."""
    s1.REPOS.update(NEW_REPOS); s1.RULES.update(NEW_RULES)
    ops = {o['operationId']: (m.upper(), p) for p, d in memos_spec['paths'].items() for m, o in d.items() if isinstance(o, dict) and 'operationId' in o}
    records, pairs, excluded, adopted, files_used = [], [], [], defaultdict(set), {}
    for h in NEW_HANDLERS:
        repo, R = h['repo'], s1.REPOS[h['repo']]
        src = s1.Src(repo, h['file']); files_used[(repo, h['file'])] = sha(src.raw)
        s, e = s1.find_def(src, h['symbol'], h.get('anchor'))
        label, rule_text = s1.RULES[h['rule']]
        if 'op_id' in h:
            meth, path = ops[h['op_id']]; route_ev = f"{R['oas_file']} operationId {h['op_id']} -> {meth} {path}; handler {h['file']}:{h['symbol']}"
        else:
            meth, path, ev = h['route']; path = s1.to_oas_path(path); route_ev = verify_route(repo, ev)
        probe = dict(service=repo, method=meth, path=path, label=label, meta=dict(variant_technical_drop=h.get('technical_drop'), rule_id=h['rule']))
        vrule, keep, vwhy = variant_decision(probe)
        parts, var_parts, locs, var_locs, removed, mod_text = [], [], [], [], [], {}
        for f, sym in h.get('helpers', []):
            hs = s1.Src(repo, f); files_used[(repo, f)] = sha(hs.raw); a, b = s1.find_def(hs, sym)
            parts.append(s1.excerpt(hs.text, (a, b))); locs.append(dict(file=f, start_line=a + 1, end_line=b + 1)); adopted[(repo, f)] |= set(range(a, b + 1))
        targets = {'handler': (src, (s, e))}
        if 'service' in h:
            ss = s1.Src(repo, h['service'][0]); files_used[(repo, ss.rel)] = sha(ss.raw); targets['service'] = (ss, s1.find_def(ss, h['service'][1]))
            if h.get('service_called', True):
                assert re.search(r'\b' + h['service'][1] + r'\(', s1.excerpt(src.text, (s, e))), (repo, h['symbol'], 'handler does not call the service')
        for t in (['service', 'handler'] if 'service' in h else ['handler']):
            tsrc, span = targets[t]; adopted[(repo, tsrc.rel)] |= set(range(span[0], span[1] + 1))
            parts.append(s1.excerpt(tsrc.text, span)); locs.append(dict(file=tsrc.rel, start_line=span[0] + 1, end_line=span[1] + 1))
            t_ops = [o for o in h['ops'] if o.get('target', 'handler') == t] if keep else []
            new_text, new_span = s1.apply_ops(tsrc, tsrc.text, span, t_ops, removed) if t_ops else (tsrc.text, span)
            mod_text[t] = (tsrc, new_text)
            var_parts.append(s1.excerpt(new_text, new_span)); var_locs.append(dict(file=tsrc.rel, start_line=new_span[0] + 1, end_line=new_span[1] + 1, modified=bool(t_ops)))
        orig_ct, var_ct = '\n\n'.join(parts), '\n\n'.join(var_parts)
        key = f'{repo}:{meth}:{path}'; checks = []
        if keep:
            for t, (tsrc, new_text) in mod_text.items():
                if new_text == tsrc.text: continue
                o0, _ = s1.syntax_ok(tsrc.lang, tsrc.text); o1, how = s1.syntax_ok(tsrc.lang, new_text)
                checks.append(dict(file=tsrc.rel, original_ok=o0, variant_ok=o1, method=how))
            residual = [l for l in var_ct.split('\n') if CHECK_RE_1B.search(l) and not (h.get('allow_residual') and re.search(h['allow_residual'], l))]
            reason = ('no change' if orig_ct == var_ct else f'syntax check failed: {checks}' if not checks or not all(c['original_ok'] and c['variant_ok'] for c in checks)
                      else f'check lines remain in variant: {residual}' if residual else None)
            if reason:
                excluded.append(dict(key=key, repo=repo, reason=reason)); continue
        if R['oas'] == 'repository_spec':
            spec = s1.spec_slice(memos_spec, path, meth); oas_status, oas_file = 'repository_spec', R['oas_file']
        else:
            spec = s1.minimal_oas(repo, meth, path, h.get('symbol')); oas_status, oas_file = 'generated_minimal', None
        pair_id = 'v3s1b-' + sha(key.encode())[:12]
        base = dict(source='opensource', service=repo, method=meth, path=path, label=label, oas_snippet=json.dumps(spec, ensure_ascii=False), erd_snippet='', security_state=s1.security_state(spec, meth, path))
        common = dict(source='opensource', project=R['repo'], repository=f"https://github.com/{R['repo']}", commit=R['commit'], license=R['license'], language=R['lang'], framework=R['framework'],
                      oas_status=oas_status, oas_file=oas_file, route_evidence=route_ev, erd_status='unknown', controller_status='available', data_version='data-v3-stage1b', split=R['split'],
                      pair_id=pair_id, label_source='rule_from_check_lines', rule_id=h['rule'], rule=rule_text, human_confirmed=False, check_lines=removed, syntax_check=checks,
                      variant_rule=vrule, variant_kept=keep, variant_drop_reason=None if keep else vwhy + (f" ({h['technical_drop']})" if h.get('technical_drop') else ''))
        records.append(dict(id=f'{pair_id}-orig', **base, controller_text=orig_ct, meta=dict(**common, pair_role='check_kept', variant_of=None, source_locations=locs)))
        if keep:
            records.append(dict(id=f'{pair_id}-var', **base, controller_text=var_ct, meta=dict(**common, pair_role='check_removed', variant_of=f'{pair_id}-orig', source_locations=var_locs)))
        pairs.append(dict(pair_id=pair_id, key=key, repo=repo, lang=R['lang'], label=label, rule=h['rule'], split=R['split'], method=meth, path=path, orig=orig_ct,
                          var=var_ct if keep else None, removed=removed, variant_kept=keep, variant_rule=vrule, variant_drop_reason=common['variant_drop_reason']))
    # detection completeness on the new repositories
    detect = dict(hits=0, adopted=0, excluded=0, unexplained=[])
    for repo, files in SCAN_1B.items():
        for rel in files:
            for i, line in enumerate(s1.read_text(s1.OS_DIR / s1.REPOS[repo]['dir'] / rel).split('\n')):
                if not CHECK_RE_1B.search(line): continue
                detect['hits'] += 1
                if i in adopted[(repo, rel)]: detect['adopted'] += 1
                elif any(r == repo and (f is None or f == rel) and re.search(rx, line) for r, f, rx, _ in EXCLUDE_1B): detect['excluded'] += 1
                else: detect['unexplained'].append(f'{repo}:{rel}:{i + 1}: {line.strip()}')
    assert not detect['unexplained'], detect['unexplained']
    return records, pairs, excluded, detect, files_used


def restage_s1(rows):
    """Stage-1 records -> 1b: variant rule, petclinic cap, data_version. Stage-1 files are not touched."""
    by = defaultdict(dict)
    for r in rows: by[r['meta']['pair_id']][r['meta']['pair_role']] = r
    out, pairs, drops = [], [], Counter()
    for pid in sorted(by):
        o, v = by[pid]['check_kept'], by[pid]['check_removed']
        vrule, keep, vwhy = variant_decision(o)
        o, v = json.loads(json.dumps(o)), json.loads(json.dumps(v))
        for r in (o, v): r['meta'].update(data_version='data-v3-stage1b', variant_rule=vrule, variant_kept=keep, variant_drop_reason=None if keep else vwhy, license=s1.REPOS[o['service']]['license'])
        out.append(o)
        if keep: out.append(v)
        else: drops[vrule] += 1
        pairs.append(dict(pair_id=pid, key=f"{o['service']}:{o['method']}:{o['path']}", repo=o['service'], lang=o['meta']['language'], label=o['label'], rule=o['meta']['rule_id'],
                          split=o['meta']['split'], method=o['method'], path=o['path'], orig=o['controller_text'], var=v['controller_text'] if keep else None,
                          removed=o['meta']['check_lines'], variant_kept=keep, variant_rule=vrule, variant_drop_reason=o['meta']['variant_drop_reason']))
    # petclinic cap: all kept-variant pairs first, then originals (seed 42) up to PETCLINIC_CAP records
    pet = [p for p in pairs if p['repo'] == 'petclinic_rest']; kept = [p for p in pet if p['variant_kept']]; rest = [p for p in pet if not p['variant_kept']]
    assert 2 * len(kept) <= PETCLINIC_CAP, len(kept)
    random.Random(SEED).shuffle(rest); chosen = {p['pair_id'] for p in kept} | {p['pair_id'] for p in rest[:PETCLINIC_CAP - 2 * len(kept)]}
    capped = [p['pair_id'] for p in pet if p['pair_id'] not in chosen]
    out = [r for r in out if not (r['service'] == 'petclinic_rest' and r['meta']['pair_id'] not in chosen)]
    pairs = [p for p in pairs if p['pair_id'] not in capped]
    return out, pairs, drops, sorted(capped)


def reviewed_ids():
    from openpyxl import load_workbook
    ws = load_workbook(REVIEWED, read_only=True)['review_pairs']; rows = list(ws.iter_rows(values_only=True)); ix = rows[0].index('pair_id')
    return {r[ix] for r in rows[1:] if r[ix]}


def review_sheet(pairs, done):
    """40 pairs not reviewed before: balanced over (language, label), one per stratum per round, seed 42 inside each stratum."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font
    rng = random.Random(SEED); strata = defaultdict(list)
    for p in sorted(pairs, key=lambda x: x['pair_id']):
        if p['pair_id'] not in done: strata[(p['lang'], p['label'])].append(p)
    for v in strata.values(): rng.shuffle(v)
    pick, k, total = [], 0, sum(len(v) for v in strata.values())
    while len(pick) < min(40, total):
        for s in sorted(strata):
            if k < len(strata[s]) and len(pick) < 40: pick.append(strata[s][k])
        k += 1
    wb = Workbook(); ws = wb.active; ws.title = 'review_pairs'
    cols = ['pair_id', 'split', 'repo', 'language', 'method', 'path', 'label', 'rule_id', 'variant_kept', 'variant_rule', 'variant_drop_reason', 'removed_check_lines',
            'original_controller_text', 'variant_controller_text', 'label_correct (Y/N)', 'variant_removes_whole_check (Y/N)', 'variant_otherwise_identical (Y/N)',
            'variant_label_inferable_from_path_schema (Y/N)', 'corrected_label', 'note', 'reviewer']
    ws.append(cols)
    for p in pick:
        ws.append([p['pair_id'], p['split'], p['repo'], p['lang'], p['method'], p['path'], p['label'], p['rule'], 'Y' if p['variant_kept'] else 'N', p['variant_rule'], p['variant_drop_reason'] or '',
                   '\n'.join(f"{x['file']}:{x['line']}  {x['text']}" for x in p['removed']), p['orig'], p['var'] or '(변형 제외)', '', '', '', '', '', '', ''])
    for c in ws[1]: c.font = Font(bold=True)
    for row in ws.iter_rows(min_row=2):
        for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    for i, w in enumerate([18, 7, 14, 10, 8, 34, 16, 22, 8, 26, 30, 50, 70, 70, 12, 14, 14, 16, 16, 30, 12]): ws.column_dimensions[chr(65 + i)].width = w
    ws.freeze_panes = 'B2'
    g = wb.create_sheet('guide')
    for line in ['data-v3 1b 검수 시트 — 1단계에서 검수한 40쌍을 뺀 나머지에서 (언어, label) 층별 균형 추출(seed 42). reviewer 열은 비워 두었다.',
                 'label_correct: 원본(검사 유지) 코드의 검사 내용이 label과 맞는가. 아니면 corrected_label에 7종 중 하나.',
                 'variant_kept=N인 쌍은 변형이 규칙상 제외된 것이다. 변형 열 3개는 비워 두고, 규칙(variant_rule)이 맞는지만 note에 적는다.',
                 'variant_label_inferable_from_path_schema: 변형(검사 없음)만 보고 경로·메서드·스키마·핸들러 본문으로 그 label을 읽어낼 수 있는가. N이면 변형 제외(manual로 바꾸지 않음).',
                 '검수 결과를 학습·프롬프트 예시에 쓰려면 별도 승인이 필요하다(AGENTS.md).']:
        g.append([line])
    g.column_dimensions['A'].width = 140
    path = REP_DIR / 'review_pairs_v3s1b.xlsx'; wb.save(path)
    return dict(path=path.relative_to(ROOT).as_posix(), pairs=len(pick), by_stratum=dict(Counter(f"{p['lang']}/{p['label']}" for p in pick)),
                new_source_pairs=sum(p['repo'] in NEW_REPOS for p in pick))


def build():
    guards = dict(start_v1=assert_data_v1('start'), start_v2=assert_data_v2('start'))
    s1_rows = jl(S1_DIR / 'pairs_train_v3s1.jsonl') + jl(S1_DIR / 'pairs_val_v3s1.jsonl')
    repro = stage1_reproducible()
    for k, lic in LICENSE_FIX.items(): s1.REPOS[k]['license'] = lic
    test = jl(ROOT / 'datasets/blade/processed/test_v30.jsonl'); test_services = {r['service'] for r in test}
    assert not ({k for k in NEW_REPOS} | {v['repo'].split('/')[1] for v in NEW_REPOS.values()}) & test_services
    memos_spec = s1.yaml.safe_load(s1.read_text(s1.OS_DIR / NEW_REPOS['memos']['dir'] / NEW_REPOS['memos']['oas_file']))
    s1_out, s1_pairs, s1_drops, capped = restage_s1(s1_rows)
    new_out, new_pairs, new_excl, detect, files_used = build_new(memos_spec)
    records, pairs = s1_out + new_out, s1_pairs + new_pairs
    test_ct = [r.get('controller_text') or '' for r in test]
    assert not [r['id'] for r in records if any(len(r['controller_text']) > 80 and r['controller_text'] in t for t in test_ct)]
    ntr_ooa = sum(r['label'] == 'owner_or_admin' and r['meta']['split'] == 'train' for r in records)
    assert ntr_ooa >= MIN_TRAIN_OOA, ntr_ooa
    assert sum(r['service'] == 'petclinic_rest' for r in records) <= PETCLINIC_CAP
    OUT_DIR.mkdir(parents=True, exist_ok=True); outs = {}
    for split in ('train', 'val'):
        p = OUT_DIR / f'pairs_{split}_v3s1b.jsonl'
        p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records if r['meta']['split'] == split), encoding='utf-8', newline='\n')
        outs[p.relative_to(ROOT).as_posix()] = dict(records=sum(r['meta']['split'] == split for r in records), sha256=sha(p.read_bytes()))
    if REVIEWED_1B.exists():   # the 1b sheet was reviewed: keep it as issued and report from the reviewed copy
        from openpyxl import load_workbook
        rows = list(load_workbook(REVIEWED_1B, read_only=True)['review_pairs'].iter_rows(values_only=True)); hdr = rows[0]
        got = [dict(zip(hdr, r)) for r in rows[1:]]
        review = dict(path=REVIEWED_1B.relative_to(ROOT).as_posix(), pairs=len(got), by_stratum=dict(Counter(f"{g['language']}/{g['label']}" for g in got)),
                      new_source_pairs=sum(g['repo'] in NEW_REPOS or g['repo'] in EXCLUDED_REPOS for g in got))
    else:
        review = review_sheet(pairs, reviewed_ids())
    manifest = dict(data_version='data-v3-stage1b', built_by='training/data/build_data_v3_pairs_1b.py', seed=SEED, frozen=False, stage1_inputs=S1_HASHES, stage1_reproduced=repro,
                    variant_rules=[dict(rule=k, keep=keep, reason=why) for k, _, keep, why in VARIANT_RULES], petclinic_cap=PETCLINIC_CAP, petclinic_capped_pairs=capped,
                    new_repositories={k: {kk: vv for kk, vv in v.items() if kk != 'dir'} | dict(clone_dir=f"datasets/blade/raw/opensource/{v['dir']}") for k, v in NEW_REPOS.items()},
                    new_source_files=[dict(repo=r, file=f, sha256=h) for (r, f), h in sorted(files_used.items())], outputs=outs,
                    detection_new=dict((k, v) for k, v in detect.items() if k != 'unexplained'), excluded_new=new_excl,
                    exclusion_rules_new=[dict(repo=r, file=f, pattern=rx, reason=why) for r, f, rx, why in EXCLUDE_1B])
    (OUT_DIR / 'manifest_v3s1b.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + '\n', encoding='utf-8', newline='\n')
    guards.update(end_v1=assert_data_v1('end'), end_v2=assert_data_v2('end'))
    report(records, pairs, s1_drops, capped, new_excl, detect, manifest, review, guards)
    return records, pairs


def report(records, pairs, s1_drops, capped, new_excl, detect, manifest, review, guards):
    allrepos = {**{k: v for k, v in s1.REPOS.items() if k not in NEW_REPOS}, **NEW_REPOS}
    tr = lambda pred: sum(1 for r in records if pred(r) and r['meta']['split'] == 'train'); va = lambda pred: sum(1 for r in records if pred(r) and r['meta']['split'] == 'val')
    t = ['# data-v3 1b단계 — 변형 label 규칙 적용, 출처 보강, petclinic 상한, 1b 검수 반영 (학습·API 라벨링 없음)\n',
         f"빌더 `training/data/build_data_v3_pairs_1b.py`, seed {SEED}. 1단계 산출물(`pairs_*_v3s1.jsonl`)은 그대로이며, 확장한 1단계 빌더를 `.cache/`에 다시 돌려 바이트 동일함을 확인했다. "
         f"쌍 {len(pairs)}개, 레코드 {len(records)}건(원본 {len(pairs)} + 유지 변형 {sum(p['variant_kept'] for p in pairs)}). 사람 확정 전, 동결 안 함.\n",
         '## 변형 규칙 (사용자 확정, 첫 일치 규칙 적용)\n', '| 규칙 | 변형 | 사유 | 1단계 쌍(petclinic 상한 후) | 새 쌍 |', '|---|---|---|---:|---:|']
    for k, _, keep, why in VARIANT_RULES:
        t.append(f"| {k} | {'유지' if keep else '제외'} | {why} | {sum(p['variant_rule'] == k for p in pairs if p['repo'] not in NEW_REPOS)} | {sum(p['variant_rule'] == k for p in pairs if p['repo'] in NEW_REPOS)} |")
    t += ['', '변형을 manual로 바꾸지 않았다. 규칙이 없는 변형은 빌더가 중단한다. 1단계 검수 40건과 1b 검수 시트(rw_axum 제외 후 38건)의 `variant_label_inferable_from_path_schema` 판정이 규칙 결과와 모두 일치해야 빌드가 통과한다(아래 일치표). 1b 검수 반영: memos self_only 8쌍(본인만, 관리자 경로 없음)의 /users/{id} 하위 자원 변형을 `keep_user_self_subresource`로 생성·유지하고, `drop_user_subresource`는 owner_or_admin에만 적용한다.', '',
          f"petclinic 상한 {PETCLINIC_CAP}건: 변형 유지 쌍(기준 데이터 쓰기 9 + 사용자 생성 1) 20건 + 원본만 {PETCLINIC_CAP - 20}건(seed 42). 상한으로 뺀 쌍 {len(capped)}개는 manifest에 기록.", '',
          '## 저장소\n', '| key | 저장소 | 커밋 | 언어 | 스타 | 라이선스 | split | 쌍 | 레코드 | 변형 유지 |', '|---|---|---|---|---:|---|---|---:|---:|---:|']
    for k, v in allrepos.items():
        ps = [p for p in pairs if p['repo'] == k]
        t.append(f"| {k} | [{v['repo']}](https://github.com/{v['repo']}) | `{v['commit'][:12]}` | {v['lang']} | {v['stars']} | {v['license']} | {v['split']} | {len(ps)} | {sum(r['service'] == k for r in records)} | {sum(p['variant_kept'] for p in ps)} |")
    t += ['', '새 출처 후보와 채택 사유:', '',
          '- NestJS: lujakob(3364)·mikro-orm(344)·neo4j-examples(48)·mutoe(44)는 수정/삭제 핸들러에 소유자 검사가 없어 탈락 → adr1enbe4udou1n(24).',
          '- Elixir Phoenix(gothinkster 892): 소유자 검사 없음(세션 403만) → 미채택. Koa는 댓글 삭제에 검사가 없어 2쌍.',
          '- owner_or_admin: memos(64k, "본인 또는 관리자" 사용자 자원·반응 "작성자 또는 관리자")와 kutt(11k, "관리자가 아니면 본인 링크로 조회 한정"). '
          'teamhephy/controller는 `IsOwnerOrAdmin`이 정의만 있고 ViewSet은 협업자 권한이 섞인 `IsAppUser`라 제외. DRF `IsOwnerOrAdmin` 코드 검색 결과는 대부분 개인 소규모 저장소였다.',
          '- memos는 메모 자체의 접근(공간 멤버십·공유·공개 범위)이 복잡해 사용자 자원·반응 핸들러만 썼다. memos 명세에 security 선언이 없어 security_state=unknown.',
          '- launchbadge/realworld-axum-sqlx(AGPL-3.0)는 사용자 결정(2026-10-26)으로 제외했다. Rust 출처는 없다.', '',
          '라이선스 미선언 저장소(GitHub API 기준 license 없음, 학습 투입 전 확인 필요): ' + ', '.join(f"{k}({v['repo']})" for k, v in allrepos.items() if v['license'] in ('none declared', 'see repository')) + '.', '',
          '## 건수\n', '| label | train | val |', '|---|---:|---:|']
    for lab in sorted({r['label'] for r in records}): t.append(f"| {lab} | {tr(lambda r: r['label'] == lab)} | {va(lambda r: r['label'] == lab)} |")
    t.append(f"| **합계** | **{tr(lambda r: True)}** | **{va(lambda r: True)}** |")
    t += ['', '| 언어 | train | val |', '|---|---:|---:|']
    for lang in sorted({r['meta']['language'] for r in records}): t.append(f"| {lang} | {tr(lambda r: r['meta']['language'] == lang)} | {va(lambda r: r['meta']['language'] == lang)} |")
    t += ['', '| label × 언어 (train 레코드) | ' + ' | '.join(sorted({r['meta']['language'] for r in records})) + ' |', '|---|' + '---:|' * len({r['meta']['language'] for r in records})]
    for lab in sorted({r['label'] for r in records}):
        t.append(f'| {lab} | ' + ' | '.join(str(tr(lambda r: r['label'] == lab and r['meta']['language'] == lg)) for lg in sorted({r['meta']['language'] for r in records})) + ' |')
    t += ['', '| 원본/변형 | train | val |', '|---|---:|---:|', f"| 원본 | {tr(lambda r: r['meta']['pair_role'] == 'check_kept')} | {va(lambda r: r['meta']['pair_role'] == 'check_kept')} |",
          f"| 변형 | {tr(lambda r: r['meta']['pair_role'] == 'check_removed')} | {va(lambda r: r['meta']['pair_role'] == 'check_removed')} |", '',
          f"train owner_or_admin {tr(lambda r: r['label'] == 'owner_or_admin')}건(목표 ≥ {MIN_TRAIN_OOA}). petclinic {sum(r['service'] == 'petclinic_rest' for r in records)}건(상한 {PETCLINIC_CAP}). "
          f"val {va(lambda r: True)}건, 언어 {sorted({r['meta']['language'] for r in records if r['meta']['split'] == 'val'})} — 목표 50건 안팎 대비 미달. "
          'owner_or_admin 출처(memos·kutt)는 train 최소 10건 조건 때문에 val에 둘 수 없었고, 새 RealWorld 구현은 저장소당 2~3쌍이라 1~2개 추가로는 50건에 닿지 않는다.', '',
          '## 탐지와 제외 (새 저장소)\n',
          f"검사 패턴 탐지 {detect['hits']}줄 = 채택 범위 {detect['adopted']} + 제외 규칙 {detect['excluded']} + 미설명 0.", '', '| 저장소 | 파일 | 제외 사유 |', '|---|---|---|']
    for r, f, rx, why in EXCLUDE_1B: t.append(f"| {r} | {f or '(전체)'} | {why} |")
    t += ['', f'변형 생성 후 제외(문법 실패·검사 잔존·무변화): {len(new_excl)}건' + ''.join(f"\n- {e['key']}: {e['reason']}" for e in new_excl), '',
          '## 1단계 검수 판정과 규칙 일치\n', '| pair_id | 경로 | 검수 판정 | 규칙 | 일치 |', '|---|---|---|---|---|']
    from openpyxl import load_workbook
    ws = load_workbook(REVIEWED, read_only=True)['review_pairs']; rows = list(ws.iter_rows(values_only=True)); hdr = rows[0]
    pi, vi = hdr.index('pair_id'), hdr.index('variant_label_inferable_from_path_schema (Y/N)')
    allp = {p['pair_id']: p for p in pairs}; s1_all = {r['meta']['pair_id']: r for r in jl(S1_DIR / 'pairs_train_v3s1.jsonl') + jl(S1_DIR / 'pairs_val_v3s1.jsonl') if r['meta']['pair_role'] == 'check_kept'}
    mism = 0
    for r in rows[1:]:
        o = s1_all[r[pi]]; k, keep, _ = variant_decision(o); ok = (r[vi] == 'Y') == keep; mism += not ok
        t.append(f"| {r[pi]} | {o['method']} {o['path']} | {r[vi]} | {k} | {'O' if ok else 'X'}{' (상한으로 제외됨)' if r[pi] not in allp else ''} |")
    assert mism == 0, f'{mism} reviewed judgments disagree with the variant rule'
    t += ['', '## 1b 검수 판정과 규칙 일치\n', '| pair_id | 저장소 | 경로 | 검수 판정 | 규칙 | 일치 |', '|---|---|---|---|---|---|']
    ws = load_workbook(REVIEWED_1B, read_only=True)['review_pairs']; rows = list(ws.iter_rows(values_only=True)); hdr = rows[0]
    pi, vi, ri = hdr.index('pair_id'), hdr.index('variant_label_inferable_from_path_schema (Y/N)'), hdr.index('repo')
    mism = 0
    for r in rows[1:]:
        if r[ri] in EXCLUDED_REPOS: t.append(f"| {r[pi]} | {r[ri]} | - | {r[vi]} | (저장소 제외) | - |"); continue
        p = allp[r[pi]]; ok = (r[vi] == 'Y') == p['variant_kept']; mism += not ok
        t.append(f"| {r[pi]} | {r[ri]} | {p['method']} {p['path']} | {r[vi]} | {p['variant_rule']} | {'O' if ok else 'X'} |")
    assert mism == 0, f'{mism} 1b reviewed judgments disagree with the variant rule'
    t += ['', '## 한계\n',
          f"- role_required는 train {tr(lambda r: r['label'] == 'role_required')}건이 전부 Java(petclinic)다. 다른 언어의 역할 검사 출처가 없다(사용자 결정: 그대로 진행).",
          f"- owner_or_admin은 train {tr(lambda r: r['label'] == 'owner_or_admin')}건이 Go(memos)·JavaScript(kutt)뿐이고 변형이 없다(규칙상 전부 제외).",
          f"- val {va(lambda r: True)}건(언어 {', '.join(sorted({r['meta']['language'] for r in records if r['meta']['split'] == 'val'}))})은 목표 50건 안팎에 못 미친다. 실험 규칙대로 학습 정상 확인용으로만 쓴다.",
          '- 라이선스 미선언 저장소가 있다(위 목록). Go·Java·TS·Kotlin·C#·PHP 변형은 파서 수준 문법 검사만 했다(컴파일 안 함).', '',
          '## 검수 시트\n',
          f"`{review['path']}` — 1단계 검수 40쌍을 뺀 {review['pairs']}쌍(새 출처 {review['new_source_pairs']}), (언어, label) 층별 균형(seed 42): "
          + ', '.join(f'{k} {v}' for k, v in sorted(review['by_stratum'].items())) + ('. 검수 완료본(rw_axum 2쌍 포함, 저장소 제외로 미반영).' if REVIEWED_1B.exists() else '. reviewer 비움. `variant_label_inferable_from_path_schema` 열 유지.'), '',
          '## 산출물\n']
    for k, v in manifest['outputs'].items(): t.append(f"- `{k}` — {v['records']}건, SHA-256 `{v['sha256']}`")
    t += ['- `datasets/blade/processed/data_v3_stage1b/manifest_v3s1b.json` — 변형 규칙·상한 제외 목록·새 저장소 커밋·원본 파일 SHA-256·탐지 집계', '',
          f"해시 가드(시작·종료): data-v1 {', '.join(guards['end_v1'].values())} / data-v2 {', '.join(guards['end_v2'].values())}. test_v30 읽기만 함. 학습·API 라벨링 없음."]
    (REP_DIR / 'stage1b_report.md').write_text('\n'.join(t) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':
    recs, prs = build()
    print(len(prs), 'pairs', len(recs), 'records', Counter((r['meta']['split'], r['label']) for r in recs))
