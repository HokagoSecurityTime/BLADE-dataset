"""data-v3 stage 1: check-kept / check-removed handler pairs from real open-source projects (no training, no API labelling).

For each selected repository (pinned commit, clone under datasets/blade/raw/opensource/, gitignored):
  1. route -> handler mapping per framework (route declarations parsed from the repository files);
  2. authorization-check lines detected by pattern scan; every detected line must be covered by an adopted handler or by a logged exclusion;
  3. label decided by the check content (rule table below), evidence = the check lines (file:line);
  4. pair = original (check kept) + variant (only the check lines removed, rest identical; variant label = original label);
     the modified whole file must parse without ERROR/MISSING nodes (tree-sitter; Python also ast) or the pair is excluded;
  5. OAS: repository spec when the repository has one (operation slice + referenced components), otherwise a minimal OAS from
     the route and its path parameters (description empty, no summary);
  6. split by repository (val = whole repositories); 7. stratified human-review sheet (40 pairs, reviewer column empty).
controller_text follows test_v30: verbatim excerpts (helpers first, handler last, blank line between), no explanatory comments.
data-v1 / data-v2 / test_v30 hashes are asserted at start and end; test_v30 is read only to check service exclusion and excerpt overlap."""
import ast, hashlib, json, random, re, sys, textwrap
from collections import Counter, defaultdict
from pathlib import Path

import tree_sitter as ts, tree_sitter_go, tree_sitter_java, tree_sitter_python, tree_sitter_ruby, tree_sitter_typescript
import tree_sitter_c_sharp, tree_sitter_javascript, tree_sitter_kotlin, tree_sitter_php, tree_sitter_rust
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.data_v1_guard import assert_data_v1
from scripts.data_v2_guard import assert_data_v2

OS_DIR = ROOT / 'datasets/blade/raw/opensource'
OUT_DIR = ROOT / 'datasets/blade/processed/data_v3_stage1'
REP_DIR = ROOT / 'reports/data_v3'
TEST = ROOT / 'datasets/blade/processed/test_v30.jsonl'
SEED = 42
REVIEW_PAIRS = 40
TEST_ONLY = {'juice-shop', 'crAPI', 'Pixi', 'DVWS-node', 'VAmPI', 'summit_club', 'quill_blog', 'folio_wiki', 'beacon_iot'}
OPTIONAL_CHECK = ['vAPI', 'DVRestaurant']   # allowed only if absent from test_v30; not used in this stage

LANG = {k: ts.Language(f()) for k, f in [('java', tree_sitter_java.language), ('go', tree_sitter_go.language), ('ruby', tree_sitter_ruby.language),
                                          ('python', tree_sitter_python.language), ('typescript', tree_sitter_typescript.language_typescript),
                                          ('javascript', tree_sitter_javascript.language), ('php', tree_sitter_php.language_php), ('csharp', tree_sitter_c_sharp.language),
                                          ('kotlin', tree_sitter_kotlin.language), ('rust', tree_sitter_rust.language)]}
RULES = {'owner_compare': ('owner_match', 'requester id compared with the object owner id; mismatch -> 403/401'),
         'owner_or_parent_owner': ('owner_match', 'requester must own the object or its parent object (comment author or article author); no admin path'),
         'owner_filter': ('owner_match', 'object lookup filtered by the requester as owner (author = current user)'),
         'owner_or_superuser': ('owner_or_admin', 'superuser passes; otherwise requester must own the object, else 403'),
         'self_or_superuser': ('owner_or_admin', 'requester may read their own user record; any other record requires superuser, else 403'),
         'superuser_dependency': ('role_required', 'route dependency get_current_active_superuser: non-superuser -> 403'),
         'role_annotation': ('role_required', '@PreAuthorize hasRole/hasAnyRole on the handler method')}
CHECK_RE = re.compile(r'403|FORBIDDEN|[Ff]orbidden|PreAuthorize|is_superuser|get_current_active_superuser|canWrite|NoAuthorization|author\.id !==|AuthorID !=|'
                      r'user_id == @current_user_id|request\.user != |author_id=current_user|author=current_user|UnAuthorized')

# ---- repositories (commit = clone HEAD at selection; stars/activity from the GitHub API on 2026-10-26) ----
REPOS = {
    'rw_spring': dict(repo='gothinkster/spring-boot-realworld-example-app', dir='gothinkster_spring-boot-realworld-example-app', commit='ee17e31aafe733d98c4853c8b9a74d7f2f6c924a',
                      lang='java', framework='Spring Boot', license='MIT', stars=1596, split='train', oas='generated', why='RealWorld Spring, most stars'),
    'rw_express': dict(repo='gothinkster/node-express-realworld-example-app', dir='gothinkster_node-express-realworld-example-app', commit='30b68e1e881462b2f4164ea09ab4c4f5699c7b0b',
                       lang='typescript', framework='Express', license='none declared', stars=3797, split='train', oas='generated', why='RealWorld Express/Node, most stars'),
    'rw_django': dict(repo='Sean-Miningah/realWorld-DjangoRestFramework', dir='Sean-Miningah_realWorld-DjangoRestFramework', commit='8e4729aaee0a3deef8fcf5ca53a02b1565440c97',
                      lang='python', framework='Django REST Framework', license='see repository', stars=66, split='val', oas='generated',
                      why='RealWorld Django by stars after gothinkster/django-realworld-example-app (1648 stars, 0 explicit authorization checks -> nothing to pair)'),
    'rw_flask': dict(repo='gothinkster/flask-realworld-example-app', dir='gothinkster_flask-realworld-example-app', commit='4b95fb2227dfeb5dd1a45d89b2bf48630b93fd28',
                     lang='python', framework='Flask', license='MIT', stars=899, split='train', oas='generated', why='RealWorld Flask, most stars'),
    'rw_rails': dict(repo='gothinkster/rails-realworld-example-app', dir='gothinkster_rails-realworld-example-app', commit='a2ae4fff78b3337683cea988c023281dcb5551b9',
                     lang='ruby', framework='Rails', license='none declared', stars=423, split='train', oas='generated', why='RealWorld Rails, most stars'),
    'rw_gin': dict(repo='gothinkster/golang-gin-realworld-example-app', dir='gothinkster_golang-gin-realworld-example-app', commit='626c372d259472148d93303f74aa9b9a1cdcef24',
                   lang='go', framework='Gin', license='MIT', stars=2718, split='train', oas='generated', why='RealWorld Go, most stars'),
    'fastapi_tpl': dict(repo='fastapi/full-stack-fastapi-template', dir='fastapi_full-stack-fastapi-template', commit='f4bcfaba7c85be3c6332cc74a20819f586dcdbc6',
                        lang='python', framework='FastAPI', license='MIT', stars=46068, split='val', oas='generated',
                        why='superuser dependency and owner-or-superuser checks; earlier used as isolated eval (external_paired_v29) -> kept out of train'),
    'petclinic_rest': dict(repo='spring-petclinic/spring-petclinic-rest', dir='spring-petclinic_spring-petclinic-rest', commit='afc8fc1d3b8ec8de69414482b3bd70a1da78cb95',
                           lang='java', framework='Spring Boot', license='Apache-2.0', stars=631, split='train', oas='repository_spec', oas_file='src/main/resources/openapi.yml',
                           why='@PreAuthorize role checks on every protected handler (petclinic.security.enable=false by default; intended policy still the annotation)'),
}
SCAN_FILES = {
    'rw_spring': ['src/main/java/io/spring/api/ArticleApi.java', 'src/main/java/io/spring/api/CommentsApi.java', 'src/main/java/io/spring/api/ArticlesApi.java',
                  'src/main/java/io/spring/api/CurrentUserApi.java', 'src/main/java/io/spring/api/ProfileApi.java', 'src/main/java/io/spring/api/UsersApi.java',
                  'src/main/java/io/spring/graphql/ArticleMutation.java', 'src/main/java/io/spring/graphql/CommentMutation.java'],
    'rw_express': ['src/app/routes/article/article.controller.ts', 'src/app/routes/article/article.service.ts', 'src/app/routes/auth/auth.controller.ts', 'src/app/routes/auth/auth.service.ts',
                   'src/app/routes/profile/profile.controller.ts', 'src/app/routes/profile/profile.service.ts'],
    'rw_django': ['articles/views.py', 'comments/views.py', 'accounts/views.py'],
    'rw_flask': ['conduit/articles/views.py', 'conduit/user/views.py', 'conduit/profile/views.py'],
    'rw_rails': ['app/controllers/articles_controller.rb', 'app/controllers/comments_controller.rb', 'app/controllers/application_controller.rb',
                 'app/controllers/profiles_controller.rb', 'app/controllers/users_controller.rb', 'app/controllers/sessions_controller.rb'],
    'rw_gin': ['articles/routers.go', 'users/routers.go'],
    'fastapi_tpl': ['backend/app/api/routes/items.py', 'backend/app/api/routes/users.py', 'backend/app/api/routes/utils.py', 'backend/app/api/routes/login.py', 'backend/app/api/routes/private.py'],
    'petclinic_rest': [f'src/main/java/org/springframework/samples/petclinic/rest/controller/{p}' for p in
                       ['v1/OwnerRestControllerV1.java', 'v1/PetRestControllerV1.java', 'v1/PetTypeRestControllerV1.java', 'v1/RootRestControllerV1.java', 'v1/SpecialtyRestControllerV1.java',
                        'v1/UserRestControllerV1.java', 'v1/VetRestControllerV1.java', 'v1/VisitRestControllerV1.java', 'v2/OwnerRestControllerV2.java', 'v2/PetRestControllerV2.java']],
}
# Detected check lines that are not adopted: (repo, file, line regex, reason). Every CHECK_RE hit outside adopted handlers must match one of these.
EXCLUDE = [
    ('rw_spring', 'src/main/java/io/spring/graphql/ArticleMutation.java', r'.', 'GraphQL mutation: no REST route / OAS operation'),
    ('rw_spring', 'src/main/java/io/spring/graphql/CommentMutation.java', r'.', 'GraphQL mutation: no REST route / OAS operation'),
    ('rw_spring', None, r'^import ', 'import line'),
    ('rw_flask', 'conduit/articles/views.py', r'author=current_user\.profile\)$', 'make_article: sets the author of a new article, not a check'),
    ('rw_express', 'src/app/routes/auth/auth.service.ts', r'throw new HttpException\(403', 'login credential failure (403), not an authorization check'),
    ('fastapi_tpl', 'backend/app/api/routes/items.py', r'if current_user\.is_superuser:', 'read_items: list scoping branch (superuser sees all, others own) — no removable check line'),
    ('fastapi_tpl', 'backend/app/api/routes/users.py', r'if current_user\.is_superuser:|status_code=403, detail="Super users are not allowed', 'delete_user_me / delete_user: self-delete guard for superusers, not an access check'),
    ('fastapi_tpl', None, r'get_current_active_superuser,$|import .*get_current_active_superuser', 'import line'),
    ('petclinic_rest', None, r'^import ', 'import line'),
]

# ---- adopted handlers. ops act on the whole file inside the handler span (or helper span); see apply_ops ----
SPR = 'src/main/java/io/spring/api/'
EXP_S = 'src/app/routes/article/article.service.ts'
FA = 'backend/app/api/routes/'
SUPERUSER_HELPER = [('backend/app/api/deps.py', 'get_current_active_superuser')]
DEP_LINE = [dict(op='drop_lines', match=r'^\s*dependencies=\[Depends\(get_current_active_superuser\)\],\s*$', count=1)]
HANDLERS = [
    # Spring RealWorld: route from class @RequestMapping + method mapping annotation
    dict(repo='rw_spring', file=SPR + 'ArticleApi.java', symbol='updateArticle', rule='owner_compare', helpers=[('src/main/java/io/spring/core/service/AuthorizationService.java', 'canWriteArticle')],
         ops=[dict(op='drop_stmt', match=r'if \(!AuthorizationService\.canWriteArticle')]),
    dict(repo='rw_spring', file=SPR + 'ArticleApi.java', symbol='deleteArticle', rule='owner_compare', helpers=[('src/main/java/io/spring/core/service/AuthorizationService.java', 'canWriteArticle')],
         ops=[dict(op='drop_stmt', match=r'if \(!AuthorizationService\.canWriteArticle')]),
    dict(repo='rw_spring', file=SPR + 'CommentsApi.java', symbol='deleteComment', rule='owner_or_parent_owner', helpers=[('src/main/java/io/spring/core/service/AuthorizationService.java', 'canWriteComment')],
         ops=[dict(op='drop_stmt', match=r'if \(!AuthorizationService\.canWriteComment')]),
    # Express RealWorld: anonymous route handler in the controller + the service function it calls (check lives in the service)
    dict(repo='rw_express', file='src/app/routes/article/article.controller.ts', route=('put', '/articles/:slug'), service=(EXP_S, 'updateArticle'), rule='owner_compare',
         ops=[dict(op='drop_stmt', match=r'if \(existingArticle\.author\.id !== id\)', target='service')]),
    dict(repo='rw_express', file='src/app/routes/article/article.controller.ts', route=('delete', '/articles/:slug'), service=(EXP_S, 'deleteArticle'), rule='owner_compare',
         ops=[dict(op='drop_stmt', match=r'if \(existingArticle\.author\.id !== id\)', target='service')]),
    dict(repo='rw_express', file='src/app/routes/article/article.controller.ts', route=('delete', '/articles/:slug/comments/:id'), service=(EXP_S, 'deleteComment'), rule='owner_compare',
         ops=[dict(op='sub', match=r'\n      author: \{\n        id: userId,\n      \},', repl='', count=1, target='service'),
              dict(op='drop_stmt', match=r'if \(comment\.author\.id !== userId\)', target='service')]),
    # Django RealWorld (DRF ModelViewSet registered on DefaultRouter)
    dict(repo='rw_django', file='articles/views.py', symbol='update', rule='owner_compare', ops=[dict(op='drop_stmt', match=r'if request\.user != article\.author:')]),
    dict(repo='rw_django', file='articles/views.py', symbol='destroy', rule='owner_compare', ops=[dict(op='drop_stmt', match=r'if request\.user != article\.author:')]),
    # Flask RealWorld: owner filter inside the lookup query
    dict(repo='rw_flask', file='conduit/articles/views.py', symbol='update_article', rule='owner_filter', ops=[dict(op='sub', match=r', author_id=current_user\.profile\.id', repl='', count=1)]),
    dict(repo='rw_flask', file='conduit/articles/views.py', symbol='delete_article', rule='owner_filter', ops=[dict(op='sub', match=r', author_id=current_user\.profile\.id', repl='', count=1)]),
    dict(repo='rw_flask', file='conduit/articles/views.py', symbol='delete_comment_on_article', rule='owner_filter', ops=[dict(op='sub', match=r', author=current_user\.profile', repl='', count=1)]),
    # Rails RealWorld: if owner ... else 403 end -> body only
    dict(repo='rw_rails', file='app/controllers/articles_controller.rb', symbol='update', rule='owner_compare', ops=[dict(op='unwrap_if', match=r'if @article\.user_id == @current_user_id')]),
    dict(repo='rw_rails', file='app/controllers/articles_controller.rb', symbol='destroy', rule='owner_compare', ops=[dict(op='unwrap_if', match=r'if @article\.user_id == @current_user_id')]),
    dict(repo='rw_rails', file='app/controllers/comments_controller.rb', symbol='destroy', rule='owner_compare', ops=[dict(op='unwrap_if', match=r'if @comment\.user_id == @current_user_id')]),
    # Gin RealWorld: check block + the lines that exist only to feed it (comment, requester lookup, existence lookup)
    dict(repo='rw_gin', file='articles/routers.go', symbol='ArticleUpdate', rule='owner_compare',
         ops=[dict(op='drop_lines', match=r'^\s*// Check if current user is the author\s*$|^\s*myUserModel := c\.MustGet|^\s*articleUserModel := GetArticleUserModel', count=3),
              dict(op='drop_stmt', match=r'if articleModel\.AuthorID != articleUserModel\.ID')]),
    dict(repo='rw_gin', file='articles/routers.go', symbol='ArticleDelete', rule='owner_compare',
         ops=[dict(op='drop_stmt', match=r'if err == nil \{'), dict(op='drop_lines', match=r'^\s*articleModel, err := FindOneArticle', count=1)]),
    dict(repo='rw_gin', file='articles/routers.go', symbol='ArticleCommentDelete', rule='owner_compare',
         ops=[dict(op='drop_stmt', match=r'if err == nil \{'), dict(op='drop_lines', match=r'^\s*commentModel, err := FindOneComment', count=1)]),
    # FastAPI template
    *[dict(repo='fastapi_tpl', file=FA + 'items.py', symbol=s, rule='owner_or_superuser',
           ops=[dict(op='drop_stmt', match=r'if not current_user\.is_superuser and \(item\.owner_id != current_user\.id\):')]) for s in ('read_item', 'update_item', 'delete_item')],
    dict(repo='fastapi_tpl', file=FA + 'users.py', symbol='read_user_by_id', rule='self_or_superuser', ops=[dict(op='drop_stmt', match=r'if not current_user\.is_superuser:')]),
    dict(repo='fastapi_tpl', file=FA + 'users.py', symbol='read_users', rule='superuser_dependency', helpers=SUPERUSER_HELPER, ops=DEP_LINE),
    dict(repo='fastapi_tpl', file=FA + 'users.py', symbol='update_user', rule='superuser_dependency', helpers=SUPERUSER_HELPER, ops=DEP_LINE),
    dict(repo='fastapi_tpl', file=FA + 'users.py', symbol='create_user', rule='superuser_dependency', helpers=SUPERUSER_HELPER,
         ops=[dict(op='sub', match=r' dependencies=\[Depends\(get_current_active_superuser\)\],', repl='', count=1)]),
    dict(repo='fastapi_tpl', file=FA + 'users.py', symbol='delete_user', rule='superuser_dependency', helpers=SUPERUSER_HELPER,
         ops=[dict(op='sub', match=r', dependencies=\[Depends\(get_current_active_superuser\)\]', repl='', count=1)], allow_residual=r'Super users are not allowed to delete themselves'),
    dict(repo='fastapi_tpl', file=FA + 'utils.py', symbol='test_email', rule='superuser_dependency', helpers=SUPERUSER_HELPER, ops=DEP_LINE),
    dict(repo='fastapi_tpl', file=FA + 'login.py', symbol='recover_password_html_content', rule='superuser_dependency', helpers=SUPERUSER_HELPER, ops=DEP_LINE),
]
# petclinic-rest: every controller method carrying @PreAuthorize (discovered, not listed by hand)
PET_ROLE = dict(rule='role_annotation', ops=[dict(op='drop_lines', match=r'^\s*@PreAuthorize\(.*\)\s*$', count=1)])


def sha(b): return hashlib.sha256(b).hexdigest()
def read_text(p): return p.read_bytes().decode('utf-8').replace('\r\n', '\n')
def indent(s): return len(s) - len(s.lstrip(' \t'))


class Src:
    """A repository file: text, lines, tree-sitter tree."""
    def __init__(self, repo, rel):
        self.repo, self.rel, self.lang = repo, rel, REPOS[repo]['lang']
        p = OS_DIR / REPOS[repo]['dir'] / rel
        self.raw = p.read_bytes(); self.text = read_text(p); self.tree = ts.Parser(LANG[self.lang]).parse(self.text.encode())

    @property
    def lines(self): return self.text.split('\n')


def walk(n):
    yield n
    for c in n.children: yield from walk(c)


def node_name(n, lang):
    if lang in ('typescript', 'javascript') and n.type == 'lexical_declaration':
        d = next((c for c in n.named_children if c.type == 'variable_declarator'), None); nm = d and d.child_by_field_name('name')
    elif n.type == 'pair':                                   # JS object property holding a function: `name: async function (...) {}`
        v = n.child_by_field_name('value'); nm = n.child_by_field_name('key') if v is not None and v.type in ('function_expression', 'arrow_function') else None
    elif lang == 'kotlin':                                   # tree-sitter-kotlin: the name is an `identifier` child, not a field
        nm = next((c for c in n.children if c.type == 'identifier'), None)
    else:
        nm = n.child_by_field_name('name')
    return nm.text.decode() if nm else None


DEF_TYPES = {'java': {'method_declaration'}, 'go': {'function_declaration', 'method_declaration'}, 'ruby': {'method'}, 'python': {'function_definition'},
             'typescript': {'lexical_declaration', 'function_declaration', 'method_definition'}, 'javascript': {'lexical_declaration', 'function_declaration', 'method_definition', 'pair'},
             'php': {'method_declaration'}, 'csharp': {'method_declaration'}, 'kotlin': {'function_declaration'}, 'rust': {'function_item'}}


def find_def(src, name, anchor=None):
    """(start_row, end_row) of the definition named `name` (Python decorators, TS export and class-member decorators, Java/Kotlin annotations, C# attributes
    included). `anchor` (regex on the first line) disambiguates same-named members. Must be unique."""
    hits = [n for n in walk(src.tree.root_node) if n.type in DEF_TYPES[src.lang] and node_name(n, src.lang) == name
            and (anchor is None or re.search(anchor, src.lines[n.start_point[0]]))]
    assert len(hits) == 1, (src.repo, src.rel, name, len(hits))
    n = hits[0]
    if n.parent is not None and n.parent.type in ('decorated_definition', 'export_statement'): n = n.parent
    start = n.start_point[0]
    if n.type == 'method_definition':
        p = n.prev_named_sibling
        while p is not None and p.type == 'decorator': start, p = p.start_point[0], p.prev_named_sibling
    return start, n.end_point[0]


def find_express_route(src, method, path):
    hits = []
    for n in walk(src.tree.root_node):
        if n.type == 'call_expression' and (f := n.child_by_field_name('function')) is not None and f.text.decode() == f'router.{method}':
            args = [a for a in n.child_by_field_name('arguments').named_children]
            if args and args[0].type == 'string' and args[0].text.decode().strip('\'"') == path: hits.append(n.parent if n.parent.type == 'expression_statement' else n)
    assert len(hits) == 1, (method, path, len(hits))
    return hits[0].start_point[0], hits[0].end_point[0], hits[0].start_point[0] + 1


def stmt_at(src, text, row):
    """Outermost statement-like node starting at `row` (re-parses `text`)."""
    tree = ts.Parser(LANG[src.lang]).parse(text.encode()); best = None
    for n in walk(tree.root_node):
        if n.start_point[0] == row and n.parent is not None and n.type not in ('program', 'module', 'source_file', 'block', 'statement_block', 'class_body'):
            if 'statement' in n.type or n.type in ('if', 'if_statement', 'expression_statement', 'if_expression'):
                if best is None or n.end_point[0] > best.end_point[0]: best = n
    assert best is not None, (src.rel, row, text.split('\n')[row])
    return best.start_point[0], best.end_point[0]


def apply_ops(src, text, span, ops, log):
    """Apply removal ops to `text` inside rows span[0]..span[1]. Returns (text, new_span). Every op must change something."""
    a, b = span
    for op in ops:
        L = text.split('\n'); seg = range(a, b + 1)
        if op['op'] == 'drop_lines':
            rows = [i for i in seg if re.search(op['match'], L[i])]
            assert len(rows) == op['count'], (src.rel, op, len(rows))
            log += [dict(file=src.rel, line=i + 1, text=L[i].strip()) for i in rows]
            L = [x for i, x in enumerate(L) if i not in rows]; b -= len(rows)
        elif op['op'] == 'drop_stmt':
            rows = [i for i in seg if re.search(op['match'], L[i])]
            assert len(rows) == 1, (src.rel, op, len(rows))
            s, e = stmt_at(src, text, rows[0] + op.get('row_offset', 0))   # row_offset: the matched line is inside a multi-line statement
            while s - 1 >= a and L[s - 1].strip().startswith(('//', '#')) and indent(L[s - 1]) == indent(L[s]): s -= 1   # comment attached to the check
            log += [dict(file=src.rel, line=i + 1, text=L[i].strip()) for i in range(s, e + 1)]
            del L[s:e + 1]; b -= e - s + 1
            if 0 < s < len(L) and not L[s - 1].strip() and not L[s].strip(): del L[s]; b -= 1                     # no double blank at the seam
        elif op['op'] == 'unwrap_if':
            rows = [i for i in seg if re.search(op['match'], L[i])]
            assert len(rows) == 1, (src.rel, op, len(rows))
            s = rows[0]; base = indent(L[s])
            el = next(i for i in range(s + 1, b + 1) if indent(L[i]) == base and L[i].strip() == 'else')
            en = next(i for i in range(el + 1, b + 1) if indent(L[i]) == base and L[i].strip() == 'end')
            body = L[s + 1:el]; d = min(indent(x) for x in body if x.strip()) - base
            log += [dict(file=src.rel, line=i + 1, text=L[i].strip()) for i in [s, *range(el, en + 1)]]
            L[s:en + 1] = [x[d:] if x.strip() else x for x in body]; b -= (en - s + 1) - len(body)
        elif op['op'] == 'sub':
            mid = '\n'.join(L[a:b + 1]); m = re.search(op['match'], mid)
            new, k = re.subn(op['match'], op['repl'], mid, count=op['count'])
            assert k == op['count'], (src.rel, op, k)
            r0 = a + mid[:m.start()].count('\n') + (1 if m.group(0).startswith('\n') else 0)
            log.append(dict(file=src.rel, line=r0 + 1, text=' '.join(m.group(0).split()), kind='substring'))
            new_lines = new.split('\n'); L = L[:a] + new_lines + L[b + 1:]; b = a + len(new_lines) - 1
        text = '\n'.join(L)
    return text, (a, b)


def excerpt(text, span): return textwrap.dedent('\n'.join(text.split('\n')[span[0]:span[1] + 1])).rstrip()


def syntax_ok(lang, text):
    if ts.Parser(LANG[lang]).parse(text.encode()).root_node.has_error: return False, 'tree-sitter ERROR/MISSING node'
    if lang == 'python':
        try: ast.parse(text)
        except SyntaxError as e: return False, f'ast: {e}'
    return True, 'tree-sitter' + (' + ast' if lang == 'python' else '')


# ---- routes ----
def to_oas_path(p): return re.sub(r'[:<]([A-Za-z_]+)>?', r'{\1}', p)


def route_of(h, src, span):
    repo, L = h['repo'], src.lines
    if repo == 'rw_spring':
        cls = re.search(r'@RequestMapping\(path = "([^"]+)"\)', src.text).group(1)
        ann = '\n'.join(L[span[0]:span[1] + 1])
        m = re.search(r'@(Get|Put|Post|Delete|Patch)Mapping(?:\(\s*(?:path = )?"([^"]*)"\s*\))?', ann)
        if m: meth, sub = m.group(1).upper(), m.group(2) or ''
        else:
            m = re.search(r'@RequestMapping\(path = "([^"]*)", method = RequestMethod\.(\w+)\)', ann); meth, sub = m.group(2), m.group(1)
        return meth, cls.rstrip('/') + ('/' + sub if sub else ''), f'{src.rel}: class @RequestMapping + method mapping'
    if repo == 'rw_express':
        pre = re.search(r"Router\(\)\.use\('([^']+)', api\)", read_text(OS_DIR / REPOS[repo]['dir'] / 'src/app/routes/routes.ts')).group(1)
        return h['route'][0].upper(), to_oas_path(pre + h['route'][1]), f"src/app/routes/routes.ts use('{pre}') + {src.rel}:{h['_route_line']} router.{h['route'][0]}"
    if repo == 'rw_django':
        urls = read_text(OS_DIR / REPOS[repo]['dir'] / 'articles/urls.py'); conf = read_text(OS_DIR / REPOS[repo]['dir'] / 'config/urls.py')
        pre = re.search(r"api_prefix = '([^']+)'", conf).group(1); res = re.search(r"register\('([^']+)', views\.ArticleView", urls).group(1)
        lookup = re.search(r"lookup_field\s*=\s*'([^']+)'", src.text).group(1)
        meth = {'update': 'PUT', 'destroy': 'DELETE', 'partial_update': 'PATCH', 'retrieve': 'GET'}[h['symbol']]
        return meth, f'/{pre}/{res}/{{{lookup}}}', f'config/urls.py api_prefix + articles/urls.py DefaultRouter register(\'{res}\') + lookup_field + ModelViewSet.{h["symbol"]}'
    if repo == 'rw_flask':
        m = re.search(r"@blueprint\.route\('([^']+)', methods=\('(\w+)',\)\)", '\n'.join(L[span[0]:span[1] + 1]))
        return m.group(2), to_oas_path(m.group(1)), f'{src.rel}: @blueprint.route'
    if repo == 'rw_rails':
        routes = read_text(OS_DIR / REPOS[repo]['dir'] / 'config/routes.rb'); assert 'scope :api' in routes and 'resources :articles, param: :slug' in routes and 'resources :comments, only: [:create, :index, :destroy]' in routes
        meth = {'update': 'PUT', 'destroy': 'DELETE'}[h['symbol']]
        path = '/api/articles/{slug}' if 'articles_controller' in src.rel else '/api/articles/{article_slug}/comments/{id}'
        return meth, path, 'config/routes.rb scope :api + resources :articles (param :slug) / nested resources :comments; Rails REST action convention'
    if repo == 'rw_gin':
        hello = read_text(OS_DIR / REPOS[repo]['dir'] / 'hello.go'); assert 'v1 := r.Group("/api")' in hello and 'articles.ArticlesRegister(v1.Group("/articles"))' in hello
        m = re.search(r'router\.(GET|PUT|POST|DELETE)\("([^"]*)", ' + h['symbol'] + r'\)', src.text)
        return m.group(1), to_oas_path('/api/articles' + m.group(2)), 'hello.go v1.Group("/api") + Group("/articles") + articles/routers.go ArticlesRegister (AuthMiddleware(true))'
    if repo == 'fastapi_tpl':
        cfg = read_text(OS_DIR / REPOS[repo]['dir'] / 'backend/app/core/config.py'); v1 = re.search(r'API_V1_STR: str = "([^"]+)"', cfg).group(1)
        m = re.search(r'APIRouter\((?:[^)]*?)prefix="([^"]*)"', src.text); pre = m.group(1) if m else ''
        m = re.search(r'@router\.(get|put|post|delete|patch)\(\s*"([^"]*)"', '\n'.join(L[span[0]:span[1] + 1]))
        return m.group(1).upper(), v1 + pre + m.group(2), f'core/config.py API_V1_STR + {src.rel} APIRouter(prefix) + @router.{m.group(1)}'
    raise KeyError(repo)


ROUTE_AUTH = {'rw_spring': 'WebSecurityConfig: non-GET /articles/** authenticated', 'rw_express': 'auth.required middleware on the route',
              'rw_django': 'permission_classes=[IsAuthenticated] for non-list/retrieve actions', 'rw_flask': '@jwt_required', 'rw_rails': 'before_action :authenticate_user!',
              'rw_gin': 'v1.Use(users.AuthMiddleware(true)) before ArticlesRegister', 'fastapi_tpl': 'CurrentUser / superuser dependency (OAuth2 bearer)'}


def minimal_oas(repo, method, path, op_id):
    params = [dict(name=n, **{'in': 'path'}, required=True, schema=dict(type='string')) for n in re.findall(r'\{(\w+)\}', path)]
    op = dict(operationId=op_id, description='', parameters=params, security=[dict(bearerAuth=[])], responses={'default': dict(description='')})
    if not params: op.pop('parameters')
    return dict(openapi='3.0.3', info=dict(title=REPOS[repo]['repo'].split('/')[1], version=''), paths={path: {method.lower(): op}},
                components=dict(securitySchemes=dict(bearerAuth=dict(type='http', scheme='bearer'))))


def spec_slice(spec, path, method):
    op = spec['paths'][path][method.lower()]; out = dict(openapi=spec['openapi'], info=spec.get('info', {}), paths={path: {method.lower(): op}})
    if spec.get('servers'): out['servers'] = spec['servers']
    if spec.get('security') is not None: out['security'] = spec['security']
    comps, todo, seen = {}, [op], set()
    while todo:
        for ref in re.findall(r'"#/components/(\w+)/([\w.-]+)"', json.dumps(todo.pop())):
            if ref in seen: continue
            seen.add(ref); obj = spec['components'][ref[0]][ref[1]]; comps.setdefault(ref[0], {})[ref[1]] = obj; todo.append(obj)
    if spec.get('components', {}).get('securitySchemes'): comps['securitySchemes'] = spec['components']['securitySchemes']
    if comps: out['components'] = comps
    return out


def security_state(spec, method, path):   # same rule as training/data/label_gitea_v30.payload
    op = spec['paths'][path][method.lower()]
    return 'explicitly_anonymous' if op.get('security') == [] and 'security' in spec else 'declared' if ('security' in op or spec.get('security')) else 'unknown'


# ---- build ----
def petclinic_handlers():
    spec = yaml.safe_load(read_text(OS_DIR / REPOS['petclinic_rest']['dir'] / REPOS['petclinic_rest']['oas_file']))
    ops = {o['operationId']: (m.upper(), p) for p, d in spec['paths'].items() for m, o in d.items() if isinstance(o, dict) and 'operationId' in o}
    out = []
    for rel in SCAN_FILES['petclinic_rest']:
        src = Src('petclinic_rest', rel)
        for n in walk(src.tree.root_node):
            mods = next((c for c in n.children if c.type == 'modifiers'), None) if n.type == 'method_declaration' else None
            if mods is not None and '@PreAuthorize' in mods.text.decode():
                name = node_name(n, 'java'); assert name in ops, name
                out.append(dict(repo='petclinic_rest', file=rel, symbol=name, _route=ops[name], **PET_ROLE))
    return out, spec


def build():
    guards = dict(start_v1=assert_data_v1('start'), start_v2=assert_data_v2('start'))
    test = [json.loads(l) for l in TEST.read_text(encoding='utf-8').splitlines() if l.strip()]
    test_services = sorted({r['service'] for r in test})
    assert not set(REPOS) & set(test_services) and not {v['repo'].split('/')[1] for v in REPOS.values()} & set(test_services)
    optional = {s: (s in test_services) for s in OPTIONAL_CHECK}
    for k, v in REPOS.items():
        head = (OS_DIR / v['dir'] / '.git' / 'HEAD').read_text().strip()
        ref = (OS_DIR / v['dir'] / '.git' / head[5:]).read_text().strip() if head.startswith('ref:') else head
        if not ref or len(ref) != 40:
            ref = (OS_DIR / v['dir'] / '.git' / 'packed-refs').read_text().split(head[5:])[0].split()[-1]
        assert ref == v['commit'], (k, ref)

    pet, pet_spec = petclinic_handlers()
    handlers = HANDLERS + pet
    records, excluded, pairs, files_used, adopted_lines = [], [], [], {}, defaultdict(set)
    for h in handlers:
        repo, R = h['repo'], REPOS[h['repo']]
        src = Src(repo, h['file']); files_used[(repo, h['file'])] = sha(src.raw)
        if 'route' in h:
            s, e, h['_route_line'] = find_express_route(src, *h['route'])
        else:
            s, e = find_def(src, h['symbol'])
        label, rule_text = RULES[h['rule']]
        # original excerpt parts: helpers, service (Express), handler
        parts, var_parts, locs, var_locs, removed = [], [], [], [], []
        for f, sym in h.get('helpers', []):
            hs = Src(repo, f); files_used[(repo, f)] = sha(hs.raw); a, b = find_def(hs, sym)
            parts.append(excerpt(hs.text, (a, b))); locs.append(dict(file=f, start_line=a + 1, end_line=b + 1)); adopted_lines[(repo, f)] |= set(range(a, b + 1))
        targets = {'handler': (src, (s, e))}
        if 'service' in h:
            ss = Src(repo, h['service'][0]); files_used[(repo, ss.rel)] = sha(ss.raw); targets['service'] = (ss, find_def(ss, h['service'][1]))
            assert re.search(r'\b' + h['service'][1] + r'\(', excerpt(src.text, (s, e))), 'handler does not call the service'
        order = ['service', 'handler'] if 'service' in h else ['handler']
        mod_text = {}
        for t in order:
            tsrc, span = targets[t]; adopted_lines[(repo, tsrc.rel)] |= set(range(span[0], span[1] + 1))
            parts.append(excerpt(tsrc.text, span)); locs.append(dict(file=tsrc.rel, start_line=span[0] + 1, end_line=span[1] + 1))
            t_ops = [o for o in h['ops'] if o.get('target', 'handler') == t]
            new_text, new_span = apply_ops(tsrc, tsrc.text, span, t_ops, removed) if t_ops else (tsrc.text, span)
            mod_text[t] = (tsrc, new_text)
            var_parts.append(excerpt(new_text, new_span)); var_locs.append(dict(file=tsrc.rel, start_line=new_span[0] + 1, end_line=new_span[1] + 1, modified=bool(t_ops)))
        orig_ct, var_ct = '\n\n'.join(parts), '\n\n'.join(var_parts)
        meth, path, route_ev = h['_route'] + ('openapi.yml operationId == method name',) if '_route' in h else route_of(h, src, (s, e))
        key = f"{repo}:{meth}:{path}"
        # syntax of every modified file, and of the originals (a file that does not parse originally cannot validate the variant)
        checks = []
        for t, (tsrc, new_text) in mod_text.items():
            if new_text == tsrc.text: continue
            ok0, how0 = syntax_ok(tsrc.lang, tsrc.text); ok1, how1 = syntax_ok(tsrc.lang, new_text)
            checks.append(dict(file=tsrc.rel, original_ok=ok0, variant_ok=ok1, method=how1))
        residual = [l for l in var_ct.split('\n') if CHECK_RE.search(l) and not (h.get('allow_residual') and re.search(h['allow_residual'], l))]
        reason = None
        if orig_ct == var_ct: reason = 'no change'
        elif not checks or not all(c['original_ok'] and c['variant_ok'] for c in checks): reason = f'syntax check failed: {checks}'
        elif residual: reason = f'check lines remain in variant: {residual}'
        if reason:
            excluded.append(dict(key=key, repo=repo, reason=reason)); continue
        if R['oas'] == 'repository_spec':
            spec = spec_slice(pet_spec, path, meth); oas_status, oas_file = 'repository_spec', R['oas_file']
        else:
            spec = minimal_oas(repo, meth, path, h.get('symbol') or h['service'][1]); oas_status, oas_file = 'generated_minimal', None
        state = security_state(spec, meth, path)
        pair_id = 'v3s1-' + sha(key.encode())[:12]
        base = dict(source='opensource', service=repo, method=meth, path=path, label=label, oas_snippet=json.dumps(spec, ensure_ascii=False), erd_snippet='', security_state=state)
        common = dict(source='opensource', project=R['repo'], repository=f"https://github.com/{R['repo']}", commit=R['commit'], license=R['license'], language=R['lang'], framework=R['framework'],
                      oas_status=oas_status, oas_file=oas_file, route_evidence=route_ev, route_authentication=ROUTE_AUTH.get(repo, 'from repository spec' if oas_file else ''),
                      erd_status='unknown', controller_status='available', data_version='data-v3-stage1', split=R['split'], pair_id=pair_id,
                      label_source='rule_from_check_lines', rule_id=h['rule'], rule=rule_text, human_confirmed=False, check_lines=removed, syntax_check=checks)
        for role, ct, lc in (('check_kept', orig_ct, locs), ('check_removed', var_ct, var_locs)):
            records.append(dict(id=f'{pair_id}-{"orig" if role == "check_kept" else "var"}', **base, controller_text=ct,
                                meta=dict(**common, pair_role=role, variant_of=None if role == 'check_kept' else f'{pair_id}-orig', source_locations=lc)))
        pairs.append(dict(pair_id=pair_id, key=key, repo=repo, lang=R['lang'], label=label, rule=h['rule'], split=R['split'], method=meth, path=path,
                          orig=orig_ct, var=var_ct, removed=removed))

    # detection completeness: every CHECK_RE hit in the scanned files is inside an adopted span or matches a logged exclusion
    detect = dict(hits=0, adopted=0, excluded=0, unexplained=[])
    for repo, files in SCAN_FILES.items():
        for rel in files:
            p = OS_DIR / REPOS[repo]['dir'] / rel
            if not p.exists(): detect['unexplained'].append(f'{repo}:{rel} missing'); continue
            for i, line in enumerate(read_text(p).split('\n')):
                if not CHECK_RE.search(line): continue
                detect['hits'] += 1
                if i in adopted_lines[(repo, rel)]: detect['adopted'] += 1
                elif any(r == repo and (f is None or f == rel) and re.search(rx, line) for r, f, rx, _ in EXCLUDE): detect['excluded'] += 1
                else: detect['unexplained'].append(f'{repo}:{rel}:{i + 1}: {line.strip()}')
    assert not detect['unexplained'], detect['unexplained']

    # no excerpt overlaps test_v30 controller text
    test_ct = [r.get('controller_text') or '' for r in test]
    overlap = [r['id'] for r in records if any(len(r['controller_text']) > 80 and r['controller_text'] in t for t in test_ct)]
    assert not overlap, overlap

    OUT_DIR.mkdir(parents=True, exist_ok=True); REP_DIR.mkdir(parents=True, exist_ok=True)
    outs = {}
    for split in ('train', 'val'):
        p = OUT_DIR / f'pairs_{split}_v3s1.jsonl'
        p.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records if r['meta']['split'] == split), encoding='utf-8', newline='\n')
        outs[p.relative_to(ROOT).as_posix()] = dict(records=sum(r['meta']['split'] == split for r in records), sha256=sha(p.read_bytes()))
    manifest = dict(data_version='data-v3-stage1', built_by='training/data/build_data_v3_pairs.py', seed=SEED, frozen=False,
                    repositories={k: {kk: vv for kk, vv in v.items() if kk != 'dir'} | dict(clone_dir=f"datasets/blade/raw/opensource/{v['dir']}") for k, v in REPOS.items()},
                    source_files=[dict(repo=r, file=f, sha256=h) for (r, f), h in sorted(files_used.items())],
                    outputs=outs, test_v30_services=test_services, optional_repos_in_test_v30=optional, detection=dict((k, v) for k, v in detect.items() if k != 'unexplained'),
                    excluded=excluded, exclusion_rules=[dict(repo=r, file=f, pattern=rx, reason=why) for r, f, rx, why in EXCLUDE])
    (OUT_DIR / 'manifest_v3s1.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + '\n', encoding='utf-8', newline='\n')
    review = review_sheet(pairs)
    guards.update(end_v1=assert_data_v1('end'), end_v2=assert_data_v2('end'))
    report(records, pairs, excluded, detect, manifest, review, guards)
    return records, pairs


def review_sheet(pairs):
    """40 pairs: balanced stratified over (language, label) — one per stratum per round until 40 — seed 42 inside each stratum."""
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font
    rng = random.Random(SEED); strata = defaultdict(list)
    for p in sorted(pairs, key=lambda x: x['pair_id']): strata[(p['lang'], p['label'])].append(p)
    for v in strata.values(): rng.shuffle(v)
    pick, k = [], 0
    while len(pick) < min(REVIEW_PAIRS, len(pairs)):
        for s in sorted(strata):
            if k < len(strata[s]) and len(pick) < REVIEW_PAIRS: pick.append(strata[s][k])
        k += 1
    wb = Workbook(); ws = wb.active; ws.title = 'review_pairs'
    cols = ['pair_id', 'split', 'repo', 'language', 'method', 'path', 'label', 'rule_id', 'removed_check_lines', 'original_controller_text', 'variant_controller_text',
            'label_correct (Y/N)', 'variant_removes_whole_check (Y/N)', 'variant_otherwise_identical (Y/N)', 'variant_label_inferable_from_path_schema (Y/N)', 'corrected_label', 'note', 'reviewer']
    ws.append(cols)
    for p in pick:
        ws.append([p['pair_id'], p['split'], p['repo'], p['lang'], p['method'], p['path'], p['label'], p['rule'],
                   '\n'.join(f"{x['file']}:{x['line']}  {x['text']}" for x in p['removed']), p['orig'], p['var'], '', '', '', '', '', '', ''])
    for c in ws[1]: c.font = Font(bold=True)
    for row in ws.iter_rows(min_row=2):
        for c in row: c.alignment = Alignment(wrap_text=True, vertical='top')
    for col, w in zip('ABCDEFGHIJKLMNOPQR', [18, 7, 14, 10, 8, 34, 16, 20, 50, 70, 70, 12, 14, 14, 16, 16, 30, 12]): ws.column_dimensions[col].width = w
    ws.freeze_panes = 'B2'
    g = wb.create_sheet('guide')
    for line in ['data-v3 stage 1 사람 검수 시트 — 쌍 40건, (언어, label) 층별 균형 추출(seed 42). reviewer 열은 비워 두었다.',
                 'label_correct: 원본(검사 유지) 코드의 검사 내용이 label과 맞는가. 맞지 않으면 corrected_label에 7종 중 하나.',
                 'variant_removes_whole_check: 변형에서 인가 검사가 남김없이 빠졌는가(쿼리 필터·의존성·주석 포함).',
                 'variant_otherwise_identical: 검사 외 줄이 원본과 같은가(들여쓰기 정리·검사 전용 조회 줄 제거는 허용).',
                 'variant_label_inferable_from_path_schema: 변형(검사 없음)만 보고 경로·스키마·OAS로 그 label을 읽어낼 수 있는가. N이면 data-v2 기준상 manual 후보다(외부 인가처럼 의도를 확인할 수 없음).',
                 '변형 label = 원본 label(의도된 정책). 검수 결과를 학습·프롬프트 예시에 쓰려면 별도 승인이 필요하다(AGENTS.md).']:
        g.append([line])
    g.column_dimensions['A'].width = 140
    path = REP_DIR / 'review_pairs_v3s1.xlsx'; wb.save(path)
    return dict(path=path.relative_to(ROOT).as_posix(), pairs=len(pick), by_stratum=dict(Counter(f"{p['lang']}/{p['label']}" for p in pick)),
                pair_ids=[p['pair_id'] for p in pick])


def report(records, pairs, excluded, detect, manifest, review, guards):
    t = ['# data-v3 1단계 — 실제 오픈소스 핸들러 "검사 유지/제거" 쌍 (학습·API 라벨링 없음)\n',
         f"빌더 `training/data/build_data_v3_pairs.py`, seed {SEED}. 쌍 {len(pairs)}개 = 레코드 {len(records)}건(원본 {len(pairs)} + 변형 {len(pairs)}). "
         'label은 원본 코드의 검사 내용으로 규칙 결정했고 변형 label = 원본 label이다. 사람 확정 전이며 동결하지 않았다.\n',
         '## 저장소 (커밋 고정)\n', '| key | 저장소 | 커밋 | 언어/프레임워크 | 스타 | split | OAS | 쌍 | 선정 이유 |', '|---|---|---|---|---:|---|---|---:|---|']
    pc = Counter(p['repo'] for p in pairs)
    for k, v in REPOS.items():
        t.append(f"| {k} | [{v['repo']}](https://github.com/{v['repo']}) | `{v['commit'][:12]}` | {v['lang']} / {v['framework']} | {v['stars']} | {v['split']} | {v['oas']} | {pc[k]} | {v['why']} |")
    t += ['', '선정에서 뺀 저장소: gothinkster/django-realworld-example-app(커밋 `29c9d42831fa`) — 핸들러에 명시적 인가 검사가 0건이라 쌍을 만들 수 없다. '
          'c4ffein/realworld-django-ninja는 클론했으나 스타 순 2순위가 아니어서 쓰지 않았다(클론만 남음, gitignore).', '',
          f"test_v30 서비스: {', '.join(manifest['test_v30_services'])} — 선정 저장소와 겹침 없음. "
          f"vAPI·DVRestaurant의 test_v30 포함 여부: {manifest['optional_repos_in_test_v30']} → 미포함이라 사용 가능하나 이번 단계에서는 쓰지 않았다(취약 설계 앱은 원본에 검사가 빠진 경우가 많아 '검사 명확 원본' 조건에 맞지 않음). "
          'controller_text가 test_v30 발췌와 겹치는 레코드: 0건.', '',
          '## 건수 (레코드 = 원본 + 변형)\n', '| split | 저장소 | 레코드 |', '|---|---|---:|']
    for split in ('train', 'val'):
        for k in REPOS:
            n = sum(r['service'] == k and r['meta']['split'] == split for r in records)
            if n: t.append(f'| {split} | {k} | {n} |')
        t.append(f"| **{split} 합계** | | **{sum(r['meta']['split'] == split for r in records)}** |")
    t += ['', '| label | train | val |', '|---|---:|---:|']
    for lab in sorted({r['label'] for r in records}):
        t.append(f"| {lab} | {sum(r['label'] == lab and r['meta']['split'] == 'train' for r in records)} | {sum(r['label'] == lab and r['meta']['split'] == 'val' for r in records)} |")
    t += ['', '| 언어 | train | val |', '|---|---:|---:|']
    for lang in sorted({r['meta']['language'] for r in records}):
        t.append(f"| {lang} | {sum(r['meta']['language'] == lang and r['meta']['split'] == 'train' for r in records)} | {sum(r['meta']['language'] == lang and r['meta']['split'] == 'val' for r in records)} |")
    t += ['', '| 규칙 (rule_id) | label | 쌍 | 근거 |', '|---|---|---:|---|']
    rc = Counter(p['rule'] for p in pairs)
    for k, (lab, why) in RULES.items(): t.append(f'| {k} | {lab} | {rc[k]} | {why} |')
    nval = sum(r['meta']['split'] == 'val' for r in records)
    t += ['', f"**목표 대비**: 코드 val 목표 150건 이상 → 실제 {nval}건(미달). 선정 기준(RealWorld 6 + 중형 1~2)으로는 검사가 명확한 핸들러 자체가 적다(RealWorld 구현당 2~3개). "
          'val 150건을 채우려면 역할·소유자 검사가 많은 저장소를 val 전용으로 2~4개 더 넣어야 한다.', '',
          '## 탐지와 제외\n',
          f"검사 패턴(403·Forbidden·PreAuthorize·is_superuser·소유자 비교·소유자 필터 등) 탐지 {detect['hits']}줄 = 채택 핸들러 안 {detect['adopted']} + 제외 규칙 {detect['excluded']} + 미설명 0. "
          '탐지된 줄이 채택·제외 어느 쪽에도 속하지 않으면 빌더가 중단한다.', '', '| 저장소 | 파일 | 제외 사유 |', '|---|---|---|']
    for r, f, rx, why in EXCLUDE: t.append(f"| {r} | {f or '(전체)'} | {why} |")
    t += ['', f'변형 생성 후 제외(문법 실패·검사 잔존·무변화): {len(excluded)}건' + ''.join(f"\n- {e['key']}: {e['reason']}" for e in excluded), '',
          '## 변형 규칙\n',
          '- 검사 문장(if 블록·애너테이션·의존성 인자·쿼리 소유자 필터)과 거기에 붙은 주석, 검사에만 쓰이던 조회 줄(Gin의 요청자·존재 조회)을 지운다. Rails의 `if 소유자 … else 403 end`는 본문만 남기고 한 단계 내어쓴다.',
          '- 지운 자리에 빈 줄이 겹치면 하나로 줄인다. 그 밖의 줄은 바이트 동일(발췌 공통 들여쓰기 제거는 원본·변형 같게 적용).',
          '- 원본 발췌의 검사 헬퍼(Spring `AuthorizationService`, FastAPI `get_current_active_superuser`)는 변형 핸들러가 더 이상 부르지 않으므로 변형 발췌에서 빠진다.',
          '- 수정한 파일 전체를 tree-sitter(언어별 문법)로 파싱해 ERROR/MISSING 노드가 없을 때만 채택, Python은 `ast.parse`도 통과해야 한다. Go·Java·TS는 컴파일러가 없어 파서 수준 검사다(미사용 변수 같은 컴파일 오류는 확인하지 않음).',
          '- OAS: petclinic-rest는 저장소 `openapi.yml`의 operation 발췌 + 참조 스키마(명세에 security 선언 없음 → security_state=unknown). 나머지는 라우트·경로 파라미터만으로 만든 최소 OAS(description 빈 문자열, summary 없음, 라우트 인증 미들웨어가 있어 bearer security 선언 → declared). 원본·변형의 OAS는 같다.', '',
          '## 주의 (학습 투입 전 결정 필요)\n',
          f"- **변형 label의 근거**: 지시대로 변형 label = 원본 label이다. data-v2 기준은 '검사가 빠져도 경로·스키마로 의도가 드러나면 그 정책, 아니면 manual'이다. "
          f"petclinic-rest 변형 {pc['petclinic_rest']}건(`@PreAuthorize`만 제거)은 경로·명세(security 선언 없음)로 역할을 읽을 근거가 없고, RealWorld 변형(빈 description의 최소 OAS)도 경로만으로는 owner_match 근거가 약하다. "
          '검수 시트의 `variant_label_inferable_from_path_schema` 열로 판정한 뒤 변형 label을 유지할지 정해야 한다.',
          f"- **분포 쏠림**: train 레코드 {sum(r['meta']['split'] == 'train' for r in records)}건 중 petclinic-rest(Java·role_required)가 {2 * pc['petclinic_rest']}건이다. train에는 owner_or_admin이 없고(전부 val의 fastapi_tpl), val은 Python만 있다.",
          '- **val 크기**: 위 목표 대비 참조. 체크포인트·문턱 선택에 쓰기에는 작다.', '',
          '## 사람 검수 시트\n',
          f"`{review['path']}` — 쌍 {review['pairs']}건, (언어, label) 층마다 한 건씩 돌아가며 뽑아 작은 층은 전부 포함(seed 42). 층별: "
          + ', '.join(f'{k} {v}' for k, v in sorted(review['by_stratum'].items())) + '. reviewer 열은 비워 두었다. 검수 결과를 학습·프롬프트 예시에 쓰려면 별도 승인이 필요하다.', '',
          '## 산출물\n']
    for k, v in manifest['outputs'].items(): t.append(f"- `{k}` — {v['records']}건, SHA-256 `{v['sha256']}`")
    t += ['- `datasets/blade/processed/data_v3_stage1/manifest_v3s1.json` — 저장소·커밋·원본 파일 SHA-256·탐지 집계·제외 목록',
          '- 클론: `datasets/blade/raw/opensource/<owner>_<repo>/` (gitignore, 경로·커밋만 기록)', '',
          f"해시 가드(시작·종료): data-v1 {', '.join(guards['end_v1'].values())} / data-v2 {', '.join(guards['end_v2'].values())}. test_v30은 읽기만 했다. 학습·API 라벨링 없음."]
    (REP_DIR / 'stage1_report.md').write_text('\n'.join(t) + '\n', encoding='utf-8', newline='\n')


if __name__ == '__main__':
    recs, prs = build()
    print(len(prs), 'pairs', len(recs), 'records', Counter((p['split'], p['label']) for p in prs))
