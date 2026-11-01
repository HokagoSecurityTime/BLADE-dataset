"""Render source-reviewed proposals; no model calls and no ground-truth export.

CURATED decisions below were made by reading cloned source, not by a classifier.
Unreviewed/ambiguous authorization remains explicitly unresolved for a human.
"""
from __future__ import annotations
import ast
from collections import Counter
import json
from pathlib import Path
import re

from training.data.sources.vuln_apis import ROOT, location, read

BASE = ROOT / 'datasets/blade/raw/vuln_apis'
# service, method, path, proposal, rationale, [(relative source, exact anchor)]
CURATED: list[tuple] = []


def decision(service: str, method: str, path: str, label: str, reason: str, *refs: tuple[str, str]) -> None:
    CURATED.append((service, method, path, label, reason, refs))


for path, function in [('/me', 'def me():'), ('/users/v1/{username}/email', 'def update_email(username):'), ('/users/v1/{username}/password', 'def update_password(username):')]:
    decision('VAmPI', 'GET' if path == '/me' else 'PUT', path, 'owner_match', 'JWT subject로 사용자를 선택하는 정상 분기. password의 vuln 분기는 타인 사용자명을 허용한다.', ('api_views/users.py', function), ('api_views/users.py', "user = User.query.filter_by(username=resp['sub']).first()"))
decision('VAmPI', 'DELETE', '/users/v1/{username}', 'role_required', '토큰 검증 후 user.admin만 삭제 허용.', ('api_views/users.py', 'if user.admin:'))
decision('VAmPI', 'GET', '/books/v1/{book_title}', 'owner_match', 'README가 책 비밀은 소유자만 열람하도록 명시하며 정상 분기는 user와 제목을 함께 필터링.', ('api_views/books.py', 'book = Book.query.filter_by(user=user, book_title=str(book_title)).first()'), ('README.md', 'only the owner of the book'))
decision('VAmPI', 'POST', '/books/v1', 'owner_match', '인증된 사용자 ID로 새 책의 소유자를 고정.', ('api_views/books.py', 'user_id=user.id)'))
for path, anchor in [('/users/v1/login', 'def login_user():'), ('/users/v1/register', 'def register_user():')]:
    decision('VAmPI', 'POST', path, 'public', '로그인·가입 진입점으로 선행 사용자 토큰을 요구하지 않음. 인증 수행과 인가 분류를 구분.', ('api_views/users.py', anchor), ('README.md', 'an unregistered user'))

JAVA = 'services/identity/src/main/java/com/crapi/'
decision('crAPI', 'GET', '/identity/api/v2/vehicle/{vehicleId}/location', 'owner_match', 'Challenge 1이 타인 차량 위치 노출을 BOLA로 명시. 컨트롤러는 carId만 서비스로 전달.', (JAVA + 'controller/VehicleController.java', 'public ResponseEntity<?> getLocationBOLA'), ('docs/challenges.md', 'Challenge 1 - Access details'))
decision('crAPI', 'GET', '/workshop/api/mechanic/mechanic_report', 'owner_match', 'Challenge 2의 타인 정비 보고서 열람. JWT 인증은 있으나 report_id 조회에 소유자 필터가 없음.', ('services/workshop/crapi/mechanic/views.py', 'service_request = ServiceRequest.objects.filter(id=report_id).first()'), ('docs/challenges.md', 'Challenge 2 - Access mechanic'))
decision('crAPI', 'GET', '/workshop/api/shop/orders/all', 'owner_match', '인증 데코레이터가 전달한 user로 주문을 필터링.', ('services/workshop/crapi/shop/views.py', 'orders = Order.objects.filter(user=user)'))
decision('crAPI', 'DELETE', '/identity/api/v2/admin/videos/{video_id}', 'role_required', 'Challenge 7이 admin 엔드포인트의 타인 영상 삭제를 BFLA로 명시.', ('docs/challenges.md', 'Leverage the predictable nature of REST APIs to find an admin endpoint'))

for resource, file, noun in [('Addresss', 'address.ts', 'Address'), ('Cards', 'payment.ts', 'Card')]:
    for method, path, anchor in [('GET', f'/api/{resource}', f'{noun}Model.findAll('), ('GET', f'/api/{resource}/{{id}}', f'{noun}Model.findOne('), ('DELETE', f'/api/{resource}/{{id}}', f'{noun}Model.destroy(')]:
        decision('juice-shop', method, path, 'owner_match', '쿼리 UserId를 appendUserId 미들웨어가 JWT 사용자 ID로 덮어쓰므로 요청 본문 소유자 위조와 구분.', ('routes/' + file, anchor), ('lib/insecurity.ts', 'req.body.UserId = authenticatedUsers.tokenMap'))
decision('juice-shop', 'GET', '/rest/basket/{id}', 'owner_match', 'basketAccessChallenge가 다른 사용자의 장바구니 조회를 취약점으로 명시하며 핸들러는 basket id만 조회.', ('routes/basket.ts', 'const basket = await BasketModel.findOne'), ('data/static/challenges.yml', "description: 'View another user''s shopping basket.'"))

for path, anchor in [('/api/user/info', "db.collection('users').find( { _id : req.user.user._id }"), ('/api/user/pictures', "db.collection('pictures').find({ creator_id : req.user.user._id}"), ('/api/user/likes', "db.collection('likes').find({ user_id : req.user.user._id}"), ('/api/user/loves', "db.collection('loves').find({ user_id : req.user.user._id}")]:
    decision('Pixi', 'GET', path, 'owner_match', 'api_token_check에서 JWT 검증 후 req.user를 설정하고 현재 사용자 ID로 데이터를 필터링.', ('api/api.js', anchor), ('api/api.js', 'req.user = user;'))
decision('DVWS-node', 'GET', '/v2/notes', 'owner_match', 'JWT에서 추출한 result.user로 목록 쿼리를 제한.', ('src/controllers/notes.js', 'const notes = await Note.find({ user: result.user }'))
decision('DVWS-node', 'POST', '/v2/notes', 'owner_match', 'JWT subject에 해당하는 result.user로 생성 노트의 소유자 고정.', ('src/controllers/notes.js', 'var new_note = new Note({ name: body.name'))
for method, anchor in [('GET', 'const wallet = await WalletModel.findOne'), ('PUT', 'await WalletModel.increment')]:
    decision('juice-shop', method, '/rest/wallet/balance', 'owner_match', 'JWT로 덮어쓴 UserId만 지갑 조회·증액에 사용.', ('routes/wallet.ts', anchor), ('lib/insecurity.ts', 'req.body.UserId = authenticatedUsers.tokenMap'))
decision('crAPI', 'GET', '/identity/api/v2/vehicle/vehicles', 'owner_match', '차량 서비스가 현재 사용자의 owner_id로 차량 목록 조회.', (JAVA + 'service/Impl/VehicleServiceImpl.java', 'vehicleDetailsRepository.findAllByOwner_id'))
for method, path, file, anchor in [
    ('GET', '/rest/order-history', 'orderHistory.ts', 'const order = await ordersCollection.find({ email: updatedEmail })'),
    ('GET', '/rest/saveLoginIp', 'saveLoginIp.ts', 'const user = await UserModel.findByPk(loggedInUser.data.id)'),
    ('GET', '/rest/user/whoami', 'currentUser.ts', 'user = security.authenticatedUsers.get(req.cookies.token)'),
    ('GET', '/rest/user/change-password', 'changePassword.ts', 'const loggedInUser = security.authenticatedUsers.get(token)'),
    ('POST', '/profile/image/url', 'profileImageUrlUpload.ts', 'const user = await UserModel.findByPk(loggedInUser.data.id)'),
    ('POST', '/profile/image/file', 'profileImageFileUpload.ts', 'const user = await UserModel.findByPk(loggedInUser.data.id)'),
    ('POST', '/rest/user/data-export', 'dataExport.ts', 'reviews = await db.reviewsCollection.find({ author: email })'),
    ('GET', '/rest/2fa/status', '2fa.ts', 'export async function status'),
    ('POST', '/rest/2fa/setup', '2fa.ts', 'export async function setup'),
    ('POST', '/rest/2fa/disable', '2fa.ts', 'export async function disable'),
]:
    decision('juice-shop', method, path, 'owner_match', '핸들러가 인증 토큰의 현재 사용자로 대상을 선택하거나 계정 작업을 수행.', ('routes/' + file, anchor))
for method, path in [('GET', '/rest/order-history/orders'), ('PUT', '/rest/order-history/{id}/delivery-status')]:
    decision('juice-shop', method, path, 'role_required', '등록된 isAccounting 미들웨어가 서명 검증 후 accounting 역할을 요구.', ('lib/insecurity.ts', 'decodedToken?.data?.role === roles.accounting'), ('server.ts', "security.isAccounting(), utils.asyncHandler("))
for method, path, file in [('PATCH', '/rest/products/reviews', 'updateProductReviews.ts'), ('PUT', '/rest/products/{id}/reviews', 'createProductReviews.ts')]:
    decision('juice-shop', method, path, 'owner_match', 'forgedReviewChallenge가 타인 명의 리뷰 작성·수정을 취약 동작으로 명시.', ('routes/' + file, 'challenges.forgedReviewChallenge'), ('data/static/challenges.yml', "description: 'Post a product review as another user"))
decision('juice-shop', 'POST', '/api/BasketItems', 'owner_match', '현재 사용자의 bid와 요청 BasketId 비교가 있으나 중복 파라미터로 확인 값과 사용 값이 달라지는 challenge.', ('routes/basketItems.ts', "Number(user.bid) != Number(basketIds[0])"), ('data/static/challenges.yml', "description: 'Put an additional product into another user"))
decision('juice-shop', 'PUT', '/api/BasketItems/{id}', 'owner_match', 'basketManipulateChallenge가 다른 사용자의 장바구니 변경을 명시.', ('routes/basketItems.ts', 'user.bid != req.body.BasketId'), ('data/static/challenges.yml', "description: 'Put an additional product into another user"))
for path in ['/api/Deliverys', '/api/Deliverys/{id}']:
    decision('juice-shop', 'GET', path, 'public', '공개 배송 옵션 조회; deluxe는 가격 차이일 뿐 접근 조건이 아니며 등록 미들웨어에 인증 요구 없음.', ('routes/delivery.ts', 'price: security.isDeluxe(req) ? method.deluxePrice : method.price'), ('server.ts', "app.get('/api/Deliverys"))
decision('juice-shop', 'GET', '/rest/products/{id}/reviews', 'public', '사용자가 undefined여도 리뷰 목록을 반환; 익명은 좋아요 기능만 제한.', ('routes/showProductReviews.ts', 'user === undefined || reviews[i].likedBy.includes(user.data.email)'))
decision('juice-shop', 'POST', '/api/Users', 'public', '서버가 명시적으로 POST를 신규 가입 진입점으로 허용.', ('server.ts', 'Only POST is allowed in order to register a new user'))
decision('juice-shop', 'POST', '/rest/user/login', 'public', '로그인 진입점은 credentials로 인증하고 새 토큰 발급.', ('routes/login.ts', 'const token = security.authorize(authenticatedUser)'))
decision('juice-shop', 'POST', '/rest/memories', 'owner_match', 'JWT 사용자 UserId를 강제로 붙인 뒤 새 메모리 소유자로 저장.', ('routes/memory.ts', 'UserId: req.body.UserId'), ('server.ts', "app.post('/rest/memories'"))
decision('Pixi', 'POST', '/api/picture/upload', 'owner_match', '검증된 JWT 사용자 ID를 업로드 사진 creator_id로 저장.', ('api/api.js', "'creator_id': req.user.user._id"))
decision('Pixi', 'PUT', '/api/user/edit_info', 'owner_match', 'JWT 사용자 _id로 프로필 갱신; admin필드 mass assignment는 별도 취약성.', ('api/api.js', '{ _id : Number(req.user.user._id) }, { $set: objForUpdate }'))
for path in ['/api/user/login', '/api/user/register', '/api/login', '/api/register']:
    decision('Pixi', 'POST', path, 'public', '가입·로그인 진입점은 api_authenticate/api_register를 호출하며 선행 토큰을 요구하지 않음.', ('api/api.js', "app.post('" + path + "'"))


for method, path, file, anchor, reason in [
    ('GET', '/v2/notes/{noteId}', 'notes.js', 'const note = await Note.findById(parseInt(req.params.noteId))', '노트 생성·목록의 사용자 귀속과 대조. 상세조회는 ID만 사용하며 JWT 검사만으로 소유 검증되지 않음.'),
    ('PUT', '/v2/notes/{noteId}', 'notes.js', 'const note = await Note.findOneAndUpdate({name: req.params.noteId }', '개인 노트 갱신에 소유 필터 없음; 목록 user 필터와 대조.'),
    ('DELETE', '/v2/notes/{noteId}', 'notes.js', 'await Note.deleteOne({ name: req.params.noteId })', '개인 노트 삭제에 소유 필터 없음; 목록 user 필터와 대조.'),
    ('POST', '/v2/notes/import/xml', 'notes.js', 'user: result.user', 'JWT 사용자에게 가져온 노트 귀속.'),
    ('POST', '/v2/passphrase', 'passphrase.js', 'const saveQuery =', 'JWT 사용자에게 개인 비밀 귀속.'),
    ('GET', '/v2/passphrase/{username}', 'passphrase.js', 'SELECT passphrase, reminder FROM passphrases WHERE username', '개인 비밀 저장의 JWT 사용자 귀속과 대조; 임의 username 조회는 소유 검토 대상.'),
    ('GET', '/v2/users/profile', 'users.js', 'const user = await User.findOne({ username: decoded.user });', 'JWT subject로 프로필 선택.'),
    ('POST', '/v2/users/profile/import/xml', 'users.js', '{ username: targetUser },', '자기 프로필 조회와 대조. XML username 임의 타깃 갱신은 인가 검토 대상.'),
    ('POST', '/download', 'files.js', 'var filename = path.resolve(', 'JWT 사용자 전용 디렉터리 경로 구성. 경로 탈출 취약점은 별도 문제.'),
    ('POST', '/upload', 'files.js', "uploadPath = __dirname + '/../../public/uploads/' + result.user", 'JWT 사용자 전용 디렉터리 업로드.'),
    ('GET', '/upload', 'files.js', "uploadPath = __dirname + '/../../public/uploads/' + \"/\" + result.user", 'JWT 사용자 전용 디렉터리 목록.'),
]:
    refs = [('src/controllers/' + file, anchor)]
    if path == '/v2/notes/{noteId}':
        refs += [('src/controllers/notes.js', 'const notes = await Note.find({ user: result.user }'), ('src/middleware/auth.js', 'req.decoded = result;')]
    if path == '/v2/passphrase/{username}':
        refs += [('src/controllers/passphrase.js', 'const saveQuery =')]
    decision('DVWS-node', method, path, 'owner_match', reason, *refs)
decision('DVWS-node', 'POST', '/v2/admin/create-user', 'role_required', 'JWT 사용자 조회 후 admin 검사 실패 시403.', ('src/controllers/users.js', 'if (!user || !user.admin) return res.status(403)'))


def cite(service: str, file: str, anchor: str, after: str | None = None) -> dict:
    path = BASE / service / file
    lines = read(path).splitlines()
    offset = next((i for i, line in enumerate(lines) if after and after in line), -1)
    hits = [i for i, line in enumerate(lines) if anchor in line and i >= offset]
    if not hits:
        raise ValueError(f'Missing reviewed evidence: {service}/{file}: {anchor}')
    start = hits[0] + 1
    return location(path, BASE / service, start, start + 2, 'reviewed_evidence')


def django_mapping(row: dict) -> None:
    if row['service'] != 'crAPI' or not row['path'].startswith('/workshop/api/'):
        return
    tail = row['path'][len('/workshop/api/'):]
    area, _, route = tail.partition('/')
    folder = 'user' if area == 'management' else area
    base = BASE / 'crAPI/services/workshop/crapi' / folder
    urlfile, views = base / 'urls.py', base / 'views.py'
    if not urlfile.exists() or not views.exists():
        return
    classes = {}
    for node in ast.parse(read(views)).body:
        if isinstance(node, ast.ClassDef):
            classes[node.name] = node
    for node in ast.walk(ast.parse(read(urlfile))):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in {'re_path', 'path'} or len(node.args) < 2:
            continue
        pattern, view = node.args[:2]
        if not isinstance(pattern, ast.Constant) or not isinstance(pattern.value, str) or not isinstance(view, ast.Call):
            continue
        normalized = re.sub(r'\(\?P<(\w+)>[^)]+\)', r'{\1}', pattern.value).strip('^$').rstrip('/')
        if normalized != route.rstrip('/'):
            continue
        owner = view.func.value if isinstance(view.func, ast.Attribute) else None
        cls = classes.get(owner.attr) if isinstance(owner, ast.Attribute) else None
        if cls:
            for method in cls.body:
                if isinstance(method, ast.FunctionDef) and method.name == row['method'].lower():
                    row['source_locations'].append(location(views, BASE / 'crAPI', method.lineno, method.end_lineno, 'django_handler'))
                    row['source_locations'].append(location(urlfile, BASE / 'crAPI', node.lineno, node.end_lineno, 'django_route'))
                    row['meta']['source_mapped'] = True


def exclusion(row: dict) -> str | None:
    path, service = row['path'], row['service']
    if service == 'Pixi' and path in {'/', '/about', '/ctf', '/login', '/logout', '/register', '/pixi', '/pictures', '/secret'}:
        return 'UI/bootstrap/static route; backend API operations retained.'
    if service == 'juice-shop' and (path.startswith(('/snippets', '/rest/continue-code', '/rest/web3', '/the/', '/this/', '/we/')) or path in {'/', '/metrics', '/profile', '/promotion', '/redirect', '/video', '/file-upload', '/rest/products/search', '/rest/languages', '/rest/country-mapping', '/rest/captcha', '/rest/image-captcha', '/rest/repeat-notification', '/rest/admin/application-configuration', '/rest/admin/application-version', '/api/Challenges', '/api/Hints', '/api/Hints/{id}'}):
        return 'Static/UI/search/challenge metadata or auxiliary puzzle route; outside object authorization evaluation.'
    if service == 'DVWS-node' and path in {'/', '/openAPI-spec.json', '/v1/info', '/v2/info', '/v2/release/{release}', '/v2/sysinfo/{command}', '/v2/users/ldap-search'}:
        return 'Landing/specification/system information or command/LDAP injection target; not object authorization.'
    if service == 'VAmPI' and path in {'/', '/createdb'}:
        return 'Landing or database initialization utility.'
    return None


def render(rows: list[dict]) -> str:
    def cell(value: object) -> str:
        return str(value).replace('|', '&#124;').replace('\n', '<br>')
    text = ['# Test 후보 — 소스 검토용', '', '제안은 에이전트의 소스 검토 결과이며 확정 정답이 아닙니다. 미해결은 근거 부족으로 표시합니다. 확정 label·비고 열은 사람이 작성합니다.', '', '| id | source | service | method | path | 제안 label | 근거(소스 파일:줄 + 코드) | controller 신호 | known_vulnerable | 확정 label | 비고 |', '|---|---|---|---|---|---|---|---|---|---|---|']
    for row in rows:
        evidence = row.get('review_evidence', [])
        detail = '<br>'.join(f"{r['file']}:{r['start_line']}<br>{r['excerpt']}" for r in evidence)
        detail += '<br>' + row['proposal_reason']
        if row['meta'].get('exclude'):
            detail += '<br>EXCLUDE: ' + row['meta']['exclude_reason']
        text.append('| ' + ' | '.join(cell(x) for x in [row['id'], 'vuln', row['service'], row['method'], row.get('effective_path', row['path']), row['proposed_label'], detail, json.dumps(row['controller_signals']), row['meta']['known_vulnerable'], '', '']) + ' |')
    return '\n'.join(text) + '\n'


def strengthen(row: dict) -> None:
    """Additional static evidence. Local absence never proves global absence."""
    repo = BASE / row['service']
    if row['service'] == 'crAPI' and row['path'].startswith('/community/'):
        routefile = repo / 'services/community/api/router/routes.go'
        normalized = re.sub(r'\{[^}]+\}', '{}', row['path'])
        for line_no, line in enumerate(read(routefile).splitlines(), 1):
            match = re.search(r'HandleFunc\("([^"]+)".*controller\.(\w+).*Methods\("(\w+)"', line)
            if not match or match[3] != row['method'] or re.sub(r'\{[^}]+\}', '{}', match[1]) != normalized:
                continue
            row['source_locations'].append(location(routefile, repo, line_no, line_no, 'go_route'))
            for file in sorted((repo / 'services/community/api/controllers').glob('*.go')):
                if file.name.endswith('_test.go'):
                    continue
                lines = read(file).splitlines()
                for i, value in enumerate(lines):
                    if re.search(r'func\s+\([^)]*\)\s+' + re.escape(match[2]) + r'\(', value):
                        row['source_locations'].append(location(file, repo, i + 1, min(i + 30, len(lines)), 'go_handler'))
                        row['meta']['source_mapped'] = True
    row['handler_excerpts_50'] = []
    row['authorization_evidence'] = []
    pattern = re.compile(r'PreAuthorize|hasRole|getUserFromToken|userId\s*==|user_id\s*==|owner_id|ownerId|UserId|jwt_auth_required|SetMiddlewareAuthentication')
    for source in row['source_locations']:
        file = repo / source['file']
        lines = read(file).splitlines()
        if source['kind'] not in {'annotation_handler', 'go_handler', 'django_handler', 'handler', 'referenced_handler_or_middleware'}:
            continue
        start = source['start_line']
        end = start + 49 if source['kind'] in {'annotation_handler', 'go_handler'} else source['end_line']
        excerpt = lines[start - 1:end]
        # Stop before the next Java route/Go function to avoid neighboring evidence.
        for i, line in enumerate(excerpt[1:], 1):
            if re.search(r'@(Get|Post|Put|Delete|Patch)Mapping|^func\s', line):
                excerpt = excerpt[:i]
                break
        if source['kind'] in {'annotation_handler', 'go_handler'}:
            depth, entered = 0, False
            for i, line in enumerate(excerpt):
                # Exclude braces inside string literals and comments from block counting.
                clean = re.sub(r'"(?:\\.|[^"\\])*"|//.*', '', line)
                depth += clean.count('{') - clean.count('}')
                entered = entered or '{' in clean
                if entered and depth == 0:
                    excerpt = excerpt[:i + 1]
                    break
        row['handler_excerpts_50'].append({'file': source['file'], 'start_line': start, 'end_line': start + len(excerpt) - 1, 'excerpt': '\n'.join(excerpt)})
        for offset, line in enumerate(excerpt):
            if pattern.search(line):
                row['authorization_evidence'].append({'file': source['file'], 'line': start + offset, 'code': line.strip(), 'status': 'static_hint_not_policy_proof'})
    row['meta']['code_review_status'] = ('available_static_auth_hints' if row['authorization_evidence'] else 'available_no_recognized_local_auth_hint') if row['handler_excerpts_50'] else 'handler_code_unavailable'
    if row['service'] == 'crAPI':
        suffix = row['path'].removeprefix('/identity/api/auth/')
        allowed = {'login', 'signup', 'forget-password', 'jwks.json', 'v2/check-otp', 'v3/check-otp', 'v2.7/user/login-with-token', 'v4.0/user/login-with-token', 'verify'}
        if (row['path'].startswith('/identity/api/auth/') and suffix in allowed) or row['path'] == '/identity/health_check':
            row['proposed_label'] = 'public'
            row['proposal_reason'] = '인증 시작·복구·검증 또는 health 진입점. WebSecurityConfig가 명시적으로 permitAll; 인증 자체의 성공 조건과 인가 분류는 구분.'
            anchor = '/identity/health_check' if row['path'] == '/identity/health_check' else '/identity/api/auth/**'
            row['review_evidence'] = [cite('crAPI', JAVA + 'config/WebSecurityConfig.java', anchor)] + [{**s, 'excerpt': '\n'.join(s['excerpt'].splitlines()[:3]), 'end_line': min(s['end_line'], s['start_line'] + 2)} for s in row['source_locations'][:1]]
            row['meta']['needs_human_judgment'] = False
            row['meta']['proposal_basis'] = 'explicit_preauth_security_configuration'
        elif row['meta']['needs_human_judgment'] and ('/admin/' in row['path'] or '/management/' in row['path']):
            row['proposed_label'] = 'role_required'
            row['proposal_reason'] = 'admin/management 경로의 역할 후보 제안. 실제 역할 검증 확인 전이며 경로 추정이므로 사람이 판단해야 함.'
            row['meta']['proposal_basis'] = 'path_heuristic_unverified_role'


def main() -> None:
    rows = [json.loads(line) for line in (ROOT / 'verification/vuln_collection_preview.jsonl').read_text(encoding='utf-8').splitlines()]
    decisions = {(s, m, p): (label, reason, refs) for s, m, p, label, reason, refs in CURATED}
    for row in rows:
        django_mapping(row)
        row['effective_path'] = ('/api' + row['path']) if row['service'] == 'DVWS-node' and any(s['file'].startswith('src/routes/') for s in row['source_locations']) else row['path']
        row['meta']['exclude_reason'] = exclusion(row)
        row['meta']['exclude'] = row['meta']['exclude_reason'] is not None
        row['meta']['review_source'] = 'agent_direct_source_review'
        key = row['service'], row['method'], row['path']
        if key in decisions:
            label, reason, refs = decisions[key]
            row['proposed_label'], row['proposal_reason'] = label, reason
            row['review_evidence'] = [cite(row['service'], *ref) for ref in refs]
            if row['service'] == 'VAmPI' and row['path'] in {'/me', '/users/v1/{username}/email', '/users/v1/{username}/password'}:
                fn = {'/me': 'def me():', '/users/v1/{username}/email': 'def update_email(username):', '/users/v1/{username}/password': 'def update_password(username):'}[row['path']]
                row['review_evidence'][-1] = cite('VAmPI', 'api_views/users.py', "user = User.query.filter_by(username=resp['sub']).first()", fn)
            if row['service'] == 'juice-shop' and row['path'] in {'/rest/order-history/orders', '/rest/order-history/{id}/delivery-status'}:
                row['review_evidence'][-1] = cite('juice-shop', 'server.ts', "app." + row['method'].lower() + "('" + row['path'].replace('{id}', ':id') + "'")
            if key == ('crAPI', 'DELETE', '/identity/api/v2/admin/videos/{video_id}'):
                row['review_evidence'].append(cite('crAPI', JAVA + 'controller/ProfileController.java', 'profileService.deleteAdminProfileVideo'))
            row['meta']['needs_human_judgment'] = False
            if key == ('crAPI', 'GET', '/identity/api/v2/vehicle/{vehicleId}/location'):
                row['review_evidence'] += [cite('crAPI', JAVA + 'service/Impl/VehicleServiceImpl.java', 'vehicleDetailsRepository.findByUuid'), cite('crAPI', 'docs/challengeSolutions.md', '/identity/api/v2/vehicle/<vehicleid>/location')]
            if key == ('VAmPI', 'GET', '/books/v1/{book_title}'):
                row['review_evidence'].append(cite('VAmPI', 'api_views/books.py', 'if vuln:  # Broken Object Level Authorization'))
            if key == ('juice-shop', 'GET', '/rest/basket/{id}'):
                row['review_evidence'].append(cite('juice-shop', 'server.ts', "app.use('/rest/basket/:id', security.isAuthorized())"))
        else:
            row['proposed_label'] = 'manual_review_required'
            row['proposal_reason'] = '근거 없음, 사람 판단 필요: 현재 수집한 핸들러·미들웨어·모델 근거만으로 7종 중 의도 정책을 확정하지 않음.'
            row['review_evidence'] = [{**s, 'excerpt': '\n'.join(s['excerpt'].splitlines()[:3]), 'end_line': min(s['end_line'], s['start_line'] + 2)} for s in row['source_locations'][:1]]
            row['meta']['needs_human_judgment'] = True
        if key in {('crAPI', 'GET', '/identity/api/v2/vehicle/{vehicleId}/location'), ('crAPI', 'GET', '/workshop/api/mechanic/mechanic_report'), ('crAPI', 'DELETE', '/identity/api/v2/admin/videos/{video_id}'), ('juice-shop', 'GET', '/rest/basket/{id}'), ('VAmPI', 'GET', '/books/v1/{book_title}')}:
            row['meta']['known_vulnerable'] = True
            row['meta']['vulnerability_sources'] = row['review_evidence']
        if key in {
            ('juice-shop', 'PATCH', '/rest/products/reviews'),
            ('juice-shop', 'PUT', '/rest/products/{id}/reviews'),
            ('juice-shop', 'POST', '/api/BasketItems'),
            ('juice-shop', 'PUT', '/api/BasketItems/{id}'),
        }:
            # These curated decisions link actual challenge assertions in handlers
            # to the corresponding authored challenge description, not path guesses.
            row['meta']['known_vulnerable'] = True
            row['meta']['vulnerability_sources'] = row['review_evidence']
        strengthen(row)
    out = ROOT / 'datasets/blade/processed/vuln_review_candidates.jsonl'
    out.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
    retained = [r for r in rows if not r['meta']['exclude']]
    report = {'collected': len(rows), 'retained': len(retained), 'excluded': len(rows) - len(retained), 'services': dict(Counter(r['service'] for r in retained)), 'proposals': dict(Counter(r['proposed_label'] for r in retained)), 'known_vulnerable': sum(r['meta']['known_vulnerable'] for r in retained), 'unresolved': sum(r['meta']['needs_human_judgment'] for r in retained), 'source_mapped': sum(r['meta']['source_mapped'] for r in retained), 'concrete_policy_code_evidence': sum(not r['meta']['needs_human_judgment'] for r in retained), 'confirmed': 0}
    report['code_review_status'] = dict(Counter(r['meta']['code_review_status'] for r in rows))
    report['retained_code_review_status'] = dict(Counter(r['meta']['code_review_status'] for r in retained))
    report['previous_grounded_proposals'] = 68
    (ROOT / 'verification/vuln_review_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
