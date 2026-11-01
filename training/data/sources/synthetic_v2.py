"""data-v2 synthetic additions (2026-10-21 instruction 3-1). Train-only. Never touches test-only services, test.jsonl/test_v30, train_v30/val_v30.

A. Authorization-removed variants for each train-only concrete implementation (orbit_tickets, copper_wallet, campus_records, relay_forum):
   <section>/authonly   — in-handler authentication only, authorization check removed            -> manual_review_required
   <section>/extauth    — authentication outside the handler (Depends / middleware / @PreAuthorize), no authorization -> manual_review_required
   <section>/extguard   — authentication outside the handler + the original authorization check kept  -> original concrete label (control)
B. Four new train-only services with framework and authorization-style diversity:
   harbor_manifests (Django REST: decorators + ORM filter), pixel_gallery (NestJS: guards), meadow_plots (Gin: middleware), atlas_leases (Rails: before_action + ORM scope).
   Each: 18 endpoints (public 2, owner 2, owner_or_admin 4, tenant 2, role 2, membership 4, compound manual 2); archive variants omit the authorization check.
OpenAPI for non-FastAPI services is a script-generated static projection (no framework export available offline); recorded as oas_status=script_projection.
"""
from __future__ import annotations
import argparse, hashlib, json, re
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / 'datasets/blade/raw/synthetic'; V2 = ROOT / 'datasets/blade/raw/synthetic_v2'
MANUAL = 'manual_review_required'
MANUAL_AUTHONLY = 'Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.'
REASON = {'public': 'Intentionally anonymous reference catalogue.', 'owner_match': 'Only the record owner may read it.', 'owner_or_admin': 'The record owner or an administrator may read it.',
          'tenant_match': 'Caller and record must share a tenant.', 'role_required': 'Only administrators may read this operational resource.',
          'membership_required': 'Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.',
          MANUAL: 'Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.'}
TRAIN_BASE = {'orbit_tickets': ('reservations', 'fastapi'), 'copper_wallet': ('transfers', 'express'), 'campus_records': ('transcripts', 'spring'), 'relay_forum': ('threads', 'fastapi')}
NEW = {'harbor_manifests': ('manifests', 'django'), 'pixel_gallery': ('artworks', 'nestjs'), 'meadow_plots': ('plots', 'gin'), 'atlas_leases': ('leases', 'rails')}
NEW_SECTIONS = [('catalogue', 'public'), ('drafts', 'owner_match'), ('shared', 'owner_or_admin'), ('moderation', 'owner_or_admin'), ('workspace', 'tenant_match'),
                ('audit', 'role_required'), ('roster', 'membership_required'), ('pins', 'membership_required'), ('council', MANUAL)]
HAS_GROUP = {'relay_forum'}  # base services with group_id/memberships

def write(base, rel, text):
    p = base / rel; p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8', newline='\n') as f: f.write(text)

def sha_files(base):
    return {str(p.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(base.rglob('*')) if p.is_file()}

def projection(name, rows, title_note):
    paths = {}
    for r in rows:
        paths[r['path']] = {'get': {'summary': r['id'].replace('_', ' ').title(), 'description': r['reason'], 'operationId': r['id'],
                                    'parameters': [{'name': 'item_id', 'in': 'path', 'required': True, 'schema': {'type': 'string'}},
                                                   {'name': 'Authorization', 'in': 'header', 'required': False, 'schema': {'type': 'string'}}],
                                    'responses': {'200': {'description': 'Fixture record', 'content': {'application/json': {'schema': {'type': 'object', 'additionalProperties': {'type': 'string'}}}}}}}}
    return {'openapi': '3.0.3', 'info': {'title': name, 'version': '1.0.0', 'description': title_note}, 'paths': paths}

# ----------------------------------------------------------------------------------------------------------------------
# A. variants of the four train-only base services
# ----------------------------------------------------------------------------------------------------------------------
PY_CHECK = {'owner_match': 'principal["id"] != obj["owner_id"]', 'owner_or_admin': 'principal["id"] != obj["owner_id"] and principal["role"] != "admin"',
            'tenant_match': 'principal["tenant_id"] != obj["tenant_id"]', 'role_required': 'principal["role"] != "admin"',
            'membership_required': '(principal["id"], obj["group_id"]) not in MEMBERSHIPS'}
JS_CHECK = {k: v.replace(' != ', ' !== ').replace(' and ', ' && ') for k, v in PY_CHECK.items() if k != 'membership_required'}
JAVA_CHECK = {'owner_match': '!principal.id().equals(obj.get("owner_id"))', 'owner_or_admin': '!principal.id().equals(obj.get("owner_id")) && !principal.role().equals("admin")',
              'tenant_match': '!principal.tenant_id().equals(obj.get("tenant_id"))', 'role_required': '!principal.role().equals("admin")'}

def base_sections(service):
    spec = yaml.safe_load((RAW / service / 'intended_labels.yaml').read_text(encoding='utf-8'))
    out = []
    for ep in spec['endpoints']:
        if ep['id'].endswith('_0') and ep['label'] in PY_CHECK and not ep['reason'].lower().startswith('a premium'):
            out.append((ep['id'].rsplit('_', 2)[-2], ep['label']))
    return out

def variant_rows(service):
    noun, fw = TRAIN_BASE[service]; rows = []
    for section, label in base_sections(service):
        for kind, lab, reason in (('authonly', MANUAL, MANUAL_AUTHONLY), ('extauth', MANUAL, MANUAL_AUTHONLY + ' Authentication is enforced outside the handler.'),
                                  ('extguard', label, REASON[label] + ' Authentication is enforced outside the handler; the authorization check is inside.')):
            rows.append(dict(id=f'{service}_{section}_{kind}', method='GET', path=f'/fixtures/{service}/{noun}/{section}/{kind}/{{item_id}}', label=lab, vulnerable=(lab == MANUAL),
                             reason=reason, variant_kind=kind, base_label=label, auth_style={'authonly': 'inline', 'extauth': 'external', 'extguard': 'external'}[kind]))
    return rows

def fastapi_variants(service, rows):
    group = service in HAS_GROUP
    code = 'from fastapi import FastAPI, Header, HTTPException, Depends\n' + f'app = FastAPI(title={service + "_variants"!r})\n'
    if group:
        code += "PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin'}}\n"
        code += "MEMBERSHIPS = {('alice', 'g_north_hikers'), ('bob', 'g_south_riders')}\n"
        code += 'OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","group_id":"g_north_hikers","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","group_id":"g_south_riders","value":"other secret"}}\n'
    else:
        code += "PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user', 'plan': 'premium'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user', 'plan': 'free'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin', 'plan': 'premium'}}\n"
        code += 'OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","value":"other secret"}}\n'
    code += 'def principal_for(token):\n    return PRINCIPALS.get(token.removeprefix("Bearer "))\n\n'
    code += 'def require_principal(authorization: str = Header(default="")):\n    """Dependency: authentication only (401). It performs no authorization."""\n    principal = principal_for(authorization)\n    if principal is None: raise HTTPException(401)\n    return principal\n\n'
    for r in rows:
        if r['variant_kind'] == 'authonly':
            code += f'@app.get({r["path"]!r}, description={r["reason"]!r})\ndef {r["id"]}(item_id: str, authorization: str = Header(default="")):\n    obj = OBJECTS.get(item_id)\n    if obj is None: raise HTTPException(404)\n    principal = principal_for(authorization)\n    if principal is None: raise HTTPException(401)\n    # Variant: object authorization check removed.\n    return obj\n\n'
        else:
            code += f'@app.get({r["path"]!r}, description={r["reason"]!r})\ndef {r["id"]}(item_id: str, principal: dict = Depends(require_principal)):\n    obj = OBJECTS.get(item_id)\n    if obj is None: raise HTTPException(404)\n'
            code += ('    if ' + PY_CHECK[r['base_label']] + ': raise HTTPException(403)\n') if r['variant_kind'] == 'extguard' else '    # Variant: authentication via dependency only; no authorization check.\n'
            code += '    return obj\n\n'
    return code

def express_variants(service, rows):
    code = ('const express = require("express");\nconst app = express();\n'
            'const principals = {"alice":{"id":"alice","tenant_id":"north","role":"user","plan":"premium"},"bob":{"id":"bob","tenant_id":"south","role":"user","plan":"free"},"admin":{"id":"root","tenant_id":"north","role":"admin","plan":"premium"}};\n'
            'const objects = {"1":{id:"1",owner_id:"alice",tenant_id:"north",value:"fixture secret"},"2":{id:"2",owner_id:"bob",tenant_id:"south",value:"other secret"}};\n'
            'function requireAuth(req, res, next) {\n  // Middleware: authentication only (401). No authorization.\n  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];\n  if (!principal) return res.sendStatus(401);\n  req.principal = principal;\n  next();\n}\n\n')
    for r in rows:
        route = json.dumps(r['path'].replace('{item_id}', ':item_id'))
        if r['variant_kind'] == 'authonly':
            code += f'app.get({route}, function {r["id"]}(req,res) {{\n  const obj = objects[req.params.item_id];\n  if (!obj) return res.sendStatus(404);\n  const principal = principals[(req.headers.authorization || "").replace(/^Bearer /, "")];\n  if (!principal) return res.sendStatus(401);\n  // Variant: object authorization check removed.\n  return res.json(obj);\n}});\n'
        else:
            code += f'app.get({route}, requireAuth, function {r["id"]}(req,res) {{\n  const obj = objects[req.params.item_id];\n  if (!obj) return res.sendStatus(404);\n  const principal = req.principal;\n'
            code += (f'  if ({JS_CHECK[r["base_label"]]}) return res.sendStatus(403);\n') if r['variant_kind'] == 'extguard' else '  // Variant: authentication via middleware only; no authorization check.\n'
            code += '  return res.json(obj);\n});\n'
    code += 'app.listen(8080, "0.0.0.0");\n'
    return code

def spring_variants(service, rows):
    code = ('package fixture;\nimport java.util.Map;\nimport org.springframework.boot.SpringApplication;\nimport org.springframework.boot.autoconfigure.SpringBootApplication;\nimport org.springframework.web.bind.annotation.*;\n'
            'import org.springframework.web.server.ResponseStatusException;\nimport org.springframework.http.HttpStatus;\nimport org.springframework.security.access.prepost.PreAuthorize;\nimport org.springframework.security.core.annotation.AuthenticationPrincipal;\n'
            '@SpringBootApplication\n@RestController\npublic class VariantsApp {\n public static void main(String[] args) { SpringApplication.run(VariantsApp.class,args); }\n record Principal(String id,String tenant_id,String role,String plan) {}\n'
            ' static final Map<String,Principal> principals=Map.of("alice",new Principal("alice","north","user","premium"),"bob",new Principal("bob","south","user","free"),"admin",new Principal("root","north","admin","premium"));\n'
            ' static final Map<String,Map<String,String>> objects=Map.of("1",Map.of("id","1","owner_id","alice","tenant_id","north","value","fixture secret"),"2",Map.of("id","2","owner_id","bob","tenant_id","south","value","other secret"));\n'
            ' // Security config (not shown) maps Bearer tokens to Principal; @PreAuthorize("isAuthenticated()") enforces authentication only.\n')
    for r in rows:
        if r['variant_kind'] == 'authonly':
            code += f' @GetMapping("{r["path"]}")\n public Map<String,String> {r["id"]}(@PathVariable("item_id") String item_id, @RequestHeader(value="Authorization",defaultValue="") String authorization) {{\n  var obj=objects.get(item_id);\n  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);\n  var principal=principals.get(authorization.replaceFirst("^Bearer ",""));\n  if(principal==null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);\n  // Variant: object authorization check removed.\n  return obj;\n }}\n'
        else:
            code += f' @PreAuthorize("isAuthenticated()")\n @GetMapping("{r["path"]}")\n public Map<String,String> {r["id"]}(@PathVariable("item_id") String item_id, @AuthenticationPrincipal Principal principal) {{\n  var obj=objects.get(item_id);\n  if(obj==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND);\n'
            code += (f'  if({JAVA_CHECK[r["base_label"]]}) throw new ResponseStatusException(HttpStatus.FORBIDDEN);\n') if r['variant_kind'] == 'extguard' else '  // Variant: authentication by @PreAuthorize only; no authorization check.\n'
            code += '  return obj;\n }\n'
    return code + '}\n'

def generate_variants(service):
    noun, fw = TRAIN_BASE[service]; rows = variant_rows(service); base = V2 / 'variants' / service
    if base.exists(): raise FileExistsError(base)
    if fw == 'fastapi':
        write(base, 'app_variants.py', fastapi_variants(service, rows)); handler = 'app_variants.py'
        import importlib.util
        spec = importlib.util.spec_from_file_location('variants_' + service, base / handler); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        write(base, 'openapi.json', json.dumps(mod.app.openapi(), indent=2)); oas_status = 'original_export'
    elif fw == 'express':
        write(base, 'app_variants.js', express_variants(service, rows)); handler = 'app_variants.js'
        write(base, 'openapi.json', json.dumps(projection(service + '_variants', rows, 'script-generated static projection (no framework export)'), indent=2)); oas_status = 'script_projection'
    else:
        write(base, 'src/main/java/fixture/VariantsApp.java', spring_variants(service, rows)); handler = 'src/main/java/fixture/VariantsApp.java'
        write(base, 'openapi.json', json.dumps(projection(service + '_variants', rows, 'script-generated static projection (no framework export)'), indent=2)); oas_status = 'script_projection'
    (base / 'schema.sql').write_bytes((RAW / service / 'schema.sql').read_bytes())
    write(base, 'intended_labels.yaml', yaml.safe_dump({'service': service, 'variant_of': service, 'partition': 'train_only', 'oas_status': oas_status, 'endpoints': rows}, sort_keys=False))
    write(base, 'README.md', f'# {service} variants (data-v2)\n\nAuthorization-removed variants of the train-only fixture {service} ({fw}). authonly: in-handler authentication, authorization removed; extauth: authentication outside the handler (dependency/middleware/@PreAuthorize), no authorization; extguard: external authentication plus the original authorization check (control). authonly/extauth are manual_review_required by design. OpenAPI: {oas_status}.\n')
    return rows, handler

# ----------------------------------------------------------------------------------------------------------------------
# B. new train-only services, four frameworks
# ----------------------------------------------------------------------------------------------------------------------
def new_rows(name):
    noun, fw = NEW[name]; rows = []
    for section, label in NEW_SECTIONS:
        for i in range(2):
            rows.append(dict(id=f'{name}_{section}_{i}', method='GET', path=f'/fixtures/{name}/{noun}/{section}/{"current" if i == 0 else "archive"}/{{item_id}}', label=label,
                             vulnerable=(i == 1 and label not in {'public', MANUAL}), reason=REASON[label]))
    return rows

def django_app(name, rows):
    noun = NEW[name][0]
    code = ('from django.http import JsonResponse, Http404\nfrom django.shortcuts import get_object_or_404\nfrom rest_framework.decorators import api_view, permission_classes\nfrom rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny\n'
            'from rest_framework.exceptions import PermissionDenied\nfrom .models import Record, Membership\n\n'
            '# Authentication: DRF TokenAuthentication in settings; @permission_classes([IsAuthenticated]) rejects anonymous callers (401).\n'
            '# IsAdminUser requires request.user.is_staff. Group membership is a Membership(user, group_id) row.\n\n')
    for r in rows:
        label, vul = r['label'], r['vulnerable']
        if label == 'public': perm = 'AllowAny'
        elif label == 'role_required' and not vul: perm = 'IsAdminUser'
        else: perm = 'IsAuthenticated'
        code += f'@api_view(["GET"])\n@permission_classes([{perm}])\ndef {r["id"]}(request, item_id):\n    """{r["reason"]}"""\n'
        if label == 'owner_match' and not vul:
            code += '    obj = get_object_or_404(Record.objects.filter(owner=request.user), pk=item_id)  # ORM filter: owner only\n'
        else:
            code += '    obj = get_object_or_404(Record, pk=item_id)\n'
            if vul: code += '    # Deliberate fixture: object authorization check omitted.\n'
            elif label == 'owner_or_admin': code += '    if obj.owner_id != request.user.id and not request.user.is_staff: raise PermissionDenied()\n'
            elif label == 'tenant_match': code += '    if obj.tenant_id != request.user.profile.tenant_id: raise PermissionDenied()\n'
            elif label == 'membership_required': code += '    if not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()\n'
            elif label == MANUAL: code += '    if obj.tenant_id != request.user.profile.tenant_id or not Membership.objects.filter(user=request.user, group_id=obj.group_id).exists(): raise PermissionDenied()\n'
        code += '    return JsonResponse({"id": obj.pk, "owner_id": obj.owner_id, "tenant_id": obj.tenant_id, "group_id": obj.group_id, "value": obj.value})\n\n'
    urls = 'from django.urls import path\nfrom . import views\nurlpatterns = [\n' + ''.join(f'    path({r["path"].lstrip("/").replace("{item_id}", "<str:item_id>")!r}, views.{r["id"]}),\n' for r in rows) + ']\n'
    models = ('from django.db import models\nfrom django.contrib.auth.models import User\n\nclass Record(models.Model):\n    owner = models.ForeignKey(User, on_delete=models.CASCADE)\n    tenant_id = models.CharField(max_length=64)\n    group_id = models.CharField(max_length=64)\n    value = models.TextField()\n\n'
              'class Membership(models.Model):\n    user = models.ForeignKey(User, on_delete=models.CASCADE)\n    group_id = models.CharField(max_length=64)\n    class Meta:\n        unique_together = ("user", "group_id")\n')
    return {'views.py': code, 'urls.py': urls, 'models.py': models}

def nestjs_app(name, rows):
    guards = ('import { CanActivate, ExecutionContext, Injectable, SetMetadata, UnauthorizedException, ForbiddenException } from "@nestjs/common";\nimport { Reflector } from "@nestjs/core";\n'
              'const PRINCIPALS: Record<string, any> = { alice: { id: "alice", tenantId: "north", role: "user" }, bob: { id: "bob", tenantId: "south", role: "user" }, admin: { id: "root", tenantId: "north", role: "admin" } };\n'
              '@Injectable()\nexport class AuthGuard implements CanActivate {\n  // Authentication only: resolves the Bearer token to a principal or throws 401. No authorization.\n  canActivate(ctx: ExecutionContext): boolean {\n    const req = ctx.switchToHttp().getRequest();\n    const principal = PRINCIPALS[(req.headers.authorization || "").replace(/^Bearer /, "")];\n    if (!principal) throw new UnauthorizedException();\n    req.principal = principal;\n    return true;\n  }\n}\n'
              'export const Roles = (...roles: string[]) => SetMetadata("roles", roles);\n@Injectable()\nexport class RolesGuard implements CanActivate {\n  constructor(private reflector: Reflector) {}\n  canActivate(ctx: ExecutionContext): boolean {\n    const roles = this.reflector.get<string[]>("roles", ctx.getHandler()) || [];\n    const principal = ctx.switchToHttp().getRequest().principal;\n    if (roles.length && !roles.includes(principal.role)) throw new ForbiddenException();\n    return true;\n  }\n}\n')
    code = ('import { Controller, Get, Param, Req, UseGuards, NotFoundException, ForbiddenException } from "@nestjs/common";\nimport { AuthGuard, RolesGuard, Roles } from "./guards";\n'
            'const OBJECTS: Record<string, any> = { "1": { id: "1", ownerId: "alice", tenantId: "north", groupId: "g_north_hikers", value: "fixture secret" }, "2": { id: "2", ownerId: "bob", tenantId: "south", groupId: "g_south_riders", value: "other secret" } };\n'
            'const MEMBERSHIPS = new Set(["alice:g_north_hikers", "bob:g_south_riders"]);\nconst isMember = (userId: string, groupId: string) => MEMBERSHIPS.has(`${userId}:${groupId}`);\n\n@Controller()\nexport class RecordsController {\n')
    for r in rows:
        label, vul = r['label'], r['vulnerable']; route = r['path'].replace('{item_id}', ':itemId')
        deco = ''
        if label != 'public':
            deco = '  @UseGuards(AuthGuard' + (', RolesGuard' if label == 'role_required' and not vul else '') + ')\n'
            if label == 'role_required' and not vul: deco += '  @Roles("admin")\n'
        code += f'  /** {r["reason"]} */\n{deco}  @Get("{route}")\n  {r["id"]}(@Param("itemId") itemId: string, @Req() req: any) {{\n    const obj = OBJECTS[itemId];\n    if (!obj) throw new NotFoundException();\n'
        if label != 'public':
            code += '    const principal = req.principal;\n'
            if vul: code += '    // Deliberate fixture: object authorization check omitted.\n'
            elif label == 'owner_match': code += '    if (principal.id !== obj.ownerId) throw new ForbiddenException();\n'
            elif label == 'owner_or_admin': code += '    if (principal.id !== obj.ownerId && principal.role !== "admin") throw new ForbiddenException();\n'
            elif label == 'tenant_match': code += '    if (principal.tenantId !== obj.tenantId) throw new ForbiddenException();\n'
            elif label == 'membership_required': code += '    if (!isMember(principal.id, obj.groupId)) throw new ForbiddenException();\n'
            elif label == MANUAL: code += '    if (principal.tenantId !== obj.tenantId || !isMember(principal.id, obj.groupId)) throw new ForbiddenException();\n'
        code += '    return obj;\n  }\n\n'
    code += '}\n'
    return {'records.controller.ts': code, 'guards.ts': guards}

def gin_app(name, rows):
    code = ('package main\n\nimport (\n\t"net/http"\n\t"strings"\n\n\t"github.com/gin-gonic/gin"\n)\n\ntype Principal struct{ ID, TenantID, Role string }\ntype Record struct{ ID, OwnerID, TenantID, GroupID, Value string }\ntype memberKey struct{ UserID, GroupID string }\n\n'
            'var principals = map[string]Principal{"alice": {"alice", "north", "user"}, "bob": {"bob", "south", "user"}, "admin": {"root", "north", "admin"}}\n'
            'var objects = map[string]Record{"1": {"1", "alice", "north", "g_north_hikers", "fixture secret"}, "2": {"2", "bob", "south", "g_south_riders", "other secret"}}\n'
            'var memberships = map[memberKey]bool{{"alice", "g_north_hikers"}: true, {"bob", "g_south_riders"}: true}\n\n'
            '// authRequired: authentication only (401). It performs no authorization.\nfunc authRequired() gin.HandlerFunc {\n\treturn func(c *gin.Context) {\n\t\tp, ok := principals[strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")]\n\t\tif !ok {\n\t\t\tc.AbortWithStatus(http.StatusUnauthorized)\n\t\t\treturn\n\t\t}\n\t\tc.Set("principal", p)\n\t\tc.Next()\n\t}\n}\n\n'
            '// requireRole: role check as route middleware (403).\nfunc requireRole(role string) gin.HandlerFunc {\n\treturn func(c *gin.Context) {\n\t\tif c.MustGet("principal").(Principal).Role != role {\n\t\t\tc.AbortWithStatus(http.StatusForbidden)\n\t\t\treturn\n\t\t}\n\t\tc.Next()\n\t}\n}\n\n')
    handlers = ''; routes = 'func main() {\n\tr := gin.Default()\n\tauthed := r.Group("/", authRequired())\n'
    for r in rows:
        label, vul = r['label'], r['vulnerable']; route = r['path'].replace('{item_id}', ':item_id')
        handlers += f'// {r["reason"]}\nfunc {r["id"]}(c *gin.Context) {{\n\tobj, ok := objects[c.Param("item_id")]\n\tif !ok {{\n\t\tc.AbortWithStatus(http.StatusNotFound)\n\t\treturn\n\t}}\n'
        if label != 'public' and not vul and label != 'role_required':
            handlers += '\tp := c.MustGet("principal").(Principal)\n'
            cond = {'owner_match': 'p.ID != obj.OwnerID', 'owner_or_admin': 'p.ID != obj.OwnerID && p.Role != "admin"', 'tenant_match': 'p.TenantID != obj.TenantID',
                    'membership_required': '!memberships[memberKey{p.ID, obj.GroupID}]', MANUAL: 'p.TenantID != obj.TenantID || !memberships[memberKey{p.ID, obj.GroupID}]'}[label]
            handlers += f'\tif {cond} {{\n\t\tc.AbortWithStatus(http.StatusForbidden)\n\t\treturn\n\t}}\n'
        elif vul: handlers += '\t// Deliberate fixture: object authorization check omitted.\n'
        handlers += '\tc.JSON(http.StatusOK, obj)\n}\n\n'
        if label == 'public': routes += f'\tr.GET("{route}", {r["id"]})\n'
        elif label == 'role_required' and not vul: routes += f'\tauthed.GET("{route}", requireRole("admin"), {r["id"]})\n'
        else: routes += f'\tauthed.GET("{route}", {r["id"]})\n'
    routes += '\tr.Run(":8080")\n}\n'
    return {'main.go': code + handlers + routes, 'go.mod': 'module fixture/' + name + '\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.10.0\n'}

def rails_app(name, rows):
    noun = NEW[name][0]
    code = ('class LeasesController < ApplicationController\n  # Authentication outside the actions: before_action :authenticate! (401). It performs no authorization.\n  before_action :authenticate!, except: [' + ', '.join(f':{r["id"]}' for r in rows if r['label'] == 'public') + ']\n'
            '  before_action :require_admin!, only: [' + ', '.join(f':{r["id"]}' for r in rows if r['label'] == 'role_required' and not r['vulnerable']) + ']\n\n')
    for r in rows:
        label, vul = r['label'], r['vulnerable']
        code += f'  # {r["reason"]}\n  def {r["id"]}\n'
        if label == 'owner_match' and not vul:
            code += '    record = current_user.records.find(params[:item_id])  # ORM scope: only the caller\'s own records\n'
        else:
            code += '    record = Record.find(params[:item_id])\n'
            if vul: code += '    # Deliberate fixture: object authorization check omitted.\n'
            elif label == 'owner_or_admin': code += '    head :forbidden and return if record.owner_id != current_user.id && !current_user.admin?\n'
            elif label == 'tenant_match': code += '    head :forbidden and return if record.tenant_id != current_user.tenant_id\n'
            elif label == 'membership_required': code += '    head :forbidden and return unless Membership.exists?(user_id: current_user.id, group_id: record.group_id)\n'
            elif label == MANUAL: code += '    head :forbidden and return if record.tenant_id != current_user.tenant_id || !Membership.exists?(user_id: current_user.id, group_id: record.group_id)\n'
        code += '    render json: record\n  end\n\n'
    code += ('  private\n\n  def authenticate!\n    @current_user = User.find_by(token: request.headers["Authorization"].to_s.delete_prefix("Bearer "))\n    head :unauthorized unless @current_user\n  end\n\n'
             '  def require_admin!\n    head :forbidden unless current_user.admin?\n  end\n\n  def current_user\n    @current_user\n  end\nend\n')
    routes = 'Rails.application.routes.draw do\n' + ''.join(f'  get "{r["path"].replace("{item_id}", ":item_id")}", to: "leases#{r["id"]}"\n' for r in rows) + 'end\n'
    return {'app/controllers/leases_controller.rb': code, 'config/routes.rb': routes}

GENERATORS = {'django': django_app, 'nestjs': nestjs_app, 'gin': gin_app, 'rails': rails_app}
HANDLER_FILE = {'django': 'views.py', 'nestjs': 'records.controller.ts', 'gin': 'main.go', 'rails': 'app/controllers/leases_controller.rb'}
AUTH_STYLE = {'django': 'decorator (@permission_classes) + ORM filter', 'nestjs': 'guards (@UseGuards/@Roles)', 'gin': 'route-group middleware', 'rails': 'before_action + ORM scope'}

def generate_new(name):
    noun, fw = NEW[name]; rows = new_rows(name); base = V2 / name
    if base.exists(): raise FileExistsError(base)
    for rel, text in GENERATORS[fw](name, rows).items(): write(base, rel, text)
    write(base, 'schema.sql', f'CREATE TABLE {name}_{noun} (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, value TEXT NOT NULL);\nCREATE TABLE {name}_memberships (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));\n')
    write(base, 'openapi.json', json.dumps(projection(name, rows, 'script-generated static projection (no framework export)'), indent=2))
    write(base, 'intended_labels.yaml', yaml.safe_dump({'service': name, 'framework': fw, 'authorization_style': AUTH_STYLE[fw], 'partition': 'train_only', 'oas_status': 'script_projection',
                                                        'group_semantics': 'membership_required = (caller_id, record.group_id) in memberships (v3.0 meaning)', 'endpoints': rows}, sort_keys=False))
    write(base, 'README.md', f'# {name} ({fw}, data-v2 train-only)\n\nAuthorization style: {AUTH_STYLE[fw]}. 18 endpoints: public 2, owner_match 2, owner_or_admin 4, tenant_match 2, role_required 2, membership_required 4 (group membership), compound tenant AND membership -> manual_review_required 2. archive variants omit the authorization check (authentication only). Not runnable offline here; OpenAPI is a script-generated projection, not a framework export. Domain "{noun}" does not overlap test-only fixtures.\n')
    return rows

# ----------------------------------------------------------------------------------------------------------------------
# records (train.jsonl format) with handler + external auth code in raw_snippet
# ----------------------------------------------------------------------------------------------------------------------
def excerpt(text, ident, fw):
    """Handler block plus the external authentication/authorization definitions it relies on."""
    lines = text.splitlines()
    if fw in ('fastapi', 'django'):
        d = next(i for i, l in enumerate(lines) if l.startswith('def ' + ident + '(')); start = d
        while start > 0 and lines[start - 1].startswith('@'): start -= 1
        end = next((i for i in range(d + 1, len(lines)) if lines[i].strip() and not lines[i].startswith((' ', '\t'))), len(lines))
        block = '\n'.join(lines[start:end]).rstrip()
        extra = ''
        if fw == 'fastapi' and 'Depends(require_principal)' in block:
            s = next(i for i, l in enumerate(lines) if l.startswith('def require_principal')); e = next(i for i in range(s + 1, len(lines)) if not lines[i].startswith(' ') and lines[i].strip()); extra = '\n'.join(lines[s:e]).rstrip()
        if fw == 'django': extra = '# DRF: @permission_classes([IsAuthenticated]) -> 401 for anonymous; IsAdminUser -> request.user.is_staff; AllowAny -> no authentication.'
        return (extra + '\n\n' if extra else '') + block
    if fw == 'express':
        start = next(i for i, l in enumerate(lines) if 'function ' + ident + '(' in l); end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith('});')) + 1
        block = '\n'.join(lines[start:end]); extra = ''
        if 'requireAuth' in lines[start]:
            s = next(i for i, l in enumerate(lines) if l.startswith('function requireAuth')); e = next(i for i in range(s + 1, len(lines)) if lines[i].startswith('}')) + 1; extra = '\n'.join(lines[s:e])
        return (extra + '\n\n' if extra else '') + block
    if fw == 'spring':
        start = next(i for i, l in enumerate(lines) if ' ' + ident + '(' in l)
        while lines[start - 1].strip().startswith('@'): start -= 1
        end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith(' }')) + 1
        return '\n'.join(lines[start:end])
    if fw == 'nestjs':
        start = next(i for i, l in enumerate(lines) if ('  ' + ident + '(') in l)
        while lines[start - 1].strip().startswith(('@', '/**')): start -= 1
        end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith('  }')) + 1
        block = '\n'.join(lines[start:end])
        extra = '// guards.ts: AuthGuard resolves the Bearer token or throws 401 (authentication only); RolesGuard compares @Roles() with principal.role (403).'
        return extra + '\n\n' + block
    if fw == 'gin':
        start = next(i for i, l in enumerate(lines) if l.startswith('func ' + ident + '(')); start -= 1  # comment line
        end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith('}')) + 1
        route = next(l for l in lines if ('"' in l) and (', ' + ident + ')') in l)
        return '// route registration: ' + route.strip() + '\n// authRequired(): Bearer -> principal or 401 (authentication only); requireRole(role): 403 unless principal.Role == role.\n\n' + '\n'.join(lines[start:end])
    if fw == 'rails':
        start = next(i for i, l in enumerate(lines) if l.strip() == 'def ' + ident); start -= 1
        end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == 'end') + 1
        ba = [l.strip() for l in lines if l.strip().startswith('before_action')]
        return '# ' + ' | '.join(ba) + '\n# authenticate!: Bearer -> current_user or 401 (authentication only); require_admin!: 403 unless current_user.admin?\n\n' + '\n'.join(lines[start:end])
    raise ValueError(fw)

def signals(label, vulnerable):
    return {'has_auth_check': label != 'public', 'admin_bypass': label == 'owner_or_admin' and not vulnerable, 'tenant_check': label in {'tenant_match', MANUAL} and not vulnerable,
            'owner_filter': label in {'owner_match', 'owner_or_admin'} and not vulnerable, 'membership_check': label in {'membership_required', MANUAL} and not vulnerable}

def records(name, base, rows, fw, handler, kind):
    oas = json.loads((base / 'openapi.json').read_text(encoding='utf-8')); ddl = (base / 'schema.sql').read_text(encoding='utf-8'); text = (base / handler).read_text(encoding='utf-8')
    out = []
    for r in rows:
        op = oas['paths'][r['path']]['get']; vul = r.get('vulnerable', False) and r['label'] != MANUAL
        sig = signals(r.get('base_label', r['label']) if r.get('variant_kind') == 'extguard' else r['label'], vul or r.get('variant_kind') in ('authonly', 'extauth'))
        sig['auth_outside_handler'] = r.get('auth_style') == 'external' or (fw in ('django', 'nestjs', 'gin', 'rails') and r['label'] != 'public')
        out.append(dict(id=r['id'], service=name if kind == 'new' else name + '_variants', method='GET', path=r['path'], oas_snippet=json.dumps({'paths': {r['path']: {'get': op}}}, ensure_ascii=False), erd_snippet=ddl,
                        controller_signals={**sig, 'raw_snippet': excerpt(text, r['id'], fw)}, label=r['label'], rationale=r['reason'], confidence=1.0, description=op.get('description', r['reason']), security_state='unknown',
                        meta=dict(source='synthetic', label_source='intended_labels', human_confirmed=False, evidence_invalid=False, flag_review=False, known_vulnerable=bool(r.get('vulnerable', False)),
                                  confidence_provenance='design_intent_not_model_probability', source_file=str((base / handler).relative_to(ROOT)).replace('\\', '/'), framework=fw, data_version='data-v2',
                                  variant_kind=r.get('variant_kind'), variant_of=(name if kind == 'variant' else None), oas_status=yaml.safe_load((base / 'intended_labels.yaml').read_text(encoding='utf-8')).get('oas_status', 'original_export'), group_membership_semantics='v3.0'),
                        training_target_fields=['label', 'rationale']))
    return out

def main():
    V2.mkdir(parents=True, exist_ok=True); allrows = []; summary = {}
    for svc, (noun, fw) in TRAIN_BASE.items():
        rows, handler = generate_variants(svc); recs = records(svc, V2 / 'variants' / svc, rows, fw, handler, 'variant'); allrows += recs
        summary[svc + '_variants'] = dict(framework=fw, records=len(recs), manual=sum(x['label'] == MANUAL for x in recs))
    for name, (noun, fw) in NEW.items():
        rows = generate_new(name); recs = records(name, V2 / name, rows, fw, HANDLER_FILE[fw], 'new'); allrows += recs
        summary[name] = dict(framework=fw, records=len(recs), labels={l: sum(x['label'] == l for x in recs) for l in sorted({x['label'] for x in recs})})
    out = ROOT / 'datasets/blade/processed/data_v2_synthetic_additions.jsonl'
    if out.exists(): raise FileExistsError(out)
    with open(out, 'w', encoding='utf-8', newline='\n') as f:
        for r in allrows: f.write(json.dumps(r, ensure_ascii=False) + '\n')
    hashes = {}
    for d in [V2 / 'variants' / s for s in TRAIN_BASE] + [V2 / n for n in NEW]: hashes.update(sha_files(d))
    manifest = dict(records=len(allrows), summary=summary, output_sha256=hashlib.sha256(out.read_bytes()).hexdigest(), source_sha256=hashes, partition='train_only',
                    labels={l: sum(x['label'] == l for x in allrows) for l in sorted({x['label'] for x in allrows})},
                    auth_outside_handler=sum(x['controller_signals']['auth_outside_handler'] for x in allrows), oas_status={k: sum(x['meta']['oas_status'] == k for x in allrows) for k in ('original_export', 'script_projection')})
    with open(ROOT / 'datasets/blade/processed/data_v2_synthetic_additions.manifest.json', 'w', encoding='utf-8', newline='\n') as f: json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(json.dumps({k: v for k, v in manifest.items() if k != 'source_sha256'}, ensure_ascii=False, indent=1))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--generate', action='store_true'); a = ap.parse_args()
    if a.generate: main()
