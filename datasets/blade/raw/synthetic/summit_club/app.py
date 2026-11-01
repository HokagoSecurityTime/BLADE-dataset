from fastapi import FastAPI, Header, HTTPException
app = FastAPI(title='summit_club')
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user'}, 'carol': {'id': 'carol', 'tenant_id': 'north', 'role': 'user'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin'}}
MEMBERSHIPS = {('alice', 'g_north_hikers'), ('bob', 'g_south_riders'), ('carol', 'g_south_riders')}  # (user_id, group_id): group membership, independent of tenant
OBJECTS = {"1": {"id": "1", "owner_id": "alice", "tenant_id": "north", "group_id": "g_north_hikers", "value": "fixture secret"}, "2": {"id": "2", "owner_id": "bob", "tenant_id": "south", "group_id": "g_south_riders", "value": "other secret"}, "3": {"id": "3", "owner_id": "carol", "tenant_id": "north", "group_id": "g_south_riders", "value": "cross-tenant group secret"}}
def principal_for(token):
    return PRINCIPALS.get(token.removeprefix("Bearer "))

@app.get('/fixtures/summit_club/expeditions/catalogue/current/{item_id}', description='Intentionally anonymous reference catalogue.')
def summit_club_catalogue_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    return obj

@app.get('/fixtures/summit_club/expeditions/catalogue/archive/{item_id}', description='Intentionally anonymous reference catalogue.')
def summit_club_catalogue_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    return obj

@app.get('/fixtures/summit_club/expeditions/drafts/current/{item_id}', description='Only the record owner may read it.')
def summit_club_drafts_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["id"] != obj["owner_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/drafts/archive/{item_id}', description='Only the record owner may read it.')
def summit_club_drafts_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/shared/current/{item_id}', description='The record owner or an administrator may read it.')
def summit_club_shared_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/shared/archive/{item_id}', description='The record owner or an administrator may read it.')
def summit_club_shared_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/workspace/current/{item_id}', description='Caller and record must share a tenant.')
def summit_club_workspace_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["tenant_id"] != obj["tenant_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/workspace/archive/{item_id}', description='Caller and record must share a tenant.')
def summit_club_workspace_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/audit/current/{item_id}', description='Only administrators may read this operational resource.')
def summit_club_audit_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/audit/archive/{item_id}', description='Only administrators may read this operational resource.')
def summit_club_audit_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/roster/current/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.')
def summit_club_roster_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/roster/archive/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.')
def summit_club_roster_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/gear/current/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.')
def summit_club_gear_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/gear/archive/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked.')
def summit_club_gear_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/summit_club/expeditions/council/current/{item_id}', description='Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.')
def summit_club_council_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["tenant_id"] != obj["tenant_id"] or (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

@app.get('/fixtures/summit_club/expeditions/council/archive/{item_id}', description='Caller must share the tenant AND be a member of the record group; two independent conditions, not expressible as one label; deny pending review.')
def summit_club_council_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["tenant_id"] != obj["tenant_id"] or (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

