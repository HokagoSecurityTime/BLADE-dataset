from fastapi import FastAPI, Header, HTTPException, Depends
app = FastAPI(title='relay_forum_variants')
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin'}}
MEMBERSHIPS = {('alice', 'g_north_hikers'), ('bob', 'g_south_riders')}
OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","group_id":"g_north_hikers","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","group_id":"g_south_riders","value":"other secret"}}
def principal_for(token):
    return PRINCIPALS.get(token.removeprefix("Bearer "))

def require_principal(authorization: str = Header(default="")):
    """Dependency: authentication only (401). It performs no authorization."""
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    return principal

@app.get('/fixtures/relay_forum/threads/drafts/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_drafts_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/drafts/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_drafts_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/drafts/extguard/{item_id}', description='Only the record owner may read it. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_drafts_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["id"] != obj["owner_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/shared/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_shared_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/shared/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_shared_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/shared/extguard/{item_id}', description='The record owner or an administrator may read it. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_shared_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/moderation/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_moderation_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/moderation/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_moderation_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/moderation/extguard/{item_id}', description='The record owner or an administrator may read it. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_moderation_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/workspace/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_workspace_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/workspace/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_workspace_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/workspace/extguard/{item_id}', description='Caller and record must share a tenant. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_workspace_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["tenant_id"] != obj["tenant_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/audit/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_audit_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/audit/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_audit_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/audit/extguard/{item_id}', description='Only administrators may read this operational resource. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_audit_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/roster/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_roster_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/roster/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_roster_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/roster/extguard/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_roster_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

@app.get('/fixtures/relay_forum/threads/pins/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def relay_forum_pins_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/relay_forum/threads/pins/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def relay_forum_pins_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/relay_forum/threads/pins/extguard/{item_id}', description='Only members of the group that owns the record ((caller_id, record.group_id) in memberships) may read it. Tenant and subscription are not checked. Authentication is enforced outside the handler; the authorization check is inside.')
def relay_forum_pins_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if (principal["id"], obj["group_id"]) not in MEMBERSHIPS: raise HTTPException(403)
    return obj

