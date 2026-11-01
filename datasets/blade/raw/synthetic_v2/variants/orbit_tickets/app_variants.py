from fastapi import FastAPI, Header, HTTPException, Depends
app = FastAPI(title='orbit_tickets_variants')
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user', 'plan': 'premium'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user', 'plan': 'free'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin', 'plan': 'premium'}}
OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","value":"other secret"}}
def principal_for(token):
    return PRINCIPALS.get(token.removeprefix("Bearer "))

def require_principal(authorization: str = Header(default="")):
    """Dependency: authentication only (401). It performs no authorization."""
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    return principal

@app.get('/fixtures/orbit_tickets/reservations/drafts/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def orbit_tickets_drafts_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/drafts/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def orbit_tickets_drafts_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/drafts/extguard/{item_id}', description='Only the record owner may read it. Authentication is enforced outside the handler; the authorization check is inside.')
def orbit_tickets_drafts_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["id"] != obj["owner_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/orbit_tickets/reservations/shared/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def orbit_tickets_shared_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/shared/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def orbit_tickets_shared_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/shared/extguard/{item_id}', description='The record owner or an administrator may read it. Authentication is enforced outside the handler; the authorization check is inside.')
def orbit_tickets_shared_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/orbit_tickets/reservations/workspace/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def orbit_tickets_workspace_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/workspace/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def orbit_tickets_workspace_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/workspace/extguard/{item_id}', description='Caller and record must share a tenant. Authentication is enforced outside the handler; the authorization check is inside.')
def orbit_tickets_workspace_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["tenant_id"] != obj["tenant_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/orbit_tickets/reservations/audit/authonly/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported.')
def orbit_tickets_audit_authonly(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Variant: object authorization check removed.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/audit/extauth/{item_id}', description='Authentication only; no requester-object relationship or role check is implemented, so no concrete label is supported. Authentication is enforced outside the handler.')
def orbit_tickets_audit_extauth(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    # Variant: authentication via dependency only; no authorization check.
    return obj

@app.get('/fixtures/orbit_tickets/reservations/audit/extguard/{item_id}', description='Only administrators may read this operational resource. Authentication is enforced outside the handler; the authorization check is inside.')
def orbit_tickets_audit_extguard(item_id: str, principal: dict = Depends(require_principal)):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    if principal["role"] != "admin": raise HTTPException(403)
    return obj

