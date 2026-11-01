from fastapi import FastAPI, Header, HTTPException
app = FastAPI(title='quill_blog')
PRINCIPALS = {'alice': {'id': 'alice', 'tenant_id': 'north', 'role': 'user', 'plan': 'premium'}, 'bob': {'id': 'bob', 'tenant_id': 'south', 'role': 'user', 'plan': 'free'}, 'admin': {'id': 'root', 'tenant_id': 'north', 'role': 'admin', 'plan': 'premium'}}
OBJECTS = {"1": {"id":"1","owner_id":"alice","tenant_id":"north","value":"fixture secret"}, "2": {"id":"2","owner_id":"bob","tenant_id":"south","value":"other secret"}}
def principal_for(token):
    return PRINCIPALS.get(token.removeprefix("Bearer "))

@app.get('/fixtures/quill_blog/entries/catalogue/current/{item_id}', description='Intentionally anonymous reference catalogue.')
def quill_blog_catalogue_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    return obj

@app.get('/fixtures/quill_blog/entries/catalogue/archive/{item_id}', description='Intentionally anonymous reference catalogue.')
def quill_blog_catalogue_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    return obj

@app.get('/fixtures/quill_blog/entries/drafts/current/{item_id}', description='Only the record owner may read it.')
def quill_blog_drafts_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["id"] != obj["owner_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/drafts/archive/{item_id}', description='Only the record owner may read it.')
def quill_blog_drafts_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/quill_blog/entries/shared/current/{item_id}', description='The record owner or an administrator may read it.')
def quill_blog_shared_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["id"] != obj["owner_id"] and principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/shared/archive/{item_id}', description='The record owner or an administrator may read it.')
def quill_blog_shared_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/quill_blog/entries/workspace/current/{item_id}', description='Caller and record must share a tenant.')
def quill_blog_workspace_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["tenant_id"] != obj["tenant_id"]: raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/workspace/archive/{item_id}', description='Caller and record must share a tenant.')
def quill_blog_workspace_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/quill_blog/entries/audit/current/{item_id}', description='Only administrators may read this operational resource.')
def quill_blog_audit_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["role"] != "admin": raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/audit/archive/{item_id}', description='Only administrators may read this operational resource.')
def quill_blog_audit_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/quill_blog/entries/subscription/current/{item_id}', description='A premium plan is required.')
def quill_blog_subscription_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if principal["plan"] != "premium": raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/subscription/archive/{item_id}', description='A premium plan is required.')
def quill_blog_subscription_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    # Deliberate fixture: object authorization check omitted.
    return obj

@app.get('/fixtures/quill_blog/entries/disputed/current/{item_id}', description='Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.')
def quill_blog_disputed_0(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if True: raise HTTPException(403)
    return obj

@app.get('/fixtures/quill_blog/entries/disputed/archive/{item_id}', description='Conflicting owner and tenant requirements are deliberately unresolved; deny pending review.')
def quill_blog_disputed_1(item_id: str, authorization: str = Header(default="")):
    obj = OBJECTS.get(item_id)
    if obj is None: raise HTTPException(404)
    principal = principal_for(authorization)
    if principal is None: raise HTTPException(401)
    if True: raise HTTPException(403)
    return obj

