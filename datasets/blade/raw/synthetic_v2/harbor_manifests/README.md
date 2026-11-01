# harbor_manifests (django, data-v2 train-only)

Authorization style: decorator (@permission_classes) + ORM filter. 18 endpoints: public 2, owner_match 2, owner_or_admin 4, tenant_match 2, role_required 2, membership_required 4 (group membership), compound tenant AND membership -> manual_review_required 2. archive variants omit the authorization check (authentication only). Not runnable offline here; OpenAPI is a script-generated projection, not a framework export. Domain "manifests" does not overlap test-only fixtures.
