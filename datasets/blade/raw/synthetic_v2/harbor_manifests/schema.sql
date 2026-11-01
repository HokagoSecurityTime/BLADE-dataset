CREATE TABLE harbor_manifests_manifests (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, value TEXT NOT NULL);
CREATE TABLE harbor_manifests_memberships (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));
