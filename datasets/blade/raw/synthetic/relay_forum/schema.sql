CREATE TABLE relay_forum_threads (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, value TEXT NOT NULL);
CREATE TABLE relay_forum_memberships (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));
