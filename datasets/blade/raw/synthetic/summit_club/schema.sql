CREATE TABLE summit_club_expeditions (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, tenant_id TEXT NOT NULL, group_id TEXT NOT NULL, value TEXT NOT NULL);
CREATE TABLE summit_club_memberships (user_id TEXT NOT NULL, group_id TEXT NOT NULL, PRIMARY KEY (user_id, group_id));
