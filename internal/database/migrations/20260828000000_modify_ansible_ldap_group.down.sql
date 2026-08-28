BEGIN;

CREATE TABLE allowed_login_groups_old
(
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, group_id)
);

INSERT INTO allowed_login_groups_old (server_id, group_id)
SELECT DISTINCT a.server_id, lg.group_id
FROM allowed_login_groups a
JOIN ldap_groups lg ON lg.id = a.ldap_group_id
ON CONFLICT DO NOTHING;

DROP TABLE allowed_login_groups;

ALTER TABLE allowed_login_groups_old RENAME TO allowed_login_groups;

ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_old_pkey TO allowed_login_groups_pkey;

ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_old_server_id_fkey TO allowed_login_groups_server_id_fkey;
ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_old_group_id_fkey TO allowed_login_groups_group_id_fkey;

COMMIT;