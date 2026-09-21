BEGIN;

CREATE TABLE allowed_login_groups_new
(
    server_id     UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ldap_group_id UUID NOT NULL REFERENCES ldap_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, ldap_group_id)
);

INSERT INTO allowed_login_groups_new (server_id, ldap_group_id)
SELECT a.server_id, lg.id
FROM allowed_login_groups a
JOIN ldap_groups lg ON lg.group_id = a.group_id
ON CONFLICT DO NOTHING;

DROP TABLE allowed_login_groups;

ALTER TABLE allowed_login_groups_new RENAME TO allowed_login_groups;

ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_new_pkey TO allowed_login_groups_pkey;

ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_new_server_id_fkey TO allowed_login_groups_server_id_fkey;
ALTER TABLE allowed_login_groups
    RENAME CONSTRAINT allowed_login_groups_new_ldap_group_id_fkey TO allowed_login_groups_ldap_group_id_fkey;

COMMIT;