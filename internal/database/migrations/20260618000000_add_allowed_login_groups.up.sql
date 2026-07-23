CREATE TABLE IF NOT EXISTS allowed_login_groups
(
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    group_id  UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,

    PRIMARY KEY (server_id, group_id)
);
