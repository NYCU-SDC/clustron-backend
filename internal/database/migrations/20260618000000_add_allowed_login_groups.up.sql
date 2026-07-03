CREATE TABLE IF NOT EXISTS allowed_login_groups
(
    group_id UUID PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE
);
