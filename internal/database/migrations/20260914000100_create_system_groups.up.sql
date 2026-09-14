CREATE TABLE IF NOT EXISTS system_groups
(
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(32) UNIQUE NOT NULL,
    gid_number  BIGINT UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ DEFAULT now(),
    updated_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS system_group_members
(
    system_group_id UUID NOT NULL REFERENCES system_groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ DEFAULT now(),

    PRIMARY KEY (system_group_id, user_id)
);
