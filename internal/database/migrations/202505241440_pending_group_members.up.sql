CREATE TABLE IF NOT EXISTS pending_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_identifier TEXT NOT NULL,
    group_id UUID NOT NULL REFERENCES groups(id),
    role_id UUID NOT NULL REFERENCES group_role(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_identifier, group_id)
);