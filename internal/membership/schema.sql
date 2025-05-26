CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS memberships (
    user_id UUID REFERENCES users(id) NOT NULL,
    group_id UUID REFERENCES groups(id) NOT NULL,
    role_id UUID REFERENCES group_role(id) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- TODO: Rename to pending_membership
CREATE TABLE IF NOT EXISTS pending_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_identifier TEXT NOT NULL,
    group_id UUID NOT NULL REFERENCES groups(id),
    role_id UUID NOT NULL REFERENCES group_role(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_identifier, group_id)
);