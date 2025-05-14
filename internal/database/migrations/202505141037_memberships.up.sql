CREATE TABLE IF NOT EXISTS memberships (
    user_id UUID REFERENCES users(id) NOT NULL,
    group_id UUID REFERENCES groups(id) NOT NULL,
    role_id UUID REFERENCES group_role(id) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);