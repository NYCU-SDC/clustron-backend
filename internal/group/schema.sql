CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    is_archived BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
    user_id UUID REFERENCES users(id) NOT NULL,
    group_id UUID REFERENCES groups(id) NOT NULL,
    role_id UUID REFERENCES group_role(id) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS group_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role VARCHAR(50),
    access_level VARCHAR(50) NOT NULL
);