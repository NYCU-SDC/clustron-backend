CREATE TABLE IF NOT EXISTS modules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    environment JSONB NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);