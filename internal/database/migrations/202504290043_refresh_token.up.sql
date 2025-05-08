CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS refresh_tokens
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) NOT NULL,
    is_active       BOOLEAN DEFAULT TRUE,
    expiration_date TIMESTAMPTZ NOT NULL
);