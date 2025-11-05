CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS env_modules (
    id         UUID PRIMARY KEY UNIQUE DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    title      TEXT NOT NULL CHECK (char_length(title) <= 200),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

CREATE TABLE IF NOT EXISTS env_module_vars (
    module_id  UUID NOT NULL REFERENCES env_modules(id) ON DELETE CASCADE,
    key     TEXT NOT NULL CHECK (char_length("key") <= 128),
    value   TEXT NOT NULL,
    position   INT  NOT NULL DEFAULT 0,
    PRIMARY KEY (module_id, "key")
);
