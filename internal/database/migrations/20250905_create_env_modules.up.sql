CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS env_modules (
    id         UUID PRIMARY KEY UNIQUE DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    title      TEXT NOT NULL CHECK (char_length(title) <= 200),
-- 大小寫不敏感 的唯一性檢查(?)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

-- 同一個使用者下，title 不重名（可選；若不想限制可刪除）
CREATE UNIQUE INDEX IF NOT EXISTS uq_env_modules_user_title
    ON env_modules(user_id, title);

-- 依 user_id 列出自己模組時會快很多
CREATE INDEX IF NOT EXISTS idx_env_modules_user
    ON env_modules(user_id);
