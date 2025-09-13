CREATE TABLE IF NOT EXISTS env_module_vars (
    module_id  UUID NOT NULL REFERENCES env_modules(id) ON DELETE CASCADE,
    "key"      TEXT NOT NULL CHECK (char_length("key") <= 128),
    "value"    TEXT NOT NULL,
    position   INT  NOT NULL DEFAULT 0,
    PRIMARY KEY (module_id, "key")
    );

-- 若常用 position 排序，可加覆合索引（可選）
CREATE INDEX IF NOT EXISTS idx_env_module_vars_order
    ON env_module_vars(module_id, position, "key");
