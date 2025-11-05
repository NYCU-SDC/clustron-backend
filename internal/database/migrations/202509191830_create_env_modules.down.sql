DROP EXTENSION IF EXISTS "pgcrypto";
DROP INDEX IF EXISTS idx_env_modules_user;
DROP INDEX IF EXISTS uq_env_modules_user_title;
DROP TABLE IF EXISTS env_modules;
DROP INDEX IF EXISTS idx_env_module_vars_order;
DROP TABLE IF EXISTS env_module_vars;

