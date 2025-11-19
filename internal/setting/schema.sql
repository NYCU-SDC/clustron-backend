CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) NOT NULL,
    full_name VARCHAR(255),
    linux_username VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS public_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) NOT NULL,
    title VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ldap_user (
    id UUID PRIMARY KEY REFERENCES users(id) NOT NULL,
    uid_number BIGINT UNIQUE NOT NULL
)