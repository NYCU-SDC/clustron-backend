CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS group_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role VARCHAR(50),
    access_level VARCHAR(50) NOT NULL
);