CREATE TYPE group_type AS ENUM ('Base', 'Admin');

CREATE TABLE IF NOT EXISTS ldap_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES groups(id) NOT NULL,
    ldap_cn VARCHAR(255) UNIQUE,
    type group_type NOT NULL,
    gid_number BIGINT UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (group_id, type)
);

ALTER TABLE groups
DROP gid_number;