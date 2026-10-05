CREATE TABLE IF NOT EXISTS server_local_groups
(
    server_id     UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    gid_number    BIGINT NOT NULL,
    discovered_at TIMESTAMPTZ DEFAULT now(),

    PRIMARY KEY (server_id, name)
);
