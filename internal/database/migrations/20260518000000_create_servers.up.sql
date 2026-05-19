CREATE TABLE IF NOT EXISTS servers
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- basic connection information
    ansible_name    VARCHAR(255) UNIQUE NOT NULL,

    -- SSH connection: either ip_address (direct IP) or ssh_config_host (via ~/.ssh/config alias)
    ip_address      VARCHAR(50),
    ssh_config_host VARCHAR(255),

    -- SSH authentication
    ssh_user        VARCHAR(255) NOT NULL,
    ssh_key_name    VARCHAR(255),

    -- Ansible & Slurm properties
    ansible_role     VARCHAR(255) NOT NULL,
    slurm_partition  VARCHAR(255),
    status           VARCHAR(255) NOT NULL DEFAULT 'unset',
    provision_detail TEXT,

    -- hardware description
    cpu_cores       INTEGER,
    memory_mb       INTEGER,

    -- time information
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_connection CHECK (ip_address IS NOT NULL OR ssh_config_host IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS servers_ip_address_key ON servers(ip_address) WHERE ip_address IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS servers_ssh_config_host_key ON servers(ssh_config_host) WHERE ssh_config_host IS NOT NULL;
