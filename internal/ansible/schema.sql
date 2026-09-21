CREATE TABLE IF NOT EXISTS servers
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- basic connection information
    ansible_name    VARCHAR(255) UNIQUE NOT NULL,

    -- SSH connection: either ip_address (direct IP) or ssh_config_host (via ~/.ssh/config alias)
    ip_address      VARCHAR(50),
    ssh_config_host VARCHAR(255),

    -- cluster-internal IP for NFS/NTP traffic (when SSH goes through a different interface)
    private_ip      VARCHAR(50),

    -- SSH authentication
    ssh_user        VARCHAR(255),
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

    CONSTRAINT servers_ansible_name_hostname_check CHECK (
        char_length(ansible_name) <= 253
        AND ansible_name ~ '^([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62}){1}(\.[a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,62})*?$'
    ),
    CONSTRAINT servers_ssh_user_connection_check CHECK (
        ip_address IS NULL OR NULLIF(ssh_user, '') IS NOT NULL
    ),
    CONSTRAINT chk_connection CHECK (ip_address IS NOT NULL OR ssh_config_host IS NOT NULL),
    CONSTRAINT servers_cluster_address_check CHECK (
        NULLIF(ip_address, '') IS NOT NULL OR NULLIF(private_ip, '') IS NOT NULL
    ),
    CONSTRAINT servers_cpu_cores_positive_check CHECK (cpu_cores >= 1),
    CONSTRAINT servers_memory_mb_positive_check CHECK (memory_mb >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS servers_ip_address_key ON servers(ip_address) WHERE ip_address IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS servers_ssh_config_host_key ON servers(ssh_config_host) WHERE ssh_config_host IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS servers_private_ip_key ON servers(private_ip) WHERE private_ip IS NOT NULL;

-- rendered into SSSD's simple_allow_groups
CREATE TABLE IF NOT EXISTS allowed_login_groups
(
    server_id     UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ldap_group_id UUID NOT NULL REFERENCES ldap_groups(id) ON DELETE CASCADE,

    PRIMARY KEY (server_id, ldap_group_id)
);
