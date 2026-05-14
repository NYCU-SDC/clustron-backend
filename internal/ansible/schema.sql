CREATE TABLE IF NOT EXISTS servers
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- basic connection information
    ansible_name    VARCHAR(255) UNIQUE NOT NULL,
    ip_address      VARCHAR(50) UNIQUE NOT NULL,
    
    -- SSH authentication
    ssh_user        VARCHAR(255) NOT NULL,
    ssh_key_name    VARCHAR(255) NOT NULL,
    
    -- Ansible & Slurm properties
    ansible_role    VARCHAR(255) NOT NULL,
    slurm_partition VARCHAR(255),
    status          VARCHAR(255) NOT NULL DEFAULT 'unset',
    
    -- hardware description
    cpu_cores       INTEGER,
    memory_mb       INTEGER,
    
    -- time information
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);