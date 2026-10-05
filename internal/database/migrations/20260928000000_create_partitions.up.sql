BEGIN;

-- Slurm partitions, referenced by servers.slurm_partition (a compute node's partition label)
-- and by partition_allowed_groups. A row exists for every label ever assigned; slurm.conf
-- only emits partitions that currently have compute nodes. Servers with a NULL
-- slurm_partition fall into 'normal', the slurm_controller template default.
CREATE TABLE IF NOT EXISTS partitions
(
    name VARCHAR(255) PRIMARY KEY
);

UPDATE servers SET slurm_partition = NULL WHERE slurm_partition = '';

INSERT INTO partitions (name)
SELECT DISTINCT slurm_partition FROM servers WHERE slurm_partition IS NOT NULL
ON CONFLICT DO NOTHING;
INSERT INTO partitions (name) VALUES ('normal') ON CONFLICT DO NOTHING;

ALTER TABLE servers
    ADD CONSTRAINT servers_slurm_partition_fkey
    FOREIGN KEY (slurm_partition) REFERENCES partitions(name) ON UPDATE CASCADE;

-- Groups allowed to submit jobs to a Slurm partition. Rendered into slurm.conf as
-- PartitionName=... AllowAccounts=<group base cn>,... A partition with no rows here is
-- left unrestricted (Slurm's default AllowAccounts=ALL). Rows reference the group's BASE
-- ldap_groups row, whose ldap_cn is the group's top-level Slurm account.
CREATE TABLE IF NOT EXISTS partition_allowed_groups
(
    partition_name VARCHAR(255) NOT NULL REFERENCES partitions(name) ON UPDATE CASCADE ON DELETE CASCADE,
    ldap_group_id  UUID NOT NULL REFERENCES ldap_groups(id) ON DELETE CASCADE,

    PRIMARY KEY (partition_name, ldap_group_id)
);

COMMIT;
