-- Groups allowed to submit jobs to a Slurm partition. Rendered into slurm.conf as
-- PartitionName=... AllowAccounts=<group base cn>,... A partition with no rows here is
-- left unrestricted (Slurm's default AllowAccounts=ALL).
--
-- Keyed by partition name because partitions are not an entity: they exist only as the
-- servers.slurm_partition label on each compute node, grouped into PartitionName lines by
-- the slurm_controller ansible template.
CREATE TABLE IF NOT EXISTS partition_allowed_groups
(
    partition_name VARCHAR(255) NOT NULL,
    group_id       UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,

    PRIMARY KEY (partition_name, group_id)
);
