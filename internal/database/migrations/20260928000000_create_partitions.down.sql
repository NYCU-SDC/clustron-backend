BEGIN;

DROP TABLE IF EXISTS partition_allowed_groups;
ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_slurm_partition_fkey;
DROP TABLE IF EXISTS partitions;

COMMIT;
