ALTER TABLE servers
    DROP COLUMN IF EXISTS mount_nfs_home,
    DROP COLUMN IF EXISTS enable_slurm;
