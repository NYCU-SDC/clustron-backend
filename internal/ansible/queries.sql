-- name: GetByID :one
SELECT * FROM servers WHERE id = $1;

-- name: GetByName :one
SELECT * FROM servers WHERE ansible_name = $1;

-- name: Create :one
INSERT INTO servers (
    ansible_name, ip_address, ssh_user, ssh_key_name, ansible_role, slurm_partition, memory_mb, cpu_cores, status
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9
) RETURNING *;

-- name: Delete :execrows
DELETE FROM servers WHERE id = $1;

-- name: UpdateIP :one
UPDATE servers SET ip_address = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateRole :one
UPDATE servers SET ansible_role = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateCPU :one
UPDATE servers SET cpu_cores = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateMem :one
UPDATE servers SET memory_mb = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateStatus :one
UPDATE servers SET status = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: ListByRoles :many
SELECT * FROM servers WHERE ansible_role = $1 ORDER BY ansible_name;

-- name: ListAll :many
SELECT * FROM servers ORDER BY ansible_name;

-- name: ListNodesByPartition :many
SELECT * FROM servers WHERE slurm_partition = $1 ORDER BY ansible_name;

-- name: ListByStatus :many
SELECT * FROM servers WHERE status = $1 ORDER BY ansible_name;