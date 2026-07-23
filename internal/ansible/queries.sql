-- name: GetByID :one
SELECT * FROM servers WHERE id = $1;

-- name: GetByName :one
SELECT * FROM servers WHERE ansible_name = $1;

-- name: Create :one
INSERT INTO servers (
    ansible_name, ip_address, ssh_config_host, private_ip, ssh_user, ssh_key_name, ansible_role, slurm_partition, memory_mb, cpu_cores, status
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
) RETURNING *;

-- name: Delete :execrows
DELETE FROM servers WHERE id = $1;

-- name: UpdateIP :one
UPDATE servers SET ip_address = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdatePrivateIP :one
UPDATE servers SET private_ip = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateRole :one
UPDATE servers SET ansible_role = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateCPU :one
UPDATE servers SET cpu_cores = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateMem :one
UPDATE servers SET memory_mb = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateStatus :one
UPDATE servers SET status = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateProvisionDetail :exec
UPDATE servers SET provision_detail = $2, updated_at = now() WHERE id = $1;

-- name: ListByRoles :many
SELECT * FROM servers WHERE ansible_role = $1 ORDER BY ansible_name;

-- name: ListAll :many
SELECT * FROM servers ORDER BY ansible_name;

-- name: ListNodesByPartition :many
SELECT * FROM servers WHERE slurm_partition = $1 ORDER BY ansible_name;

-- name: ListByStatus :many
SELECT * FROM servers WHERE status = $1 ORDER BY ansible_name;

-- name: ListAllowedLoginGroupCNsByServerID :many
SELECT lg.ldap_cn
FROM allowed_login_groups alg
JOIN ldap_groups lg ON lg.group_id = alg.group_id AND lg.type = 'BASE'
WHERE alg.server_id = $1 AND lg.ldap_cn IS NOT NULL
ORDER BY lg.ldap_cn;

-- name: ListServerAllowedLoginGroups :many
SELECT alg.group_id, g.title, lg.ldap_cn
FROM allowed_login_groups alg
JOIN groups g ON g.id = alg.group_id
JOIN ldap_groups lg ON lg.group_id = alg.group_id AND lg.type = 'BASE'
WHERE alg.server_id = $1
ORDER BY g.title;

-- name: ClearServerAllowedLoginGroups :exec
DELETE FROM allowed_login_groups WHERE server_id = $1;

-- name: AddServerAllowedLoginGroup :exec
INSERT INTO allowed_login_groups (server_id, group_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: ExistServerAllowedLoginGroup :one
SELECT EXISTS (SELECT 1 FROM allowed_login_groups WHERE server_id = $1) AS exists;

-- name: ExistBaseLdapGroup :one
SELECT EXISTS (SELECT 1 FROM ldap_groups WHERE group_id = $1 AND type = 'BASE') AS exists;
