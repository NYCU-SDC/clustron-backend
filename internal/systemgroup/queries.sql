-- name: Create :one
INSERT INTO system_groups (name, gid_number, description) VALUES ($1, $2, $3) RETURNING *;

-- name: GetByID :one
SELECT * FROM system_groups WHERE id = $1;

-- name: ListAll :many
SELECT * FROM system_groups ORDER BY name;

-- name: ListNames :many
SELECT name FROM system_groups;

-- name: Delete :exec
DELETE FROM system_groups WHERE id = $1;

-- name: AddMember :exec
INSERT INTO system_group_members (system_group_id, user_id) VALUES ($1, $2);

-- name: RemoveMember :execrows
DELETE FROM system_group_members WHERE system_group_id = $1 AND user_id = $2;

-- name: ListMembers :many
SELECT u.id, u.email, u.full_name, m.created_at
FROM system_group_members AS m
JOIN users AS u ON u.id = m.user_id
WHERE m.system_group_id = $1
ORDER BY u.email;
