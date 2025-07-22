-- name: GetAll :many
SELECT * FROM group_role;

-- name: ExistsByRoleName :one
SELECT EXISTS (
    SELECT 1 FROM group_role WHERE role_name = $1
) AS role_exists;

-- name: Create :one
INSERT INTO group_role (role_name, access_level) VALUES ($1, $2) RETURNING *;

-- name: CreateWithID :one
INSERT INTO group_role (id, role_name, access_level) VALUES ($1, $2, $3) RETURNING *;

-- name: Update :one
UPDATE group_role SET role_name = $1, access_level = $2 WHERE id = $3 RETURNING *;

-- name: Delete :exec
DELETE FROM group_role WHERE id = $1;

-- name: GetByID :one
SELECT * FROM group_role WHERE id = $1;

-- name: GetUserGroupRole :one
SELECT gr.* FROM group_role AS gr JOIN memberships AS m ON m.role_id = gr.id WHERE m.user_id = $1 AND m.group_id = $2;

-- name: GetByName :one
SELECT * FROM group_role WHERE role_name = $1;