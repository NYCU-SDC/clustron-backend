-- name: GetAll :many
SELECT * FROM groups;

-- name: GetByID :one
SELECT * FROM groups WHERE id = $1;

-- name:GetByUserID :many
SELECT group FROM mamberships WHERE user_id = $1;

-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: Update :one
UPDATE groups SET title = $2, description = $3 WHERE id = $1 RETURNING *;

-- name: Archive :one
UPDATE groups SET is_archived = TRUE WHERE id = $1 RETURNING *;

-- name: Unarchive :one
UPDATE groups SET is_archived = FALSE WHERE id = $1 RETURNING *;