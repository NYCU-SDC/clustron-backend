-- name: GetAllGroupCount :one
SELECT COUNT(*) FROM groups;

-- name: GetUserGroupCount :one
SELECT COUNT(*) FROM memberships WHERE user_id = $1;

-- name: GetWithPageASC :many
SELECT * FROM groups ORDER BY @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: GetWithPageDESC :many
SELECT * FROM groups ORDER BY @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: FindById :one
SELECT * FROM groups WHERE id = $1;

-- name: FindByUserIdASC :many
SELECT group_id FROM memberships WHERE user_id = $1 ORDER BY @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: FindByUserIdDESC :many
SELECT group_id FROM memberships WHERE user_id = $1 ORDER BY @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: Update :one
UPDATE groups SET title = $2, description = $3 WHERE id = $1 RETURNING *;

-- name: Archive :one
UPDATE groups SET is_archived = TRUE WHERE id = $1 RETURNING *;

-- name: Unarchive :one
UPDATE groups SET is_archived = FALSE WHERE id = $1 RETURNING *;