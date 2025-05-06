-- name: GetAllGroupsCount :one
SELECT COUNT(*) FROM groups;

-- name: GetUserGroupsCount :one
SELECT COUNT(*) FROM memberships WHERE user_id = $1;

-- name: GetWithPageASC :many
SELECT * FROM groups ORDER BY @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: GetWithPageDESC :many
SELECT * FROM groups ORDER BY @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: FindById :one
SELECT * FROM groups WHERE id = $1;

-- name: FindUserGroupById :one
SELECT g.* FROM groups AS g JOIN memberships AS m ON m.group_id = g.id WHERE m.user_id = $1 AND m.group_id = $2;

-- name: FindByUserWithPageASC :many
SELECT g.* FROM groups AS g JOIN memberships AS m ON m.group_id = g.id WHERE m.user_id = $1 ORDER BY @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: FindByUserWithPageDESC :many
SELECT g.* FROM groups AS g JOIN memberships AS m ON m.group_id = g.id WHERE m.user_id = $1 ORDER BY @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: Update :one
UPDATE groups SET title = $2, description = $3 WHERE id = $1 RETURNING *;

-- name: Archive :one
UPDATE groups SET is_archived = TRUE WHERE id = $1 RETURNING *;

-- name: Unarchive :one
UPDATE groups SET is_archived = FALSE WHERE id = $1 RETURNING *;

-- name: GetUserGroupMembership :one
SELECT * FROM memberships WHERE user_id = $1 AND group_id = $2;

-- name: AccessLevelFromRole :one
SELECT access_level FROM group_role WHERE id = $1;