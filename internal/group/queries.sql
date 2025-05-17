-- name: CountAll :one
SELECT COUNT(*) FROM groups;

-- name: CountByUser :one
SELECT COUNT(*) FROM memberships WHERE user_id = $1;

-- name: ListAscPaged :many
SELECT * FROM groups ORDER BY @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: ListDescPaged :many
SELECT * FROM groups ORDER BY @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: ListByUserAscPaged :many
SELECT
    g.*,
    gr.*
FROM
    groups AS g
JOIN
    memberships AS m ON m.group_id = g.id
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    m.user_id = $1
ORDER BY
    @SortBy::text ASC LIMIT @Size OFFSET @page;

-- name: ListByUserDescPaged :many
SELECT
    g.*,
    gr.*
FROM
    groups AS g
JOIN
    memberships AS m ON m.group_id = g.id
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    m.user_id = $1
ORDER BY
    @SortBy::text DESC LIMIT @Size OFFSET @page;

-- name: Get :one
SELECT * FROM groups WHERE id = $1;

-- name: GetIfMember :one
SELECT g.* FROM groups AS g JOIN memberships AS m ON m.group_id = g.id WHERE m.user_id = $1 AND m.group_id = $2;

-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: Update :one
UPDATE groups SET title = $2, description = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: Archive :one
UPDATE groups SET is_archived = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: Unarchive :one
UPDATE groups SET is_archived = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: ListMembershipsByUser :many
SELECT
    m.group_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM
    memberships AS m
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1;

-- name: GetMembershipsByUser :one
SELECT
    m.group_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM
    memberships AS m
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1 AND group_id = $2;

-- name: GetUserGroupRole :one
SELECT gr.* FROM group_role AS gr JOIN memberships AS m ON m.role_id = gr.id WHERE m.user_id = $1 AND m.group_id = $2;

-- name: GetGroupRoleByID :one
SELECT * FROM group_role WHERE id = $1;