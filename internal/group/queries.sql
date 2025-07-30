-- name: CountAll :one
SELECT COUNT(*) FROM groups;

-- name: CountByUser :one
SELECT COUNT(*) FROM memberships WHERE user_id = $1;

-- name: ListAscPaged :many
SELECT * FROM groups ORDER BY created_at ASC LIMIT @Size OFFSET @Skip;

-- name: ListDescPaged :many
SELECT * FROM groups ORDER BY created_at DESC LIMIT @Size OFFSET @Skip;

-- name: ListIfMemberAscPaged :many
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
    g.created_at ASC LIMIT @Size OFFSET @Skip;

-- name: ListIfMemberDescPaged :many
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
    g.created_at DESC LIMIT @Size OFFSET @Skip;

-- name: GetByID :one
SELECT * FROM groups WHERE id = $1;

-- name: GetIfMember :one
SELECT g.* FROM groups AS g JOIN memberships AS m ON m.group_id = g.id WHERE m.user_id = $1 AND m.group_id = $2;

-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: CreateWithID :one
INSERT INTO groups (id, title, description) VALUES ($1, $2, $3) RETURNING *;

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
    gr.role_name,
    gr.access_level
FROM
    memberships AS m
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1;

-- name: GetMembershipByUser :one
SELECT
    m.group_id,
    m.role_id,
    gr.role_name,
    gr.access_level
FROM
    memberships AS m
JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1 AND group_id = $2;

-- name: ListGidNumbers :many
SELECT gid_number FROM groups WHERE gid_number IS NOT NULL ORDER BY gid_number;

-- name: UpdateGidNumber :exec
UPDATE groups SET gid_number = $2 WHERE id = $1;

-- name: GetMembersByGroupID :many
SELECT
    *
FROM memberships
WHERE group_id = $1;

-- name: ListLinksByGroup :many
SELECT
    l.id,
    l.title,
    l.url
FROM
    links AS l
JOIN
    groups AS g ON g.id = l.group_id
WHERE
    g.id = $1;

-- name: CreateLink :one
INSERT INTO links (group_id, title, url) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateLink :one
UPDATE links SET title = $2, url = $3 WHERE id = $1 RETURNING *;

-- name: DeleteLink :exec
DELETE FROM links WHERE id = $1;