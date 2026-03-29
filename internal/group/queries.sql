-- name: CountAll :one
SELECT COUNT(*) FROM groups;

-- name: CountByUser :one
SELECT COUNT(*) FROM memberships WHERE user_id = $1;

-- name: ListGroupsPaged :many
SELECT
    g.*,
    lg.ldap_cn
FROM groups AS g
LEFT JOIN ldap_groups AS lg ON g.id = lg.group_id AND lg.type = 'BASE'
ORDER BY
    -- Dynamic Sorting Logic
    CASE WHEN sqlc.narg('sort')::text = 'asc' THEN g.created_at END ASC,
    CASE WHEN sqlc.narg('sort')::text = 'desc' THEN g.created_at END DESC,
    -- Default fallback to ensure deterministic order
    g.id ASC
LIMIT @Size OFFSET @Skip;

-- name: ListIfMemberPaged :many
SELECT
    g.*,
    gr.*,
    lg.ldap_cn
FROM groups AS g
JOIN memberships AS m ON m.group_id = g.id
JOIN group_role AS gr ON gr.id = m.role_id
LEFT JOIN ldap_groups AS lg ON g.id = lg.group_id AND lg.type = 'BASE'
WHERE m.user_id = $1
ORDER BY
    -- Dynamic Sorting Logic
    CASE WHEN sqlc.narg('sort')::text = 'asc' THEN g.created_at END ASC,
    CASE WHEN sqlc.narg('sort')::text = 'desc' THEN g.created_at END DESC,
    -- Default fallback to ensure deterministic order
    g.id ASC
LIMIT @Size OFFSET @Skip;

-- name: GetByID :one
SELECT g.*, lg.ldap_cn
FROM groups AS g
LEFT JOIN ldap_groups AS lg ON lg.group_id = g.id AND lg.type = 'BASE'
WHERE g.id = $1;

-- name: GetIfMember :one
SELECT g.*, lg.ldap_cn
FROM groups AS g
JOIN memberships AS m ON m.group_id = g.id
LEFT JOIN ldap_groups AS lg ON lg.group_id = g.id AND lg.type = 'BASE'
WHERE m.user_id = $1 AND m.group_id = $2;
-- name: Create :one
INSERT INTO groups (title, description) VALUES ($1, $2) RETURNING *;

-- name: CreateWithID :one
INSERT INTO groups (id, title, description) VALUES ($1, $2, $3) RETURNING *;

-- name: Update :one
UPDATE groups SET title = $2, description = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: Delete :exec
DELETE FROM groups WHERE id = $1;

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

-- name: CreateLDAPBaseGroup :one
INSERT INTO ldap_groups (group_id, ldap_cn, type, gid_number)
VALUES ($1, $2, 'BASE', $3) RETURNING *;

-- name: CreateLDAPAdminGroup :one
INSERT INTO ldap_groups (group_id, ldap_cn, type, gid_number)
VALUES ($1, $2, 'ADMIN', $3) RETURNING *;