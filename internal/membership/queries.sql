-- name: ListDescPaged :many
SELECT
    m.group_id,
    m.user_id,
    u.full_name,
    u.email,
    u.student_id,
    m.role_id,
    gr.role_name,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
WHERE group_id = $1 AND u.id IN (SELECT unnest(@UserIDs::UUID[]))
ORDER BY gr.role_name DESC
LIMIT @Size OFFSET @Skip;

-- name: ListAscPaged :many
SELECT
    m.group_id,
    m.user_id,
    u.full_name,
    u.email,
    u.student_id,
    m.role_id,
    gr.role_name,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
WHERE group_id = $1 AND u.id IN (SELECT unnest(@UserIDs::UUID[]))
ORDER BY gr.role_name ASC
LIMIT @Size OFFSET @Skip;

-- name: ExistsByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM memberships AS m
    JOIN users AS u ON u.id = m.user_id
    WHERE group_id = $1 AND (u.student_id = $2 OR u.email = $2)
);

-- name: ExistsByID :one
SELECT EXISTS (
    SELECT 1
    FROM memberships
    WHERE group_id = $1 AND user_id = $2
) AS exists;

-- name: GetByUser :one
SELECT
    m.user_id,
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

-- name: GetOwnerByGroupID :one
SELECT
    m.user_id
FROM
    memberships AS m
        JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    m.group_id = $1 AND gr.access_level = 'GROUP_OWNER';

-- name: CountByGroupID :one
SELECT COUNT(*) FROM memberships
WHERE group_id = $1;

-- name: CreateOrUpdatePending :one
INSERT INTO pending_memberships (user_identifier, group_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_identifier, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING *;

-- name: ExistsPendingByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM pending_memberships
    WHERE group_id = $1 AND user_identifier = $2
) AS exists;

-- name: GetPendingByIdentifier :one
SELECT *
FROM pending_memberships
WHERE group_id = $1 AND user_identifier = $2;

-- name: UpdatePending :one
UPDATE pending_memberships
SET role_id = $1
WHERE group_id = $2 AND user_identifier = $3
RETURNING *;

-- name: GetPendingByUserIdentifier :many
SELECT
    pm.id,
    pm.user_identifier,
    pm.group_id,
    pm.role_id,
    gr.role_name,
    gr.access_level,
    g.is_archived
FROM pending_memberships AS pm
JOIN group_role AS gr ON gr.id = pm.role_id
Join groups As g ON g.id = pm.group_id
WHERE pm.user_identifier = @email OR pm.user_identifier = @student_id;

-- name: ListPendingMembersDescPaged :many
SELECT
    pm.id,
    pm.user_identifier,
    pm.group_id,
    pm.role_id,
    gr.role_name,
    gr.access_level
FROM pending_memberships AS pm
JOIN group_role AS gr ON gr.id = pm.role_id
WHERE pm.group_id = $1
ORDER BY gr.role_name DESC
LIMIT @Size OFFSET @Skip;

-- name: ListPendingMembersAscPaged :many
SELECT
    pm.id,
    pm.user_identifier,
    pm.group_id,
    pm.role_id,
    gr.role_name,
    gr.access_level
FROM pending_memberships AS pm
JOIN group_role AS gr ON gr.id = pm.role_id
WHERE pm.group_id = $1
ORDER BY gr.role_name ASC
LIMIT @Size OFFSET @Skip;

-- name: CountPendingByGroupID :one
SELECT COUNT(*) FROM pending_memberships
WHERE group_id = $1;

-- name: GetPendingByID :one
SELECT
    pm.id,
    pm.user_identifier,
    pm.group_id,
    pm.role_id,
    gr.role_name,
    gr.access_level
FROM pending_memberships AS pm
JOIN group_role AS gr ON gr.id = pm.role_id
WHERE pm.id = $1;

-- name: UpdatePendingByID :one
UPDATE pending_memberships
SET role_id = $1
WHERE id = $2
RETURNING *;

-- name: DeletePendingByID :exec
DELETE FROM pending_memberships
WHERE id = $1;

-- name: CreateOrUpdate :one
INSERT INTO memberships (group_id, user_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING *;

-- name: Delete :exec
DELETE FROM memberships
WHERE group_id = $1 AND user_id = $2;

-- name: UpdateRole :one
UPDATE memberships
SET role_id = $1
WHERE group_id = $2 AND user_id = $3
RETURNING *;