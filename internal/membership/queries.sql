-- name: ListDescPaged :many
SELECT
    m.group_id,
    m.user_id,
    s.username,
    u.email,
    u.student_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
JOIN settings AS s ON s.user_id = u.id
WHERE group_id = $1
ORDER BY @SortBy::text DESC
LIMIT @Size OFFSET @Skip;

-- name: ListAscPaged :many
SELECT
    m.group_id,
    m.user_id,
    s.username,
    u.email,
    u.student_id,
    m.role_id,
    gr.role,
    gr.access_level
FROM memberships AS m
JOIN group_role AS gr ON gr.id = m.role_id
JOIN users AS u ON u.id = m.user_id
JOIN settings AS s ON s.user_id = u.id
WHERE group_id = $1
ORDER BY @SortBy::text ASC
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
    gr.role,
    gr.access_level
FROM
    memberships AS m
        JOIN
    group_role AS gr ON gr.id = m.role_id
WHERE
    user_id = $1 AND group_id = $2;

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

-- name: DeletePendingByID :exec
DELETE FROM pending_memberships
WHERE id = $1;

-- name: GetPendingByUserIdentifier :many
SELECT
    pm.id,
    pm.user_identifier,
    pm.group_id,
    pm.role_id,
    gr.role,
    gr.access_level
FROM pending_memberships AS pm
JOIN group_role AS gr ON gr.id = pm.role_id
WHERE pm.user_identifier = @email OR pm.user_identifier = @student_id;

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