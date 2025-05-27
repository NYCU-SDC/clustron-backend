-- name: ListGroupMembersDescPaged :many
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
LIMIT @Size OFFSET @page;

-- name: ListGroupMembersAscPaged :many
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
LIMIT @Size OFFSET @page;

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

-- name: GetMembershipByUser :one
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

-- name: AddOrUpdatePending :one
INSERT INTO pending_group_members (user_identifier, group_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_identifier, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING *;

-- name: ExistsPendingByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM pending_group_members
    WHERE group_id = $1 AND user_identifier = $2
) AS exists;

-- name: GetPendingByIdentifier :one
SELECT *
FROM pending_group_members
WHERE group_id = $1 AND user_identifier = $2;

-- name: UpdatePending :one
UPDATE pending_group_members
SET role_id = $1
WHERE group_id = $2 AND user_identifier = $3
RETURNING *;

-- name: AddOrUpdate :one
INSERT INTO memberships (group_id, user_id, role_id)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, group_id) DO UPDATE SET role_id = EXCLUDED.role_id
RETURNING *;

-- name: Delete :exec
DELETE FROM memberships
WHERE group_id = $1 AND user_id = $2;

-- name: UpdateMembershipRole :one
UPDATE memberships
SET role_id = $1
WHERE group_id = $2 AND user_id = $3
RETURNING *;