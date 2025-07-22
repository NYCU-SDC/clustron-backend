-- name: ExistsByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM login_info
    WHERE identifier = $1
) AS exists;

-- name: ExistsByEmail :one
SELECT EXISTS (
    SELECT 1
    FROM login_info
    WHERE email = $1
) AS exists;

-- name: GetByIdentifier :one
SELECT *
FROM login_info
WHERE identifier = $1;

-- name: GetByUserID :many
SELECT *
FROM login_info
WHERE user_id = $1;

-- name: GetEmailByUserID :one
SELECT email
FROM login_info
WHERE user_id = $1 AND is_linked = FALSE;

-- name: GetByEmail :one
SELECT *
FROM login_info
WHERE email = $1;

-- name: Create :one
INSERT INTO login_info (user_id, providerType, identifier, email)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: Update :one
UPDATE login_info
SET providerType = $1, identifier = $2, email = $3, updated_at = NOW()
WHERE id = $4
RETURNING *;

-- name: Delete :exec
DELETE FROM login_info WHERE id = $1;