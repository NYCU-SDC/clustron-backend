-- name: ExistsInfoByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM login_info
    WHERE identifier = $1
) AS exists;

-- name: ExistsInfoByEmail :one
SELECT EXISTS (
    SELECT 1
    FROM login_info
    WHERE email = $1
) AS exists;

-- name: GetInfoByIdentifier :one
SELECT *
FROM login_info
WHERE identifier = $1;

-- name: GetInfoByUserID :many
SELECT *
FROM login_info
WHERE user_id = $1;

-- name: GetInfoByEmail :one
SELECT *
FROM login_info
WHERE email = $1;

-- name: CreateInfo :one
INSERT INTO login_info (user_id, providerType, identifier, email)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UpdateInfo :one
UPDATE login_info
SET providerType = $1, identifier = $2, email = $3, updated_at = NOW()
WHERE id = $4
RETURNING *;

-- name: DeleteInfo :exec
DELETE FROM login_info WHERE id = $1;

-- name: GetTokenByID :one
SELECT * FROM login_tokens WHERE id = $1;

-- name: CreateToken :one
INSERT INTO login_tokens (user_id, callback, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: InactivateToken :one
UPDATE login_tokens
SET is_active = FALSE
WHERE id = $1
RETURNING *;

-- name: DeleteExpiredTokens :exec
DELETE FROM login_tokens
WHERE expires_at < NOW() OR is_active = FALSE;