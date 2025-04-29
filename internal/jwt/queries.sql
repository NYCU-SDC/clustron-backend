-- name: GetByID :one
SELECT * FROM refresh_tokens WHERE id = $1;

-- name: GetUserByRefreshToken :one
SELECT u.* FROM refresh_tokens r JOIN users u ON r.user_id = u.id WHERE r.id = $1;

-- name: Create :one
INSERT INTO refresh_tokens (user_id, expiration_date) VALUES ($1, $2) RETURNING *;

-- name: Inactivate :one
UPDATE refresh_tokens SET is_active = FALSE WHERE id = $1 RETURNING *;

-- name: Delete :execrows
DELETE FROM refresh_tokens WHERE expiration_date > now() OR is_active = FALSE;