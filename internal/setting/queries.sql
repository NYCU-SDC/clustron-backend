-- name: GetSetting :one
SELECT * FROM settings WHERE user_id = $1;

-- name: UpdateSetting :one
UPDATE settings SET username = $2, linux_username = $3 WHERE user_id = $1 RETURNING *;

-- name: GetPublicKeys :many
SELECT * FROM public_keys WHERE user_id = $1;

-- name: GetPublicKey :one
SELECT * FROM public_keys WHERE id = $1;

-- name: AddPublicKey :one
INSERT INTO public_keys (user_id, title, public_key) VALUES ($1, $2, $3) RETURNING *;

-- name: DeletePublicKey :exec
DELETE FROM public_keys WHERE id = $1;