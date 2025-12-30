-- name: GetSetting :one
SELECT * FROM settings WHERE user_id = $1;

-- name: ExistByUserID :one
SELECT EXISTS (SELECT 1 FROM settings WHERE user_id = $1) AS exists;

-- name: ExistByLinuxUsername :one
SELECT EXISTS (SELECT 1 FROM settings WHERE linux_username = $1) AS exists;

-- name: CreateSetting :one
INSERT INTO settings (user_id, full_name, linux_username) VALUES ($1, $2, '') RETURNING *;

-- name: UpdateSetting :one
UPDATE settings SET full_name = $2, linux_username = $3 WHERE user_id = $1 RETURNING *;

-- name: GetPublicKeys :many
SELECT * FROM public_keys WHERE user_id = $1;

-- name: GetPublicKey :one
SELECT * FROM public_keys WHERE id = $1;

-- name: ExistPublicKey :one
SELECT EXISTS (SELECT 1 FROM public_keys WHERE public_key = $1) AS exists;

-- name: CreatePublicKey :one
INSERT INTO public_keys (user_id, title, public_key) VALUES ($1, $2, $3) RETURNING *;

-- name: DeletePublicKey :exec
DELETE FROM public_keys WHERE id = $1;

-- name: GetUIDByUserID :one
SELECT uid_number FROM ldap_user WHERE id = $1;

-- name: CreateLDAPUser :exec
INSERT INTO ldap_user (id, uid_number) VALUES ($1, $2);