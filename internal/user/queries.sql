-- name: GetByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetEmailByID :one
SELECT email FROM users WHERE id = $1;

-- name: GetRoleByID :one
SELECT role FROM users WHERE id = $1;

-- name: ExistsByIdentifier :one
SELECT EXISTS (
    SELECT 1 FROM users WHERE email = $1 OR student_id = $1
) AS email_exists;

-- name: Create :one
INSERT INTO users (email, role, student_id, updated_at) VALUES ($1, $2, $3, now()) RETURNING *;

-- name: CreateWithID :one
INSERT INTO users (id, email, role, student_id, updated_at)
VALUES ($1, $2, $3, $4, now())
RETURNING *;

-- name: Delete :execrows
DELETE FROM users WHERE id = $1;

-- name: GetIdByEmail :one
SELECT id FROM users WHERE email = $1;

-- name: GetIdByStudentId :one
SELECT id FROM users WHERE student_id = $1;

-- name: UpdateRole :one
UPDATE users SET role = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: UpdateStudentID :one
UPDATE users SET student_id = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: ListUidNumbers :many
SELECT uid_number FROM users WHERE uid_number IS NOT NULL ORDER BY uid_number;

-- name: SetUidNumber :exec
UPDATE users SET uid_number = $2 WHERE id = $1;

-- name: ListLoginMethods :many
SELECT providertype, email FROM login_info WHERE user_id = $1;
