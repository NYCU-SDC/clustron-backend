-- name: GetByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: ExistsByEmail :one
SELECT EXISTS (
    SELECT 1 FROM users WHERE email = $1
) AS email_exists;

-- name: Create :one
INSERT INTO users (email, role, student_id, updated_at) VALUES ($1, $2, $3, now()) RETURNING *;

-- name: Delete :execrows
DELETE FROM users WHERE id = $1;