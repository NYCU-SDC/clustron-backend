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


-- name: UpdateFullName :one
UPDATE users SET full_name = $2, updated_at = now() WHERE id = $1 RETURNING *;

-- name: ListLoginMethods :many
SELECT providertype, email FROM login_info WHERE user_id = $1;

-- name: CountSearchByIdentifier :one
SELECT COUNT(*) FROM users WHERE email ILIKE @Query || '%' OR student_id ILIKE @Query || '%';

-- name: SearchByIdentifier :many
SELECT
    COALESCE(
        CASE
            WHEN email ILIKE @Query || '%' THEN email
            WHEN student_id ILIKE @Query || '%' THEN student_id
        END, ''
    )::TEXT AS identifier
FROM users
WHERE email ILIKE @Query || '%' OR student_id ILIKE @Query || '%'
ORDER BY identifier
LIMIT @Size OFFSET @Skip;

-- name: ListUsers :many
SELECT id, full_name, email, student_id, role
FROM users
WHERE
    (sqlc.narg('search')::text IS NULL OR (email ILIKE '%' || sqlc.narg('search') || '%' OR student_id ILIKE '%' || sqlc.narg('search') || '%' OR full_name ILIKE '%' || sqlc.narg('search') || '%'))
  AND (sqlc.narg('role')::text IS NULL OR role = sqlc.narg('role'))
ORDER BY
    CASE WHEN sqlc.narg('sort_by')::text = 'fullName' AND sqlc.narg('sort')::text = 'asc' THEN full_name END ASC,
    CASE WHEN sqlc.narg('sort_by')::text = 'fullName' AND sqlc.narg('sort')::text = 'desc' THEN full_name END DESC,
    CASE WHEN sqlc.narg('sort_by')::text = 'email' AND sqlc.narg('sort')::text = 'asc' THEN email END ASC,
    CASE WHEN sqlc.narg('sort_by')::text = 'email' AND sqlc.narg('sort')::text = 'desc' THEN email END DESC,
    CASE WHEN sqlc.narg('sort_by')::text = 'studentId' AND sqlc.narg('sort')::text = 'asc' THEN student_id END ASC,
    CASE WHEN sqlc.narg('sort_by')::text = 'studentId' AND sqlc.narg('sort')::text = 'desc' THEN student_id END DESC,
    created_at DESC
LIMIT $1 OFFSET $2;

-- name: CountUsers :one
SELECT COUNT(*)
FROM users
WHERE
    (sqlc.narg('search')::text IS NULL OR (email ILIKE '%' || sqlc.narg('search') || '%' OR student_id ILIKE '%' || sqlc.narg('search') || '%' OR full_name ILIKE '%' || sqlc.narg('search') || '%'))
  AND (sqlc.narg('role')::text IS NULL OR role = sqlc.narg('role'));
