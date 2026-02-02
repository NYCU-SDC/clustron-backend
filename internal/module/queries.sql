-- queries.sql

-- name: CreateModule :one
INSERT INTO modules (
    user_id,
    title,
    description,
    environment
) VALUES (
             $1, $2, $3, $4
         )
    RETURNING *;

-- name: GetModule :one
SELECT *
FROM modules
WHERE id = $1;

-- name: ListModules :many
SELECT *
FROM modules
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: UpdateModule :one
UPDATE modules
SET
    title = $3,
    description = $4,
    environment = $5,
    updated_at = NOW()
WHERE id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteModule :exec
DELETE FROM modules
WHERE id = $1 AND user_id = $2;