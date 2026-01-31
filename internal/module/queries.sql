-- queries.sql

-- name: CreateModule :one
INSERT INTO modules (
    title,
    description,
    environment
) VALUES (
             $1, $2, $3
         )
RETURNING *;

-- name: GetModule :one
SELECT *
FROM modules
WHERE id = $1 LIMIT 1;

-- name: ListModules :many
SELECT *
FROM modules
ORDER BY created_at DESC LIMIT @Size OFFSET @Skip;

-- name: UpdateModule :one
UPDATE modules
SET
    title = $2,
    description = $3,
    environment = $4,
    updated_at = NOW()
WHERE id = $1
    RETURNING *;

-- name: DeleteModule :exec
DELETE FROM modules
WHERE id = $1;