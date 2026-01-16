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
-- 調整點：
-- 1. 改用命名參數 @limit 和 @offset (符合專案習慣的 @Size/@Skip 風格)
-- 2. 使用 CURRENT_TIMESTAMP 維持一致性
SELECT *
FROM modules
ORDER BY created_at DESC
    LIMIT @Size OFFSET @Skip;

-- name: UpdateModule :one
UPDATE modules
SET
    title = $2,
    description = $3,
    environment = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE id = $1
    RETURNING *;

-- name: DeleteModule :exec
DELETE FROM modules
WHERE id = $1;