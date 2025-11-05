-- name: CountAllModules :one
SELECT COUNT(*) FROM env_modules;

-- name: CountModulesByUser :one
SELECT COUNT(*) FROM env_modules WHERE user_id = $1;

-- name: ListModulesAscPaged :many
SELECT * FROM env_modules ORDER BY created_at ASC LIMIT @Size OFFSET @Skip;

-- name: ListModulesDescPaged :many
SELECT * FROM env_modules ORDER BY created_at DESC LIMIT @Size OFFSET @Skip;

-- name: ListUserModulesAscPaged :many
SELECT * FROM env_modules WHERE user_id = $1 ORDER BY created_at ASC LIMIT @Size OFFSET @Skip;

-- name: ListUserModulesDescPaged :many
SELECT * FROM env_modules WHERE user_id = $1 ORDER BY created_at DESC LIMIT @Size OFFSET @Skip;

-- name: GetModuleByID :one
SELECT * FROM env_modules WHERE id = $1;

-- name: GetModuleIfOwner :one
SELECT * FROM env_modules WHERE id = $1 AND user_id = $2;

-- name: CreateModule :one
INSERT INTO env_modules (user_id, title) VALUES ($1, $2) RETURNING *;

-- name: CreateModuleWithID :one
INSERT INTO env_modules (id, user_id, title) VALUES ($1, $2, $3) RETURNING *;

-- name: UpdateModule :one
UPDATE env_modules SET title = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: DeleteModule :exec
DELETE FROM env_modules WHERE id = $1;

-- name: ArchiveModule :one
UPDATE env_modules SET is_archived = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: UnarchiveModule :one
UPDATE env_modules SET is_archived = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING *;

-- name: ListModuleVariables :many
SELECT * FROM env_module_vars WHERE module_id = $1 ORDER BY position ASC;

-- name: GetModuleVariable :one
SELECT * FROM env_module_vars WHERE module_id = $1 AND key = $2;

-- name: UpsertModuleVariable :one
INSERT INTO env_module_vars (module_id, key, value, position)
VALUES ($1, $2, $3, $4)
    ON CONFLICT (module_id, key)
DO UPDATE SET value = EXCLUDED.value, position = EXCLUDED.position
           RETURNING *;

-- name: UpdateModuleVariables :exec
DELETE FROM env_module_vars WHERE module_id = $1;

-- name: UpdateModuleVariableValue :one
UPDATE env_module_vars SET value = $3, position = $4 WHERE module_id = $1 AND key = $2 RETURNING *;

-- name: DeleteModuleVariable :exec
DELETE FROM env_module_vars WHERE module_id = $1 AND key = $2;

-- name: GetModuleWithVariables :one
SELECT
    m.*,
    COALESCE(json_agg(
                     json_build_object(
                             'key', v.key,
                             'value', v.value,
                             'position', v.position
                     ) ORDER BY v.position
             ) FILTER (WHERE v.key IS NOT NULL), '[]') as variables
FROM env_modules m
         LEFT JOIN env_module_vars v ON m.id = v.module_id
WHERE m.id = $1
GROUP BY m.id;

-- name: ListUserModulesWithStats :many
SELECT
    m.*,
    COUNT(v.key) as variable_count
FROM env_modules m
         LEFT JOIN env_module_vars v ON m.id = v.module_id
WHERE m.user_id = $1
GROUP BY m.id
ORDER BY m.created_at DESC;

-- name: SearchUserModules :many
SELECT * FROM env_modules
WHERE user_id = $1 AND title ILIKE @SearchTitle
ORDER BY created_at DESC
    LIMIT @Size OFFSET @Skip;

-- name: CheckVariableExists :one
SELECT EXISTS(SELECT 1 FROM env_module_vars WHERE module_id = $1 AND key = $2) as exists;