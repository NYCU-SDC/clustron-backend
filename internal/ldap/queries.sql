-- name: GetAllUidNumbers :many
SELECT number FROM ldap_numbers WHERE type = 'user' ORDER BY number;

-- name: GetAllGidNumbers :many
SELECT number FROM ldap_numbers WHERE type = 'group' ORDER BY number;

-- name: InsertUidNumber :exec
INSERT INTO ldap_numbers (number, type) VALUES ($1, 'user');

-- name: InsertGidNumber :exec
INSERT INTO ldap_numbers (number, type) VALUES ($1, 'group');