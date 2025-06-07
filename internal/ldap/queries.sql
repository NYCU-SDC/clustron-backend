-- name: GetAllUidNumbers :many
SELECT number FROM ldap_numbers WHERE type = 'user' ORDER BY number;

-- name: GetAllGidNumbers :many
SELECT number FROM ldap_numbers WHERE type = 'group' ORDER BY number; 