-- name: GetLDAPBaseGroupCNByGroupID :one
SELECT ldap_cn FROM ldap_groups WHERE group_id = $1 AND type = 'BASE';

-- name: GetLDAPAdminGroupCNByGroupID :one
SELECT ldap_cn FROM ldap_groups WHERE group_id = $1 AND type = 'ADMIN';

-- name: GetLDAPGroupCNByID :one
SELECT ldap_cn
FROM ldap_groups
WHERE id = $1 AND ldap_cn IS NOT NULL AND ldap_cn <> '';
