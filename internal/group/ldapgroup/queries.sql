-- name: GetLDAPBaseGroupCNByGroupID :one
SELECT ldap_cn FROM ldap_groups WHERE group_id = $1 AND type = 'BASE';

-- name: GetLDAPAdminGroupCNByGroupID :one
SELECT ldap_cn FROM ldap_groups WHERE group_id = $1 AND type = 'ADMIN';
