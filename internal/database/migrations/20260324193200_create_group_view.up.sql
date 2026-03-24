CREATE VIEW groups_with_ldap_cn AS
SELECT
    g.id,
    g.title,
    g.description,
    g.is_archived,
    g.created_at,
    g.updated_at,
    lg.ldap_cn
FROM groups AS g
LEFT JOIN ldap_groups AS lg ON g.id = lg.group_id AND lg.type = 'BASE';