-- Revert memberships: remove CASCADE and restore standard reference
ALTER TABLE memberships
DROP CONSTRAINT memberships_group_id_fkey,
  ADD CONSTRAINT memberships_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id);

-- Revert pending_memberships: remove CASCADE and restore standard reference
ALTER TABLE pending_memberships
DROP CONSTRAINT pending_memberships_group_id_fkey,
  ADD CONSTRAINT pending_memberships_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id);

-- Revert ldap_groups: remove CASCADE and restore standard reference
ALTER TABLE ldap_groups
DROP CONSTRAINT ldap_groups_group_id_fkey,
  ADD CONSTRAINT ldap_groups_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id);

-- Revert links: remove CASCADE and restore standard reference
ALTER TABLE links
DROP CONSTRAINT links_group_id_fkey,
  ADD CONSTRAINT links_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id);