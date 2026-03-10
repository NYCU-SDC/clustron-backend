-- Update memberships
ALTER TABLE memberships
DROP CONSTRAINT memberships_group_id_fkey,
  ADD CONSTRAINT memberships_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;

-- Update pending_memberships
ALTER TABLE pending_memberships
DROP CONSTRAINT pending_memberships_group_id_fkey,
  ADD CONSTRAINT pending_memberships_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;

-- Update ldap_groups
ALTER TABLE ldap_groups
DROP CONSTRAINT ldap_groups_group_id_fkey,
  ADD CONSTRAINT ldap_groups_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;

-- Update links
ALTER TABLE links
DROP CONSTRAINT links_group_id_fkey,
  ADD CONSTRAINT links_group_id_fkey
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE;