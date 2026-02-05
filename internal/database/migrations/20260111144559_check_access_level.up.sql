ALTER TABLE group_role
ADD CONSTRAINT check_access_level
CHECK (access_level IN ('GROUP_OWNER', 'GROUP_ADMIN', 'USER'));