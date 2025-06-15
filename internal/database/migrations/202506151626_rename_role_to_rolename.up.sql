ALTER TABLE group_role
ADD COLUMN role_name VARCHAR(50) NOT NULL ;
UPDATE group_role SET role_name = role;