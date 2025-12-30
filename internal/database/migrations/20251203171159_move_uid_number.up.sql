BEGIN;

INSERT INTO ldap_user (id, uid_number)
SELECT id, uid_number
FROM users
WHERE uid_number IS NOT NULL;

ALTER TABLE users
DROP COLUMN uid_number;

COMMIT;