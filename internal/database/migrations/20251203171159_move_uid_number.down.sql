BEGIN;

ALTER TABLE users
ADD COLUMN uid_number INTEGER;

UPDATE users u
SET uid_number = lu.uid_number
FROM ldap_user lu
WHERE u.id = lu.id;

COMMIT;