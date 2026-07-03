BEGIN;

ALTER TABLE ldap_user ALTER COLUMN uid_number DROP DEFAULT;

DROP SEQUENCE IF EXISTS ldap_user_uid_number_seq;

COMMIT;
