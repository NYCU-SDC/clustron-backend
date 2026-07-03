BEGIN;

CREATE SEQUENCE IF NOT EXISTS ldap_user_uid_number_seq
    AS BIGINT START WITH 10000 INCREMENT BY 1 MINVALUE 10000 NO MAXVALUE
    OWNED BY ldap_user.uid_number;

ALTER TABLE ldap_user
    ALTER COLUMN uid_number SET DEFAULT nextval('ldap_user_uid_number_seq');

COMMIT;
