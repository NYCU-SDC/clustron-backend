DROP TABLE IF EXISTS login_tokens;

ALTER TABLE login_info
    DROP CONSTRAINT unique_identifier;