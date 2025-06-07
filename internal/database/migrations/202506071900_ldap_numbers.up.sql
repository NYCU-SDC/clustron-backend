CREATE TABLE IF NOT EXISTS ldap_numbers (
    number INTEGER PRIMARY KEY,
    type VARCHAR(10) NOT NULL -- 'user' or 'group'
);