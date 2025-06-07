CREATE TABLE IF NOT EXISTS ldap_numbers (
    number INTEGER NOT NULL,
    type VARCHAR(10) NOT NULL, -- 'user' or 'group'
    PRIMARY KEY (type, number)
);