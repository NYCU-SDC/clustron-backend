CREATE TABLE ldap_numbers (
    number INTEGER NOT NULL,
    type VARCHAR(10) NOT NULL, -- 'user' or 'group'
    PRIMARY KEY (type, number)
);