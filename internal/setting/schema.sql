CREATE TABLE IF NOT EXISTS settings (
    user_id UUID REFERENCES users(id) NOT NULL,
    username VARCHAR(255) NOT NULL,
    linux_username VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS public_keys (
    user_id UUID REFERENCES users(id) NOT NULL,
    keyname VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    PRIMARY KEY (user_id, keyname)
)