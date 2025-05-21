CREATE TABLE IF NOT EXISTS settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) NOT NULL,
    username VARCHAR(255),
    linux_username VARCHAR(255)
);