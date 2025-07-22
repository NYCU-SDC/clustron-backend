CREATE TABLE IF NOT EXISTS login_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) NOT NULL,
    providerType VARCHAR(50) NOT NULL,
    identifier VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    is_linked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

