CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS group_role (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role VARCHAR(50),
    access_level VARCHAR(50) NOT NULL
);

INSERT INTO group_role (id, role, access_level) VALUES
('e02311a8-5a17-444a-b5bb-5c04afa8fa88', 'group_owner', 'GROUP_OWNER'),
('524db082-9d0d-4515-b70c-af3766414bd7', 'teacher_assistant', 'GROUP_ADMIN'),
('de2ed988-a34f-40d3-af70-7e54fa266b37', 'student', 'USER'),
('c5e8a9c9-0b71-434a-ae61-b66983736217', 'auditor', 'USER');