INSERT INTO users (id, email, role, uid_number, student_id) VALUES
('6755aa20-0752-4c0a-9a09-8bcfe8d225da', 'testuser@example.com', 'user', 20001, 'S12345678'),
('474410d9-5eb9-4359-a469-4e5c7366f9ee', 'testadmin@example.com', 'admin', 20003, 'S12345680'),
('4336d85b-9a5f-486c-a7a8-075dc4f84da3', 'testorganizer@example.com', 'organizer', 20004, 'S12345681');

-- insert settings for users
INSERT INTO settings (user_id, full_name, linux_username) VALUES
('6755aa20-0752-4c0a-9a09-8bcfe8d225da', 'Test User', 'testuser'),
('474410d9-5eb9-4359-a469-4e5c7366f9ee', 'Test Admin', 'testadmin'),
('4336d85b-9a5f-486c-a7a8-075dc4f84da3', 'Test Organizer', 'testorganizer');