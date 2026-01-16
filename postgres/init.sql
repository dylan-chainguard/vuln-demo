-- Initialize database
CREATE DATABASE vulndb;

\c vulndb;

-- Create a simple users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, email) VALUES
    ('admin', 'admin@example.com'),
    ('user1', 'user1@example.com'),
    ('user2', 'user2@example.com');

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE vulndb TO vulnuser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO vulnuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO vulnuser;
