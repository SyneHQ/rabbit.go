-- Migration for rabbit.go database schema
-- PostgreSQL Database Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Teams table
CREATE TABLE IF NOT EXISTS "Team" (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Team tokens table (references existing Team table without constraint)
CREATE TABLE IF NOT EXISTS team_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id VARCHAR(255) NOT NULL, -- References Team(id) but no constraint since it's managed elsewhere
    token VARCHAR(512) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE
);

-- Port assignments table
CREATE TABLE IF NOT EXISTS port_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id VARCHAR(255) NOT NULL, -- References Team(id) but no constraint
    token_id UUID NOT NULL REFERENCES team_tokens(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(20) NOT NULL DEFAULT 'tcp',
    is_reserved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(port, protocol),
    CONSTRAINT valid_protocol CHECK (protocol IN ('tcp', 'udp', 'http', 'https'))
);

-- Connection sessions table (for active connections tracking)
CREATE TABLE IF NOT EXISTS connection_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id VARCHAR(255) NOT NULL, -- References Team(id) but no constraint
    token_id UUID NOT NULL REFERENCES team_tokens(id) ON DELETE CASCADE,
    port_assign_id UUID NOT NULL REFERENCES port_assignments(id) ON DELETE CASCADE,
    client_ip VARCHAR(45) NOT NULL,
    server_port INTEGER NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    status VARCHAR(20) DEFAULT 'active',
    CONSTRAINT valid_session_status CHECK (status IN ('active', 'inactive'))
);

-- Connection logs table (for historical tracking)
CREATE TABLE IF NOT EXISTS connection_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_id VARCHAR(255) NOT NULL, -- References Team(id) but no constraint
    token_id UUID NOT NULL REFERENCES team_tokens(id) ON DELETE CASCADE,
    port_assign_id UUID NOT NULL REFERENCES port_assignments(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    client_port INTEGER,
    server_port INTEGER NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE,
    bytes_received BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    connection_time_ms BIGINT,
    status VARCHAR(20) DEFAULT 'active',
    error_message TEXT,
    user_agent TEXT,
    request_path TEXT,
    CONSTRAINT valid_log_status CHECK (status IN ('active', 'closed', 'error', 'timeout'))
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_team_tokens_team_id ON team_tokens(team_id);
CREATE INDEX IF NOT EXISTS idx_team_tokens_token ON team_tokens(token) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_team_tokens_active ON team_tokens(is_active, expires_at);

CREATE INDEX IF NOT EXISTS idx_port_assignments_team_id ON port_assignments(team_id);
CREATE INDEX IF NOT EXISTS idx_port_assignments_token_id ON port_assignments(token_id);
CREATE INDEX IF NOT EXISTS idx_port_assignments_port ON port_assignments(port, protocol);

CREATE INDEX IF NOT EXISTS idx_connection_sessions_team_id ON connection_sessions(team_id);
CREATE INDEX IF NOT EXISTS idx_connection_sessions_token_id ON connection_sessions(token_id);
CREATE INDEX IF NOT EXISTS idx_connection_sessions_status ON connection_sessions(status);
CREATE INDEX IF NOT EXISTS idx_connection_sessions_started_at ON connection_sessions(started_at);

CREATE INDEX IF NOT EXISTS idx_connection_logs_team_id ON connection_logs(team_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_token_id ON connection_logs(token_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_session_id ON connection_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_connection_logs_started_at ON connection_logs(started_at);
CREATE INDEX IF NOT EXISTS idx_connection_logs_status ON connection_logs(status);
CREATE INDEX IF NOT EXISTS idx_connection_logs_client_ip ON connection_logs(client_ip);

-- Function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updating updated_at columns (drop and recreate to avoid conflicts)
DROP TRIGGER IF EXISTS update_teams_updated_at ON "Team";
CREATE TRIGGER update_teams_updated_at BEFORE UPDATE ON "Team"
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_port_assignments_updated_at ON port_assignments;
CREATE TRIGGER update_port_assignments_updated_at BEFORE UPDATE ON port_assignments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate connection time when ending a session
CREATE OR REPLACE FUNCTION calculate_connection_time()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.ended_at IS NOT NULL AND OLD.ended_at IS NULL THEN
        NEW.connection_time_ms = EXTRACT(EPOCH FROM (NEW.ended_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for calculating connection time (drop and recreate to avoid conflicts)
DROP TRIGGER IF EXISTS calculate_connection_time_trigger ON connection_logs;
CREATE TRIGGER calculate_connection_time_trigger BEFORE UPDATE ON connection_logs
    FOR EACH ROW EXECUTE FUNCTION calculate_connection_time();

-- View for connection statistics
CREATE OR REPLACE VIEW connection_stats AS
SELECT
    cl.team_id,
    DATE(cl.started_at) as date,
    COUNT(*) as total_connections,
    COUNT(CASE WHEN cl.status = 'active' THEN 1 END) as active_connections,
    COALESCE(SUM(cl.bytes_received), 0) as total_bytes_received,
    COALESCE(SUM(cl.bytes_sent), 0) as total_bytes_sent,
    COALESCE(AVG(cl.connection_time_ms), 0) as avg_connection_time_ms
FROM connection_logs cl
GROUP BY cl.team_id, DATE(cl.started_at);