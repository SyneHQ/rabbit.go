-- Clean-up SQL for rabbit.go database (safe for dev/test environments)
-- WARNING: Do NOT run in production unless you intend to delete ALL data!

-- Disable triggers to avoid foreign key issues during truncation
ALTER TABLE IF connection_logs DISABLE TRIGGER ALL;
ALTER TABLE IF EXISTS connection_sessions DISABLE TRIGGER ALL;
ALTER TABLE IF EXISTS port_assignments DISABLE TRIGGER ALL;
ALTER TABLE IF EXISTS team_tokens DISABLE TRIGGER ALL;

-- Truncate all tables and restart identity (cascade to handle FKs)
TRUNCATE TABLE IF EXISTS connection_logs RESTART IDENTITY CASCADE;
TRUNCATE TABLE IF EXISTS connection_sessions RESTART IDENTITY CASCADE;
TRUNCATE TABLE IF EXISTS port_assignments RESTART IDENTITY CASCADE;
TRUNCATE TABLE IF EXISTS team_tokens RESTART IDENTITY CASCADE;

-- Re-enable triggers
ALTER TABLE IF EXISTS connection_logs ENABLE TRIGGER ALL;
ALTER TABLE IF EXISTS connection_sessions ENABLE TRIGGER ALL;
ALTER TABLE IF EXISTS port_assignments ENABLE TRIGGER ALL;
ALTER TABLE IF EXISTS team_tokens ENABLE TRIGGER ALL;

-- Drop the Team table (correct table name is "Team" with quotes, not teams)
DROP TABLE IF EXISTS team_tokens CASCADE;
DROP TABLE IF EXISTS port_assignments CASCADE;
DROP TABLE IF EXISTS connection_sessions CASCADE;
DROP TABLE IF EXISTS connection_logs CASCADE;
DROP VIEW IF EXISTS connection_stats CASCADE;

-- Drop all the indexes
DROP INDEX IF EXISTS idx_team_tokens_team_id;
DROP INDEX IF EXISTS idx_team_tokens_token;
DROP INDEX IF EXISTS idx_team_tokens_active;
DROP INDEX IF EXISTS idx_port_assignments_team_id;
DROP INDEX IF EXISTS idx_port_assignments_token_id;
DROP INDEX IF EXISTS idx_port_assignments_port;
DROP INDEX IF EXISTS idx_connection_sessions_team_id;
DROP INDEX IF EXISTS idx_connection_sessions_token_id;
DROP INDEX IF EXISTS idx_connection_sessions_status;
DROP INDEX IF EXISTS idx_connection_sessions_started_at;
DROP INDEX IF EXISTS idx_connection_logs_team_id;
DROP INDEX IF EXISTS idx_connection_logs_token_id;
DROP INDEX IF EXISTS idx_connection_logs_session_id;
DROP INDEX IF EXISTS idx_connection_logs_started_at;
DROP INDEX IF EXISTS idx_connection_logs_status;
DROP INDEX IF EXISTS idx_connection_logs_client_ip;

-- Drop all the functions
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP FUNCTION IF EXISTS calculate_connection_time();

-- Drop all the triggers
DROP TRIGGER IF EXISTS update_teams_updated_at ON teams;
DROP TRIGGER IF EXISTS update_port_assignments_updated_at ON port_assignments;
DROP TRIGGER IF EXISTS calculate_connection_time_trigger ON connection_logs;

-- Drop the foreign key constraint on team_tokens.team_id if it exists
ALTER TABLE IF EXISTS team_tokens DROP CONSTRAINT IF EXISTS team_tokens_team_id_fkey;
