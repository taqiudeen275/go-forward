-- Rollback Admin Audit and Security Logging Migration
-- This migration removes all audit logging tables and functions

-- Drop views first
DROP VIEW IF EXISTS admin_activity_summary;

-- Drop functions
DROP FUNCTION IF EXISTS cleanup_old_audit_logs(INTEGER);
DROP FUNCTION IF EXISTS create_security_event(VARCHAR, VARCHAR, TEXT, VARCHAR, UUID, UUID, JSONB, INET, TEXT, VARCHAR);
DROP FUNCTION IF EXISTS log_admin_action(UUID, VARCHAR, VARCHAR, VARCHAR, VARCHAR, JSONB, INET, TEXT, VARCHAR, BOOLEAN, TEXT);

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS security_notifications;
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS sql_execution_logs;
DROP TABLE IF EXISTS admin_access_logs;

-- Note: Indexes and triggers are automatically dropped with their tables
