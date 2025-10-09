-- Rollback Audit and Security Logging Schema Migration

-- Drop functions
DROP FUNCTION IF EXISTS log_security_event(VARCHAR(50), VARCHAR(20), VARCHAR(50), VARCHAR(255), TEXT, UUID, UUID, VARCHAR(255), UUID, VARCHAR(100), JSONB, INET, TEXT, VARCHAR(255), VARCHAR(255), VARCHAR(50), DECIMAL(3,2));
DROP FUNCTION IF EXISTS log_admin_action(UUID, UUID, VARCHAR(100), VARCHAR(255), UUID, JSONB, INET, TEXT, VARCHAR(255), VARCHAR(255), VARCHAR(20), VARCHAR(50), TEXT, INTEGER);
DROP FUNCTION IF EXISTS cleanup_expired_admin_sessions();
DROP FUNCTION IF EXISTS update_admin_session_activity();

-- Drop triggers
DROP TRIGGER IF EXISTS update_admin_sessions_activity ON admin_sessions;
DROP TRIGGER IF EXISTS update_security_events_updated_at ON security_events;

-- Drop indexes for admin_sessions
DROP INDEX IF EXISTS idx_admin_sessions_active_expires;
DROP INDEX IF EXISTS idx_admin_sessions_user_active;
DROP INDEX IF EXISTS idx_admin_sessions_metadata;
DROP INDEX IF EXISTS idx_admin_sessions_capabilities;
DROP INDEX IF EXISTS idx_admin_sessions_security_flags;
DROP INDEX IF EXISTS idx_admin_sessions_mfa_verified;
DROP INDEX IF EXISTS idx_admin_sessions_created_at;
DROP INDEX IF EXISTS idx_admin_sessions_last_activity;
DROP INDEX IF EXISTS idx_admin_sessions_expires_at;
DROP INDEX IF EXISTS idx_admin_sessions_is_active;
DROP INDEX IF EXISTS idx_admin_sessions_ip_address;
DROP INDEX IF EXISTS idx_admin_sessions_admin_role_id;
DROP INDEX IF EXISTS idx_admin_sessions_user_id;
DROP INDEX IF EXISTS idx_admin_sessions_session_token;

-- Drop indexes for security_events
DROP INDEX IF EXISTS idx_security_events_user_timestamp;
DROP INDEX IF EXISTS idx_security_events_unresolved;
DROP INDEX IF EXISTS idx_security_events_severity_timestamp;
DROP INDEX IF EXISTS idx_security_events_details;
DROP INDEX IF EXISTS idx_security_events_false_positive;
DROP INDEX IF EXISTS idx_security_events_resolved;
DROP INDEX IF EXISTS idx_security_events_acknowledged;
DROP INDEX IF EXISTS idx_security_events_session_id;
DROP INDEX IF EXISTS idx_security_events_ip_address;
DROP INDEX IF EXISTS idx_security_events_timestamp;
DROP INDEX IF EXISTS idx_security_events_resource_id;
DROP INDEX IF EXISTS idx_security_events_resource;
DROP INDEX IF EXISTS idx_security_events_admin_role_id;
DROP INDEX IF EXISTS idx_security_events_user_id;
DROP INDEX IF EXISTS idx_security_events_category;
DROP INDEX IF EXISTS idx_security_events_severity;
DROP INDEX IF EXISTS idx_security_events_event_type;

-- Drop indexes for sql_execution_logs
DROP INDEX IF EXISTS idx_sql_execution_logs_status_timestamp;
DROP INDEX IF EXISTS idx_sql_execution_logs_validation_timestamp;
DROP INDEX IF EXISTS idx_sql_execution_logs_user_timestamp;
DROP INDEX IF EXISTS idx_sql_execution_logs_dangerous_operations;
DROP INDEX IF EXISTS idx_sql_execution_logs_security_warnings;
DROP INDEX IF EXISTS idx_sql_execution_logs_affected_tables;
DROP INDEX IF EXISTS idx_sql_execution_logs_session_id;
DROP INDEX IF EXISTS idx_sql_execution_logs_ip_address;
DROP INDEX IF EXISTS idx_sql_execution_logs_timestamp;
DROP INDEX IF EXISTS idx_sql_execution_logs_execution_status;
DROP INDEX IF EXISTS idx_sql_execution_logs_validation_result;
DROP INDEX IF EXISTS idx_sql_execution_logs_query_type;
DROP INDEX IF EXISTS idx_sql_execution_logs_query_hash;
DROP INDEX IF EXISTS idx_sql_execution_logs_admin_role_id;
DROP INDEX IF EXISTS idx_sql_execution_logs_user_id;

-- Drop indexes for admin_access_logs
DROP INDEX IF EXISTS idx_admin_access_logs_outcome_timestamp;
DROP INDEX IF EXISTS idx_admin_access_logs_action_timestamp;
DROP INDEX IF EXISTS idx_admin_access_logs_user_timestamp;
DROP INDEX IF EXISTS idx_admin_access_logs_details;
DROP INDEX IF EXISTS idx_admin_access_logs_request_id;
DROP INDEX IF EXISTS idx_admin_access_logs_session_id;
DROP INDEX IF EXISTS idx_admin_access_logs_ip_address;
DROP INDEX IF EXISTS idx_admin_access_logs_timestamp;
DROP INDEX IF EXISTS idx_admin_access_logs_outcome;
DROP INDEX IF EXISTS idx_admin_access_logs_resource_id;
DROP INDEX IF EXISTS idx_admin_access_logs_resource;
DROP INDEX IF EXISTS idx_admin_access_logs_action;
DROP INDEX IF EXISTS idx_admin_access_logs_admin_role_id;
DROP INDEX IF EXISTS idx_admin_access_logs_user_id;

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS sql_execution_logs;
DROP TABLE IF EXISTS admin_access_logs;