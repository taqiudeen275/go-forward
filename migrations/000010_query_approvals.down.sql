-- Rollback Query Approvals Migration
-- This migration removes all query approval related tables and functions

-- Drop views first (depend on tables)
DROP VIEW IF EXISTS approval_dashboard;
DROP VIEW IF EXISTS active_query_approvals;

-- Drop triggers
DROP TRIGGER IF EXISTS trigger_create_approval_history ON query_approvals;
DROP TRIGGER IF EXISTS trigger_update_query_approvals_updated_at ON query_approvals;

-- Drop functions
DROP FUNCTION IF EXISTS increment_approval_execution(UUID);
DROP FUNCTION IF EXISTS is_approval_valid(UUID);
DROP FUNCTION IF EXISTS create_approval_history();
DROP FUNCTION IF EXISTS update_query_approvals_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_approval_history_created_at;
DROP INDEX IF EXISTS idx_approval_history_performed_by;
DROP INDEX IF EXISTS idx_approval_history_approval_id;

DROP INDEX IF EXISTS idx_approval_notifications_recipient;
DROP INDEX IF EXISTS idx_approval_notifications_sent;
DROP INDEX IF EXISTS idx_approval_notifications_approval_id;

DROP INDEX IF EXISTS idx_query_approvals_created_at;
DROP INDEX IF EXISTS idx_query_approvals_expires_at;
DROP INDEX IF EXISTS idx_query_approvals_status;
DROP INDEX IF EXISTS idx_query_approvals_approved_by;
DROP INDEX IF EXISTS idx_query_approvals_requested_by;
DROP INDEX IF EXISTS idx_query_approvals_hash;
DROP INDEX IF EXISTS idx_query_approvals_unique_pending;

-- Drop tables (in reverse order of creation due to foreign key constraints)
DROP TABLE IF EXISTS approval_history;
DROP TABLE IF EXISTS approval_notifications;
DROP TABLE IF EXISTS query_approvals;

-- Remove approval settings from table_security_config
DELETE FROM table_security_config
WHERE table_name = '*' AND config_type = 'approval_settings';
