-- Migration rollback: Remove table_name column from audit_logs
-- Description: Remove table_name, record_id, and metadata columns from audit_logs
-- Created: 2025-10-13

BEGIN;

-- Drop indexes
DROP INDEX IF EXISTS idx_audit_logs_table_name;
DROP INDEX IF EXISTS idx_audit_logs_record_id;

-- Remove columns
ALTER TABLE audit_logs DROP COLUMN IF EXISTS table_name;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS record_id;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS metadata;

COMMIT;