-- Migration: Add table_name column to audit_logs
-- Description: Add table_name and record_id columns to audit_logs for better tracking
-- Created: 2025-10-13

BEGIN;

-- Add table_name column to audit_logs
ALTER TABLE audit_logs ADD COLUMN table_name VARCHAR(100);

-- Add record_id column to audit_logs (for tracking specific record operations)
ALTER TABLE audit_logs ADD COLUMN record_id VARCHAR(255);

-- Add metadata column to audit_logs (for additional structured data)
ALTER TABLE audit_logs ADD COLUMN metadata JSONB DEFAULT '{}';

-- Update existing audit_logs to have empty table_name where null
UPDATE audit_logs SET table_name = '' WHERE table_name IS NULL;

-- Create index on table_name for better query performance
CREATE INDEX idx_audit_logs_table_name ON audit_logs(table_name);
CREATE INDEX idx_audit_logs_record_id ON audit_logs(record_id);

-- Update the audit_logs table comment
COMMENT ON COLUMN audit_logs.table_name IS 'Name of the table being audited';
COMMENT ON COLUMN audit_logs.record_id IS 'ID of the specific record being audited';
COMMENT ON COLUMN audit_logs.metadata IS 'Additional structured data for the audit event';

COMMIT;