-- Rollback Migration: Initial Schema
-- Description: Drop initial database schema
-- Created: 2024-01-01T00:00:00Z

-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_templates_updated_at ON templates;

-- Drop functions
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP FUNCTION IF EXISTS clean_expired_records();

-- Drop tables (in reverse order of creation due to foreign keys)
DROP TABLE IF EXISTS rate_limits;
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS templates;
DROP TABLE IF EXISTS otp_codes;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS admin_sessions;
DROP TABLE IF EXISTS users;

-- Drop enum types
DROP TYPE IF EXISTS audit_severity;
DROP TYPE IF EXISTS template_type;
DROP TYPE IF EXISTS mfa_method;
DROP TYPE IF EXISTS admin_level;

-- Drop extensions (be careful with this in production)
-- DROP EXTENSION IF EXISTS "pgcrypto";
-- DROP EXTENSION IF EXISTS "uuid-ossp";