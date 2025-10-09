-- Rollback MFA and API Keys Schema Migration

-- Drop functions
DROP FUNCTION IF EXISTS get_mfa_stats();
DROP FUNCTION IF EXISTS get_api_key_stats(UUID);
DROP FUNCTION IF EXISTS hash_backup_codes(JSONB);
DROP FUNCTION IF EXISTS validate_api_key_scopes(JSONB);
DROP FUNCTION IF EXISTS cleanup_expired_api_keys();

-- Drop triggers
DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;
DROP TRIGGER IF EXISTS update_mfa_configurations_updated_at ON mfa_configurations;

-- Drop tables
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_configurations;