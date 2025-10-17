-- Migration: Remove Template System (Simple)
-- Description: Drops all template-related tables and functions

-- Drop triggers first
DROP TRIGGER IF EXISTS trigger_update_templates_updated_at ON templates;

-- Drop functions
DROP FUNCTION IF EXISTS update_templates_updated_at();

-- Drop indexes
DROP INDEX IF EXISTS idx_templates_type_purpose_language;
DROP INDEX IF EXISTS idx_templates_is_default;
DROP INDEX IF EXISTS idx_templates_is_active;
DROP INDEX IF EXISTS idx_templates_created_by;
DROP INDEX IF EXISTS idx_templates_created_at;
DROP INDEX IF EXISTS idx_templates_unique_default;

DROP INDEX IF EXISTS idx_template_versions_template_id;
DROP INDEX IF EXISTS idx_template_versions_version;
DROP INDEX IF EXISTS idx_template_versions_unique;

DROP INDEX IF EXISTS idx_template_usage_template_id;
DROP INDEX IF EXISTS idx_template_usage_used_at;
DROP INDEX IF EXISTS idx_template_usage_success;

-- Drop tables (in reverse order due to foreign key constraints)
DROP TABLE IF EXISTS template_usage;
DROP TABLE IF EXISTS template_versions;
DROP TABLE IF EXISTS templates;