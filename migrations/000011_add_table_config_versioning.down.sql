-- Rollback Table Configuration Versioning and Templates Migration

-- Drop functions
DROP FUNCTION IF EXISTS validate_table_configuration_conflicts(VARCHAR(255), VARCHAR(255), UUID);
DROP FUNCTION IF EXISTS get_table_configuration_stats();
DROP FUNCTION IF EXISTS apply_configuration_template(UUID, VARCHAR(255), VARCHAR(255), VARCHAR(255), TEXT, UUID);

-- Drop tables
DROP TABLE IF EXISTS table_configuration_versions;
DROP TABLE IF EXISTS table_configuration_templates;