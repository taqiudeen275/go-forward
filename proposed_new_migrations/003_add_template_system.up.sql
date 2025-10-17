-- Migration: Add Template System (Simple)
-- Description: Creates basic template tables without default data

-- Add missing columns to existing templates table
ALTER TABLE templates 
ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;

-- Drop foreign key constraints temporarily to change column types
ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_created_by_fkey;
ALTER TABLE templates DROP CONSTRAINT IF EXISTS templates_updated_by_fkey;

-- Update column types
ALTER TABLE templates 
ALTER COLUMN created_by TYPE VARCHAR(255),
ALTER COLUMN updated_by TYPE VARCHAR(255);

-- Template versions table for version history
CREATE TABLE IF NOT EXISTS template_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    subject TEXT,
    content TEXT NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    change_log TEXT
);

-- Template usage tracking table
CREATE TABLE IF NOT EXISTS template_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES templates(id) ON DELETE CASCADE,
    used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    success BOOLEAN NOT NULL DEFAULT true
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_templates_type_purpose_language ON templates(type, purpose, language);
CREATE INDEX IF NOT EXISTS idx_templates_is_default ON templates(is_default) WHERE is_default = true;
CREATE INDEX IF NOT EXISTS idx_templates_is_active ON templates(is_active);
CREATE INDEX IF NOT EXISTS idx_templates_created_by ON templates(created_by);
CREATE INDEX IF NOT EXISTS idx_templates_created_at ON templates(created_at);

CREATE INDEX IF NOT EXISTS idx_template_versions_template_id ON template_versions(template_id);
CREATE INDEX IF NOT EXISTS idx_template_versions_version ON template_versions(template_id, version);

CREATE INDEX IF NOT EXISTS idx_template_usage_template_id ON template_usage(template_id);
CREATE INDEX IF NOT EXISTS idx_template_usage_used_at ON template_usage(used_at);
CREATE INDEX IF NOT EXISTS idx_template_usage_success ON template_usage(success);

-- Unique constraint to ensure only one default template per type/purpose/language
CREATE UNIQUE INDEX IF NOT EXISTS idx_templates_unique_default 
ON templates(type, purpose, language) 
WHERE is_default = true;

-- Unique constraint for template versions
CREATE UNIQUE INDEX IF NOT EXISTS idx_template_versions_unique 
ON template_versions(template_id, version);

-- Add trigger to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_templates_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_templates_updated_at
    BEFORE UPDATE ON templates
    FOR EACH ROW
    EXECUTE FUNCTION update_templates_updated_at();

-- Add comments for documentation
COMMENT ON TABLE templates IS 'Stores customizable email and SMS templates with versioning support';
COMMENT ON TABLE template_versions IS 'Stores version history for templates';
COMMENT ON TABLE template_usage IS 'Tracks template usage statistics for analytics';

COMMENT ON COLUMN templates.type IS 'Template type: email or sms';
COMMENT ON COLUMN templates.purpose IS 'Template purpose: login, registration, verification, etc.';
COMMENT ON COLUMN templates.language IS 'Template language code (ISO 639-1)';
COMMENT ON COLUMN templates.version IS 'Current version number of the template';
COMMENT ON COLUMN templates.subject IS 'Email subject line (null for SMS templates)';
COMMENT ON COLUMN templates.content IS 'Template content with variable placeholders';
COMMENT ON COLUMN templates.variables IS 'JSON array of available variables for this template';
COMMENT ON COLUMN templates.is_default IS 'Whether this is the default template for its type/purpose/language';
COMMENT ON COLUMN templates.is_active IS 'Whether this template is active and can be used';
COMMENT ON COLUMN templates.metadata IS 'Additional metadata for the template';