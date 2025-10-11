-- Migration: Add Template System
-- Description: Creates tables for customizable email and SMS templates with versioning support

-- Templates table
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(20) NOT NULL CHECK (type IN ('email', 'sms')),
    purpose VARCHAR(50) NOT NULL CHECK (purpose IN (
        'login', 'registration', 'verification', 'password_reset', 
        'mfa_setup', 'account_lockout', 'welcome', 'security_alert'
    )),
    language VARCHAR(5) NOT NULL DEFAULT 'en',
    version INTEGER NOT NULL DEFAULT 1,
    subject TEXT, -- For email templates
    content TEXT NOT NULL,
    variables JSONB DEFAULT '[]'::jsonb,
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_by VARCHAR(255) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

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

-- Insert default email templates
INSERT INTO templates (type, purpose, language, subject, content, variables, is_default, is_active, created_by, updated_by) VALUES
-- Login OTP Email
('email', 'login', 'en', 'Login Verification Code - {{app_name}}', 
'Hello {{user_name}},

Your login verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

If you didn''t request this code, please ignore this email.

Best regards,
{{app_name}} Team', 
'[
    {"name": "user_name", "description": "User''s display name", "type": "string", "required": false, "example": "John Doe"},
    {"name": "otp_code", "description": "One-time password code", "type": "string", "required": true, "example": "123456"},
    {"name": "expiry_minutes", "description": "OTP expiry time in minutes", "type": "number", "required": false, "example": 10},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward Framework"}
]'::jsonb, 
true, true, 'system', 'system'),

-- Registration OTP Email
('email', 'registration', 'en', 'Welcome to {{app_name}} - Verify Your Account',
'Welcome {{user_name}},

Thank you for registering with {{app_name}}!

Your verification code is: {{otp_code}}

This code will expire in {{expiry_minutes}} minutes.

Best regards,
{{app_name}} Team',
'[
    {"name": "user_name", "description": "User''s display name", "type": "string", "required": false, "example": "John Doe"},
    {"name": "otp_code", "description": "One-time password code", "type": "string", "required": true, "example": "123456"},
    {"name": "expiry_minutes", "description": "OTP expiry time in minutes", "type": "number", "required": false, "example": 10},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward Framework"}
]'::jsonb,
true, true, 'system', 'system'),

-- Password Reset Email
('email', 'password_reset', 'en', 'Password Reset Request - {{app_name}}',
'Hello {{user_name}},

You requested a password reset for your account.

Click the link below to reset your password:
{{reset_url}}

This link will expire in {{expiry_hours}} hours.

If you didn''t request this reset, please ignore this email.

Best regards,
{{app_name}} Team',
'[
    {"name": "user_name", "description": "User''s display name", "type": "string", "required": false, "example": "John Doe"},
    {"name": "reset_url", "description": "Password reset URL", "type": "string", "required": true, "example": "https://app.example.com/reset?token=abc123"},
    {"name": "expiry_hours", "description": "Reset token expiry time in hours", "type": "number", "required": false, "example": 24},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward Framework"}
]'::jsonb,
true, true, 'system', 'system');

-- Insert default SMS templates
INSERT INTO templates (type, purpose, language, content, variables, is_default, is_active, created_by, updated_by) VALUES
-- Login OTP SMS
('sms', 'login', 'en', 'Your {{app_name}} verification code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.',
'[
    {"name": "otp_code", "description": "One-time password code", "type": "string", "required": true, "example": "123456"},
    {"name": "expiry_minutes", "description": "OTP expiry time in minutes", "type": "number", "required": false, "example": 10},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward"}
]'::jsonb,
true, true, 'system', 'system'),

-- Registration OTP SMS
('sms', 'registration', 'en', 'Welcome to {{app_name}}! Your verification code is: {{otp_code}}. Valid for {{expiry_minutes}} minutes.',
'[
    {"name": "otp_code", "description": "One-time password code", "type": "string", "required": true, "example": "123456"},
    {"name": "expiry_minutes", "description": "OTP expiry time in minutes", "type": "number", "required": false, "example": 10},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward"}
]'::jsonb,
true, true, 'system', 'system'),

-- Password Reset SMS
('sms', 'password_reset', 'en', '{{app_name}}: Reset your password using this link: {{reset_url}} (expires in {{expiry_hours}}h)',
'[
    {"name": "reset_url", "description": "Password reset URL", "type": "string", "required": true, "example": "https://app.example.com/reset?token=abc123"},
    {"name": "expiry_hours", "description": "Reset token expiry time in hours", "type": "number", "required": false, "example": 24},
    {"name": "app_name", "description": "Application name", "type": "string", "required": false, "example": "Go Forward"}
]'::jsonb,
true, true, 'system', 'system');

-- Create initial template versions for all default templates
INSERT INTO template_versions (template_id, version, subject, content, variables, created_by, change_log)
SELECT id, version, subject, content, variables, created_by, 'Initial version'
FROM templates
WHERE created_by = 'system';

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