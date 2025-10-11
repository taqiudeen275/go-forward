-- Migration: Initial Schema
-- Description: Create initial database schema with users, admins, security, and audit logs
-- Created: 2024-01-01T00:00:00Z

-- Enable Row Level Security
ALTER DATABASE goforward SET row_security = on;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create enum types
CREATE TYPE admin_level AS ENUM ('system_admin', 'super_admin', 'regular_admin', 'moderator');
CREATE TYPE mfa_method AS ENUM ('totp', 'backup_codes', 'sms', 'email');
CREATE TYPE template_type AS ENUM ('email', 'sms');
CREATE TYPE audit_severity AS ENUM ('low', 'medium', 'high', 'critical');

-- Users table with admin capabilities
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    username VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    
    -- Admin fields
    admin_level admin_level,
    capabilities JSONB DEFAULT '{}',
    assigned_tables TEXT[] DEFAULT '{}',
    
    -- Security fields
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    backup_codes TEXT[],
    last_login TIMESTAMP WITH TIME ZONE,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    
    -- Standard fields
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id)
);

-- Admin sessions table
CREATE TABLE admin_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    refresh_token VARCHAR(255) UNIQUE,
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    permissions JSONB DEFAULT '{}',
    last_used TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- OTP codes table
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255),
    phone VARCHAR(20),
    code VARCHAR(10) NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- login, registration, verification, password_reset
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Communication templates table
CREATE TABLE templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type template_type NOT NULL,
    purpose VARCHAR(50) NOT NULL, -- login, registration, verification, password_reset
    language VARCHAR(10) DEFAULT 'en',
    subject VARCHAR(255), -- For email templates
    content TEXT NOT NULL,
    variables JSONB DEFAULT '[]',
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(type, purpose, language)
);

-- Audit logs table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    success BOOLEAN DEFAULT TRUE,
    error_code VARCHAR(50),
    severity audit_severity DEFAULT 'medium',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security events table
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    user_id UUID REFERENCES users(id),
    ip_address INET,
    user_agent TEXT,
    details JSONB DEFAULT '{}',
    severity audit_severity DEFAULT 'medium',
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting table
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) NOT NULL,
    count INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    
    UNIQUE(key)
);

-- Create indexes for performance
CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_phone ON users(phone) WHERE phone IS NOT NULL;
CREATE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL;
CREATE INDEX idx_users_admin_level ON users(admin_level) WHERE admin_level IS NOT NULL;
CREATE INDEX idx_users_created_at ON users(created_at);

CREATE INDEX idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX idx_admin_sessions_token ON admin_sessions(session_token);
CREATE INDEX idx_admin_sessions_expires_at ON admin_sessions(expires_at);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

CREATE INDEX idx_otp_codes_user_id ON otp_codes(user_id);
CREATE INDEX idx_otp_codes_email ON otp_codes(email);
CREATE INDEX idx_otp_codes_phone ON otp_codes(phone);
CREATE INDEX idx_otp_codes_expires_at ON otp_codes(expires_at);

CREATE INDEX idx_templates_type_purpose ON templates(type, purpose);
CREATE INDEX idx_templates_active ON templates(is_active) WHERE is_active = TRUE;

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_severity ON audit_logs(severity);

CREATE INDEX idx_security_events_type ON security_events(event_type);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_created_at ON security_events(created_at);
CREATE INDEX idx_security_events_resolved ON security_events(resolved);

CREATE INDEX idx_rate_limits_key ON rate_limits(key);
CREATE INDEX idx_rate_limits_expires_at ON rate_limits(expires_at);

-- Row Level Security Policies

-- Users table RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Users can see their own record
CREATE POLICY users_own_record ON users
    FOR ALL
    TO public
    USING (id = current_setting('app.current_user_id')::UUID);

-- System admins can see all users
CREATE POLICY users_system_admin ON users
    FOR ALL
    TO public
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level = 'system_admin'
        )
    );

-- Super admins can see non-system-admin users
CREATE POLICY users_super_admin ON users
    FOR ALL
    TO public
    USING (
        admin_level != 'system_admin' AND
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level IN ('system_admin', 'super_admin')
        )
    );

-- Admin sessions RLS
ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY admin_sessions_own ON admin_sessions
    FOR ALL
    TO public
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Audit logs RLS
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Users can see their own audit logs
CREATE POLICY audit_logs_own ON audit_logs
    FOR SELECT
    TO public
    USING (user_id = current_setting('app.current_user_id')::UUID);

-- Admins can see all audit logs
CREATE POLICY audit_logs_admin ON audit_logs
    FOR SELECT
    TO public
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level IS NOT NULL
        )
    );

-- Security events RLS (admin only)
ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY security_events_admin ON security_events
    FOR ALL
    TO public
    USING (
        EXISTS (
            SELECT 1 FROM users u 
            WHERE u.id = current_setting('app.current_user_id')::UUID 
            AND u.admin_level IS NOT NULL
        )
    );

-- Functions for updated_at triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_templates_updated_at BEFORE UPDATE ON templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean expired records
CREATE OR REPLACE FUNCTION clean_expired_records()
RETURNS void AS $$
BEGIN
    -- Clean expired OTP codes
    DELETE FROM otp_codes WHERE expires_at < NOW();
    
    -- Clean expired admin sessions
    DELETE FROM admin_sessions WHERE expires_at < NOW();
    
    -- Clean expired rate limits
    DELETE FROM rate_limits WHERE expires_at < NOW();
    
    -- Clean old audit logs (based on retention policy)
    DELETE FROM audit_logs 
    WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Insert default templates
INSERT INTO templates (type, purpose, language, subject, content, is_default, is_active) VALUES
('email', 'login', 'en', 'Login Verification Code', 
 'Your login verification code is: {{code}}. This code will expire in {{expiration}} minutes.', 
 true, true),
('email', 'registration', 'en', 'Welcome! Verify Your Email', 
 'Welcome! Your verification code is: {{code}}. Please verify your email to complete registration.', 
 true, true),
('email', 'password_reset', 'en', 'Password Reset Code', 
 'Your password reset code is: {{code}}. This code will expire in {{expiration}} minutes.', 
 true, true),
('sms', 'login', 'en', NULL, 
 'Your login code: {{code}}. Expires in {{expiration}} min.', 
 true, true),
('sms', 'registration', 'en', NULL, 
 'Welcome! Your verification code: {{code}}', 
 true, true),
('sms', 'password_reset', 'en', NULL, 
 'Password reset code: {{code}}. Expires in {{expiration}} min.', 
 true, true);