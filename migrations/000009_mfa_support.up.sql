-- Multi-Factor Authentication Support Migration
-- This migration adds comprehensive MFA support for administrative users

-- Create user MFA settings table
CREATE TABLE IF NOT EXISTS user_mfa_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    totp_secret VARCHAR(255), -- Base32 encoded TOTP secret (encrypted at application level)
    backup_codes TEXT[], -- Array of hashed backup codes
    recovery_codes TEXT[], -- Array of hashed recovery codes for emergency access
    is_enabled BOOLEAN DEFAULT FALSE,
    is_enforced BOOLEAN DEFAULT FALSE, -- Whether MFA is mandatory for this user
    method VARCHAR(50) DEFAULT 'totp', -- 'totp', 'sms', 'email', 'authenticator'
    phone_verified BOOLEAN DEFAULT FALSE, -- For SMS-based MFA
    email_verified BOOLEAN DEFAULT FALSE, -- For email-based MFA
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_backup_used_at TIMESTAMP WITH TIME ZONE,
    setup_completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create MFA attempts tracking for security monitoring
CREATE TABLE IF NOT EXISTS mfa_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255),
    method VARCHAR(50) NOT NULL, -- 'totp', 'backup_code', 'recovery_code', 'sms', 'email'
    attempt_type VARCHAR(50) NOT NULL, -- 'verification', 'setup', 'disable'
    code_used VARCHAR(255), -- Hashed version of the code used
    success BOOLEAN DEFAULT FALSE,
    failure_reason VARCHAR(100), -- 'invalid_code', 'expired', 'rate_limit', 'max_attempts'
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create MFA bypass tokens for emergency access
CREATE TABLE IF NOT EXISTS mfa_bypass_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL, -- SHA-256 hash of bypass token
    reason VARCHAR(255) NOT NULL, -- Reason for bypass (admin emergency, device lost, etc.)
    created_by UUID REFERENCES users(id), -- Admin who created the bypass
    used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_single_use BOOLEAN DEFAULT TRUE,
    usage_count INTEGER DEFAULT 0,
    max_usage INTEGER DEFAULT 1,
    ip_address INET, -- IP where token was used
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create MFA devices table for managing trusted devices
CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL, -- Unique device identifier
    device_name VARCHAR(255), -- User-friendly device name
    device_type VARCHAR(50), -- 'browser', 'mobile_app', 'desktop'
    trust_expires_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, device_fingerprint)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_mfa_settings_user_id ON user_mfa_settings(user_id);
CREATE INDEX IF NOT EXISTS idx_user_mfa_settings_enabled ON user_mfa_settings(user_id, is_enabled);
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_user_id ON mfa_attempts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_session ON mfa_attempts(session_id);
CREATE INDEX IF NOT EXISTS idx_mfa_attempts_success ON mfa_attempts(success, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mfa_bypass_tokens_user_id ON mfa_bypass_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_bypass_tokens_expires ON mfa_bypass_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_mfa_bypass_tokens_token ON mfa_bypass_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_user_id ON mfa_trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_fingerprint ON mfa_trusted_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_expires ON mfa_trusted_devices(trust_expires_at);

-- Create triggers for updated_at columns
CREATE TRIGGER update_user_mfa_settings_updated_at
    BEFORE UPDATE ON user_mfa_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_mfa_trusted_devices_updated_at
    BEFORE UPDATE ON mfa_trusted_devices
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create function to check if user has MFA enabled
CREATE OR REPLACE FUNCTION user_has_mfa_enabled(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    mfa_enabled BOOLEAN := FALSE;
BEGIN
    SELECT is_enabled INTO mfa_enabled
    FROM user_mfa_settings
    WHERE user_id = p_user_id;

    RETURN COALESCE(mfa_enabled, FALSE);
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create function to check if MFA is required for user based on admin role
CREATE OR REPLACE FUNCTION user_requires_mfa(p_user_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    requires_mfa BOOLEAN := FALSE;
    admin_level INTEGER;
BEGIN
    -- Check if user has MFA enforced directly
    SELECT is_enforced INTO requires_mfa
    FROM user_mfa_settings
    WHERE user_id = p_user_id;

    IF requires_mfa THEN
        RETURN TRUE;
    END IF;

    -- Check if user has admin role that requires MFA
    SELECT get_user_admin_level(p_user_id) INTO admin_level;

    -- System admins and super admins require MFA
    IF admin_level <= 2 THEN
        RETURN TRUE;
    END IF;

    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create function to validate MFA attempt and track security
CREATE OR REPLACE FUNCTION log_mfa_attempt(
    p_user_id UUID,
    p_method VARCHAR,
    p_attempt_type VARCHAR,
    p_success BOOLEAN,
    p_failure_reason VARCHAR DEFAULT NULL,
    p_session_id VARCHAR DEFAULT NULL,
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    attempt_id UUID;
    failed_attempts INTEGER;
BEGIN
    -- Log the attempt
    INSERT INTO mfa_attempts (
        user_id, session_id, method, attempt_type, success,
        failure_reason, ip_address, user_agent
    ) VALUES (
        p_user_id, p_session_id, p_method, p_attempt_type, p_success,
        p_failure_reason, p_ip_address, p_user_agent
    ) RETURNING id INTO attempt_id;

    -- Check for suspicious activity (multiple failed attempts)
    IF NOT p_success THEN
        SELECT COUNT(*) INTO failed_attempts
        FROM mfa_attempts
        WHERE user_id = p_user_id
        AND success = FALSE
        AND created_at > NOW() - INTERVAL '15 minutes';

        -- Create security event for multiple failed MFA attempts
        IF failed_attempts >= 5 THEN
            PERFORM create_security_event(
                'mfa_multiple_failures',
                'Multiple MFA verification failures',
                format('User has %s failed MFA attempts in the last 15 minutes', failed_attempts),
                'high',
                p_user_id,
                NULL,
                jsonb_build_object('failed_attempts', failed_attempts, 'method', p_method),
                p_ip_address,
                p_user_agent,
                p_session_id
            );
        END IF;
    END IF;

    RETURN attempt_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to check if device is trusted
CREATE OR REPLACE FUNCTION is_trusted_device(p_user_id UUID, p_device_fingerprint VARCHAR)
RETURNS BOOLEAN AS $$
DECLARE
    is_trusted BOOLEAN := FALSE;
BEGIN
    SELECT EXISTS(
        SELECT 1
        FROM mfa_trusted_devices
        WHERE user_id = p_user_id
        AND device_fingerprint = p_device_fingerprint
        AND is_active = TRUE
        AND (trust_expires_at IS NULL OR trust_expires_at > NOW())
    ) INTO is_trusted;

    RETURN is_trusted;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

-- Create function to clean up expired MFA data
CREATE OR REPLACE FUNCTION cleanup_expired_mfa_data()
RETURNS INTEGER AS $$
DECLARE
    cleanup_count INTEGER := 0;
BEGIN
    -- Clean up expired bypass tokens
    DELETE FROM mfa_bypass_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS cleanup_count = ROW_COUNT;

    -- Clean up expired trusted devices
    DELETE FROM mfa_trusted_devices
    WHERE trust_expires_at IS NOT NULL AND trust_expires_at < NOW();

    -- Clean up old MFA attempts (keep for 90 days)
    DELETE FROM mfa_attempts WHERE created_at < NOW() - INTERVAL '90 days';

    RETURN cleanup_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create view for MFA security overview
CREATE OR REPLACE VIEW mfa_security_overview AS
SELECT
    u.id as user_id,
    u.email,
    u.username,
    ums.is_enabled as mfa_enabled,
    ums.is_enforced as mfa_enforced,
    ums.method as mfa_method,
    ums.last_used_at as mfa_last_used,
    get_user_admin_level(u.id) as admin_level,
    user_requires_mfa(u.id) as requires_mfa,
    COUNT(mtd.id) as trusted_devices_count,
    (
        SELECT COUNT(*)
        FROM mfa_attempts ma
        WHERE ma.user_id = u.id
        AND ma.created_at > NOW() - INTERVAL '30 days'
        AND ma.success = FALSE
    ) as failed_attempts_30d
FROM users u
LEFT JOIN user_mfa_settings ums ON u.id = ums.user_id
LEFT JOIN mfa_trusted_devices mtd ON u.id = mtd.user_id AND mtd.is_active = TRUE
WHERE EXISTS (
    SELECT 1 FROM user_admin_roles uar
    WHERE uar.user_id = u.id AND uar.is_active = TRUE
)
GROUP BY u.id, u.email, u.username, ums.is_enabled, ums.is_enforced, ums.method, ums.last_used_at;

-- Auto-enable MFA enforcement for system and super admins
CREATE OR REPLACE FUNCTION auto_enforce_mfa_for_admins()
RETURNS TRIGGER AS $$
BEGIN
    -- When a user gets system_admin or super_admin role, enforce MFA
    IF NEW.is_active = TRUE THEN
        INSERT INTO user_mfa_settings (user_id, is_enforced)
        VALUES (NEW.user_id, TRUE)
        ON CONFLICT (user_id) DO UPDATE SET
            is_enforced = TRUE,
            updated_at = NOW();

        -- Create security event to notify about MFA enforcement
        PERFORM create_security_event(
            'mfa_auto_enforced',
            'MFA automatically enforced for admin user',
            format('MFA enforcement enabled due to admin role assignment'),
            'medium',
            NEW.user_id,
            NULL,
            jsonb_build_object('role_assignment_id', NEW.id),
            NULL,
            NULL,
            NULL
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to auto-enforce MFA for high-privilege users
CREATE TRIGGER auto_enforce_mfa_trigger
    AFTER INSERT OR UPDATE ON user_admin_roles
    FOR EACH ROW
    WHEN (EXISTS (
        SELECT 1 FROM admin_roles
        WHERE id = NEW.role_id
        AND level <= 2  -- system_admin (1) and super_admin (2)
        AND is_active = TRUE
    ))
    EXECUTE FUNCTION auto_enforce_mfa_for_admins();

-- Grant permissions to authenticated role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT SELECT, INSERT, UPDATE ON user_mfa_settings TO authenticated;
        GRANT SELECT, INSERT ON mfa_attempts TO authenticated;
        GRANT SELECT, INSERT, UPDATE ON mfa_bypass_tokens TO authenticated;
        GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_trusted_devices TO authenticated;
        GRANT SELECT ON mfa_security_overview TO authenticated;
    END IF;
END $$;

-- Add helpful comments
COMMENT ON TABLE user_mfa_settings IS 'Multi-factor authentication settings for users';
COMMENT ON TABLE mfa_attempts IS 'Log of all MFA verification attempts for security monitoring';
COMMENT ON TABLE mfa_bypass_tokens IS 'Emergency bypass tokens for MFA when users lose access';
COMMENT ON TABLE mfa_trusted_devices IS 'Trusted devices that can skip MFA for limited time';
COMMENT ON FUNCTION user_has_mfa_enabled(UUID) IS 'Check if user has MFA enabled';
COMMENT ON FUNCTION user_requires_mfa(UUID) IS 'Check if user is required to use MFA based on role';
COMMENT ON FUNCTION log_mfa_attempt IS 'Log MFA attempts and detect suspicious activity';
COMMENT ON FUNCTION is_trusted_device(UUID, VARCHAR) IS 'Check if device is trusted for MFA bypass';
COMMENT ON VIEW mfa_security_overview IS 'Comprehensive view of MFA security status for admin users';
