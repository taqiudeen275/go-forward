-- Admin Audit and Security Logging Migration
-- This migration creates comprehensive audit logging and security event tracking

-- Create admin access logs table for all administrative actions
CREATE TABLE IF NOT EXISTS admin_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    session_id VARCHAR(255), -- Session identifier for correlation
    action VARCHAR(100) NOT NULL, -- 'login', 'sql_execute', 'user_create', 'role_assign', etc.
    resource_type VARCHAR(100), -- 'user', 'table', 'system', 'role', 'config', etc.
    resource_id VARCHAR(255), -- ID of affected resource
    resource_name VARCHAR(255), -- Human-readable name of resource
    details JSONB DEFAULT '{}', -- Action-specific details and parameters
    ip_address INET,
    user_agent TEXT,
    request_method VARCHAR(10), -- HTTP method if applicable
    request_path TEXT, -- API endpoint if applicable
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    execution_time_ms INTEGER, -- Time taken to complete the action
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create SQL execution logs for database query auditing
CREATE TABLE IF NOT EXISTS sql_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    session_id VARCHAR(255),
    query_text TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of normalized query
    query_type VARCHAR(50), -- 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL', etc.
    affected_tables TEXT[], -- List of tables involved in the query
    execution_time_ms INTEGER,
    rows_affected INTEGER,
    rows_returned INTEGER,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    error_code VARCHAR(10), -- SQL error code if applicable
    ip_address INET,
    user_agent TEXT,
    risk_level VARCHAR(20) DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    requires_approval BOOLEAN DEFAULT FALSE, -- Whether query required additional approval
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create security events table for security incident tracking
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(100) NOT NULL, -- 'failed_login', 'privilege_escalation', 'suspicious_activity', 'mfa_bypass_attempt'
    event_category VARCHAR(50) DEFAULT 'security', -- 'security', 'compliance', 'performance', 'system'
    severity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    affected_user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- User being acted upon (if different)
    session_id VARCHAR(255),
    title VARCHAR(255) NOT NULL, -- Brief description of the event
    description TEXT, -- Detailed description
    details JSONB DEFAULT '{}', -- Event-specific data
    ip_address INET,
    user_agent TEXT,
    request_path TEXT,
    automated_response JSONB DEFAULT '{}', -- Any automated actions taken
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    false_positive BOOLEAN DEFAULT FALSE, -- Mark as false positive
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create admin sessions table for enhanced session tracking
CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255), -- Device/browser fingerprint
    location_data JSONB DEFAULT '{}', -- GeoIP data if available
    mfa_verified BOOLEAN DEFAULT FALSE,
    mfa_verified_at TIMESTAMP WITH TIME ZONE,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    logout_reason VARCHAR(100), -- 'user_logout', 'timeout', 'admin_revoke', 'security_logout'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ended_at TIMESTAMP WITH TIME ZONE
);

-- Create notification logs for security alerts
CREATE TABLE IF NOT EXISTS security_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    security_event_id UUID REFERENCES security_events(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL, -- 'email', 'sms', 'webhook', 'in_app'
    recipient VARCHAR(255) NOT NULL, -- Email, phone, or user ID
    subject VARCHAR(255),
    message TEXT,
    delivery_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'sent', 'delivered', 'failed'
    delivery_attempts INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create comprehensive indexes for performance and querying
-- Admin access logs indexes
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_user_id ON admin_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_action ON admin_access_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_resource ON admin_access_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_created_at ON admin_access_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_session ON admin_access_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_success ON admin_access_logs(success, created_at DESC);

-- SQL execution logs indexes
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_user_id ON sql_execution_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_hash ON sql_execution_logs(query_hash);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_type ON sql_execution_logs(query_type);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_created_at ON sql_execution_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_risk ON sql_execution_logs(risk_level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_tables ON sql_execution_logs USING GIN(affected_tables);

-- Security events indexes
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_resolved ON security_events(resolved, severity);

-- Admin sessions indexes
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_session_id ON admin_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_active ON admin_sessions(is_active, last_activity);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);

-- Security notifications indexes
CREATE INDEX IF NOT EXISTS idx_security_notifications_event_id ON security_notifications(security_event_id);
CREATE INDEX IF NOT EXISTS idx_security_notifications_status ON security_notifications(delivery_status, created_at);
CREATE INDEX IF NOT EXISTS idx_security_notifications_recipient ON security_notifications(recipient);

-- Create function to log admin actions automatically
CREATE OR REPLACE FUNCTION log_admin_action(
    p_user_id UUID,
    p_action VARCHAR,
    p_resource_type VARCHAR DEFAULT NULL,
    p_resource_id VARCHAR DEFAULT NULL,
    p_resource_name VARCHAR DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_session_id VARCHAR DEFAULT NULL,
    p_success BOOLEAN DEFAULT TRUE,
    p_error_message TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    log_id UUID;
    role_id UUID;
BEGIN
    -- Get the user's current admin role (highest level)
    SELECT ar.id INTO role_id
    FROM user_admin_roles uar
    JOIN admin_roles ar ON uar.role_id = ar.id
    WHERE uar.user_id = p_user_id
    AND uar.is_active = TRUE
    AND ar.is_active = TRUE
    AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
    ORDER BY ar.level
    LIMIT 1;

    -- Insert the log entry
    INSERT INTO admin_access_logs (
        user_id, admin_role_id, session_id, action, resource_type,
        resource_id, resource_name, details, ip_address, user_agent,
        success, error_message
    ) VALUES (
        p_user_id, role_id, p_session_id, p_action, p_resource_type,
        p_resource_id, p_resource_name, p_details, p_ip_address, p_user_agent,
        p_success, p_error_message
    ) RETURNING id INTO log_id;

    RETURN log_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to create security events
CREATE OR REPLACE FUNCTION create_security_event(
    p_event_type VARCHAR,
    p_title VARCHAR,
    p_description TEXT DEFAULT NULL,
    p_severity VARCHAR DEFAULT 'medium',
    p_user_id UUID DEFAULT NULL,
    p_affected_user_id UUID DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_session_id VARCHAR DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    event_id UUID;
BEGIN
    INSERT INTO security_events (
        event_type, title, description, severity, user_id, affected_user_id,
        details, ip_address, user_agent, session_id
    ) VALUES (
        p_event_type, p_title, p_description, p_severity, p_user_id, p_affected_user_id,
        p_details, p_ip_address, p_user_agent, p_session_id
    ) RETURNING id INTO event_id;

    -- Auto-trigger high/critical severity alerts
    IF p_severity IN ('high', 'critical') THEN
        -- This would trigger notifications (implementation depends on your notification system)
        PERFORM pg_notify('security_alert', json_build_object('event_id', event_id, 'severity', p_severity)::text);
    END IF;

    RETURN event_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create function to clean up old audit logs (for maintenance)
CREATE OR REPLACE FUNCTION cleanup_old_audit_logs(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    cutoff_date TIMESTAMP WITH TIME ZONE;
BEGIN
    cutoff_date := NOW() - (retention_days || ' days')::INTERVAL;

    -- Clean up admin access logs
    DELETE FROM admin_access_logs WHERE created_at < cutoff_date;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;

    -- Clean up SQL execution logs (keep critical ones longer)
    DELETE FROM sql_execution_logs
    WHERE created_at < cutoff_date
    AND risk_level NOT IN ('high', 'critical');

    -- Clean up resolved security events (keep unresolved ones)
    DELETE FROM security_events
    WHERE created_at < cutoff_date
    AND resolved = TRUE
    AND severity NOT IN ('high', 'critical');

    -- Clean up old admin sessions
    DELETE FROM admin_sessions
    WHERE created_at < cutoff_date
    AND is_active = FALSE;

    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Create view for admin activity summary
CREATE OR REPLACE VIEW admin_activity_summary AS
SELECT
    u.id as user_id,
    u.email,
    u.username,
    ar.name as admin_role,
    ar.level as role_level,
    COUNT(aal.*) as total_actions,
    COUNT(CASE WHEN aal.success = FALSE THEN 1 END) as failed_actions,
    MAX(aal.created_at) as last_activity,
    COUNT(DISTINCT aal.session_id) as session_count
FROM users u
JOIN user_admin_roles uar ON u.id = uar.user_id
JOIN admin_roles ar ON uar.role_id = ar.id
LEFT JOIN admin_access_logs aal ON u.id = aal.user_id
WHERE uar.is_active = TRUE
AND ar.is_active = TRUE
AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
GROUP BY u.id, u.email, u.username, ar.name, ar.level;

-- Grant permissions to authenticated role
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        GRANT SELECT, INSERT, UPDATE ON admin_access_logs TO authenticated;
        GRANT SELECT, INSERT, UPDATE ON sql_execution_logs TO authenticated;
        GRANT SELECT, INSERT, UPDATE ON security_events TO authenticated;
        GRANT SELECT, INSERT, UPDATE, DELETE ON admin_sessions TO authenticated;
        GRANT SELECT, INSERT, UPDATE ON security_notifications TO authenticated;
        GRANT SELECT ON admin_activity_summary TO authenticated;
    END IF;
END $$;

-- Add helpful comments
COMMENT ON TABLE admin_access_logs IS 'Comprehensive audit log of all administrative actions';
COMMENT ON TABLE sql_execution_logs IS 'Audit log of all SQL queries executed by admins';
COMMENT ON TABLE security_events IS 'Security incidents and events requiring attention';
COMMENT ON TABLE admin_sessions IS 'Enhanced session tracking for administrative users';
COMMENT ON TABLE security_notifications IS 'Log of security alert notifications sent';
COMMENT ON FUNCTION log_admin_action IS 'Centralized function to log administrative actions';
COMMENT ON FUNCTION create_security_event IS 'Function to create and track security events';
COMMENT ON VIEW admin_activity_summary IS 'Summary view of admin user activity and statistics';
