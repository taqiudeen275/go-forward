-- Audit and Security Logging Schema Migration
-- This migration creates tables for comprehensive audit logging and security monitoring

-- Create admin_access_logs table for administrative actions
CREATE TABLE IF NOT EXISTS admin_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    resource_id UUID,
    details JSONB DEFAULT '{}',
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    
    -- Outcome and timing
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'PARTIAL')),
    error_code VARCHAR(50),
    error_message TEXT,
    execution_time_ms INTEGER,
    
    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for admin_access_logs
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_user_id ON admin_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_admin_role_id ON admin_access_logs(admin_role_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_action ON admin_access_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_resource ON admin_access_logs(resource);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_resource_id ON admin_access_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_outcome ON admin_access_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_timestamp ON admin_access_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_ip_address ON admin_access_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_session_id ON admin_access_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_request_id ON admin_access_logs(request_id);

-- Create GIN index for JSONB details
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_details ON admin_access_logs USING GIN(details);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_user_timestamp ON admin_access_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_action_timestamp ON admin_access_logs(action, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_access_logs_outcome_timestamp ON admin_access_logs(outcome, timestamp DESC);

-- Create sql_execution_logs table for SQL query auditing
CREATE TABLE IF NOT EXISTS sql_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    
    -- SQL Query Information
    query_text TEXT NOT NULL,
    query_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of the query
    query_type VARCHAR(20) NOT NULL, -- SELECT, INSERT, UPDATE, DELETE, DDL, etc.
    affected_tables JSONB DEFAULT '[]',
    
    -- Execution context
    database_name VARCHAR(255),
    schema_name VARCHAR(255),
    connection_id VARCHAR(255),
    
    -- Security validation
    validation_result VARCHAR(20) NOT NULL CHECK (validation_result IN ('ALLOWED', 'BLOCKED', 'WARNING')),
    security_warnings JSONB DEFAULT '[]',
    dangerous_operations JSONB DEFAULT '[]',
    
    -- Execution results
    execution_status VARCHAR(20) NOT NULL CHECK (execution_status IN ('SUCCESS', 'ERROR', 'TIMEOUT', 'CANCELLED')),
    rows_affected INTEGER,
    execution_time_ms INTEGER,
    error_message TEXT,
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    
    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for sql_execution_logs
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_user_id ON sql_execution_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_admin_role_id ON sql_execution_logs(admin_role_id);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_query_hash ON sql_execution_logs(query_hash);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_query_type ON sql_execution_logs(query_type);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_validation_result ON sql_execution_logs(validation_result);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_execution_status ON sql_execution_logs(execution_status);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_timestamp ON sql_execution_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_ip_address ON sql_execution_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_session_id ON sql_execution_logs(session_id);

-- Create GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_affected_tables ON sql_execution_logs USING GIN(affected_tables);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_security_warnings ON sql_execution_logs USING GIN(security_warnings);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_dangerous_operations ON sql_execution_logs USING GIN(dangerous_operations);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_user_timestamp ON sql_execution_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_validation_timestamp ON sql_execution_logs(validation_result, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sql_execution_logs_status_timestamp ON sql_execution_logs(execution_status, timestamp DESC);

-- Create security_events table for security incident tracking
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    category VARCHAR(50) NOT NULL, -- AUTHENTICATION, AUTHORIZATION, DATA_ACCESS, SYSTEM, etc.
    
    -- User and context information
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    resource VARCHAR(255),
    resource_id UUID,
    action VARCHAR(100),
    
    -- Event details
    title VARCHAR(255) NOT NULL,
    description TEXT,
    details JSONB DEFAULT '{}',
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    
    -- Detection and response
    detection_method VARCHAR(50), -- RULE_BASED, ML_BASED, MANUAL, etc.
    confidence_score DECIMAL(3,2), -- 0.00 to 1.00
    false_positive BOOLEAN DEFAULT FALSE,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    
    -- Resolution
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    
    -- Metadata
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for security_events
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(category);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_admin_role_id ON security_events(admin_role_id);
CREATE INDEX IF NOT EXISTS idx_security_events_resource ON security_events(resource);
CREATE INDEX IF NOT EXISTS idx_security_events_resource_id ON security_events(resource_id);
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_session_id ON security_events(session_id);
CREATE INDEX IF NOT EXISTS idx_security_events_acknowledged ON security_events(acknowledged);
CREATE INDEX IF NOT EXISTS idx_security_events_resolved ON security_events(resolved);
CREATE INDEX IF NOT EXISTS idx_security_events_false_positive ON security_events(false_positive);

-- Create GIN index for JSONB details
CREATE INDEX IF NOT EXISTS idx_security_events_details ON security_events USING GIN(details);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_security_events_severity_timestamp ON security_events(severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_unresolved ON security_events(resolved, timestamp DESC) WHERE resolved = FALSE;
CREATE INDEX IF NOT EXISTS idx_security_events_user_timestamp ON security_events(user_id, timestamp DESC);

-- Create admin_sessions table for enhanced session management
CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) NOT NULL UNIQUE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    admin_role_id UUID REFERENCES admin_roles(id) ON DELETE SET NULL,
    
    -- Session security
    ip_address INET NOT NULL,
    user_agent TEXT,
    fingerprint VARCHAR(255), -- Browser/device fingerprint
    
    -- MFA and security flags
    mfa_verified BOOLEAN DEFAULT FALSE,
    mfa_verified_at TIMESTAMP WITH TIME ZONE,
    requires_mfa BOOLEAN DEFAULT FALSE,
    security_flags JSONB DEFAULT '[]',
    
    -- Session lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Termination tracking
    terminated_at TIMESTAMP WITH TIME ZONE,
    termination_reason VARCHAR(50), -- LOGOUT, TIMEOUT, SECURITY, ADMIN_ACTION, etc.
    terminated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    
    -- Session metadata
    capabilities JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}'
);

-- Create indexes for admin_sessions
CREATE INDEX IF NOT EXISTS idx_admin_sessions_session_token ON admin_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_role_id ON admin_sessions(admin_role_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_ip_address ON admin_sessions(ip_address);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_is_active ON admin_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_last_activity ON admin_sessions(last_activity DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_created_at ON admin_sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_mfa_verified ON admin_sessions(mfa_verified);

-- Create GIN indexes for JSONB columns
CREATE INDEX IF NOT EXISTS idx_admin_sessions_security_flags ON admin_sessions USING GIN(security_flags);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_capabilities ON admin_sessions USING GIN(capabilities);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_metadata ON admin_sessions USING GIN(metadata);

-- Create composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_active ON admin_sessions(user_id, is_active, last_activity DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_active_expires ON admin_sessions(is_active, expires_at) WHERE is_active = TRUE;

-- Create triggers for updated_at columns
CREATE TRIGGER update_security_events_updated_at 
    BEFORE UPDATE ON security_events 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- Create function to automatically update last_activity on admin_sessions
CREATE OR REPLACE FUNCTION update_admin_session_activity()
RETURNS TRIGGER AS $
BEGIN
    NEW.last_activity = NOW();
    RETURN NEW;
END;
$ language 'plpgsql';

-- Create trigger to update last_activity on admin_sessions updates
CREATE TRIGGER update_admin_sessions_activity 
    BEFORE UPDATE ON admin_sessions 
    FOR EACH ROW 
    EXECUTE FUNCTION update_admin_session_activity();

-- Create function to clean up expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_admin_sessions()
RETURNS INTEGER AS $
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE admin_sessions 
    SET 
        is_active = FALSE,
        terminated_at = NOW(),
        termination_reason = 'TIMEOUT'
    WHERE 
        is_active = TRUE 
        AND expires_at < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$ language 'plpgsql';

-- Create function to log admin actions automatically
CREATE OR REPLACE FUNCTION log_admin_action(
    p_user_id UUID,
    p_admin_role_id UUID,
    p_action VARCHAR(100),
    p_resource VARCHAR(255) DEFAULT NULL,
    p_resource_id UUID DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_session_id VARCHAR(255) DEFAULT NULL,
    p_request_id VARCHAR(255) DEFAULT NULL,
    p_outcome VARCHAR(20) DEFAULT 'SUCCESS',
    p_error_code VARCHAR(50) DEFAULT NULL,
    p_error_message TEXT DEFAULT NULL,
    p_execution_time_ms INTEGER DEFAULT NULL
)
RETURNS UUID AS $
DECLARE
    log_id UUID;
BEGIN
    INSERT INTO admin_access_logs (
        user_id, admin_role_id, action, resource, resource_id, details,
        ip_address, user_agent, session_id, request_id, outcome,
        error_code, error_message, execution_time_ms
    ) VALUES (
        p_user_id, p_admin_role_id, p_action, p_resource, p_resource_id, p_details,
        p_ip_address, p_user_agent, p_session_id, p_request_id, p_outcome,
        p_error_code, p_error_message, p_execution_time_ms
    ) RETURNING id INTO log_id;
    
    RETURN log_id;
END;
$ language 'plpgsql';

-- Create function to log security events
CREATE OR REPLACE FUNCTION log_security_event(
    p_event_type VARCHAR(50),
    p_severity VARCHAR(20),
    p_category VARCHAR(50),
    p_title VARCHAR(255),
    p_description TEXT DEFAULT NULL,
    p_user_id UUID DEFAULT NULL,
    p_admin_role_id UUID DEFAULT NULL,
    p_resource VARCHAR(255) DEFAULT NULL,
    p_resource_id UUID DEFAULT NULL,
    p_action VARCHAR(100) DEFAULT NULL,
    p_details JSONB DEFAULT '{}',
    p_ip_address INET DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_session_id VARCHAR(255) DEFAULT NULL,
    p_request_id VARCHAR(255) DEFAULT NULL,
    p_detection_method VARCHAR(50) DEFAULT NULL,
    p_confidence_score DECIMAL(3,2) DEFAULT NULL
)
RETURNS UUID AS $
DECLARE
    event_id UUID;
BEGIN
    INSERT INTO security_events (
        event_type, severity, category, title, description,
        user_id, admin_role_id, resource, resource_id, action, details,
        ip_address, user_agent, session_id, request_id,
        detection_method, confidence_score
    ) VALUES (
        p_event_type, p_severity, p_category, p_title, p_description,
        p_user_id, p_admin_role_id, p_resource, p_resource_id, p_action, p_details,
        p_ip_address, p_user_agent, p_session_id, p_request_id,
        p_detection_method, p_confidence_score
    ) RETURNING id INTO event_id;
    
    RETURN event_id;
END;
$ language 'plpgsql';