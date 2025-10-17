-- Query Approvals Migration
-- This migration creates tables for managing SQL query approvals for high-risk operations

-- Create query_approvals table for managing approval workflow
CREATE TABLE IF NOT EXISTS query_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of normalized query
    query TEXT NOT NULL, -- Original query text
    requested_by UUID REFERENCES users(id) ON DELETE CASCADE,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'approved', 'denied', 'expired'
    reason TEXT, -- Approval/denial reason
    risk_level VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    query_type VARCHAR(50), -- 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL', etc.
    affected_tables TEXT[], -- List of tables involved
    execution_count INTEGER DEFAULT 0, -- How many times this approved query has been executed
    max_executions INTEGER DEFAULT 1, -- Maximum allowed executions (-1 for unlimited)
    request_details JSONB DEFAULT '{}', -- Additional request context
    approval_details JSONB DEFAULT '{}', -- Additional approval context
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '24 hours'),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_at TIMESTAMP WITH TIME ZONE,
    denied_at TIMESTAMP WITH TIME ZONE
);

-- Create approval_notifications table for tracking approval notifications
CREATE TABLE IF NOT EXISTS approval_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query_approval_id UUID REFERENCES query_approvals(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL, -- 'request', 'approval', 'denial', 'expiration'
    recipient_type VARCHAR(20) NOT NULL, -- 'user', 'role', 'email'
    recipient_id VARCHAR(255) NOT NULL, -- User ID, role name, or email address
    subject VARCHAR(255),
    message TEXT,
    sent BOOLEAN DEFAULT FALSE,
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create approval_history table for audit trail
CREATE TABLE IF NOT EXISTS approval_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    query_approval_id UUID REFERENCES query_approvals(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- 'created', 'approved', 'denied', 'expired', 'executed'
    performed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    previous_status VARCHAR(20),
    new_status VARCHAR(20),
    comment TEXT,
    additional_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_query_approvals_hash ON query_approvals(query_hash);
CREATE INDEX IF NOT EXISTS idx_query_approvals_requested_by ON query_approvals(requested_by);
CREATE INDEX IF NOT EXISTS idx_query_approvals_approved_by ON query_approvals(approved_by);
CREATE INDEX IF NOT EXISTS idx_query_approvals_status ON query_approvals(status);
CREATE INDEX IF NOT EXISTS idx_query_approvals_expires_at ON query_approvals(expires_at);
CREATE INDEX IF NOT EXISTS idx_query_approvals_created_at ON query_approvals(created_at);

CREATE INDEX IF NOT EXISTS idx_approval_notifications_approval_id ON approval_notifications(query_approval_id);
CREATE INDEX IF NOT EXISTS idx_approval_notifications_sent ON approval_notifications(sent);
CREATE INDEX IF NOT EXISTS idx_approval_notifications_recipient ON approval_notifications(recipient_type, recipient_id);

CREATE INDEX IF NOT EXISTS idx_approval_history_approval_id ON approval_history(query_approval_id);
CREATE INDEX IF NOT EXISTS idx_approval_history_performed_by ON approval_history(performed_by);
CREATE INDEX IF NOT EXISTS idx_approval_history_created_at ON approval_history(created_at);

-- Add unique constraint to prevent duplicate pending requests
CREATE UNIQUE INDEX IF NOT EXISTS idx_query_approvals_unique_pending
ON query_approvals(query_hash, requested_by)
WHERE status = 'pending';

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_query_approvals_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_query_approvals_updated_at
    BEFORE UPDATE ON query_approvals
    FOR EACH ROW
    EXECUTE FUNCTION update_query_approvals_updated_at();

-- Create trigger to automatically create history entries
CREATE OR REPLACE FUNCTION create_approval_history()
RETURNS TRIGGER AS $$
DECLARE
    action_name VARCHAR(50);
    performer_id UUID;
BEGIN
    -- Determine action type
    IF TG_OP = 'INSERT' THEN
        action_name := 'created';
        performer_id := NEW.requested_by;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.status != NEW.status THEN
            CASE NEW.status
                WHEN 'approved' THEN
                    action_name := 'approved';
                    performer_id := NEW.approved_by;
                WHEN 'denied' THEN
                    action_name := 'denied';
                    performer_id := NEW.approved_by;
                WHEN 'expired' THEN
                    action_name := 'expired';
                    performer_id := NULL;
                ELSE
                    action_name := 'updated';
                    performer_id := NEW.approved_by;
            END CASE;
        ELSE
            RETURN NEW; -- No status change, no history entry needed
        END IF;
    END IF;

    -- Insert history record
    INSERT INTO approval_history (
        query_approval_id,
        action,
        performed_by,
        previous_status,
        new_status,
        additional_data
    ) VALUES (
        COALESCE(NEW.id, OLD.id),
        action_name,
        performer_id,
        CASE WHEN TG_OP = 'UPDATE' THEN OLD.status ELSE NULL END,
        NEW.status,
        jsonb_build_object(
            'operation', TG_OP,
            'execution_count', NEW.execution_count,
            'max_executions', NEW.max_executions
        )
    );

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_create_approval_history
    AFTER INSERT OR UPDATE ON query_approvals
    FOR EACH ROW
    EXECUTE FUNCTION create_approval_history();

-- Create function to check if query approval is still valid
CREATE OR REPLACE FUNCTION is_approval_valid(approval_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    approval_record RECORD;
BEGIN
    SELECT status, expires_at, execution_count, max_executions
    INTO approval_record
    FROM query_approvals
    WHERE id = approval_id;

    -- Check if approval exists
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Check if approved
    IF approval_record.status != 'approved' THEN
        RETURN FALSE;
    END IF;

    -- Check if expired
    IF approval_record.expires_at < NOW() THEN
        -- Auto-expire the approval
        UPDATE query_approvals
        SET status = 'expired', updated_at = NOW()
        WHERE id = approval_id;
        RETURN FALSE;
    END IF;

    -- Check execution limit
    IF approval_record.max_executions > 0 AND
       approval_record.execution_count >= approval_record.max_executions THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Create function to increment execution count
CREATE OR REPLACE FUNCTION increment_approval_execution(approval_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    UPDATE query_approvals
    SET execution_count = execution_count + 1,
        updated_at = NOW()
    WHERE id = approval_id
      AND status = 'approved'
      AND (max_executions = -1 OR execution_count < max_executions)
      AND expires_at > NOW();

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Create view for active approvals
CREATE VIEW active_query_approvals AS
SELECT
    qa.*,
    u1.email as requester_email,
    u2.email as approver_email,
    CASE
        WHEN qa.expires_at < NOW() THEN 'expired'
        WHEN qa.max_executions > 0 AND qa.execution_count >= qa.max_executions THEN 'exhausted'
        ELSE qa.status
    END as effective_status
FROM query_approvals qa
LEFT JOIN users u1 ON qa.requested_by = u1.id
LEFT JOIN users u2 ON qa.approved_by = u2.id
WHERE qa.status IN ('pending', 'approved')
  AND qa.expires_at > NOW()
ORDER BY qa.created_at DESC;

-- Create view for approval dashboard
CREATE VIEW approval_dashboard AS
SELECT
    DATE(qa.created_at) as request_date,
    qa.status,
    qa.risk_level,
    qa.query_type,
    COUNT(*) as count,
    AVG(EXTRACT(EPOCH FROM (COALESCE(qa.approved_at, qa.denied_at, NOW()) - qa.created_at))/3600) as avg_response_time_hours
FROM query_approvals qa
WHERE qa.created_at > NOW() - INTERVAL '30 days'
GROUP BY DATE(qa.created_at), qa.status, qa.risk_level, qa.query_type
ORDER BY request_date DESC, count DESC;

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE ON query_approvals TO authenticated;
GRANT SELECT, INSERT ON approval_notifications TO authenticated;
GRANT SELECT ON approval_history TO authenticated;
GRANT SELECT ON active_query_approvals TO authenticated;
GRANT SELECT ON approval_dashboard TO authenticated;

-- Grant execute permissions on functions
GRANT EXECUTE ON FUNCTION is_approval_valid(UUID) TO authenticated;
GRANT EXECUTE ON FUNCTION increment_approval_execution(UUID) TO authenticated;

-- Insert default approval settings (optional)
-- These could be used to configure global approval requirements
INSERT INTO table_security_config (table_name, config_type, config_data) VALUES
('*', 'approval_settings', jsonb_build_object(
    'auto_approve_selects', false,
    'require_approval_for_deletes', true,
    'require_approval_for_updates_without_where', true,
    'require_approval_for_schema_changes', true,
    'max_rows_without_approval', 1000,
    'approval_timeout_hours', 24,
    'max_executions_per_approval', 1
)) ON CONFLICT (table_name, config_type) DO NOTHING;
