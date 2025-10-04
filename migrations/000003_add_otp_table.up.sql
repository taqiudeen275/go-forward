-- Create OTP table for one-time password authentication
CREATE TABLE IF NOT EXISTS otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    type VARCHAR(10) NOT NULL CHECK (type IN ('email', 'sms')),
    recipient VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for OTP table
CREATE INDEX IF NOT EXISTS idx_otps_user_id ON otps(user_id);
CREATE INDEX IF NOT EXISTS idx_otps_recipient ON otps(recipient);
CREATE INDEX IF NOT EXISTS idx_otps_type ON otps(type);
CREATE INDEX IF NOT EXISTS idx_otps_expires_at ON otps(expires_at);
CREATE INDEX IF NOT EXISTS idx_otps_used ON otps(used);
CREATE INDEX IF NOT EXISTS idx_otps_code ON otps(code);

-- Create composite index for efficient OTP lookup
CREATE INDEX IF NOT EXISTS idx_otps_recipient_type_used ON otps(recipient, type, used);