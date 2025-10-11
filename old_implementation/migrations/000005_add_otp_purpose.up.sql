-- Add purpose column to otps table
ALTER TABLE otps ADD COLUMN purpose VARCHAR(20) NOT NULL DEFAULT 'verification';

-- Update existing OTPs to have verification purpose
UPDATE otps SET purpose = 'verification' WHERE purpose = 'verification';

-- Add index for better query performance
CREATE INDEX idx_otps_recipient_type_purpose ON otps(recipient, type, purpose);