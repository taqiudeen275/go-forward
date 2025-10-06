-- Add code_hash column and remove plain text code column for security
ALTER TABLE otps ADD COLUMN code_hash VARCHAR(128);

-- Update existing OTPs (this will invalidate them, but that's acceptable for security)
-- We can't convert existing plain text codes to hashes, so we'll mark them as used
UPDATE otps SET used = true WHERE code_hash IS NULL;

-- Remove the plain text code column
ALTER TABLE otps DROP COLUMN code;

-- Make code_hash NOT NULL now that we've handled existing data
ALTER TABLE otps ALTER COLUMN code_hash SET NOT NULL;

-- Add index for better performance on hash lookups
CREATE INDEX idx_otps_code_hash ON otps(code_hash) WHERE used = false;