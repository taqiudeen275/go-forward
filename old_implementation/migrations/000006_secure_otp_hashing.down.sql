-- Remove index
DROP INDEX IF EXISTS idx_otps_code_hash;

-- Add back the plain text code column
ALTER TABLE otps ADD COLUMN code VARCHAR(10);

-- Remove the secure hash column
ALTER TABLE otps DROP COLUMN IF EXISTS code_hash;