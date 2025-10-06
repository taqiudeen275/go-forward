-- Remove index
DROP INDEX IF EXISTS idx_otps_recipient_type_purpose;

-- Remove purpose column from otps table
ALTER TABLE otps DROP COLUMN IF EXISTS purpose;