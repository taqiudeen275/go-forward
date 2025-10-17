-- Migration rollback: Remove token blacklist table
-- Description: Remove token blacklist table
-- Created: 2025-10-13

BEGIN;

-- Drop indexes
DROP INDEX IF EXISTS idx_token_blacklist_user_blacklisted;

-- Drop table
DROP TABLE IF EXISTS token_blacklist;

COMMIT;