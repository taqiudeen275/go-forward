-- Migration: Add token blacklist table
-- Description: Add token blacklist table for JWT token invalidation
-- Created: 2025-10-13

BEGIN;

-- Create token blacklist table
CREATE TABLE IF NOT EXISTS token_blacklist (
    user_id UUID NOT NULL,
    blacklisted_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for efficient lookups
CREATE INDEX idx_token_blacklist_user_blacklisted ON token_blacklist(user_id, blacklisted_at);

-- Add comment
COMMENT ON TABLE token_blacklist IS 'Tracks blacklisted JWT tokens by user and timestamp';
COMMENT ON COLUMN token_blacklist.user_id IS 'User whose tokens are blacklisted';
COMMENT ON COLUMN token_blacklist.blacklisted_at IS 'Timestamp when tokens were blacklisted - tokens issued before this time are invalid';
COMMENT ON COLUMN token_blacklist.created_at IS 'When the blacklist entry was created';

COMMIT;