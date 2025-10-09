package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// MFARepository handles MFA-related database operations
type MFARepository struct {
	db *database.DB
}

// NewMFARepository creates a new MFA repository
func NewMFARepository(db *database.DB) *MFARepository {
	return &MFARepository{
		db: db,
	}
}

// CreateMFAConfiguration creates a new MFA configuration
func (r *MFARepository) CreateMFAConfiguration(ctx context.Context, config *MFAConfiguration) error {
	query := `
		INSERT INTO mfa_configurations (user_id, method, secret, backup_codes, is_enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id) DO UPDATE SET
			method = EXCLUDED.method,
			secret = EXCLUDED.secret,
			backup_codes = EXCLUDED.backup_codes,
			is_enabled = EXCLUDED.is_enabled,
			updated_at = EXCLUDED.updated_at
	`

	// Convert backup codes to JSON
	backupCodesJSON, err := json.Marshal(config.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	err = r.db.Exec(ctx, query,
		config.UserID,
		string(config.Method),
		config.Secret,
		backupCodesJSON,
		config.IsEnabled,
		config.CreatedAt,
		config.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create MFA configuration: %w", err)
	}

	return nil
}

// GetMFAConfiguration retrieves MFA configuration for a user
func (r *MFARepository) GetMFAConfiguration(ctx context.Context, userID string) (*MFAConfiguration, error) {
	query := `
		SELECT user_id, method, secret, backup_codes, is_enabled, last_used, created_at, updated_at
		FROM mfa_configurations
		WHERE user_id = $1
	`

	config := &MFAConfiguration{}
	var methodStr string
	var backupCodesJSON []byte

	err := r.db.QueryRow(ctx, query, userID).Scan(
		&config.UserID,
		&methodStr,
		&config.Secret,
		&backupCodesJSON,
		&config.IsEnabled,
		&config.LastUsed,
		&config.CreatedAt,
		&config.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("MFA configuration not found")
		}
		return nil, fmt.Errorf("failed to get MFA configuration: %w", err)
	}

	config.Method = MFAMethod(methodStr)

	// Unmarshal backup codes
	if len(backupCodesJSON) > 0 {
		if err := json.Unmarshal(backupCodesJSON, &config.BackupCodes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal backup codes: %w", err)
		}
	}

	return config, nil
}

// UpdateMFAConfiguration updates an existing MFA configuration
func (r *MFARepository) UpdateMFAConfiguration(ctx context.Context, config *MFAConfiguration) error {
	query := `
		UPDATE mfa_configurations 
		SET method = $2, secret = $3, backup_codes = $4, is_enabled = $5, last_used = $6, updated_at = $7
		WHERE user_id = $1
	`

	// Convert backup codes to JSON
	backupCodesJSON, err := json.Marshal(config.BackupCodes)
	if err != nil {
		return fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	config.UpdatedAt = time.Now()

	err = r.db.Exec(ctx, query,
		config.UserID,
		string(config.Method),
		config.Secret,
		backupCodesJSON,
		config.IsEnabled,
		config.LastUsed,
		config.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update MFA configuration: %w", err)
	}

	return nil
}

// DeleteMFAConfiguration deletes MFA configuration for a user
func (r *MFARepository) DeleteMFAConfiguration(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_configurations WHERE user_id = $1`

	err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA configuration: %w", err)
	}

	return nil
}

// CreateAPIKey creates a new API key
func (r *MFARepository) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	query := `
		INSERT INTO api_keys (id, user_id, name, key_hash, scopes, expires_at, is_active, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	// Convert scopes and metadata to JSON
	scopesJSON, err := json.Marshal(apiKey.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	metadataJSON, err := json.Marshal(apiKey.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = r.db.Exec(ctx, query,
		apiKey.ID,
		apiKey.UserID,
		apiKey.Name,
		apiKey.KeyHash,
		scopesJSON,
		apiKey.ExpiresAt,
		apiKey.IsActive,
		apiKey.CreatedAt,
		apiKey.UpdatedAt,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}

	return nil
}

// GetAPIKey retrieves an API key by ID
func (r *MFARepository) GetAPIKey(ctx context.Context, keyID string) (*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, scopes, expires_at, last_used, is_active, created_at, updated_at, metadata
		FROM api_keys
		WHERE id = $1
	`

	apiKey := &APIKey{}
	var scopesJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, keyID).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.Name,
		&apiKey.KeyHash,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsed,
		&apiKey.IsActive,
		&apiKey.CreatedAt,
		&apiKey.UpdatedAt,
		&metadataJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("API key not found")
		}
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// Unmarshal JSON fields
	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &apiKey.Scopes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
		}
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &apiKey.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return apiKey, nil
}

// GetAPIKeyByHash retrieves an API key by its hash
func (r *MFARepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, scopes, expires_at, last_used, is_active, created_at, updated_at, metadata
		FROM api_keys
		WHERE key_hash = $1 AND is_active = true AND (expires_at IS NULL OR expires_at > NOW())
	`

	apiKey := &APIKey{}
	var scopesJSON, metadataJSON []byte

	err := r.db.QueryRow(ctx, query, keyHash).Scan(
		&apiKey.ID,
		&apiKey.UserID,
		&apiKey.Name,
		&apiKey.KeyHash,
		&scopesJSON,
		&apiKey.ExpiresAt,
		&apiKey.LastUsed,
		&apiKey.IsActive,
		&apiKey.CreatedAt,
		&apiKey.UpdatedAt,
		&metadataJSON,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("API key not found or expired")
		}
		return nil, fmt.Errorf("failed to get API key by hash: %w", err)
	}

	// Unmarshal JSON fields
	if len(scopesJSON) > 0 {
		if err := json.Unmarshal(scopesJSON, &apiKey.Scopes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
		}
	}

	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &apiKey.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return apiKey, nil
}

// ListAPIKeys lists all API keys for a user
func (r *MFARepository) ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, scopes, expires_at, last_used, is_active, created_at, updated_at, metadata
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []*APIKey
	for rows.Next() {
		apiKey := &APIKey{}
		var scopesJSON, metadataJSON []byte

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.UserID,
			&apiKey.Name,
			&apiKey.KeyHash,
			&scopesJSON,
			&apiKey.ExpiresAt,
			&apiKey.LastUsed,
			&apiKey.IsActive,
			&apiKey.CreatedAt,
			&apiKey.UpdatedAt,
			&metadataJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", err)
		}

		// Unmarshal JSON fields
		if len(scopesJSON) > 0 {
			if err := json.Unmarshal(scopesJSON, &apiKey.Scopes); err != nil {
				return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
			}
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &apiKey.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		apiKeys = append(apiKeys, apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API key rows: %w", err)
	}

	return apiKeys, nil
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (r *MFARepository) UpdateAPIKeyLastUsed(ctx context.Context, keyID string) error {
	query := `UPDATE api_keys SET last_used = NOW() WHERE id = $1`

	err := r.db.Exec(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to update API key last used: %w", err)
	}

	return nil
}

// RevokeAPIKey revokes an API key by setting it inactive
func (r *MFARepository) RevokeAPIKey(ctx context.Context, keyID string) error {
	query := `UPDATE api_keys SET is_active = false, updated_at = NOW() WHERE id = $1`

	err := r.db.Exec(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}

	return nil
}

// CreateAdminSession creates a new admin session
func (r *MFARepository) CreateAdminSession(ctx context.Context, session *AdminSession) error {
	query := `
		INSERT INTO admin_sessions (
			id, session_token, user_id, admin_role_id, ip_address, user_agent, fingerprint,
			mfa_verified, mfa_verified_at, requires_mfa, security_flags,
			created_at, last_activity, expires_at, is_active,
			capabilities, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`

	// Convert JSON fields
	securityFlagsJSON, err := json.Marshal(session.SecurityFlags)
	if err != nil {
		return fmt.Errorf("failed to marshal security flags: %w", err)
	}

	capabilitiesJSON, err := json.Marshal(session.Capabilities)
	if err != nil {
		return fmt.Errorf("failed to marshal capabilities: %w", err)
	}

	metadataJSON := []byte("{}")
	if len(metadataJSON) == 0 {
		metadataJSON = []byte("{}")
	}

	// Get admin role ID (placeholder - in real implementation, this would be looked up)
	var adminRoleID *string

	err = r.db.Exec(ctx, query,
		session.ID,
		session.ID, // Using session ID as token for now
		session.UserID,
		adminRoleID,
		session.IPAddress,
		session.UserAgent,
		"", // fingerprint placeholder
		session.MFAVerified,
		nil, // mfa_verified_at
		session.RequiresMFA,
		securityFlagsJSON,
		session.CreatedAt,
		session.LastActivity,
		session.ExpiresAt,
		session.IsActive,
		capabilitiesJSON,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to create admin session: %w", err)
	}

	return nil
}

// GetAdminSession retrieves an admin session by ID
func (r *MFARepository) GetAdminSession(ctx context.Context, sessionID string) (*AdminSession, error) {
	query := `
		SELECT 
			s.id, s.user_id, s.ip_address, s.user_agent,
			s.mfa_verified, s.requires_mfa, s.security_flags,
			s.created_at, s.last_activity, s.expires_at, s.is_active,
			s.capabilities,
			COALESCE(ar.level::text, '') as admin_level
		FROM admin_sessions s
		LEFT JOIN admin_roles ar ON s.admin_role_id = ar.id
		WHERE s.id = $1 AND s.is_active = true AND s.expires_at > NOW()
	`

	session := &AdminSession{}
	var securityFlagsJSON, capabilitiesJSON []byte
	var adminLevelStr string

	err := r.db.QueryRow(ctx, query, sessionID).Scan(
		&session.ID,
		&session.UserID,
		&session.IPAddress,
		&session.UserAgent,
		&session.MFAVerified,
		&session.RequiresMFA,
		&securityFlagsJSON,
		&session.CreatedAt,
		&session.LastActivity,
		&session.ExpiresAt,
		&session.IsActive,
		&capabilitiesJSON,
		&adminLevelStr,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("admin session not found or expired")
		}
		return nil, fmt.Errorf("failed to get admin session: %w", err)
	}

	// Parse admin level
	if adminLevelStr != "" {
		session.AdminLevel = AdminLevel(adminLevelStr)
	}

	// Unmarshal JSON fields
	if len(securityFlagsJSON) > 0 {
		if err := json.Unmarshal(securityFlagsJSON, &session.SecurityFlags); err != nil {
			return nil, fmt.Errorf("failed to unmarshal security flags: %w", err)
		}
	}

	if len(capabilitiesJSON) > 0 {
		if err := json.Unmarshal(capabilitiesJSON, &session.Capabilities); err != nil {
			return nil, fmt.Errorf("failed to unmarshal capabilities: %w", err)
		}
	}

	return session, nil
}

// UpdateAdminSessionActivity updates the last activity timestamp
func (r *MFARepository) UpdateAdminSessionActivity(ctx context.Context, sessionID string) error {
	query := `UPDATE admin_sessions SET last_activity = NOW() WHERE id = $1`

	err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to update admin session activity: %w", err)
	}

	return nil
}

// InvalidateAdminSession invalidates an admin session
func (r *MFARepository) InvalidateAdminSession(ctx context.Context, sessionID string, reason string) error {
	query := `
		UPDATE admin_sessions 
		SET is_active = false, terminated_at = NOW(), termination_reason = $2
		WHERE id = $1
	`

	err := r.db.Exec(ctx, query, sessionID, reason)
	if err != nil {
		return fmt.Errorf("failed to invalidate admin session: %w", err)
	}

	return nil
}

// GetActiveAdminSessions retrieves all active sessions for a user
func (r *MFARepository) GetActiveAdminSessions(ctx context.Context, userID string) ([]*AdminSession, error) {
	query := `
		SELECT 
			s.id, s.user_id, s.ip_address, s.user_agent,
			s.mfa_verified, s.requires_mfa, s.security_flags,
			s.created_at, s.last_activity, s.expires_at, s.is_active,
			s.capabilities,
			COALESCE(ar.level::text, '') as admin_level
		FROM admin_sessions s
		LEFT JOIN admin_roles ar ON s.admin_role_id = ar.id
		WHERE s.user_id = $1 AND s.is_active = true AND s.expires_at > NOW()
		ORDER BY s.last_activity DESC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active admin sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*AdminSession
	for rows.Next() {
		session := &AdminSession{}
		var securityFlagsJSON, capabilitiesJSON []byte
		var adminLevelStr string

		err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.IPAddress,
			&session.UserAgent,
			&session.MFAVerified,
			&session.RequiresMFA,
			&securityFlagsJSON,
			&session.CreatedAt,
			&session.LastActivity,
			&session.ExpiresAt,
			&session.IsActive,
			&capabilitiesJSON,
			&adminLevelStr,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan admin session row: %w", err)
		}

		// Parse admin level
		if adminLevelStr != "" {
			session.AdminLevel = AdminLevel(adminLevelStr)
		}

		// Unmarshal JSON fields
		if len(securityFlagsJSON) > 0 {
			if err := json.Unmarshal(securityFlagsJSON, &session.SecurityFlags); err != nil {
				return nil, fmt.Errorf("failed to unmarshal security flags: %w", err)
			}
		}

		if len(capabilitiesJSON) > 0 {
			if err := json.Unmarshal(capabilitiesJSON, &session.Capabilities); err != nil {
				return nil, fmt.Errorf("failed to unmarshal capabilities: %w", err)
			}
		}

		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating admin session rows: %w", err)
	}

	return sessions, nil
}
