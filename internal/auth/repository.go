package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Repository handles database operations for authentication
type Repository interface {
	// User operations
	CreateUser(ctx context.Context, user *UnifiedUser) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*UnifiedUser, error)
	GetUserByEmail(ctx context.Context, email string) (*UnifiedUser, error)
	GetUserByPhone(ctx context.Context, phone string) (*UnifiedUser, error)
	GetUserByUsername(ctx context.Context, username string) (*UnifiedUser, error)
	UpdateUser(ctx context.Context, user *UnifiedUser) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*UnifiedUser, error)

	// Admin operations
	PromoteToAdmin(ctx context.Context, userID uuid.UUID, level AdminLevel, capabilities *AdminCapabilities, promotedBy uuid.UUID) error
	DemoteAdmin(ctx context.Context, userID uuid.UUID, demotedBy uuid.UUID) error
	ListAdmins(ctx context.Context, filter *AdminFilter) ([]*UnifiedUser, error)

	// Session operations
	CreateSession(ctx context.Context, session *AdminSession) error
	GetSessionByToken(ctx context.Context, token string) (*AdminSession, error)
	UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error
	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
	CleanExpiredSessions(ctx context.Context) error

	// API Key operations
	CreateAPIKey(ctx context.Context, apiKey *APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]*APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error
	DeleteAPIKey(ctx context.Context, id uuid.UUID) error

	// OTP operations
	CreateOTP(ctx context.Context, otp *OTPCode) error
	GetOTPByCode(ctx context.Context, code string, purpose string) (*OTPCode, error)
	GetOTPByIdentifier(ctx context.Context, identifier string, purpose string) (*OTPCode, error)
	UpdateOTPAttempts(ctx context.Context, id uuid.UUID, attempts int) error
	MarkOTPUsed(ctx context.Context, id uuid.UUID) error
	InvalidateOTPsByIdentifier(ctx context.Context, identifier string, purpose string) error
	CleanExpiredOTPs(ctx context.Context) error

	// Template operations
	CreateTemplate(ctx context.Context, template *Template) error
	GetTemplate(ctx context.Context, templateType TemplateType, purpose string, language string) (*Template, error)
	UpdateTemplate(ctx context.Context, template *Template) error
	DeleteTemplate(ctx context.Context, id uuid.UUID) error
	ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*Template, error)

	// Audit operations
	CreateAuditLog(ctx context.Context, log *AuditLog) error
	ListAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error)

	// Security event operations
	CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error
	ListSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error)
	ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID) error

	// Rate limiting operations
	GetRateLimit(ctx context.Context, key string) (*RateLimit, error)
	UpsertRateLimit(ctx context.Context, rateLimit *RateLimit) error
	CleanExpiredRateLimits(ctx context.Context) error

	// MFA recovery operations
	CreateMFARecovery(ctx context.Context, recovery *MFARecovery) error
	GetMFARecoveryByCode(ctx context.Context, recoveryCode string) (*MFARecovery, error)
	GetMFARecoveryByID(ctx context.Context, id uuid.UUID) (*MFARecovery, error)
	UpdateMFARecovery(ctx context.Context, recovery *MFARecovery) error
	ListMFARecovery(ctx context.Context, userID uuid.UUID) ([]*MFARecovery, error)

	// Emergency access operations
	CreateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error
	GetEmergencyAccessByID(ctx context.Context, id uuid.UUID) (*EmergencyAccess, error)
	GetEmergencyAccessByToken(ctx context.Context, token string) (*EmergencyAccess, error)
	UpdateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error
	ListEmergencyAccess(ctx context.Context, filter *EmergencyAccessFilter) ([]*EmergencyAccess, error)
}

// UserFilter represents filters for user queries
type UserFilter struct {
	AdminLevel *AdminLevel `json:"admin_level"`
	Verified   *bool       `json:"verified"`
	Locked     *bool       `json:"locked"`
	Search     string      `json:"search"`
	Limit      int         `json:"limit"`
	Offset     int         `json:"offset"`
}

// AdminFilter represents filters for admin queries
type AdminFilter struct {
	Level  *AdminLevel `json:"level"`
	Search string      `json:"search"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// TemplateFilter represents filters for template queries
type TemplateFilter struct {
	Type     *TemplateType `json:"type"`
	Purpose  string        `json:"purpose"`
	Language string        `json:"language"`
	Active   *bool         `json:"active"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
}

// AuditFilter represents filters for audit log queries
type AuditFilter struct {
	UserID    *uuid.UUID     `json:"user_id"`
	Action    string         `json:"action"`
	Resource  string         `json:"resource"`
	Severity  *AuditSeverity `json:"severity"`
	Success   *bool          `json:"success"`
	StartDate *time.Time     `json:"start_date"`
	EndDate   *time.Time     `json:"end_date"`
	Limit     int            `json:"limit"`
	Offset    int            `json:"offset"`
}

// SecurityEventFilter represents filters for security event queries
type SecurityEventFilter struct {
	EventType string         `json:"event_type"`
	UserID    *uuid.UUID     `json:"user_id"`
	Severity  *AuditSeverity `json:"severity"`
	Resolved  *bool          `json:"resolved"`
	StartDate *time.Time     `json:"start_date"`
	EndDate   *time.Time     `json:"end_date"`
	Limit     int            `json:"limit"`
	Offset    int            `json:"offset"`
}

// repository implements the Repository interface
type repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new auth repository
func NewRepository(db *pgxpool.Pool) Repository {
	return &repository{db: db}
}

// User operations

// CreateUser creates a new user in the database
func (r *repository) CreateUser(ctx context.Context, user *UnifiedUser) error {
	query := `
		INSERT INTO users (
			id, email, phone, username, password_hash, email_verified, phone_verified,
			admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			metadata, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)`

	_, err := r.db.Exec(ctx, query,
		user.ID, user.Email, user.Phone, user.Username, user.PasswordHash,
		user.EmailVerified, user.PhoneVerified, user.AdminLevel, user.Capabilities,
		pq.Array(user.AssignedTables), user.MFAEnabled, user.MFASecret,
		pq.Array(user.BackupCodes), user.Metadata, user.CreatedBy, user.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create user")
	}

	return nil
}

// GetUserByID retrieves a user by ID
func (r *repository) GetUserByID(ctx context.Context, id uuid.UUID) (*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE id = $1`

	var user UnifiedUser
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by ID")
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *repository) GetUserByEmail(ctx context.Context, email string) (*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE email = $1`

	var user UnifiedUser
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by email")
	}

	return &user, nil
}

// GetUserByPhone retrieves a user by phone
func (r *repository) GetUserByPhone(ctx context.Context, phone string) (*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE phone = $1`

	var user UnifiedUser
	err := r.db.QueryRow(ctx, query, phone).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by phone")
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (r *repository) GetUserByUsername(ctx context.Context, username string) (*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE username = $1`

	var user UnifiedUser
	err := r.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by username")
	}

	return &user, nil
}

// UpdateUser updates an existing user
func (r *repository) UpdateUser(ctx context.Context, user *UnifiedUser) error {
	query := `
		UPDATE users SET
			email = $2, phone = $3, username = $4, password_hash = $5,
			email_verified = $6, phone_verified = $7, admin_level = $8,
			capabilities = $9, assigned_tables = $10, mfa_enabled = $11,
			mfa_secret = $12, backup_codes = $13, last_login = $14,
			failed_attempts = $15, locked_until = $16, metadata = $17,
			updated_by = $18, updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query,
		user.ID, user.Email, user.Phone, user.Username, user.PasswordHash,
		user.EmailVerified, user.PhoneVerified, user.AdminLevel, user.Capabilities,
		pq.Array(user.AssignedTables), user.MFAEnabled, user.MFASecret,
		pq.Array(user.BackupCodes), user.LastLogin, user.FailedAttempts,
		user.LockedUntil, user.Metadata, user.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to update user")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("user not found")
	}

	return nil
}

// DeleteUser deletes a user by ID
func (r *repository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to delete user")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("user not found")
	}

	return nil
}

// ListUsers retrieves users with filtering
func (r *repository) ListUsers(ctx context.Context, filter *UserFilter) ([]*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	if filter.AdminLevel != nil {
		argCount++
		query += fmt.Sprintf(" AND admin_level = $%d", argCount)
		args = append(args, *filter.AdminLevel)
	}

	if filter.Verified != nil {
		argCount++
		if *filter.Verified {
			query += fmt.Sprintf(" AND (email_verified = true OR phone_verified = true)")
		} else {
			query += fmt.Sprintf(" AND email_verified = false AND phone_verified = false")
		}
	}

	if filter.Locked != nil {
		argCount++
		if *filter.Locked {
			query += fmt.Sprintf(" AND locked_until > NOW()")
		} else {
			query += fmt.Sprintf(" AND (locked_until IS NULL OR locked_until <= NOW())")
		}
	}

	if filter.Search != "" {
		argCount++
		query += fmt.Sprintf(" AND (email ILIKE $%d OR username ILIKE $%d OR phone ILIKE $%d)", argCount, argCount, argCount)
		args = append(args, "%"+filter.Search+"%")
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list users")
	}
	defer rows.Close()

	var users []*UnifiedUser
	for rows.Next() {
		var user UnifiedUser
		err := rows.Scan(
			&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
			&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
			pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
			pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
			&user.LockedUntil, &user.Metadata, &user.CreatedAt, &user.UpdatedAt,
			&user.CreatedBy, &user.UpdatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan user")
		}
		users = append(users, &user)
	}

	return users, nil
}

// Admin operations

// PromoteToAdmin promotes a user to admin with specified level and capabilities
func (r *repository) PromoteToAdmin(ctx context.Context, userID uuid.UUID, level AdminLevel, capabilities *AdminCapabilities, promotedBy uuid.UUID) error {
	query := `
		UPDATE users SET
			admin_level = $2,
			capabilities = $3,
			updated_by = $4,
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query, userID, level, capabilities, promotedBy)
	if err != nil {
		return errors.Wrap(err, "failed to promote user to admin")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("user not found")
	}

	return nil
}

// DemoteAdmin removes admin privileges from a user
func (r *repository) DemoteAdmin(ctx context.Context, userID uuid.UUID, demotedBy uuid.UUID) error {
	query := `
		UPDATE users SET
			admin_level = NULL,
			capabilities = NULL,
			assigned_tables = '{}',
			updated_by = $2,
			updated_at = NOW()
		WHERE id = $1 AND admin_level IS NOT NULL`

	result, err := r.db.Exec(ctx, query, userID, demotedBy)
	if err != nil {
		return errors.Wrap(err, "failed to demote admin")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("admin user not found")
	}

	return nil
}

// ListAdmins retrieves admin users with filtering
func (r *repository) ListAdmins(ctx context.Context, filter *AdminFilter) ([]*UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE admin_level IS NOT NULL`

	args := []interface{}{}
	argCount := 0

	if filter.Level != nil {
		argCount++
		query += fmt.Sprintf(" AND admin_level = $%d", argCount)
		args = append(args, *filter.Level)
	}

	if filter.Search != "" {
		argCount++
		query += fmt.Sprintf(" AND (email ILIKE $%d OR username ILIKE $%d)", argCount, argCount)
		args = append(args, "%"+filter.Search+"%")
	}

	query += " ORDER BY admin_level, created_at DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list admins")
	}
	defer rows.Close()

	var admins []*UnifiedUser
	for rows.Next() {
		var admin UnifiedUser
		err := rows.Scan(
			&admin.ID, &admin.Email, &admin.Phone, &admin.Username, &admin.PasswordHash,
			&admin.EmailVerified, &admin.PhoneVerified, &admin.AdminLevel, &admin.Capabilities,
			pq.Array(&admin.AssignedTables), &admin.MFAEnabled, &admin.MFASecret,
			pq.Array(&admin.BackupCodes), &admin.LastLogin, &admin.FailedAttempts,
			&admin.LockedUntil, &admin.Metadata, &admin.CreatedAt, &admin.UpdatedAt,
			&admin.CreatedBy, &admin.UpdatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan admin")
		}
		admins = append(admins, &admin)
	}

	return admins, nil
}

// Session operations

// CreateSession creates a new admin session
func (r *repository) CreateSession(ctx context.Context, session *AdminSession) error {
	query := `
		INSERT INTO admin_sessions (
			id, user_id, session_token, refresh_token, ip_address, user_agent, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		session.ID, session.UserID, session.SessionToken, session.RefreshToken,
		session.IPAddress, session.UserAgent, session.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create session")
	}

	return nil
}

// GetSessionByToken retrieves a session by token
func (r *repository) GetSessionByToken(ctx context.Context, token string) (*AdminSession, error) {
	query := `
		SELECT id, user_id, session_token, refresh_token, ip_address, user_agent,
			   expires_at, created_at, last_activity
		FROM admin_sessions WHERE session_token = $1`

	var session AdminSession
	err := r.db.QueryRow(ctx, query, token).Scan(
		&session.ID, &session.UserID, &session.SessionToken, &session.RefreshToken,
		&session.IPAddress, &session.UserAgent, &session.ExpiresAt,
		&session.CreatedAt, &session.LastActivity,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("session not found")
		}
		return nil, errors.Wrap(err, "failed to get session by token")
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity time for a session
func (r *repository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	query := `UPDATE admin_sessions SET last_activity = NOW() WHERE id = $1`

	result, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to update session activity")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("session not found")
	}

	return nil
}

// DeleteSession deletes a session by ID
func (r *repository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	query := `DELETE FROM admin_sessions WHERE id = $1`

	result, err := r.db.Exec(ctx, query, sessionID)
	if err != nil {
		return errors.Wrap(err, "failed to delete session")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("session not found")
	}

	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (r *repository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	query := `DELETE FROM admin_sessions WHERE user_id = $1`

	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return errors.Wrap(err, "failed to delete user sessions")
	}

	return nil
}

// CleanExpiredSessions removes expired sessions
func (r *repository) CleanExpiredSessions(ctx context.Context) error {
	query := `DELETE FROM admin_sessions WHERE expires_at < NOW()`

	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return errors.Wrap(err, "failed to clean expired sessions")
	}

	return nil

}

// API Key operations

// CreateAPIKey creates a new API key
func (r *repository) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	query := `
		INSERT INTO api_keys (
			id, user_id, name, key_hash, permissions, expires_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		apiKey.ID, apiKey.UserID, apiKey.Name, apiKey.KeyHash,
		apiKey.Permissions, apiKey.ExpiresAt, apiKey.CreatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create API key")
	}

	return nil
}

// GetAPIKeyByHash retrieves an API key by hash
func (r *repository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, permissions, last_used, expires_at,
			   created_at, created_by
		FROM api_keys WHERE key_hash = $1`

	var apiKey APIKey
	err := r.db.QueryRow(ctx, query, keyHash).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
		&apiKey.Permissions, &apiKey.LastUsed, &apiKey.ExpiresAt,
		&apiKey.CreatedAt, &apiKey.CreatedBy,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("API key not found")
		}
		return nil, errors.Wrap(err, "failed to get API key by hash")
	}

	return &apiKey, nil
}

// ListAPIKeys retrieves API keys for a user
func (r *repository) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]*APIKey, error) {
	query := `
		SELECT id, user_id, name, key_hash, permissions, last_used, expires_at,
			   created_at, created_by
		FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list API keys")
	}
	defer rows.Close()

	var apiKeys []*APIKey
	for rows.Next() {
		var apiKey APIKey
		err := rows.Scan(
			&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyHash,
			&apiKey.Permissions, &apiKey.LastUsed, &apiKey.ExpiresAt,
			&apiKey.CreatedAt, &apiKey.CreatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan API key")
		}
		apiKeys = append(apiKeys, &apiKey)
	}

	return apiKeys, nil
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (r *repository) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used = NOW() WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to update API key last used")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("API key not found")
	}

	return nil
}

// DeleteAPIKey deletes an API key by ID
func (r *repository) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to delete API key")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("API key not found")
	}

	return nil
}

// OTP operations

// CreateOTP creates a new OTP code
func (r *repository) CreateOTP(ctx context.Context, otp *OTPCode) error {
	query := `
		INSERT INTO otp_codes (
			id, user_id, email, phone, code, purpose, max_attempts, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	_, err := r.db.Exec(ctx, query,
		otp.ID, otp.UserID, otp.Email, otp.Phone, otp.Code,
		otp.Purpose, otp.MaxAttempts, otp.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create OTP")
	}

	return nil
}

// GetOTPByCode retrieves an OTP by code and purpose
func (r *repository) GetOTPByCode(ctx context.Context, code string, purpose string) (*OTPCode, error) {
	query := `
		SELECT id, user_id, email, phone, code, purpose, attempts, max_attempts,
			   expires_at, used_at, created_at
		FROM otp_codes WHERE code = $1 AND purpose = $2 AND used_at IS NULL`

	var otp OTPCode
	err := r.db.QueryRow(ctx, query, code, purpose).Scan(
		&otp.ID, &otp.UserID, &otp.Email, &otp.Phone, &otp.Code,
		&otp.Purpose, &otp.Attempts, &otp.MaxAttempts, &otp.ExpiresAt,
		&otp.UsedAt, &otp.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("OTP not found")
		}
		return nil, errors.Wrap(err, "failed to get OTP by code")
	}

	return &otp, nil
}

// GetOTPByIdentifier retrieves the latest unused OTP by email/phone and purpose
func (r *repository) GetOTPByIdentifier(ctx context.Context, identifier string, purpose string) (*OTPCode, error) {
	query := `
		SELECT id, user_id, email, phone, code, purpose, attempts, max_attempts,
			   expires_at, used_at, created_at
		FROM otp_codes 
		WHERE (email = $1 OR phone = $1) AND purpose = $2 AND used_at IS NULL
		ORDER BY created_at DESC LIMIT 1`

	var otp OTPCode
	err := r.db.QueryRow(ctx, query, identifier, purpose).Scan(
		&otp.ID, &otp.UserID, &otp.Email, &otp.Phone, &otp.Code,
		&otp.Purpose, &otp.Attempts, &otp.MaxAttempts, &otp.ExpiresAt,
		&otp.UsedAt, &otp.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("OTP not found")
		}
		return nil, errors.Wrap(err, "failed to get OTP by identifier")
	}

	return &otp, nil
}

// UpdateOTPAttempts updates the attempt count for an OTP
func (r *repository) UpdateOTPAttempts(ctx context.Context, id uuid.UUID, attempts int) error {
	query := `UPDATE otp_codes SET attempts = $2 WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id, attempts)
	if err != nil {
		return errors.Wrap(err, "failed to update OTP attempts")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("OTP not found")
	}

	return nil
}

// MarkOTPUsed marks an OTP as used
func (r *repository) MarkOTPUsed(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE otp_codes SET used_at = NOW() WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to mark OTP as used")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("OTP not found")
	}

	return nil
}

// InvalidateOTPsByIdentifier marks all unused OTPs for an identifier and purpose as used
func (r *repository) InvalidateOTPsByIdentifier(ctx context.Context, identifier string, purpose string) error {
	query := `
		UPDATE otp_codes 
		SET used_at = NOW() 
		WHERE (email = $1 OR phone = $1) 
		AND purpose = $2 
		AND used_at IS NULL 
		AND expires_at > NOW()`

	_, err := r.db.Exec(ctx, query, identifier, purpose)
	if err != nil {
		return errors.Wrap(err, "failed to invalidate existing OTPs")
	}

	return nil
}

// CleanExpiredOTPs removes expired OTP codes
func (r *repository) CleanExpiredOTPs(ctx context.Context) error {
	query := `DELETE FROM otp_codes WHERE expires_at < NOW()`

	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return errors.Wrap(err, "failed to clean expired OTPs")
	}

	return nil
}

// Template operations

// CreateTemplate creates a new template
func (r *repository) CreateTemplate(ctx context.Context, template *Template) error {
	query := `
		INSERT INTO templates (
			id, type, purpose, language, subject, content, variables,
			is_default, is_active, created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.Exec(ctx, query,
		template.ID, template.Type, template.Purpose, template.Language,
		template.Subject, template.Content, template.Variables,
		template.IsDefault, template.IsActive, template.CreatedBy, template.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create template")
	}

	return nil
}

// GetTemplate retrieves a template by type, purpose, and language
func (r *repository) GetTemplate(ctx context.Context, templateType TemplateType, purpose string, language string) (*Template, error) {
	query := `
		SELECT id, type, purpose, language, subject, content, variables,
			   is_default, is_active, created_by, created_at, updated_by, updated_at
		FROM templates 
		WHERE type = $1 AND purpose = $2 AND language = $3 AND is_active = true
		ORDER BY is_default DESC LIMIT 1`

	var template Template
	err := r.db.QueryRow(ctx, query, templateType, purpose, language).Scan(
		&template.ID, &template.Type, &template.Purpose, &template.Language,
		&template.Subject, &template.Content, &template.Variables,
		&template.IsDefault, &template.IsActive, &template.CreatedBy,
		&template.CreatedAt, &template.UpdatedBy, &template.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("template not found")
		}
		return nil, errors.Wrap(err, "failed to get template")
	}

	return &template, nil
}

// UpdateTemplate updates an existing template
func (r *repository) UpdateTemplate(ctx context.Context, template *Template) error {
	query := `
		UPDATE templates SET
			subject = $2, content = $3, variables = $4, is_default = $5,
			is_active = $6, updated_by = $7, updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query,
		template.ID, template.Subject, template.Content, template.Variables,
		template.IsDefault, template.IsActive, template.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to update template")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("template not found")
	}

	return nil
}

// DeleteTemplate deletes a template by ID
func (r *repository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM templates WHERE id = $1 AND is_default = false`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to delete template")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("template not found or is default template")
	}

	return nil
}

// ListTemplates retrieves templates with filtering
func (r *repository) ListTemplates(ctx context.Context, filter *TemplateFilter) ([]*Template, error) {
	query := `
		SELECT id, type, purpose, language, subject, content, variables,
			   is_default, is_active, created_by, created_at, updated_by, updated_at
		FROM templates WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	if filter.Type != nil {
		argCount++
		query += fmt.Sprintf(" AND type = $%d", argCount)
		args = append(args, *filter.Type)
	}

	if filter.Purpose != "" {
		argCount++
		query += fmt.Sprintf(" AND purpose = $%d", argCount)
		args = append(args, filter.Purpose)
	}

	if filter.Language != "" {
		argCount++
		query += fmt.Sprintf(" AND language = $%d", argCount)
		args = append(args, filter.Language)
	}

	if filter.Active != nil {
		argCount++
		query += fmt.Sprintf(" AND is_active = $%d", argCount)
		args = append(args, *filter.Active)
	}

	query += " ORDER BY type, purpose, language, is_default DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list templates")
	}
	defer rows.Close()

	var templates []*Template
	for rows.Next() {
		var template Template
		err := rows.Scan(
			&template.ID, &template.Type, &template.Purpose, &template.Language,
			&template.Subject, &template.Content, &template.Variables,
			&template.IsDefault, &template.IsActive, &template.CreatedBy,
			&template.CreatedAt, &template.UpdatedBy, &template.UpdatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan template")
		}
		templates = append(templates, &template)
	}

	return templates, nil
}

// Audit operations

// CreateAuditLog creates a new audit log entry
func (r *repository) CreateAuditLog(ctx context.Context, log *AuditLog) error {
	query := `
		INSERT INTO audit_logs (
			id, user_id, action, resource, resource_id, details, ip_address,
			user_agent, request_id, success, error_code, severity
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.db.Exec(ctx, query,
		log.ID, log.UserID, log.Action, log.Resource, log.ResourceID,
		log.Details, log.IPAddress, log.UserAgent, log.RequestID,
		log.Success, log.ErrorCode, log.Severity,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create audit log")
	}

	return nil
}

// ListAuditLogs retrieves audit logs with filtering
func (r *repository) ListAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	query := `
		SELECT id, user_id, action, resource, resource_id, details, ip_address,
			   user_agent, request_id, success, error_code, severity, created_at
		FROM audit_logs WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	if filter.UserID != nil {
		argCount++
		query += fmt.Sprintf(" AND user_id = $%d", argCount)
		args = append(args, *filter.UserID)
	}

	if filter.Action != "" {
		argCount++
		query += fmt.Sprintf(" AND action ILIKE $%d", argCount)
		args = append(args, "%"+filter.Action+"%")
	}

	if filter.Resource != "" {
		argCount++
		query += fmt.Sprintf(" AND resource ILIKE $%d", argCount)
		args = append(args, "%"+filter.Resource+"%")
	}

	if filter.Severity != nil {
		argCount++
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, *filter.Severity)
	}

	if filter.Success != nil {
		argCount++
		query += fmt.Sprintf(" AND success = $%d", argCount)
		args = append(args, *filter.Success)
	}

	if filter.StartDate != nil {
		argCount++
		query += fmt.Sprintf(" AND created_at >= $%d", argCount)
		args = append(args, *filter.StartDate)
	}

	if filter.EndDate != nil {
		argCount++
		query += fmt.Sprintf(" AND created_at <= $%d", argCount)
		args = append(args, *filter.EndDate)
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list audit logs")
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		err := rows.Scan(
			&log.ID, &log.UserID, &log.Action, &log.Resource, &log.ResourceID,
			&log.Details, &log.IPAddress, &log.UserAgent, &log.RequestID,
			&log.Success, &log.ErrorCode, &log.Severity, &log.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan audit log")
		}
		logs = append(logs, &log)
	}

	return logs, nil
}

// Security event operations

// CreateSecurityEvent creates a new security event
func (r *repository) CreateSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	query := `
		INSERT INTO security_events (
			id, event_type, user_id, ip_address, user_agent, details, severity
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		event.ID, event.EventType, event.UserID, event.IPAddress,
		event.UserAgent, event.Details, event.Severity,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create security event")
	}

	return nil
}

// ListSecurityEvents retrieves security events with filtering
func (r *repository) ListSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	query := `
		SELECT id, event_type, user_id, ip_address, user_agent, details, severity,
			   resolved, resolved_by, resolved_at, created_at
		FROM security_events WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	if filter.EventType != "" {
		argCount++
		query += fmt.Sprintf(" AND event_type = $%d", argCount)
		args = append(args, filter.EventType)
	}

	if filter.UserID != nil {
		argCount++
		query += fmt.Sprintf(" AND user_id = $%d", argCount)
		args = append(args, *filter.UserID)
	}

	if filter.Severity != nil {
		argCount++
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, *filter.Severity)
	}

	if filter.Resolved != nil {
		argCount++
		query += fmt.Sprintf(" AND resolved = $%d", argCount)
		args = append(args, *filter.Resolved)
	}

	if filter.StartDate != nil {
		argCount++
		query += fmt.Sprintf(" AND created_at >= $%d", argCount)
		args = append(args, *filter.StartDate)
	}

	if filter.EndDate != nil {
		argCount++
		query += fmt.Sprintf(" AND created_at <= $%d", argCount)
		args = append(args, *filter.EndDate)
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list security events")
	}
	defer rows.Close()

	var events []*SecurityEvent
	for rows.Next() {
		var event SecurityEvent
		err := rows.Scan(
			&event.ID, &event.EventType, &event.UserID, &event.IPAddress,
			&event.UserAgent, &event.Details, &event.Severity, &event.Resolved,
			&event.ResolvedBy, &event.ResolvedAt, &event.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan security event")
		}
		events = append(events, &event)
	}

	return events, nil
}

// ResolveSecurityEvent marks a security event as resolved
func (r *repository) ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID) error {
	query := `
		UPDATE security_events SET
			resolved = true, resolved_by = $2, resolved_at = NOW()
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id, resolvedBy)
	if err != nil {
		return errors.Wrap(err, "failed to resolve security event")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("security event not found")
	}

	return nil
}

// Rate limiting operations

// GetRateLimit retrieves a rate limit entry by key
func (r *repository) GetRateLimit(ctx context.Context, key string) (*RateLimit, error) {
	query := `
		SELECT id, key, count, window_start, expires_at
		FROM rate_limits WHERE key = $1`

	var rateLimit RateLimit
	err := r.db.QueryRow(ctx, query, key).Scan(
		&rateLimit.ID, &rateLimit.Key, &rateLimit.Count,
		&rateLimit.WindowStart, &rateLimit.ExpiresAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("rate limit not found")
		}
		return nil, errors.Wrap(err, "failed to get rate limit")
	}

	return &rateLimit, nil
}

// UpsertRateLimit creates or updates a rate limit entry
func (r *repository) UpsertRateLimit(ctx context.Context, rateLimit *RateLimit) error {
	query := `
		INSERT INTO rate_limits (id, key, count, window_start, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (key) DO UPDATE SET
			count = $3,
			window_start = $4,
			expires_at = $5`

	_, err := r.db.Exec(ctx, query,
		rateLimit.ID, rateLimit.Key, rateLimit.Count,
		rateLimit.WindowStart, rateLimit.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to upsert rate limit")
	}

	return nil
}

// CleanExpiredRateLimits removes expired rate limit entries
func (r *repository) CleanExpiredRateLimits(ctx context.Context) error {
	query := `DELETE FROM rate_limits WHERE expires_at < NOW()`

	_, err := r.db.Exec(ctx, query)
	if err != nil {
		return errors.Wrap(err, "failed to clean expired rate limits")
	}

	return nil
}

// Emergency access operations

// CreateEmergencyAccess creates a new emergency access entry
func (r *repository) CreateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error {
	query := `
		INSERT INTO emergency_access (
			id, access_token, created_by, reason, admin_level, ip_restriction, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.Exec(ctx, query,
		access.ID, access.AccessToken, access.CreatedBy, access.Reason,
		access.AdminLevel, access.IPRestriction, access.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create emergency access")
	}

	return nil
}

// GetEmergencyAccessByID retrieves emergency access by ID
func (r *repository) GetEmergencyAccessByID(ctx context.Context, id uuid.UUID) (*EmergencyAccess, error) {
	query := `
		SELECT id, access_token, created_by, reason, admin_level, ip_restriction,
			   expires_at, used_at, used_by, revoked_at, revoked_by, created_at
		FROM emergency_access WHERE id = $1`

	var access EmergencyAccess
	err := r.db.QueryRow(ctx, query, id).Scan(
		&access.ID, &access.AccessToken, &access.CreatedBy, &access.Reason,
		&access.AdminLevel, &access.IPRestriction, &access.ExpiresAt,
		&access.UsedAt, &access.UsedBy, &access.RevokedAt, &access.RevokedBy,
		&access.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("emergency access not found")
		}
		return nil, errors.Wrap(err, "failed to get emergency access by ID")
	}

	return &access, nil
}

// GetEmergencyAccessByToken retrieves emergency access by token
func (r *repository) GetEmergencyAccessByToken(ctx context.Context, token string) (*EmergencyAccess, error) {
	query := `
		SELECT id, access_token, created_by, reason, admin_level, ip_restriction,
			   expires_at, used_at, used_by, revoked_at, revoked_by, created_at
		FROM emergency_access WHERE access_token = $1`

	var access EmergencyAccess
	err := r.db.QueryRow(ctx, query, token).Scan(
		&access.ID, &access.AccessToken, &access.CreatedBy, &access.Reason,
		&access.AdminLevel, &access.IPRestriction, &access.ExpiresAt,
		&access.UsedAt, &access.UsedBy, &access.RevokedAt, &access.RevokedBy,
		&access.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("emergency access not found")
		}
		return nil, errors.Wrap(err, "failed to get emergency access by token")
	}

	return &access, nil
}

// UpdateEmergencyAccess updates an emergency access entry
func (r *repository) UpdateEmergencyAccess(ctx context.Context, access *EmergencyAccess) error {
	query := `
		UPDATE emergency_access SET
			used_at = $2, used_by = $3, revoked_at = $4, revoked_by = $5
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query,
		access.ID, access.UsedAt, access.UsedBy, access.RevokedAt, access.RevokedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to update emergency access")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("emergency access not found")
	}

	return nil
}

// ListEmergencyAccess retrieves emergency access entries with filtering
func (r *repository) ListEmergencyAccess(ctx context.Context, filter *EmergencyAccessFilter) ([]*EmergencyAccess, error) {
	query := `
		SELECT id, access_token, created_by, reason, admin_level, ip_restriction,
			   expires_at, used_at, used_by, revoked_at, revoked_by, created_at
		FROM emergency_access WHERE 1=1`

	args := []interface{}{}
	argCount := 0

	if filter.CreatedBy != nil {
		argCount++
		query += fmt.Sprintf(" AND created_by = $%d", argCount)
		args = append(args, *filter.CreatedBy)
	}

	if filter.Active != nil {
		if *filter.Active {
			query += " AND expires_at > NOW() AND revoked_at IS NULL"
		} else {
			query += " AND (expires_at <= NOW() OR revoked_at IS NOT NULL)"
		}
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		argCount++
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		argCount++
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list emergency access")
	}
	defer rows.Close()

	var accessList []*EmergencyAccess
	for rows.Next() {
		var access EmergencyAccess
		err := rows.Scan(
			&access.ID, &access.AccessToken, &access.CreatedBy, &access.Reason,
			&access.AdminLevel, &access.IPRestriction, &access.ExpiresAt,
			&access.UsedAt, &access.UsedBy, &access.RevokedAt, &access.RevokedBy,
			&access.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan emergency access")
		}
		accessList = append(accessList, &access)
	}

	return accessList, nil
}

// MFA recovery operations

// CreateMFARecovery creates a new MFA recovery record
func (r *repository) CreateMFARecovery(ctx context.Context, recovery *MFARecovery) error {
	query := `
		INSERT INTO mfa_recovery (
			id, user_id, recovery_code, method, expires_at
		) VALUES ($1, $2, $3, $4, $5)`

	_, err := r.db.Exec(ctx, query,
		recovery.ID, recovery.UserID, recovery.RecoveryCode,
		recovery.Method, recovery.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create MFA recovery")
	}

	return nil
}

// GetMFARecoveryByCode retrieves an MFA recovery by recovery code
func (r *repository) GetMFARecoveryByCode(ctx context.Context, recoveryCode string) (*MFARecovery, error) {
	query := `
		SELECT id, user_id, recovery_code, method, expires_at, used_at, created_at
		FROM mfa_recovery 
		WHERE recovery_code = $1 AND used_at IS NULL`

	var recovery MFARecovery
	err := r.db.QueryRow(ctx, query, recoveryCode).Scan(
		&recovery.ID, &recovery.UserID, &recovery.RecoveryCode,
		&recovery.Method, &recovery.ExpiresAt, &recovery.UsedAt,
		&recovery.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("MFA recovery not found")
		}
		return nil, errors.Wrap(err, "failed to get MFA recovery by code")
	}

	return &recovery, nil
}

// GetMFARecoveryByID retrieves an MFA recovery by ID
func (r *repository) GetMFARecoveryByID(ctx context.Context, id uuid.UUID) (*MFARecovery, error) {
	query := `
		SELECT id, user_id, recovery_code, method, expires_at, used_at, created_at
		FROM mfa_recovery WHERE id = $1`

	var recovery MFARecovery
	err := r.db.QueryRow(ctx, query, id).Scan(
		&recovery.ID, &recovery.UserID, &recovery.RecoveryCode,
		&recovery.Method, &recovery.ExpiresAt, &recovery.UsedAt,
		&recovery.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NewNotFound("MFA recovery not found")
		}
		return nil, errors.Wrap(err, "failed to get MFA recovery by ID")
	}

	return &recovery, nil
}

// UpdateMFARecovery updates an MFA recovery record
func (r *repository) UpdateMFARecovery(ctx context.Context, recovery *MFARecovery) error {
	query := `
		UPDATE mfa_recovery SET
			used_at = $2
		WHERE id = $1`

	result, err := r.db.Exec(ctx, query, recovery.ID, recovery.UsedAt)
	if err != nil {
		return errors.Wrap(err, "failed to update MFA recovery")
	}

	if result.RowsAffected() == 0 {
		return errors.NewNotFound("MFA recovery not found")
	}

	return nil
}

// ListMFARecovery retrieves MFA recovery records for a user
func (r *repository) ListMFARecovery(ctx context.Context, userID uuid.UUID) ([]*MFARecovery, error) {
	query := `
		SELECT id, user_id, recovery_code, method, expires_at, used_at, created_at
		FROM mfa_recovery 
		WHERE user_id = $1 
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list MFA recovery")
	}
	defer rows.Close()

	var recoveries []*MFARecovery
	for rows.Next() {
		var recovery MFARecovery
		err := rows.Scan(
			&recovery.ID, &recovery.UserID, &recovery.RecoveryCode,
			&recovery.Method, &recovery.ExpiresAt, &recovery.UsedAt,
			&recovery.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan MFA recovery")
		}
		recoveries = append(recoveries, &recovery)
	}

	return recoveries, nil
}
