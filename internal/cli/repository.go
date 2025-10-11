package cli

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// JSONMap is a helper type for scanning JSON fields
type JSONMap map[string]interface{}

// Scan implements the sql.Scanner interface
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(map[string]interface{})
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("cannot scan %T into JSONMap", value)
	}

	if len(bytes) == 0 {
		*j = make(map[string]interface{})
		return nil
	}

	return json.Unmarshal(bytes, j)
}

// Value implements the driver.Valuer interface
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// cliRepository implements a simplified repository for CLI operations using database/sql
type cliRepository struct {
	db *sql.DB
}

// NewCLIRepository creates a new CLI repository
func NewCLIRepository(db *sql.DB) auth.Repository {
	return &cliRepository{db: db}
}

// GetUserByID retrieves a user by ID
func (r *cliRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*auth.UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE id = $1`

	var user auth.UnifiedUser
	var metadata JSONMap
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err == nil {
		user.Metadata = map[string]interface{}(metadata)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by ID")
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (r *cliRepository) GetUserByEmail(ctx context.Context, email string) (*auth.UnifiedUser, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified,
			   admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			   last_login, failed_attempts, locked_until, metadata, created_at, updated_at,
			   created_by, updated_by
		FROM users WHERE email = $1`

	var user auth.UnifiedUser
	var metadata JSONMap
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.Phone, &user.Username, &user.PasswordHash,
		&user.EmailVerified, &user.PhoneVerified, &user.AdminLevel, &user.Capabilities,
		pq.Array(&user.AssignedTables), &user.MFAEnabled, &user.MFASecret,
		pq.Array(&user.BackupCodes), &user.LastLogin, &user.FailedAttempts,
		&user.LockedUntil, &metadata, &user.CreatedAt, &user.UpdatedAt,
		&user.CreatedBy, &user.UpdatedBy,
	)

	if err == nil {
		user.Metadata = map[string]interface{}(metadata)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFound("user not found")
		}
		return nil, errors.Wrap(err, "failed to get user by email")
	}

	return &user, nil
}

// CreateUser creates a new user in the database
func (r *cliRepository) CreateUser(ctx context.Context, user *auth.UnifiedUser) error {
	query := `
		INSERT INTO users (
			id, email, phone, username, password_hash, email_verified, phone_verified,
			admin_level, capabilities, assigned_tables, mfa_enabled, mfa_secret, backup_codes,
			metadata, created_by, updated_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)`

	metadata := JSONMap(user.Metadata)
	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.Phone, user.Username, user.PasswordHash,
		user.EmailVerified, user.PhoneVerified, user.AdminLevel, user.Capabilities,
		pq.Array(user.AssignedTables), user.MFAEnabled, user.MFASecret,
		pq.Array(user.BackupCodes), metadata, user.CreatedBy, user.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create user")
	}

	return nil
}

// UpdateUser updates an existing user
func (r *cliRepository) UpdateUser(ctx context.Context, user *auth.UnifiedUser) error {
	query := `
		UPDATE users SET
			email = $2, phone = $3, username = $4, password_hash = $5,
			email_verified = $6, phone_verified = $7, admin_level = $8,
			capabilities = $9, assigned_tables = $10, mfa_enabled = $11,
			mfa_secret = $12, backup_codes = $13, last_login = $14,
			failed_attempts = $15, locked_until = $16, metadata = $17,
			updated_by = $18, updated_at = NOW()
		WHERE id = $1`

	metadata := JSONMap(user.Metadata)
	result, err := r.db.ExecContext(ctx, query,
		user.ID, user.Email, user.Phone, user.Username, user.PasswordHash,
		user.EmailVerified, user.PhoneVerified, user.AdminLevel, user.Capabilities,
		pq.Array(user.AssignedTables), user.MFAEnabled, user.MFASecret,
		pq.Array(user.BackupCodes), user.LastLogin, user.FailedAttempts,
		user.LockedUntil, metadata, user.UpdatedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to update user")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}

	if rowsAffected == 0 {
		return errors.NewNotFound("user not found")
	}

	return nil
}

// ListAdmins retrieves admin users with filtering
func (r *cliRepository) ListAdmins(ctx context.Context, filter *auth.AdminFilter) ([]*auth.UnifiedUser, error) {
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

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list admins")
	}
	defer rows.Close()

	var admins []*auth.UnifiedUser
	for rows.Next() {
		var admin auth.UnifiedUser
		var metadata JSONMap
		err := rows.Scan(
			&admin.ID, &admin.Email, &admin.Phone, &admin.Username, &admin.PasswordHash,
			&admin.EmailVerified, &admin.PhoneVerified, &admin.AdminLevel, &admin.Capabilities,
			pq.Array(&admin.AssignedTables), &admin.MFAEnabled, &admin.MFASecret,
			pq.Array(&admin.BackupCodes), &admin.LastLogin, &admin.FailedAttempts,
			&admin.LockedUntil, &metadata, &admin.CreatedAt, &admin.UpdatedAt,
			&admin.CreatedBy, &admin.UpdatedBy,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan admin")
		}
		admin.Metadata = map[string]interface{}(metadata)
		admins = append(admins, &admin)
	}

	return admins, nil
}

// CreateEmergencyAccess creates a new emergency access entry
func (r *cliRepository) CreateEmergencyAccess(ctx context.Context, access *auth.EmergencyAccess) error {
	query := `
		INSERT INTO emergency_access (
			id, access_token, created_by, reason, admin_level, ip_restriction, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := r.db.ExecContext(ctx, query,
		access.ID, access.AccessToken, access.CreatedBy, access.Reason,
		access.AdminLevel, access.IPRestriction, access.ExpiresAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create emergency access")
	}

	return nil
}

// GetEmergencyAccessByID retrieves emergency access by ID
func (r *cliRepository) GetEmergencyAccessByID(ctx context.Context, id uuid.UUID) (*auth.EmergencyAccess, error) {
	query := `
		SELECT id, access_token, created_by, reason, admin_level, ip_restriction,
			   expires_at, used_at, used_by, revoked_at, revoked_by, created_at
		FROM emergency_access WHERE id = $1`

	var access auth.EmergencyAccess
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&access.ID, &access.AccessToken, &access.CreatedBy, &access.Reason,
		&access.AdminLevel, &access.IPRestriction, &access.ExpiresAt,
		&access.UsedAt, &access.UsedBy, &access.RevokedAt, &access.RevokedBy,
		&access.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.NewNotFound("emergency access not found")
		}
		return nil, errors.Wrap(err, "failed to get emergency access by ID")
	}

	return &access, nil
}

// UpdateEmergencyAccess updates an emergency access entry
func (r *cliRepository) UpdateEmergencyAccess(ctx context.Context, access *auth.EmergencyAccess) error {
	query := `
		UPDATE emergency_access SET
			used_at = $2, used_by = $3, revoked_at = $4, revoked_by = $5
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query,
		access.ID, access.UsedAt, access.UsedBy, access.RevokedAt, access.RevokedBy,
	)

	if err != nil {
		return errors.Wrap(err, "failed to update emergency access")
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrap(err, "failed to get rows affected")
	}

	if rowsAffected == 0 {
		return errors.NewNotFound("emergency access not found")
	}

	return nil
}

// ListEmergencyAccess retrieves emergency access entries with filtering
func (r *cliRepository) ListEmergencyAccess(ctx context.Context, filter *auth.EmergencyAccessFilter) ([]*auth.EmergencyAccess, error) {
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

	if filter.Active != nil && *filter.Active {
		query += " AND revoked_at IS NULL AND expires_at > NOW()"
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

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list emergency access")
	}
	defer rows.Close()

	var accessEntries []*auth.EmergencyAccess
	for rows.Next() {
		var access auth.EmergencyAccess
		err := rows.Scan(
			&access.ID, &access.AccessToken, &access.CreatedBy, &access.Reason,
			&access.AdminLevel, &access.IPRestriction, &access.ExpiresAt,
			&access.UsedAt, &access.UsedBy, &access.RevokedAt, &access.RevokedBy,
			&access.CreatedAt,
		)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan emergency access")
		}
		accessEntries = append(accessEntries, &access)
	}

	return accessEntries, nil
}

// Stub implementations for other Repository methods (not needed for CLI)

func (r *cliRepository) GetUserByPhone(ctx context.Context, phone string) (*auth.UnifiedUser, error) {
	return nil, errors.NewNotImplemented("GetUserByPhone not implemented for CLI")
}

func (r *cliRepository) GetUserByUsername(ctx context.Context, username string) (*auth.UnifiedUser, error) {
	return nil, errors.NewNotImplemented("GetUserByUsername not implemented for CLI")
}

func (r *cliRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return errors.NewNotImplemented("DeleteUser not implemented for CLI")
}

func (r *cliRepository) ListUsers(ctx context.Context, filter *auth.UserFilter) ([]*auth.UnifiedUser, error) {
	return nil, errors.NewNotImplemented("ListUsers not implemented for CLI")
}

func (r *cliRepository) PromoteToAdmin(ctx context.Context, userID uuid.UUID, level auth.AdminLevel, capabilities *auth.AdminCapabilities, promotedBy uuid.UUID) error {
	return errors.NewNotImplemented("PromoteToAdmin not implemented for CLI")
}

func (r *cliRepository) DemoteAdmin(ctx context.Context, userID uuid.UUID, demotedBy uuid.UUID) error {
	return errors.NewNotImplemented("DemoteAdmin not implemented for CLI")
}

func (r *cliRepository) CreateSession(ctx context.Context, session *auth.AdminSession) error {
	return errors.NewNotImplemented("CreateSession not implemented for CLI")
}

func (r *cliRepository) GetSessionByToken(ctx context.Context, token string) (*auth.AdminSession, error) {
	return nil, errors.NewNotImplemented("GetSessionByToken not implemented for CLI")
}

func (r *cliRepository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	return errors.NewNotImplemented("UpdateSessionActivity not implemented for CLI")
}

func (r *cliRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	return errors.NewNotImplemented("DeleteSession not implemented for CLI")
}

func (r *cliRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	return errors.NewNotImplemented("DeleteUserSessions not implemented for CLI")
}

func (r *cliRepository) CleanExpiredSessions(ctx context.Context) error {
	return errors.NewNotImplemented("CleanExpiredSessions not implemented for CLI")
}

func (r *cliRepository) CreateAPIKey(ctx context.Context, apiKey *auth.APIKey) error {
	return errors.NewNotImplemented("CreateAPIKey not implemented for CLI")
}

func (r *cliRepository) GetAPIKeyByHash(ctx context.Context, keyHash string) (*auth.APIKey, error) {
	return nil, errors.NewNotImplemented("GetAPIKeyByHash not implemented for CLI")
}

func (r *cliRepository) ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]*auth.APIKey, error) {
	return nil, errors.NewNotImplemented("ListAPIKeys not implemented for CLI")
}

func (r *cliRepository) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return errors.NewNotImplemented("UpdateAPIKeyLastUsed not implemented for CLI")
}

func (r *cliRepository) DeleteAPIKey(ctx context.Context, id uuid.UUID) error {
	return errors.NewNotImplemented("DeleteAPIKey not implemented for CLI")
}

func (r *cliRepository) CreateOTP(ctx context.Context, otp *auth.OTPCode) error {
	return errors.NewNotImplemented("CreateOTP not implemented for CLI")
}

func (r *cliRepository) GetOTPByCode(ctx context.Context, code string, purpose string) (*auth.OTPCode, error) {
	return nil, errors.NewNotImplemented("GetOTPByCode not implemented for CLI")
}

func (r *cliRepository) GetOTPByIdentifier(ctx context.Context, identifier string, purpose string) (*auth.OTPCode, error) {
	return nil, errors.NewNotImplemented("GetOTPByIdentifier not implemented for CLI")
}

func (r *cliRepository) UpdateOTPAttempts(ctx context.Context, id uuid.UUID, attempts int) error {
	return errors.NewNotImplemented("UpdateOTPAttempts not implemented for CLI")
}

func (r *cliRepository) MarkOTPUsed(ctx context.Context, id uuid.UUID) error {
	return errors.NewNotImplemented("MarkOTPUsed not implemented for CLI")
}

func (r *cliRepository) InvalidateOTPsByIdentifier(ctx context.Context, identifier string, purpose string) error {
	return errors.NewNotImplemented("InvalidateOTPsByIdentifier not implemented for CLI")
}

func (r *cliRepository) CleanExpiredOTPs(ctx context.Context) error {
	return errors.NewNotImplemented("CleanExpiredOTPs not implemented for CLI")
}

func (r *cliRepository) CreateTemplate(ctx context.Context, template *auth.Template) error {
	return errors.NewNotImplemented("CreateTemplate not implemented for CLI")
}

func (r *cliRepository) GetTemplate(ctx context.Context, templateType auth.TemplateType, purpose string, language string) (*auth.Template, error) {
	return nil, errors.NewNotImplemented("GetTemplate not implemented for CLI")
}

func (r *cliRepository) UpdateTemplate(ctx context.Context, template *auth.Template) error {
	return errors.NewNotImplemented("UpdateTemplate not implemented for CLI")
}

func (r *cliRepository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	return errors.NewNotImplemented("DeleteTemplate not implemented for CLI")
}

func (r *cliRepository) ListTemplates(ctx context.Context, filter *auth.TemplateFilter) ([]*auth.Template, error) {
	return nil, errors.NewNotImplemented("ListTemplates not implemented for CLI")
}

func (r *cliRepository) CreateAuditLog(ctx context.Context, log *auth.AuditLog) error {
	return errors.NewNotImplemented("CreateAuditLog not implemented for CLI")
}

func (r *cliRepository) ListAuditLogs(ctx context.Context, filter *auth.AuditFilter) ([]*auth.AuditLog, error) {
	return nil, errors.NewNotImplemented("ListAuditLogs not implemented for CLI")
}

func (r *cliRepository) CreateSecurityEvent(ctx context.Context, event *auth.SecurityEvent) error {
	return errors.NewNotImplemented("CreateSecurityEvent not implemented for CLI")
}

func (r *cliRepository) ListSecurityEvents(ctx context.Context, filter *auth.SecurityEventFilter) ([]*auth.SecurityEvent, error) {
	return nil, errors.NewNotImplemented("ListSecurityEvents not implemented for CLI")
}

func (r *cliRepository) ResolveSecurityEvent(ctx context.Context, id uuid.UUID, resolvedBy uuid.UUID) error {
	return errors.NewNotImplemented("ResolveSecurityEvent not implemented for CLI")
}

func (r *cliRepository) GetRateLimit(ctx context.Context, key string) (*auth.RateLimit, error) {
	return nil, errors.NewNotImplemented("GetRateLimit not implemented for CLI")
}

func (r *cliRepository) UpsertRateLimit(ctx context.Context, rateLimit *auth.RateLimit) error {
	return errors.NewNotImplemented("UpsertRateLimit not implemented for CLI")
}

func (r *cliRepository) CleanExpiredRateLimits(ctx context.Context) error {
	return errors.NewNotImplemented("CleanExpiredRateLimits not implemented for CLI")
}

func (r *cliRepository) CreateMFARecovery(ctx context.Context, recovery *auth.MFARecovery) error {
	return errors.NewNotImplemented("CreateMFARecovery not implemented for CLI")
}

func (r *cliRepository) GetMFARecoveryByCode(ctx context.Context, recoveryCode string) (*auth.MFARecovery, error) {
	return nil, errors.NewNotImplemented("GetMFARecoveryByCode not implemented for CLI")
}

func (r *cliRepository) GetMFARecoveryByID(ctx context.Context, id uuid.UUID) (*auth.MFARecovery, error) {
	return nil, errors.NewNotImplemented("GetMFARecoveryByID not implemented for CLI")
}

func (r *cliRepository) UpdateMFARecovery(ctx context.Context, recovery *auth.MFARecovery) error {
	return errors.NewNotImplemented("UpdateMFARecovery not implemented for CLI")
}

func (r *cliRepository) ListMFARecovery(ctx context.Context, userID uuid.UUID) ([]*auth.MFARecovery, error) {
	return nil, errors.NewNotImplemented("ListMFARecovery not implemented for CLI")
}

func (r *cliRepository) GetEmergencyAccessByToken(ctx context.Context, token string) (*auth.EmergencyAccess, error) {
	return nil, errors.NewNotImplemented("GetEmergencyAccessByToken not implemented for CLI")
}
