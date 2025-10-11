package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// UserRepository handles user database operations
type UserRepository struct {
	db *database.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *database.DB) *UserRepository {
	return &UserRepository{
		db: db,
	}
}

// Create creates a new user in the database
func (r *UserRepository) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	// Convert metadata to JSON
	metadataJSON, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	err = r.db.Exec(ctx, query,
		user.ID,
		user.Email,
		user.Phone,
		user.Username,
		user.PasswordHash,
		user.EmailVerified,
		user.PhoneVerified,
		metadataJSON,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// GetByPhone retrieves a user by phone
func (r *UserRepository) GetByPhone(ctx context.Context, phone string) (*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
		WHERE phone = $1
	`

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, phone).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
		WHERE username = $1
	`

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, username).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// GetByIdentifier retrieves a user by email, phone, or username
func (r *UserRepository) GetByIdentifier(ctx context.Context, identifier string) (*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
		WHERE email = $1 OR phone = $1 OR username = $1
	`

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, identifier).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// Update updates a user in the database
func (r *UserRepository) Update(ctx context.Context, id string, updates *UpdateUserRequest) (*User, error) {
	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}
	argIndex := 1

	if updates.Email != nil {
		setParts = append(setParts, fmt.Sprintf("email = $%d", argIndex))
		args = append(args, updates.Email)
		argIndex++
	}

	if updates.Phone != nil {
		setParts = append(setParts, fmt.Sprintf("phone = $%d", argIndex))
		args = append(args, updates.Phone)
		argIndex++
	}

	if updates.Username != nil {
		setParts = append(setParts, fmt.Sprintf("username = $%d", argIndex))
		args = append(args, updates.Username)
		argIndex++
	}

	if updates.EmailVerified != nil {
		setParts = append(setParts, fmt.Sprintf("email_verified = $%d", argIndex))
		args = append(args, *updates.EmailVerified)
		argIndex++
	}

	if updates.PhoneVerified != nil {
		setParts = append(setParts, fmt.Sprintf("phone_verified = $%d", argIndex))
		args = append(args, *updates.PhoneVerified)
		argIndex++
	}

	if updates.Metadata != nil {
		metadataJSON, err := json.Marshal(updates.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		setParts = append(setParts, fmt.Sprintf("metadata = $%d", argIndex))
		args = append(args, metadataJSON)
		argIndex++
	}

	if len(setParts) == 0 {
		return r.GetByID(ctx, id) // No updates, return current user
	}

	// Add updated_at
	setParts = append(setParts, "updated_at = NOW()")

	// Add WHERE clause
	args = append(args, id)
	whereClause := fmt.Sprintf("WHERE id = $%d", argIndex)

	query := fmt.Sprintf(`
		UPDATE users 
		SET %s 
		%s
		RETURNING id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
	`, strings.Join(setParts, ", "), whereClause)

	user := &User{}
	var metadataJSON []byte

	err := r.db.QueryRow(ctx, query, args...).Scan(
		&user.ID,
		&user.Email,
		&user.Phone,
		&user.Username,
		&user.PasswordHash,
		&user.EmailVerified,
		&user.PhoneVerified,
		&metadataJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Unmarshal metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return user, nil
}

// Delete deletes a user from the database
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.Pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// List retrieves users with optional filtering
func (r *UserRepository) List(ctx context.Context, filter *UserFilter) ([]*User, error) {
	query := `
		SELECT id, email, phone, username, password_hash, email_verified, phone_verified, metadata, created_at, updated_at
		FROM users
	`

	whereParts := []string{}
	args := []interface{}{}
	argIndex := 1

	if filter != nil {
		if filter.Email != nil {
			whereParts = append(whereParts, fmt.Sprintf("email = $%d", argIndex))
			args = append(args, *filter.Email)
			argIndex++
		}

		if filter.Phone != nil {
			whereParts = append(whereParts, fmt.Sprintf("phone = $%d", argIndex))
			args = append(args, *filter.Phone)
			argIndex++
		}

		if filter.Username != nil {
			whereParts = append(whereParts, fmt.Sprintf("username = $%d", argIndex))
			args = append(args, *filter.Username)
			argIndex++
		}

		if filter.EmailVerified != nil {
			whereParts = append(whereParts, fmt.Sprintf("email_verified = $%d", argIndex))
			args = append(args, *filter.EmailVerified)
			argIndex++
		}

		if filter.PhoneVerified != nil {
			whereParts = append(whereParts, fmt.Sprintf("phone_verified = $%d", argIndex))
			args = append(args, *filter.PhoneVerified)
			argIndex++
		}
	}

	if len(whereParts) > 0 {
		query += " WHERE " + strings.Join(whereParts, " AND ")
	}

	query += " ORDER BY created_at DESC"

	if filter != nil {
		if filter.Limit > 0 {
			query += fmt.Sprintf(" LIMIT $%d", argIndex)
			args = append(args, filter.Limit)
			argIndex++
		}

		if filter.Offset > 0 {
			query += fmt.Sprintf(" OFFSET $%d", argIndex)
			args = append(args, filter.Offset)
		}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var metadataJSON []byte

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Phone,
			&user.Username,
			&user.PasswordHash,
			&user.EmailVerified,
			&user.PhoneVerified,
			&metadataJSON,
			&user.CreatedAt,
			&user.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}

		// Unmarshal metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &user.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, nil
}

// Exists checks if a user exists with the given identifier
func (r *UserRepository) Exists(ctx context.Context, identifier string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM users 
			WHERE email = $1 OR phone = $1 OR username = $1
		)
	`

	var exists bool
	err := r.db.QueryRow(ctx, query, identifier).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return exists, nil
}

// CreatePasswordResetToken creates a new password reset token
func (r *UserRepository) CreatePasswordResetToken(ctx context.Context, token *PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (id, user_id, token, expires_at, used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	err := r.db.Exec(ctx, query,
		token.ID,
		token.UserID,
		token.Token,
		token.ExpiresAt,
		token.Used,
		token.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create password reset token: %w", err)
	}

	return nil
}

// GetPasswordResetToken retrieves a password reset token by token string
func (r *UserRepository) GetPasswordResetToken(ctx context.Context, token string) (*PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used, created_at
		FROM password_reset_tokens
		WHERE token = $1 AND used = false AND expires_at > NOW()
	`

	resetToken := &PasswordResetToken{}

	err := r.db.QueryRow(ctx, query, token).Scan(
		&resetToken.ID,
		&resetToken.UserID,
		&resetToken.Token,
		&resetToken.ExpiresAt,
		&resetToken.Used,
		&resetToken.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("password reset token not found or expired")
		}
		return nil, fmt.Errorf("failed to get password reset token: %w", err)
	}

	return resetToken, nil
}

// MarkPasswordResetTokenUsed marks a password reset token as used
func (r *UserRepository) MarkPasswordResetTokenUsed(ctx context.Context, tokenID string) error {
	query := `UPDATE password_reset_tokens SET used = true WHERE id = $1`

	err := r.db.Exec(ctx, query, tokenID)
	if err != nil {
		return fmt.Errorf("failed to mark password reset token as used: %w", err)
	}

	return nil
}

// CleanupExpiredPasswordResetTokens removes expired password reset tokens
func (r *UserRepository) CleanupExpiredPasswordResetTokens(ctx context.Context) error {
	query := `DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = true`

	err := r.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired password reset tokens: %w", err)
	}

	return nil
}

// UpdatePassword updates a user's password hash
func (r *UserRepository) UpdatePassword(ctx context.Context, id string, hashedPassword string) error {
	query := `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2`

	err := r.db.Exec(ctx, query, hashedPassword, id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// CreateOTP creates a new OTP in the database
func (r *UserRepository) CreateOTP(ctx context.Context, otp *OTP) error {
	query := `
		INSERT INTO otps (id, user_id, code_hash, type, purpose, recipient, expires_at, used, attempts, max_attempts, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	err := r.db.Exec(ctx, query,
		otp.ID,
		otp.UserID,
		otp.CodeHash, // Store hash instead of plain text
		string(otp.Type),
		string(otp.Purpose),
		otp.Recipient,
		otp.ExpiresAt,
		otp.Used,
		otp.Attempts,
		otp.MaxAttempts,
		otp.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create OTP: %w", err)
	}

	return nil
}

// GetOTP retrieves an OTP by recipient, type, and code
func (r *UserRepository) GetOTP(ctx context.Context, recipient string, otpType OTPType, code string) (*OTP, error) {
	query := `
		SELECT id, user_id, code, type, recipient, expires_at, used, attempts, max_attempts, created_at
		FROM otps
		WHERE recipient = $1 AND type = $2 AND code = $3 AND used = false
		ORDER BY created_at DESC
		LIMIT 1
	`

	otp := &OTP{}
	var otpTypeStr string

	err := r.db.QueryRow(ctx, query, recipient, string(otpType), code).Scan(
		&otp.ID,
		&otp.UserID,
		&otp.Code,
		&otpTypeStr,
		&otp.Recipient,
		&otp.ExpiresAt,
		&otp.Used,
		&otp.Attempts,
		&otp.MaxAttempts,
		&otp.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("OTP not found")
		}
		return nil, fmt.Errorf("failed to get OTP: %w", err)
	}

	otp.Type = OTPType(otpTypeStr)
	return otp, nil
}

// GetLatestOTP retrieves the latest OTP for a recipient and type
func (r *UserRepository) GetLatestOTP(ctx context.Context, recipient string, otpType OTPType) (*OTP, error) {
	query := `
		SELECT id, user_id, code, type, recipient, expires_at, used, attempts, max_attempts, created_at
		FROM otps
		WHERE recipient = $1 AND type = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	otp := &OTP{}
	var otpTypeStr string

	err := r.db.QueryRow(ctx, query, recipient, string(otpType)).Scan(
		&otp.ID,
		&otp.UserID,
		&otp.Code,
		&otpTypeStr,
		&otp.Recipient,
		&otp.ExpiresAt,
		&otp.Used,
		&otp.Attempts,
		&otp.MaxAttempts,
		&otp.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("OTP not found")
		}
		return nil, fmt.Errorf("failed to get latest OTP: %w", err)
	}

	otp.Type = OTPType(otpTypeStr)
	return otp, nil
}

// MarkOTPUsed marks an OTP as used
func (r *UserRepository) MarkOTPUsed(ctx context.Context, otpID string) error {
	query := `UPDATE otps SET used = true WHERE id = $1`

	err := r.db.Exec(ctx, query, otpID)
	if err != nil {
		return fmt.Errorf("failed to mark OTP as used: %w", err)
	}

	return nil
}

// IncrementOTPAttempts increments the attempt count for an OTP
func (r *UserRepository) IncrementOTPAttempts(ctx context.Context, otpID string) error {
	query := `UPDATE otps SET attempts = attempts + 1 WHERE id = $1`

	err := r.db.Exec(ctx, query, otpID)
	if err != nil {
		return fmt.Errorf("failed to increment OTP attempts: %w", err)
	}

	return nil
}

// CleanupExpiredOTPs removes expired OTPs
func (r *UserRepository) CleanupExpiredOTPs(ctx context.Context) error {
	query := `DELETE FROM otps WHERE expires_at < NOW() OR used = true`

	err := r.db.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired OTPs: %w", err)
	}

	return nil
}

// GetLatestOTPWithPurpose retrieves the latest OTP for a recipient, type, and purpose
func (r *UserRepository) GetLatestOTPWithPurpose(ctx context.Context, recipient string, otpType OTPType, purpose OTPPurpose) (*OTP, error) {
	query := `
		SELECT id, user_id, code_hash, type, purpose, recipient, expires_at, used, attempts, max_attempts, created_at
		FROM otps
		WHERE recipient = $1 AND type = $2 AND purpose = $3
		ORDER BY created_at DESC
		LIMIT 1
	`

	otp := &OTP{}
	var otpTypeStr, purposeStr string

	err := r.db.QueryRow(ctx, query, recipient, string(otpType), string(purpose)).Scan(
		&otp.ID,
		&otp.UserID,
		&otp.CodeHash, // Retrieve hash instead of plain text
		&otpTypeStr,
		&purposeStr,
		&otp.Recipient,
		&otp.ExpiresAt,
		&otp.Used,
		&otp.Attempts,
		&otp.MaxAttempts,
		&otp.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("OTP not found")
		}
		return nil, fmt.Errorf("failed to get latest OTP with purpose: %w", err)
	}

	otp.Type = OTPType(otpTypeStr)
	otp.Purpose = OTPPurpose(purposeStr)
	return otp, nil
}
