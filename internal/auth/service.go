package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// AuthService defines the authentication service interface
type AuthService interface {
	// Standard authentication
	Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error)
	Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error)
	LoginWithCookies(ctx context.Context, req *LoginRequest) (*AuthResponse, *http.Cookie, *http.Cookie, error)
	RefreshToken(ctx context.Context, token string) (*AuthResponse, error)
	Logout(ctx context.Context, sessionID uuid.UUID) error

	// OTP authentication
	SendOTP(ctx context.Context, req *OTPRequest) error
	VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error)

	// Admin authentication
	AuthenticateAdmin(ctx context.Context, req *AdminAuthRequest) (*AdminAuthResponse, error)
	CreateSystemAdmin(ctx context.Context, req *CreateSystemAdminRequest) (*UnifiedUser, error)
	PromoteToAdmin(ctx context.Context, userID uuid.UUID, level AdminLevel, promotedBy uuid.UUID) error

	// Session management
	CreateAdminSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*AdminSession, error)
	ValidateSession(ctx context.Context, sessionToken string) (*AdminSession, *UnifiedUser, error)

	// Password management
	ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error
	ResetPassword(ctx context.Context, req *ResetPasswordRequest) error

	// Account security
	LockAccount(ctx context.Context, userID uuid.UUID, reason string) error
	UnlockAccount(ctx context.Context, userID uuid.UUID, unlockedBy uuid.UUID) error

	// Validation
	ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error)
	ValidatePassword(password string) error
}

// Request/Response types
type RegisterRequest struct {
	Email    *string `json:"email"`
	Phone    *string `json:"phone"`
	Username *string `json:"username"`
	Password string  `json:"password"`
}

type LoginRequest struct {
	Identifier string `json:"identifier"` // email, phone, or username
	Password   string `json:"password"`
}

type OTPRequest struct {
	Identifier string `json:"identifier"` // email or phone
	Purpose    string `json:"purpose"`    // login, registration, verification, password_reset
}

type VerifyOTPRequest struct {
	Identifier string `json:"identifier"`
	Code       string `json:"code"`
	Purpose    string `json:"purpose"`
}

type AdminAuthRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	MFACode    string `json:"mfa_code,omitempty"`
}

type CreateSystemAdminRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username,omitempty"`
}

type ResetPasswordRequest struct {
	Identifier  string `json:"identifier"`
	OTPCode     string `json:"otp_code"`
	NewPassword string `json:"new_password"`
}

type AuthResponse struct {
	User         *UnifiedUser `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

type AdminAuthResponse struct {
	User         *UnifiedUser  `json:"user"`
	Session      *AdminSession `json:"session"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	ExpiresAt    time.Time     `json:"expires_at"`
}

// JWT Claims
type JWTClaims struct {
	UserID     uuid.UUID   `json:"user_id"`
	Email      string      `json:"email,omitempty"`
	AdminLevel *AdminLevel `json:"admin_level,omitempty"`
	SessionID  *uuid.UUID  `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

// authService implements the AuthService interface
type authService struct {
	repo   Repository
	config *config.Config
}

// NewAuthService creates a new authentication service
func NewAuthService(repo Repository, cfg *config.Config) AuthService {
	return &authService{
		repo:   repo,
		config: cfg,
	}
}

// Register creates a new user account
func (s *authService) Register(ctx context.Context, req *RegisterRequest) (*AuthResponse, error) {
	// Validate input
	if req.Email == nil && req.Phone == nil && req.Username == nil {
		return nil, errors.NewAuthError("at least one identifier (email, phone, or username) is required")
	}

	if err := s.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Check for existing users
	if req.Email != nil {
		if existing, _ := s.repo.GetUserByEmail(ctx, *req.Email); existing != nil {
			return nil, errors.NewAuthError("email already registered")
		}
	}

	if req.Phone != nil {
		if existing, _ := s.repo.GetUserByPhone(ctx, *req.Phone); existing != nil {
			return nil, errors.NewAuthError("phone number already registered")
		}
	}

	if req.Username != nil {
		if existing, _ := s.repo.GetUserByUsername(ctx, *req.Username); existing != nil {
			return nil, errors.NewAuthError("username already taken")
		}
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash password")
	}

	// Create user
	user := &UnifiedUser{
		ID:           uuid.New(),
		Email:        req.Email,
		Phone:        req.Phone,
		Username:     req.Username,
		PasswordHash: hashedPassword,
		Metadata:     make(map[string]any),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to create user")
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := s.generateTokens(user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate tokens")
	}

	// Create audit log
	s.createAuditLog(ctx, user.ID, AuditActions.UserCreate, "users", user.ID.String(), true, nil)

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// Login authenticates a user with credentials
func (s *authService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	// Find user by identifier
	user, err := s.findUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		s.createSecurityEvent(ctx, nil, SecurityEventTypes.LoginFailure, req.Identifier, "user not found")
		return nil, errors.NewAuthError("invalid credentials")
	}

	// Check if account is locked
	if user.IsLocked() {
		s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.LoginFailure, req.Identifier, "account locked")
		return nil, errors.NewAuthError("account is locked")
	}

	// Verify password
	if !s.verifyPassword(req.Password, user.PasswordHash) {
		// Increment failed attempts
		user.FailedAttempts++
		if user.FailedAttempts >= s.config.Auth.MaxFailedAttempts {
			lockUntil := time.Now().Add(s.config.Auth.LockoutDuration)
			user.LockedUntil = &lockUntil
			s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.AccountLockout, req.Identifier, "max failed attempts reached")
		}

		s.repo.UpdateUser(ctx, user)
		s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.LoginFailure, req.Identifier, "invalid password")
		return nil, errors.NewAuthError("invalid credentials")
	}

	// Reset failed attempts on successful login
	user.FailedAttempts = 0
	user.LockedUntil = nil
	now := time.Now().UTC()
	user.LastLogin = &now
	user.UpdatedAt = now

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to update user login info")
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := s.generateTokens(user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate tokens")
	}

	// Create audit log
	s.createAuditLog(ctx, user.ID, AuditActions.Login, "users", user.ID.String(), true, nil)
	s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.LoginSuccess, req.Identifier, "successful login")

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// LoginWithCookies authenticates a user and returns HTTP-only cookies
func (s *authService) LoginWithCookies(ctx context.Context, req *LoginRequest) (*AuthResponse, *http.Cookie, *http.Cookie, error) {
	// Perform standard login
	authResp, err := s.Login(ctx, req)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create HTTP-only cookies
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    authResp.AccessToken,
		Path:     "/",
		HttpOnly: s.config.Auth.CookieHTTPOnly,
		Secure:   s.config.Auth.CookieSecure,
		SameSite: s.getSameSiteAttribute(),
		Expires:  authResp.ExpiresAt,
	}

	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    authResp.RefreshToken,
		Path:     "/",
		HttpOnly: s.config.Auth.CookieHTTPOnly,
		Secure:   s.config.Auth.CookieSecure,
		SameSite: s.getSameSiteAttribute(),
		Expires:  time.Now().Add(s.config.Auth.RefreshExpiration),
	}

	return authResp, accessCookie, refreshCookie, nil
}

// RefreshToken generates new tokens using a refresh token
func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Parse and validate refresh token
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.NewAuthError("invalid refresh token")
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return nil, errors.NewAuthError("user not found")
	}

	// Check if account is locked
	if user.IsLocked() {
		return nil, errors.NewAuthError("account is locked")
	}

	// Generate new tokens
	accessToken, newRefreshToken, expiresAt, err := s.generateTokens(user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate tokens")
	}

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// Logout invalidates a user session
func (s *authService) Logout(ctx context.Context, sessionID uuid.UUID) error {
	if err := s.repo.DeleteSession(ctx, sessionID); err != nil {
		return errors.Wrap(err, "failed to delete session")
	}

	return nil
}

// SendOTP generates and sends an OTP code
func (s *authService) SendOTP(ctx context.Context, req *OTPRequest) error {
	// Generate OTP code
	code, err := s.generateOTPCode()
	if err != nil {
		return errors.Wrap(err, "failed to generate OTP code")
	}

	// Determine if identifier is email or phone
	var email, phone *string
	if strings.Contains(req.Identifier, "@") {
		email = &req.Identifier
	} else {
		phone = &req.Identifier
	}

	// Create OTP record
	otp := &OTPCode{
		ID:          uuid.New(),
		Email:       email,
		Phone:       phone,
		Code:        code,
		Purpose:     req.Purpose,
		MaxAttempts: 3,
		ExpiresAt:   time.Now().Add(s.config.Auth.OTPExpiration),
		CreatedAt:   time.Now().UTC(),
	}

	// Try to find existing user for audit purposes
	var userID *uuid.UUID
	if email != nil {
		if user, _ := s.repo.GetUserByEmail(ctx, *email); user != nil {
			otp.UserID = &user.ID
			userID = &user.ID
		}
	} else if phone != nil {
		if user, _ := s.repo.GetUserByPhone(ctx, *phone); user != nil {
			otp.UserID = &user.ID
			userID = &user.ID
		}
	}

	if err := s.repo.CreateOTP(ctx, otp); err != nil {
		return errors.Wrap(err, "failed to create OTP")
	}

	// TODO: Send OTP via email or SMS (will be implemented in template system task)
	// For now, we'll just log it (in development mode, this could be useful)
	if s.config.IsDevelopment() {
		fmt.Printf("OTP Code for %s: %s\n", req.Identifier, code)
	}

	// Create audit log
	if userID != nil {
		s.createAuditLog(ctx, *userID, "otp_sent", "otp_codes", otp.ID.String(), true, map[string]any{
			"purpose":    req.Purpose,
			"identifier": req.Identifier,
		})
	}

	return nil
}

// VerifyOTP verifies an OTP code and returns authentication response
func (s *authService) VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*AuthResponse, error) {
	// Get OTP by identifier and purpose
	otp, err := s.repo.GetOTPByIdentifier(ctx, req.Identifier, req.Purpose)
	if err != nil {
		s.createSecurityEvent(ctx, nil, "otp_verification_failed", req.Identifier, "OTP not found")
		return nil, errors.NewAuthError("invalid or expired OTP")
	}

	// Check if OTP is expired
	if otp.IsExpired() {
		s.createSecurityEvent(ctx, otp.UserID, "otp_verification_failed", req.Identifier, "OTP expired")
		return nil, errors.NewAuthError("OTP has expired")
	}

	// Check if OTP is already used
	if otp.IsUsed() {
		s.createSecurityEvent(ctx, otp.UserID, "otp_verification_failed", req.Identifier, "OTP already used")
		return nil, errors.NewAuthError("OTP has already been used")
	}

	// Check attempts
	if !otp.CanAttempt() {
		s.createSecurityEvent(ctx, otp.UserID, "otp_verification_failed", req.Identifier, "max attempts exceeded")
		return nil, errors.NewAuthError("maximum OTP attempts exceeded")
	}

	// Verify code
	if subtle.ConstantTimeCompare([]byte(req.Code), []byte(otp.Code)) != 1 {
		// Increment attempts
		otp.Attempts++
		s.repo.UpdateOTPAttempts(ctx, otp.ID, otp.Attempts)
		s.createSecurityEvent(ctx, otp.UserID, "otp_verification_failed", req.Identifier, "invalid code")
		return nil, errors.NewAuthError("invalid OTP code")
	}

	// Mark OTP as used
	if err := s.repo.MarkOTPUsed(ctx, otp.ID); err != nil {
		return nil, errors.Wrap(err, "failed to mark OTP as used")
	}

	// Find or create user based on purpose
	var user *UnifiedUser
	if req.Purpose == "registration" {
		// Create new user for registration
		user = &UnifiedUser{
			ID:        uuid.New(),
			Email:     otp.Email,
			Phone:     otp.Phone,
			Metadata:  make(map[string]any),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}

		// Set verification status
		if otp.Email != nil {
			user.EmailVerified = true
		}
		if otp.Phone != nil {
			user.PhoneVerified = true
		}

		if err := s.repo.CreateUser(ctx, user); err != nil {
			return nil, errors.Wrap(err, "failed to create user")
		}

		s.createAuditLog(ctx, user.ID, AuditActions.UserCreate, "users", user.ID.String(), true, nil)
	} else {
		// Find existing user
		if otp.Email != nil {
			user, err = s.repo.GetUserByEmail(ctx, *otp.Email)
		} else if otp.Phone != nil {
			user, err = s.repo.GetUserByPhone(ctx, *otp.Phone)
		}

		if err != nil {
			return nil, errors.NewAuthError("user not found")
		}

		// Update verification status if needed
		if req.Purpose == "verification" {
			if otp.Email != nil && !user.EmailVerified {
				user.EmailVerified = true
				user.UpdatedAt = time.Now().UTC()
				s.repo.UpdateUser(ctx, user)
			}
			if otp.Phone != nil && !user.PhoneVerified {
				user.PhoneVerified = true
				user.UpdatedAt = time.Now().UTC()
				s.repo.UpdateUser(ctx, user)
			}
		}
	}

	// Generate tokens
	accessToken, refreshToken, expiresAt, err := s.generateTokens(user)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate tokens")
	}

	// Create audit log
	s.createAuditLog(ctx, user.ID, "otp_verified", "otp_codes", otp.ID.String(), true, map[string]any{
		"purpose": req.Purpose,
	})

	return &AuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// AuthenticateAdmin authenticates an admin user with enhanced security
func (s *authService) AuthenticateAdmin(ctx context.Context, req *AdminAuthRequest) (*AdminAuthResponse, error) {
	// Find user
	user, err := s.findUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		s.createSecurityEvent(ctx, nil, SecurityEventTypes.LoginFailure, req.Identifier, "admin user not found")
		return nil, errors.NewAuthError("invalid credentials")
	}

	// Check if user is admin
	if !user.IsAdmin() {
		s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.UnauthorizedAccess, req.Identifier, "non-admin attempted admin login")
		return nil, errors.NewAuthError("insufficient privileges")
	}

	// Check if account is locked
	if user.IsLocked() {
		s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.LoginFailure, req.Identifier, "admin account locked")
		return nil, errors.NewAuthError("account is locked")
	}

	// Verify password
	if !s.verifyPassword(req.Password, user.PasswordHash) {
		user.FailedAttempts++
		if user.FailedAttempts >= s.config.Auth.MaxFailedAttempts {
			lockUntil := time.Now().Add(s.config.Auth.LockoutDuration)
			user.LockedUntil = &lockUntil
		}
		s.repo.UpdateUser(ctx, user)
		s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.LoginFailure, req.Identifier, "invalid admin password")
		return nil, errors.NewAuthError("invalid credentials")
	}

	// Check MFA if enabled and required
	if user.MFAEnabled && req.MFACode == "" {
		return nil, errors.NewAuthError("MFA code required")
	}

	// TODO: Verify MFA code (will be implemented in MFA task)

	// Reset failed attempts
	user.FailedAttempts = 0
	user.LockedUntil = nil
	now := time.Now().UTC()
	user.LastLogin = &now
	user.UpdatedAt = now

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to update admin login info")
	}

	// Create admin session
	session, err := s.CreateAdminSession(ctx, user.ID, "", "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create admin session")
	}

	// Generate tokens with session ID
	accessToken, refreshToken, expiresAt, err := s.generateTokensWithSession(user, session.ID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate tokens")
	}

	// Create audit log
	s.createAuditLog(ctx, user.ID, AuditActions.Login, "admin_sessions", session.ID.String(), true, map[string]any{
		"admin_level": user.AdminLevel,
		"session_id":  session.ID,
	})

	return &AdminAuthResponse{
		User:         user,
		Session:      session,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// CreateSystemAdmin creates a system administrator (CLI only)
func (s *authService) CreateSystemAdmin(ctx context.Context, req *CreateSystemAdminRequest) (*UnifiedUser, error) {
	// Validate input
	if err := s.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Check if email already exists
	if existing, _ := s.repo.GetUserByEmail(ctx, req.Email); existing != nil {
		return nil, errors.NewAuthError("email already registered")
	}

	// Check if username already exists (if provided)
	if req.Username != "" {
		if existing, _ := s.repo.GetUserByUsername(ctx, req.Username); existing != nil {
			return nil, errors.NewAuthError("username already taken")
		}
	}

	// Hash password
	hashedPassword, err := s.hashPassword(req.Password)
	if err != nil {
		return nil, errors.Wrap(err, "failed to hash password")
	}

	// Create system admin user
	adminLevel := AdminLevelSystemAdmin
	capabilities := GetDefaultCapabilities(AdminLevelSystemAdmin)

	var username *string
	if req.Username != "" {
		username = &req.Username
	}

	user := &UnifiedUser{
		ID:             uuid.New(),
		Email:          &req.Email,
		Username:       username,
		PasswordHash:   hashedPassword,
		EmailVerified:  true, // System admins are pre-verified
		AdminLevel:     &adminLevel,
		Capabilities:   &capabilities,
		AssignedTables: []string{}, // System admins have access to all tables
		Metadata:       make(map[string]any),
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to create system admin")
	}

	// Create audit log
	s.createAuditLog(ctx, user.ID, AuditActions.UserCreate, "users", user.ID.String(), true, map[string]any{
		"admin_level": AdminLevelSystemAdmin,
		"created_via": "cli",
	})

	return user, nil
}

// PromoteToAdmin promotes a user to admin level
func (s *authService) PromoteToAdmin(ctx context.Context, userID uuid.UUID, level AdminLevel, promotedBy uuid.UUID) error {
	// Get the user being promoted
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Get the promoter
	promoter, err := s.repo.GetUserByID(ctx, promotedBy)
	if err != nil {
		return errors.Wrap(err, "promoter not found")
	}

	// Validate promotion permissions
	if err := ValidateAdminPromotion(promoter, level); err != nil {
		return err
	}

	// Get default capabilities for the level
	capabilities := GetDefaultCapabilities(level)

	// Promote user
	if err := s.repo.PromoteToAdmin(ctx, userID, level, &capabilities, promotedBy); err != nil {
		return errors.Wrap(err, "failed to promote user to admin")
	}

	// Create audit log
	s.createAuditLog(ctx, promotedBy, AuditActions.AdminPromote, "users", userID.String(), true, map[string]any{
		"target_user": userID,
		"admin_level": level,
		"promoted_by": promotedBy,
	})

	// Create security event
	identifier := ""
	if user.Email != nil {
		identifier = *user.Email
	}
	s.createSecurityEvent(ctx, &userID, SecurityEventTypes.AdminPromotion, identifier, fmt.Sprintf("promoted to %s", level))

	return nil
}

// CreateAdminSession creates a new admin session
func (s *authService) CreateAdminSession(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*AdminSession, error) {
	// Generate session tokens
	sessionToken, err := s.generateSecureToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate session token")
	}

	refreshToken, err := s.generateSecureToken()
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate refresh token")
	}

	session := &AdminSession{
		ID:           uuid.New(),
		UserID:       userID,
		SessionToken: sessionToken,
		RefreshToken: &refreshToken,
		IPAddress:    &ipAddress,
		UserAgent:    &userAgent,
		ExpiresAt:    time.Now().Add(s.config.Admin.SessionTimeout),
		CreatedAt:    time.Now().UTC(),
		LastActivity: time.Now().UTC(),
	}

	if err := s.repo.CreateSession(ctx, session); err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	return session, nil
}

// ValidateSession validates an admin session token
func (s *authService) ValidateSession(ctx context.Context, sessionToken string) (*AdminSession, *UnifiedUser, error) {
	// Get session
	session, err := s.repo.GetSessionByToken(ctx, sessionToken)
	if err != nil {
		return nil, nil, errors.NewAuthError("invalid session")
	}

	// Check if session is expired
	if session.IsExpired() {
		s.repo.DeleteSession(ctx, session.ID)
		return nil, nil, errors.NewAuthError("session expired")
	}

	// Get user
	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, errors.NewAuthError("user not found")
	}

	// Check if user is still admin
	if !user.IsAdmin() {
		s.repo.DeleteSession(ctx, session.ID)
		return nil, nil, errors.NewAuthError("user no longer has admin privileges")
	}

	// Update session activity
	s.repo.UpdateSessionActivity(ctx, session.ID)

	return session, user, nil
}

// ChangePassword changes a user's password
func (s *authService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	// Get user
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Verify old password
	if !s.verifyPassword(oldPassword, user.PasswordHash) {
		s.createSecurityEvent(ctx, &userID, "password_change_failed", "", "invalid old password")
		return errors.NewAuthError("invalid current password")
	}

	// Validate new password
	if err := s.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		return errors.Wrap(err, "failed to hash new password")
	}

	// Update password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to update password")
	}

	// Invalidate all user sessions (force re-login)
	s.repo.DeleteUserSessions(ctx, userID)

	// Create audit log
	s.createAuditLog(ctx, userID, AuditActions.PasswordChange, "users", userID.String(), true, nil)

	return nil
}

// ResetPassword resets a user's password using OTP
func (s *authService) ResetPassword(ctx context.Context, req *ResetPasswordRequest) error {
	// Verify OTP first
	otpReq := &VerifyOTPRequest{
		Identifier: req.Identifier,
		Code:       req.OTPCode,
		Purpose:    "password_reset",
	}

	// We don't need the auth response, just verification
	_, err := s.VerifyOTP(ctx, otpReq)
	if err != nil {
		return err
	}

	// Find user
	user, err := s.findUserByIdentifier(ctx, req.Identifier)
	if err != nil {
		return errors.NewAuthError("user not found")
	}

	// Validate new password
	if err := s.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := s.hashPassword(req.NewPassword)
	if err != nil {
		return errors.Wrap(err, "failed to hash new password")
	}

	// Update password
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now().UTC()
	user.FailedAttempts = 0 // Reset failed attempts
	user.LockedUntil = nil  // Unlock account if locked

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to update password")
	}

	// Invalidate all user sessions
	s.repo.DeleteUserSessions(ctx, user.ID)

	// Create audit log
	s.createAuditLog(ctx, user.ID, AuditActions.PasswordChange, "users", user.ID.String(), true, map[string]any{
		"reset_via": "otp",
	})

	// Create security event
	s.createSecurityEvent(ctx, &user.ID, SecurityEventTypes.PasswordReset, req.Identifier, "password reset via OTP")

	return nil
}

// LockAccount locks a user account
func (s *authService) LockAccount(ctx context.Context, userID uuid.UUID, reason string) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Lock account indefinitely (until manually unlocked)
	lockUntil := time.Now().Add(24 * 365 * time.Hour) // 1 year from now
	user.LockedUntil = &lockUntil
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to lock account")
	}

	// Invalidate all user sessions
	s.repo.DeleteUserSessions(ctx, userID)

	// Create audit log
	s.createAuditLog(ctx, userID, "account_locked", "users", userID.String(), true, map[string]any{
		"reason": reason,
	})

	// Create security event
	s.createSecurityEvent(ctx, &userID, SecurityEventTypes.AccountLockout, "", reason)

	return nil
}

// UnlockAccount unlocks a user account
func (s *authService) UnlockAccount(ctx context.Context, userID uuid.UUID, unlockedBy uuid.UUID) error {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return errors.Wrap(err, "user not found")
	}

	// Unlock account
	user.LockedUntil = nil
	user.FailedAttempts = 0
	user.UpdatedAt = time.Now().UTC()

	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return errors.Wrap(err, "failed to unlock account")
	}

	// Create audit log
	s.createAuditLog(ctx, unlockedBy, "account_unlocked", "users", userID.String(), true, map[string]any{
		"unlocked_by": unlockedBy,
	})

	return nil
}

// ValidateToken validates a JWT token and returns claims
func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Auth.JWTSecret), nil
	})

	if err != nil {
		return nil, errors.NewAuthError("invalid token")
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.NewAuthError("invalid token claims")
}

// ValidatePassword validates password strength
func (s *authService) ValidatePassword(password string) error {
	if len(password) < s.config.Auth.PasswordMinLength {
		return errors.NewAuthError(fmt.Sprintf("password must be at least %d characters long", s.config.Auth.PasswordMinLength))
	}

	if s.config.Auth.RequireSpecialChars {
		hasUpper := false
		hasLower := false
		hasDigit := false
		hasSpecial := false

		for _, char := range password {
			switch {
			case char >= 'A' && char <= 'Z':
				hasUpper = true
			case char >= 'a' && char <= 'z':
				hasLower = true
			case char >= '0' && char <= '9':
				hasDigit = true
			case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
				hasSpecial = true
			}
		}

		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			return errors.NewAuthError("password must contain uppercase, lowercase, digit, and special character")
		}
	}

	return nil
}

// Helper methods

// findUserByIdentifier finds a user by email, phone, or username
func (s *authService) findUserByIdentifier(ctx context.Context, identifier string) (*UnifiedUser, error) {
	// Try email first
	if strings.Contains(identifier, "@") {
		return s.repo.GetUserByEmail(ctx, identifier)
	}

	// Try phone number (simple check for digits)
	if len(identifier) > 5 && strings.ContainsAny(identifier, "0123456789") {
		if user, err := s.repo.GetUserByPhone(ctx, identifier); err == nil {
			return user, nil
		}
	}

	// Try username
	return s.repo.GetUserByUsername(ctx, identifier)
}

// generateTokens generates access and refresh tokens
func (s *authService) generateTokens(user *UnifiedUser) (string, string, time.Time, error) {
	return s.generateTokensWithSession(user, uuid.Nil)
}

// generateTokensWithSession generates tokens with optional session ID
func (s *authService) generateTokensWithSession(user *UnifiedUser, sessionID uuid.UUID) (string, string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(s.config.Auth.JWTExpiration)

	// Create access token claims
	accessClaims := &JWTClaims{
		UserID:     user.ID,
		AdminLevel: user.AdminLevel,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "go-forward",
			Subject:   user.ID.String(),
		},
	}

	if user.Email != nil {
		accessClaims.Email = *user.Email
	}

	if sessionID != uuid.Nil {
		accessClaims.SessionID = &sessionID
	}

	// Generate access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.config.Auth.JWTSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Create refresh token claims
	refreshExpiresAt := now.Add(s.config.Auth.RefreshExpiration)
	refreshClaims := &JWTClaims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "go-forward",
			Subject:   user.ID.String(),
		},
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Auth.JWTSecret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessTokenString, refreshTokenString, expiresAt, nil
}

// generateOTPCode generates a random OTP code
func (s *authService) generateOTPCode() (string, error) {
	const digits = "0123456789"
	code := make([]byte, s.config.Auth.OTPLength)

	for i := range code {
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", err
		}
		code[i] = digits[randomBytes[0]%byte(len(digits))]
	}

	return string(code), nil
}

// generateSecureToken generates a cryptographically secure random token
func (s *authService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// getSameSiteAttribute converts string to http.SameSite
func (s *authService) getSameSiteAttribute() http.SameSite {
	switch strings.ToLower(s.config.Auth.CookieSameSite) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

// createAuditLog creates an audit log entry
func (s *authService) createAuditLog(ctx context.Context, userID uuid.UUID, action, resource, resourceID string, success bool, details map[string]any) {
	auditLog := &AuditLog{
		ID:         uuid.New(),
		UserID:     &userID,
		Action:     action,
		Resource:   &resource,
		ResourceID: &resourceID,
		Details:    details,
		Success:    success,
		Severity:   AuditSeverityMedium,
		CreatedAt:  time.Now().UTC(),
	}

	// Don't fail the main operation if audit logging fails
	s.repo.CreateAuditLog(ctx, auditLog)
}

// hashPassword hashes a password using bcrypt
func (s *authService) hashPassword(password string) (string, error) {
	cost := s.config.Auth.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

// verifyPassword verifies a password against its hash
func (s *authService) verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// createSecurityEvent creates a security event
func (s *authService) createSecurityEvent(ctx context.Context, userID *uuid.UUID, eventType, identifier, details string) {
	event := &SecurityEvent{
		ID:        uuid.New(),
		EventType: eventType,
		UserID:    userID,
		Details: map[string]any{
			"identifier": identifier,
			"details":    details,
		},
		Severity:  AuditSeverityMedium,
		Resolved:  false,
		CreatedAt: time.Now().UTC(),
	}

	// Don't fail the main operation if security event logging fails
	s.repo.CreateSecurityEvent(ctx, event)
}
