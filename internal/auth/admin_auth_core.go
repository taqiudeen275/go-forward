package auth

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AdminLevel represents the hierarchical admin levels
type AdminLevel string

const (
	SystemAdmin  AdminLevel = "system_admin"
	SuperAdmin   AdminLevel = "super_admin"
	RegularAdmin AdminLevel = "regular_admin"
	Moderator    AdminLevel = "moderator"
)

// AdminCapabilities defines what an admin can do
type AdminCapabilities struct {
	// System-level capabilities (System Admin only)
	CanAccessSQL        bool `json:"can_access_sql"`
	CanManageDatabase   bool `json:"can_manage_database"`
	CanManageSystem     bool `json:"can_manage_system"`
	CanCreateSuperAdmin bool `json:"can_create_super_admin"`

	// Super admin capabilities
	CanCreateAdmins    bool `json:"can_create_admins"`
	CanManageAllTables bool `json:"can_manage_all_tables"`
	CanManageAuth      bool `json:"can_manage_auth"`
	CanManageStorage   bool `json:"can_manage_storage"`
	CanViewAllLogs     bool `json:"can_view_all_logs"`

	// Regular admin capabilities
	CanManageUsers     bool     `json:"can_manage_users"`
	CanManageContent   bool     `json:"can_manage_content"`
	AssignedTables     []string `json:"assigned_tables"`
	AssignedUserGroups []string `json:"assigned_user_groups"`

	// Moderator capabilities
	CanViewReports     bool `json:"can_view_reports"`
	CanModerateContent bool `json:"can_moderate_content"`
	CanViewBasicLogs   bool `json:"can_view_basic_logs"`

	// Common capabilities
	CanViewDashboard bool `json:"can_view_dashboard"`
	CanExportData    bool `json:"can_export_data"`
}

// MFAMethod represents multi-factor authentication methods
type MFAMethod string

const (
	MFAMethodTOTP        MFAMethod = "totp"
	MFAMethodBackupCodes MFAMethod = "backup_codes"
)

// SecurityContext provides context for authorization decisions
type SecurityContext struct {
	UserID      string            `json:"user_id"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	SessionID   string            `json:"session_id"`
	RequestID   string            `json:"request_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Environment string            `json:"environment"`
	Metadata    map[string]string `json:"metadata"`
}

// SecurityMetadata contains additional security information
type SecurityMetadata struct {
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	Location    string            `json:"location,omitempty"`
	DeviceInfo  string            `json:"device_info,omitempty"`
	RequestID   string            `json:"request_id,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Additional  map[string]string `json:"additional,omitempty"`
}

// AdminAuthRequest represents an admin authentication request
type AdminAuthRequest struct {
	Identifier string           `json:"identifier" validate:"required"`
	Password   string           `json:"password" validate:"required"`
	MFACode    string           `json:"mfa_code,omitempty"`
	Context    SecurityContext  `json:"context"`
	Metadata   SecurityMetadata `json:"metadata"`
}

// AdminAuthResponse represents an admin authentication response
type AdminAuthResponse struct {
	User         *User             `json:"user"`
	AdminLevel   AdminLevel        `json:"admin_level"`
	Capabilities AdminCapabilities `json:"capabilities"`
	Session      *AdminSession     `json:"session"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	ExpiresIn    int               `json:"expires_in"`
	RequiresMFA  bool              `json:"requires_mfa"`
}

// MFASetup represents MFA setup information
type MFASetup struct {
	Secret      string    `json:"secret"`
	QRCodeURL   string    `json:"qr_code_url"`
	BackupCodes []string  `json:"backup_codes"`
	Method      MFAMethod `json:"method"`
}

// TOTPSecret represents TOTP secret information
type TOTPSecret struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qr_code_url"`
	Issuer    string `json:"issuer"`
	Account   string `json:"account"`
}

// APIKey represents an API key for service authentication
type APIKey struct {
	ID        string            `json:"id" db:"id"`
	UserID    string            `json:"user_id" db:"user_id"`
	Name      string            `json:"name" db:"name"`
	KeyHash   string            `json:"-" db:"key_hash"`
	Scopes    []string          `json:"scopes" db:"scopes"`
	ExpiresAt *time.Time        `json:"expires_at" db:"expires_at"`
	LastUsed  *time.Time        `json:"last_used" db:"last_used"`
	IsActive  bool              `json:"is_active" db:"is_active"`
	CreatedAt time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt time.Time         `json:"updated_at" db:"updated_at"`
	Metadata  map[string]string `json:"metadata" db:"metadata"`
}

// APIKeyInfo represents API key information for validation
type APIKeyInfo struct {
	ID         string            `json:"id"`
	UserID     string            `json:"user_id"`
	Name       string            `json:"name"`
	Scopes     []string          `json:"scopes"`
	ExpiresAt  *time.Time        `json:"expires_at"`
	LastUsed   *time.Time        `json:"last_used"`
	AdminLevel AdminLevel        `json:"admin_level"`
	Metadata   map[string]string `json:"metadata"`
}

// UserInfo represents user information from token validation
type UserInfo struct {
	UserID      string `json:"user_id"`
	SessionID   string `json:"session_id"`
	MFAVerified bool   `json:"mfa_verified"`
	ExpiresAt   int64  `json:"expires_at"`
}

// AdminSession represents enhanced admin session management
type AdminSession struct {
	ID           string            `json:"id" db:"id"`
	UserID       string            `json:"user_id" db:"user_id"`
	AdminLevel   AdminLevel        `json:"admin_level" db:"admin_level"`
	Capabilities AdminCapabilities `json:"capabilities" db:"capabilities"`
	IPAddress    string            `json:"ip_address" db:"ip_address"`
	UserAgent    string            `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	LastActivity time.Time         `json:"last_activity" db:"last_activity"`
	ExpiresAt    time.Time         `json:"expires_at" db:"expires_at"`
	IsActive     bool              `json:"is_active" db:"is_active"`

	// Security features
	RequiresMFA   bool     `json:"requires_mfa" db:"requires_mfa"`
	MFAVerified   bool     `json:"mfa_verified" db:"mfa_verified"`
	SecurityFlags []string `json:"security_flags" db:"security_flags"`
}

// MFAConfiguration represents multi-factor authentication setup
type MFAConfiguration struct {
	UserID      string     `json:"user_id" db:"user_id"`
	Method      MFAMethod  `json:"method" db:"method"`
	Secret      string     `json:"secret" db:"secret"`
	BackupCodes []string   `json:"backup_codes" db:"backup_codes"`
	IsEnabled   bool       `json:"is_enabled" db:"is_enabled"`
	LastUsed    *time.Time `json:"last_used" db:"last_used"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// SecurityAlert represents security-related alerts
type SecurityAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
}

// AuthenticationCore interface defines enhanced authentication methods
type AuthenticationCore interface {
	// Enhanced authentication methods
	AuthenticateAdmin(ctx context.Context, req AdminAuthRequest) (*AdminAuthResponse, error)
	EnableMFA(ctx context.Context, userID string, method MFAMethod) (*MFASetup, error)
	VerifyMFA(ctx context.Context, userID string, code string) error
	DisableMFA(ctx context.Context, userID string) error

	// Session management
	CreateAdminSession(ctx context.Context, userID string, capabilities AdminCapabilities, context SecurityContext) (*AdminSession, error)
	ValidateSession(ctx context.Context, sessionID string) (*AdminSession, error)
	InvalidateSession(ctx context.Context, sessionID string) error
	RefreshSession(ctx context.Context, sessionID string) (*AdminSession, error)
	GetActiveSessions(ctx context.Context, userID string) ([]*AdminSession, error)

	// Token validation
	ValidateToken(token string) (*UserInfo, error)

	// API key management
	CreateAPIKey(ctx context.Context, userID string, name string, scopes []string, expiresAt *time.Time) (*APIKey, error)
	ValidateAPIKey(ctx context.Context, key string) (*APIKeyInfo, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
	ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, keyID string) error

	// Security monitoring
	RecordAuthAttempt(ctx context.Context, userID string, success bool, metadata SecurityMetadata) error
	DetectSuspiciousActivity(ctx context.Context, userID string) (*SecurityAlert, error)
	TriggerAccountLockout(ctx context.Context, userID string, reason string) error
	ClearSecurityFlags(ctx context.Context, userID string) error
}

// MFAService interface defines multi-factor authentication operations
type MFAService interface {
	GenerateTOTPSecret(userID string) (*TOTPSecret, error)
	ValidateTOTPCode(userID string, code string) error
	GenerateBackupCodes(userID string) ([]string, error)
	ValidateBackupCode(userID string, code string) error
	GetMFAConfiguration(ctx context.Context, userID string) (*MFAConfiguration, error)
	UpdateMFAConfiguration(ctx context.Context, config *MFAConfiguration) error
}

// AuthenticationCoreImpl implements the AuthenticationCore interface
type AuthenticationCoreImpl struct {
	userRepo        UserRepositoryInterface
	adminRepo       *AdminRepository
	mfaRepo         *MFARepository
	jwtManager      *JWTManager
	securityMonitor *SecurityMonitor
	mfaService      MFAService
	hasher          *PasswordHasher
	validator       *Validator
}

// NewAuthenticationCore creates a new authentication core
func NewAuthenticationCore(userRepo UserRepositoryInterface, adminRepo *AdminRepository, mfaRepo *MFARepository, jwtManager *JWTManager) *AuthenticationCoreImpl {
	return &AuthenticationCoreImpl{
		userRepo:        userRepo,
		adminRepo:       adminRepo,
		mfaRepo:         mfaRepo,
		jwtManager:      jwtManager,
		securityMonitor: NewSecurityMonitor(),
		mfaService:      NewMFAService(userRepo, mfaRepo),
		hasher:          NewPasswordHasher(),
		validator:       NewValidator(),
	}
}

// AuthenticateAdmin authenticates an admin user with enhanced security
func (ac *AuthenticationCoreImpl) AuthenticateAdmin(ctx context.Context, req AdminAuthRequest) (*AdminAuthResponse, error) {
	// Validate request
	if req.Identifier == "" || req.Password == "" {
		return nil, fmt.Errorf("identifier and password are required")
	}

	// Record authentication attempt
	defer func() {
		ac.RecordAuthAttempt(ctx, req.Identifier, false, req.Metadata)
	}()

	// Get user by identifier
	user, err := ac.userRepo.GetByIdentifier(ctx, req.Identifier)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Validate password
	err = ac.hasher.ValidatePassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Get admin level and capabilities (this would come from admin_roles table)
	adminLevel, capabilities, err := ac.getAdminCapabilities(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("user is not an admin")
	}

	// Check if MFA is required
	mfaConfig, err := ac.mfaService.GetMFAConfiguration(ctx, user.ID)
	requiresMFA := err == nil && mfaConfig.IsEnabled

	// If MFA is required and no code provided, return partial response
	if requiresMFA && req.MFACode == "" {
		return &AdminAuthResponse{
			User:        user,
			AdminLevel:  adminLevel,
			RequiresMFA: true,
		}, nil
	}

	// Verify MFA if required
	if requiresMFA && req.MFACode != "" {
		err = ac.VerifyMFA(ctx, user.ID, req.MFACode)
		if err != nil {
			return nil, fmt.Errorf("invalid MFA code")
		}
	}

	// Create admin session
	session, err := ac.CreateAdminSession(ctx, user.ID, capabilities, req.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate JWT tokens with admin claims
	tokenPair, err := ac.generateAdminTokens(user, adminLevel, capabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Record successful authentication
	ac.RecordAuthAttempt(ctx, user.ID, true, req.Metadata)

	return &AdminAuthResponse{
		User:         user,
		AdminLevel:   adminLevel,
		Capabilities: capabilities,
		Session:      session,
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
		ExpiresIn:    int(tokenPair.ExpiresIn),
		RequiresMFA:  false,
	}, nil
}

// EnableMFA enables multi-factor authentication for a user
func (ac *AuthenticationCoreImpl) EnableMFA(ctx context.Context, userID string, method MFAMethod) (*MFASetup, error) {
	switch method {
	case MFAMethodTOTP:
		return ac.enableTOTP(ctx, userID)
	case MFAMethodBackupCodes:
		return ac.enableBackupCodes(ctx, userID)
	default:
		return nil, fmt.Errorf("unsupported MFA method: %s", method)
	}
}

// enableTOTP enables TOTP-based MFA
func (ac *AuthenticationCoreImpl) enableTOTP(ctx context.Context, userID string) (*MFASetup, error) {
	// Generate TOTP secret
	totpSecret, err := ac.mfaService.GenerateTOTPSecret(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// Generate backup codes
	backupCodes, err := ac.mfaService.GenerateBackupCodes(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Save MFA configuration
	mfaConfig := &MFAConfiguration{
		UserID:      userID,
		Method:      MFAMethodTOTP,
		Secret:      totpSecret.Secret,
		BackupCodes: backupCodes,
		IsEnabled:   true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = ac.mfaService.UpdateMFAConfiguration(ctx, mfaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to save MFA configuration: %w", err)
	}

	return &MFASetup{
		Secret:      totpSecret.Secret,
		QRCodeURL:   totpSecret.QRCodeURL,
		BackupCodes: backupCodes,
		Method:      MFAMethodTOTP,
	}, nil
}

// enableBackupCodes enables backup codes only
func (ac *AuthenticationCoreImpl) enableBackupCodes(ctx context.Context, userID string) (*MFASetup, error) {
	// Generate backup codes
	backupCodes, err := ac.mfaService.GenerateBackupCodes(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Save MFA configuration
	mfaConfig := &MFAConfiguration{
		UserID:      userID,
		Method:      MFAMethodBackupCodes,
		BackupCodes: backupCodes,
		IsEnabled:   true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	err = ac.mfaService.UpdateMFAConfiguration(ctx, mfaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to save MFA configuration: %w", err)
	}

	return &MFASetup{
		BackupCodes: backupCodes,
		Method:      MFAMethodBackupCodes,
	}, nil
}

// VerifyMFA verifies a multi-factor authentication code
func (ac *AuthenticationCoreImpl) VerifyMFA(ctx context.Context, userID string, code string) error {
	// Get MFA configuration
	mfaConfig, err := ac.mfaService.GetMFAConfiguration(ctx, userID)
	if err != nil {
		return fmt.Errorf("MFA not configured for user")
	}

	if !mfaConfig.IsEnabled {
		return fmt.Errorf("MFA is not enabled for user")
	}

	// Try TOTP first if configured
	if mfaConfig.Method == MFAMethodTOTP && mfaConfig.Secret != "" {
		err = ac.mfaService.ValidateTOTPCode(userID, code)
		if err == nil {
			// Update last used timestamp
			mfaConfig.LastUsed = &time.Time{}
			*mfaConfig.LastUsed = time.Now()
			ac.mfaService.UpdateMFAConfiguration(ctx, mfaConfig)
			return nil
		}
	}

	// Try backup codes
	err = ac.mfaService.ValidateBackupCode(userID, code)
	if err == nil {
		// Update last used timestamp
		mfaConfig.LastUsed = &time.Time{}
		*mfaConfig.LastUsed = time.Now()
		ac.mfaService.UpdateMFAConfiguration(ctx, mfaConfig)
		return nil
	}

	return fmt.Errorf("invalid MFA code")
}

// DisableMFA disables multi-factor authentication for a user
func (ac *AuthenticationCoreImpl) DisableMFA(ctx context.Context, userID string) error {
	// Get current MFA configuration
	mfaConfig, err := ac.mfaService.GetMFAConfiguration(ctx, userID)
	if err != nil {
		return fmt.Errorf("MFA not configured for user")
	}

	// Disable MFA
	mfaConfig.IsEnabled = false
	mfaConfig.UpdatedAt = time.Now()

	return ac.mfaService.UpdateMFAConfiguration(ctx, mfaConfig)
}

// getAdminCapabilities retrieves admin level and capabilities for a user
func (ac *AuthenticationCoreImpl) getAdminCapabilities(ctx context.Context, userID string) (AdminLevel, AdminCapabilities, error) {
	// Check if user is an admin
	isAdmin, err := ac.adminRepo.IsUserAdmin(ctx, userID)
	if err != nil {
		return "", AdminCapabilities{}, fmt.Errorf("failed to check admin status: %w", err)
	}

	if !isAdmin {
		return "", AdminCapabilities{}, fmt.Errorf("user is not an admin")
	}

	// Get admin level
	adminLevel, err := ac.adminRepo.GetUserAdminLevel(ctx, userID)
	if err != nil {
		return "", AdminCapabilities{}, fmt.Errorf("failed to get admin level: %w", err)
	}

	// Get capabilities
	capabilities, err := ac.adminRepo.GetUserAdminCapabilities(ctx, userID)
	if err != nil {
		return "", AdminCapabilities{}, fmt.Errorf("failed to get admin capabilities: %w", err)
	}

	return adminLevel, *capabilities, nil
}

// generateAdminTokens generates JWT tokens with admin-specific claims
func (ac *AuthenticationCoreImpl) generateAdminTokens(user *User, adminLevel AdminLevel, capabilities AdminCapabilities) (*TokenPair, error) {
	// For now, use existing JWT manager
	// In a full implementation, you might want to add admin-specific claims
	return ac.jwtManager.GenerateTokenPair(user)
}

// CreateAdminSession creates a new admin session with security controls
func (ac *AuthenticationCoreImpl) CreateAdminSession(ctx context.Context, userID string, capabilities AdminCapabilities, securityContext SecurityContext) (*AdminSession, error) {
	sessionID := uuid.New().String()
	now := time.Now()

	// Session expires in 8 hours for regular sessions, 4 hours for system admins
	var expiresAt time.Time
	if capabilities.CanAccessSQL {
		expiresAt = now.Add(4 * time.Hour) // Shorter session for system admins
	} else {
		expiresAt = now.Add(8 * time.Hour)
	}

	session := &AdminSession{
		ID:            sessionID,
		UserID:        userID,
		AdminLevel:    ac.getAdminLevelFromCapabilities(capabilities),
		Capabilities:  capabilities,
		IPAddress:     securityContext.IPAddress,
		UserAgent:     securityContext.UserAgent,
		CreatedAt:     now,
		LastActivity:  now,
		ExpiresAt:     expiresAt,
		IsActive:      true,
		RequiresMFA:   capabilities.CanAccessSQL, // System admins require MFA
		MFAVerified:   false,
		SecurityFlags: []string{},
	}

	// Save session to database
	err := ac.mfaRepo.CreateAdminSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to save admin session: %w", err)
	}

	return session, nil
}

// ValidateSession validates an admin session and updates last activity
func (ac *AuthenticationCoreImpl) ValidateSession(ctx context.Context, sessionID string) (*AdminSession, error) {
	session, err := ac.mfaRepo.GetAdminSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin session: %w", err)
	}

	// Update last activity
	err = ac.mfaRepo.UpdateAdminSessionActivity(ctx, sessionID)
	if err != nil {
		// Log error but don't fail validation
		fmt.Printf("Warning: failed to update session activity: %v\n", err)
	}

	return session, nil
}

// InvalidateSession invalidates an admin session
func (ac *AuthenticationCoreImpl) InvalidateSession(ctx context.Context, sessionID string) error {
	return ac.mfaRepo.InvalidateAdminSession(ctx, sessionID, "LOGOUT")
}

// RefreshSession refreshes an admin session's expiration time
func (ac *AuthenticationCoreImpl) RefreshSession(ctx context.Context, sessionID string) (*AdminSession, error) {
	// Get current session
	session, err := ac.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to validate session for refresh: %w", err)
	}

	// Extend expiration time
	now := time.Now()
	var newExpiresAt time.Time
	if session.Capabilities.CanAccessSQL {
		newExpiresAt = now.Add(4 * time.Hour) // System admin sessions
	} else {
		newExpiresAt = now.Add(8 * time.Hour) // Regular admin sessions
	}

	session.ExpiresAt = newExpiresAt
	session.LastActivity = now

	// Update in database would go here
	// For now, return the updated session
	return session, nil
}

// GetActiveSessions retrieves all active sessions for a user
func (ac *AuthenticationCoreImpl) GetActiveSessions(ctx context.Context, userID string) ([]*AdminSession, error) {
	return ac.mfaRepo.GetActiveAdminSessions(ctx, userID)
}

// CreateAPIKey creates a new API key for service authentication
func (ac *AuthenticationCoreImpl) CreateAPIKey(ctx context.Context, userID string, name string, scopes []string, expiresAt *time.Time) (*APIKey, error) {
	keyID := uuid.New().String()

	// Generate a secure API key
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate API key: %w", err)
	}

	// Encode as base32 for readability
	keyString := base32.StdEncoding.EncodeToString(keyBytes)

	// Hash the key for storage
	keyHash, err := ac.hasher.HashPassword(keyString)
	if err != nil {
		return nil, fmt.Errorf("failed to hash API key: %w", err)
	}

	apiKey := &APIKey{
		ID:        keyID,
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		Scopes:    scopes,
		ExpiresAt: expiresAt,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Metadata:  make(map[string]string),
	}

	// Save API key to database
	err = ac.mfaRepo.CreateAPIKey(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save API key: %w", err)
	}

	// Return the API key with the plain text key (only time it's exposed)
	// Create a copy to avoid modifying the stored version
	returnKey := *apiKey
	returnKey.KeyHash = keyString // Set plain text key for return
	return &returnKey, nil
}

// ValidateAPIKey validates an API key and returns key information
func (ac *AuthenticationCoreImpl) ValidateAPIKey(ctx context.Context, key string) (*APIKeyInfo, error) {
	// Hash the provided key
	keyHash, err := ac.hasher.HashPassword(key)
	if err != nil {
		return nil, fmt.Errorf("failed to hash API key: %w", err)
	}

	// Find matching key in database
	apiKey, err := ac.mfaRepo.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("API key not found or invalid: %w", err)
	}

	// Get user's admin level
	adminLevel, err := ac.adminRepo.GetUserAdminLevel(ctx, apiKey.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin level for API key user: %w", err)
	}

	// Update last used timestamp
	err = ac.mfaRepo.UpdateAPIKeyLastUsed(ctx, apiKey.ID)
	if err != nil {
		// Log error but don't fail validation
		fmt.Printf("Warning: failed to update API key last used: %v\n", err)
	}

	return &APIKeyInfo{
		ID:         apiKey.ID,
		UserID:     apiKey.UserID,
		Name:       apiKey.Name,
		Scopes:     apiKey.Scopes,
		ExpiresAt:  apiKey.ExpiresAt,
		LastUsed:   apiKey.LastUsed,
		AdminLevel: adminLevel,
		Metadata:   apiKey.Metadata,
	}, nil
}

// RevokeAPIKey revokes an API key
func (ac *AuthenticationCoreImpl) RevokeAPIKey(ctx context.Context, keyID string) error {
	return ac.mfaRepo.RevokeAPIKey(ctx, keyID)
}

// ListAPIKeys lists all API keys for a user
func (ac *AuthenticationCoreImpl) ListAPIKeys(ctx context.Context, userID string) ([]*APIKey, error) {
	return ac.mfaRepo.ListAPIKeys(ctx, userID)
}

// UpdateAPIKeyLastUsed updates the last used timestamp for an API key
func (ac *AuthenticationCoreImpl) UpdateAPIKeyLastUsed(ctx context.Context, keyID string) error {
	return ac.mfaRepo.UpdateAPIKeyLastUsed(ctx, keyID)
}

// RecordAuthAttempt records an authentication attempt for security monitoring
func (ac *AuthenticationCoreImpl) RecordAuthAttempt(ctx context.Context, userID string, success bool, metadata SecurityMetadata) error {
	// Use existing security monitor for basic functionality
	if !success {
		return ac.securityMonitor.RecordFailedAttempt(userID)
	} else {
		ac.securityMonitor.ClearFailedAttempts(userID)
	}

	// TODO: Implement comprehensive audit logging
	// This would log to admin_access_logs table

	return nil
}

// DetectSuspiciousActivity analyzes user activity for suspicious patterns
func (ac *AuthenticationCoreImpl) DetectSuspiciousActivity(ctx context.Context, userID string) (*SecurityAlert, error) {
	// Check if user is currently locked out
	if ac.securityMonitor.IsLocked(userID) {
		return &SecurityAlert{
			ID:          uuid.New().String(),
			Type:        "account_lockout",
			Severity:    "high",
			Title:       "Account Locked",
			Description: "Account has been temporarily locked due to multiple failed authentication attempts",
			UserID:      userID,
			Timestamp:   time.Now(),
			Resolved:    false,
		}, nil
	}

	// TODO: Implement more sophisticated suspicious activity detection
	// This could include:
	// - Multiple login attempts from different IPs
	// - Login attempts at unusual times
	// - Rapid succession of failed attempts
	// - Geographic anomalies

	return nil, nil
}

// TriggerAccountLockout locks an account due to suspicious activity
func (ac *AuthenticationCoreImpl) TriggerAccountLockout(ctx context.Context, userID string, reason string) error {
	// Use security monitor to record failed attempts until lockout
	for i := 0; i < 5; i++ { // Trigger lockout by exceeding failed attempts
		ac.securityMonitor.RecordFailedAttempt(userID)
	}

	// TODO: Implement proper account lockout in database
	// This would update user status and create audit log entry

	return nil
}

// ClearSecurityFlags clears security flags for a user
func (ac *AuthenticationCoreImpl) ClearSecurityFlags(ctx context.Context, userID string) error {
	// Clear security monitor flags
	ac.securityMonitor.ClearFailedAttempts(userID)

	// TODO: Implement security flags clearing in database
	// This would clear flags in admin_sessions and security_events tables

	return nil
}

// ValidateToken validates a JWT token and returns user information
func (ac *AuthenticationCoreImpl) ValidateToken(token string) (*UserInfo, error) {
	// Use JWT manager to validate token
	claims, err := ac.jwtManager.ValidateAccessToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Extract user information from claims
	userInfo := &UserInfo{
		UserID:      claims.UserID,
		SessionID:   "",    // SessionID would need to be added to Claims or retrieved separately
		MFAVerified: false, // MFAVerified would need to be added to Claims or retrieved separately
		ExpiresAt:   claims.ExpiresAt.Unix(),
	}

	return userInfo, nil
}

// getAdminLevelFromCapabilities determines admin level from capabilities
func (ac *AuthenticationCoreImpl) getAdminLevelFromCapabilities(capabilities AdminCapabilities) AdminLevel {
	if capabilities.CanAccessSQL {
		return SystemAdmin
	}
	if capabilities.CanCreateAdmins {
		return SuperAdmin
	}
	if capabilities.CanManageUsers {
		return RegularAdmin
	}
	return Moderator
}
