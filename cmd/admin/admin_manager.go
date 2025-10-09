package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// AdminManager handles admin management operations
type AdminManager struct {
	userRepo   auth.UserRepositoryInterface
	adminRepo  *auth.AdminRepository
	mfaRepo    *auth.MFARepository
	jwtManager *auth.JWTManager
	hasher     *auth.PasswordHasher
	validator  *auth.Validator
}

// CreateSystemAdminRequest represents a request to create a system admin
type CreateSystemAdminRequest struct {
	Email       string      `json:"email"`
	Username    string      `json:"username"`
	Password    string      `json:"password"`
	Environment Environment `json:"environment"`
	CreatedBy   string      `json:"created_by"`
}

// SystemAdminResponse represents a created system admin
type SystemAdminResponse struct {
	ID         string          `json:"id"`
	Email      string          `json:"email"`
	Username   string          `json:"username"`
	AdminLevel auth.AdminLevel `json:"admin_level"`
	CreatedAt  time.Time       `json:"created_at"`
	CreatedBy  string          `json:"created_by"`
}

// PromoteAdminRequest represents a request to promote a user to admin
type PromoteAdminRequest struct {
	UserID     string          `json:"user_id"`
	ToLevel    auth.AdminLevel `json:"to_level"`
	Reason     string          `json:"reason"`
	PromotedBy string          `json:"promoted_by"`
}

// PromoteAdminResponse represents the result of admin promotion
type PromoteAdminResponse struct {
	UserID        string           `json:"user_id"`
	PreviousLevel *auth.AdminLevel `json:"previous_level"`
	NewLevel      auth.AdminLevel  `json:"new_level"`
	PromotedAt    time.Time        `json:"promoted_at"`
	PromotedBy    string           `json:"promoted_by"`
	Reason        string           `json:"reason"`
}

// DemoteAdminRequest represents a request to demote an admin
type DemoteAdminRequest struct {
	UserID    string           `json:"user_id"`
	ToLevel   *auth.AdminLevel `json:"to_level"` // nil means remove admin status
	Reason    string           `json:"reason"`
	DemotedBy string           `json:"demoted_by"`
}

// DemoteAdminResponse represents the result of admin demotion
type DemoteAdminResponse struct {
	UserID        string           `json:"user_id"`
	PreviousLevel auth.AdminLevel  `json:"previous_level"`
	NewLevel      *auth.AdminLevel `json:"new_level"` // nil means regular user
	DemotedAt     time.Time        `json:"demoted_at"`
	DemotedBy     string           `json:"demoted_by"`
	Reason        string           `json:"reason"`
}

// AdminInfo represents admin information for listing
type AdminInfo struct {
	ID           string                 `json:"id"`
	Email        string                 `json:"email"`
	Username     string                 `json:"username"`
	AdminLevel   auth.AdminLevel        `json:"admin_level"`
	IsActive     bool                   `json:"is_active"`
	CreatedAt    time.Time              `json:"created_at"`
	LastActiveAt *time.Time             `json:"last_active_at"`
	Capabilities auth.AdminCapabilities `json:"capabilities"`
}

// AdminFilter represents filters for listing admins
type AdminFilter struct {
	Level        *auth.AdminLevel `json:"level"`
	ShowInactive bool             `json:"show_inactive"`
	Limit        int              `json:"limit"`
	Offset       int              `json:"offset"`
}

// NewAdminManager creates a new admin manager
func NewAdminManager(userRepo auth.UserRepositoryInterface, adminRepo *auth.AdminRepository, mfaRepo *auth.MFARepository, jwtManager *auth.JWTManager) *AdminManager {
	return &AdminManager{
		userRepo:   userRepo,
		adminRepo:  adminRepo,
		mfaRepo:    mfaRepo,
		jwtManager: jwtManager,
		hasher:     auth.NewPasswordHasher(),
		validator:  auth.NewValidator(),
	}
}

// ValidateSystemAdminRequest validates a system admin creation request
func (am *AdminManager) ValidateSystemAdminRequest(email, username, password string) error {
	// Validate email
	if err := am.validator.ValidateEmail(email); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	// Validate username
	if err := am.validator.ValidateUsername(username); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	// Validate password
	if err := am.validator.ValidatePassword(password); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	return nil
}

// CreateSystemAdmin creates a new system administrator
func (am *AdminManager) CreateSystemAdmin(ctx context.Context, req *CreateSystemAdminRequest) (*SystemAdminResponse, error) {
	// Check if user already exists
	existingUser, err := am.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Check username uniqueness
	if req.Username != "" {
		existingUser, err = am.userRepo.GetByUsername(ctx, req.Username)
		if err == nil && existingUser != nil {
			return nil, fmt.Errorf("user with username %s already exists", req.Username)
		}
	}

	// Hash password
	hashedPassword, err := am.hasher.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	userID := uuid.New().String()
	user := &auth.User{
		ID:            userID,
		Email:         &req.Email,
		Username:      &req.Username,
		PasswordHash:  hashedPassword,
		EmailVerified: true, // System admins are pre-verified
		PhoneVerified: false,
		Metadata:      make(map[string]interface{}),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Add admin metadata
	user.Metadata["admin_created_by"] = req.CreatedBy
	user.Metadata["admin_created_via"] = "CLI"
	user.Metadata["admin_environment"] = string(req.Environment)

	err = am.userRepo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Get system admin role ID
	systemAdminRole, err := am.adminRepo.GetAdminRoleByName(ctx, "System Admin")
	if err != nil {
		// Rollback user creation
		am.userRepo.Delete(ctx, userID)
		return nil, fmt.Errorf("failed to get system admin role: %w", err)
	}

	// Assign system admin role
	err = am.adminRepo.AssignAdminRole(ctx, userID, systemAdminRole.ID, req.CreatedBy)
	if err != nil {
		// Rollback user creation
		am.userRepo.Delete(ctx, userID)
		return nil, fmt.Errorf("failed to assign admin role: %w", err)
	}

	return &SystemAdminResponse{
		ID:         userID,
		Email:      req.Email,
		Username:   req.Username,
		AdminLevel: auth.SystemAdmin,
		CreatedAt:  user.CreatedAt,
		CreatedBy:  req.CreatedBy,
	}, nil
}

// GetUserAdminLevel gets the admin level for a user
func (am *AdminManager) GetUserAdminLevel(ctx context.Context, userID string) (auth.AdminLevel, error) {
	return am.adminRepo.GetUserAdminLevel(ctx, userID)
}

// PromoteAdmin promotes a user to admin or upgrades admin level
func (am *AdminManager) PromoteAdmin(ctx context.Context, req *PromoteAdminRequest) (*PromoteAdminResponse, error) {
	// Check if user exists
	user, err := am.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get current admin level (if any)
	var previousLevel *auth.AdminLevel
	currentLevel, err := am.adminRepo.GetUserAdminLevel(ctx, req.UserID)
	if err == nil {
		previousLevel = &currentLevel
	}

	// Validate promotion is allowed
	if previousLevel != nil && !am.isValidPromotion(*previousLevel, req.ToLevel) {
		return nil, fmt.Errorf("invalid promotion from %s to %s", *previousLevel, req.ToLevel)
	}

	// Get role ID for the target level
	roleName := am.adminLevelToRoleName(req.ToLevel)
	targetRole, err := am.adminRepo.GetAdminRoleByName(ctx, roleName)
	if err != nil {
		return nil, fmt.Errorf("failed to get target admin role: %w", err)
	}

	// Assign new admin role
	err = am.adminRepo.AssignAdminRole(ctx, req.UserID, targetRole.ID, req.PromotedBy)
	if err != nil {
		return nil, fmt.Errorf("failed to assign admin role: %w", err)
	}

	// Log promotion in user metadata
	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}
	user.Metadata["last_promotion"] = map[string]interface{}{
		"from":        previousLevel,
		"to":          req.ToLevel,
		"promoted_by": req.PromotedBy,
		"promoted_at": time.Now(),
		"reason":      req.Reason,
	}

	// Update user metadata
	updateReq := &auth.UpdateUserRequest{
		Metadata: user.Metadata,
	}
	_, err = am.userRepo.Update(ctx, req.UserID, updateReq)
	if err != nil {
		// Log error but don't fail the promotion
		fmt.Printf("Warning: failed to update user metadata: %v\n", err)
	}

	return &PromoteAdminResponse{
		UserID:        req.UserID,
		PreviousLevel: previousLevel,
		NewLevel:      req.ToLevel,
		PromotedAt:    time.Now(),
		PromotedBy:    req.PromotedBy,
		Reason:        req.Reason,
	}, nil
}

// DemoteAdmin demotes an admin to a lower level or removes admin status
func (am *AdminManager) DemoteAdmin(ctx context.Context, req *DemoteAdminRequest) (*DemoteAdminResponse, error) {
	// Check if user exists and is an admin
	user, err := am.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Get current admin level
	currentLevel, err := am.adminRepo.GetUserAdminLevel(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("user is not an admin: %w", err)
	}

	// Validate demotion is allowed
	if req.ToLevel != nil && !am.isValidDemotion(currentLevel, *req.ToLevel) {
		return nil, fmt.Errorf("invalid demotion from %s to %s", currentLevel, *req.ToLevel)
	}

	// Get current role ID
	currentRoles, err := am.adminRepo.GetUserAdminRoles(ctx, req.UserID)
	if err != nil || len(currentRoles) == 0 {
		return nil, fmt.Errorf("failed to get current admin roles: %w", err)
	}

	// Perform demotion
	if req.ToLevel == nil {
		// Remove admin status entirely - revoke all roles
		for _, role := range currentRoles {
			err = am.adminRepo.RevokeAdminRole(ctx, req.UserID, role.ID, req.DemotedBy)
			if err != nil {
				return nil, fmt.Errorf("failed to revoke admin role %s: %w", role.ID, err)
			}
		}
	} else {
		// Demote to lower level - revoke current roles and assign new one
		for _, role := range currentRoles {
			err = am.adminRepo.RevokeAdminRole(ctx, req.UserID, role.ID, req.DemotedBy)
			if err != nil {
				return nil, fmt.Errorf("failed to revoke admin role %s: %w", role.ID, err)
			}
		}

		// Get new role ID
		newRoleName := am.adminLevelToRoleName(*req.ToLevel)
		newRole, err := am.adminRepo.GetAdminRoleByName(ctx, newRoleName)
		if err != nil {
			return nil, fmt.Errorf("failed to get new admin role: %w", err)
		}

		err = am.adminRepo.AssignAdminRole(ctx, req.UserID, newRole.ID, req.DemotedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to assign new admin role: %w", err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to demote admin: %w", err)
	}

	// Log demotion in user metadata
	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}
	user.Metadata["last_demotion"] = map[string]interface{}{
		"from":       currentLevel,
		"to":         req.ToLevel,
		"demoted_by": req.DemotedBy,
		"demoted_at": time.Now(),
		"reason":     req.Reason,
	}

	// Update user metadata
	updateReq := &auth.UpdateUserRequest{
		Metadata: user.Metadata,
	}
	_, err = am.userRepo.Update(ctx, req.UserID, updateReq)
	if err != nil {
		// Log error but don't fail the demotion
		fmt.Printf("Warning: failed to update user metadata: %v\n", err)
	}

	return &DemoteAdminResponse{
		UserID:        req.UserID,
		PreviousLevel: currentLevel,
		NewLevel:      req.ToLevel,
		DemotedAt:     time.Now(),
		DemotedBy:     req.DemotedBy,
		Reason:        req.Reason,
	}, nil
}

// ListAdmins lists all administrators with optional filtering
func (am *AdminManager) ListAdmins(ctx context.Context, filter *AdminFilter) ([]*AdminInfo, error) {
	// Get all admin users - for now, we'll implement a simple version
	// In a full implementation, this would be a proper method in AdminRepository
	admins, err := am.listAdminsSimple(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list admins: %w", err)
	}

	var result []*AdminInfo
	for _, admin := range admins {
		// Get user details
		user, err := am.userRepo.GetByID(ctx, admin.UserID)
		if err != nil {
			continue // Skip if user not found
		}

		// Get capabilities
		capabilities, err := am.adminRepo.GetUserAdminCapabilities(ctx, admin.UserID)
		if err != nil {
			capabilities = &auth.AdminCapabilities{} // Default empty capabilities
		}

		adminInfo := &AdminInfo{
			ID:           admin.UserID,
			Email:        getStringValue(user.Email),
			Username:     getStringValue(user.Username),
			AdminLevel:   admin.AdminLevel,
			IsActive:     admin.IsActive,
			CreatedAt:    admin.CreatedAt,
			LastActiveAt: admin.LastActiveAt,
			Capabilities: *capabilities,
		}

		result = append(result, adminInfo)
	}

	return result, nil
}

// isValidPromotion checks if a promotion from one level to another is valid
func (am *AdminManager) isValidPromotion(from, to auth.AdminLevel) bool {
	// Define promotion hierarchy
	hierarchy := map[auth.AdminLevel]int{
		auth.Moderator:    1,
		auth.RegularAdmin: 2,
		auth.SuperAdmin:   3,
		auth.SystemAdmin:  4,
	}

	fromLevel, fromExists := hierarchy[from]
	toLevel, toExists := hierarchy[to]

	// Both levels must be valid and promotion must be upward
	return fromExists && toExists && toLevel > fromLevel
}

// isValidDemotion checks if a demotion from one level to another is valid
func (am *AdminManager) isValidDemotion(from, to auth.AdminLevel) bool {
	// Define demotion hierarchy
	hierarchy := map[auth.AdminLevel]int{
		auth.Moderator:    1,
		auth.RegularAdmin: 2,
		auth.SuperAdmin:   3,
		auth.SystemAdmin:  4,
	}

	fromLevel, fromExists := hierarchy[from]
	toLevel, toExists := hierarchy[to]

	// Both levels must be valid and demotion must be downward
	return fromExists && toExists && toLevel < fromLevel
}

// getStringValue safely gets string value from pointer
func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// listAdminsSimple provides a simple implementation of listing admins
// In a full implementation, this would be in the AdminRepository
func (am *AdminManager) listAdminsSimple(ctx context.Context, filter *AdminFilter) ([]*AdminListItem, error) {
	// This is a placeholder implementation
	// In reality, you would query the database for admin users
	return []*AdminListItem{}, nil
}

// AdminListItem represents an admin in the list
type AdminListItem struct {
	UserID       string          `json:"user_id"`
	AdminLevel   auth.AdminLevel `json:"admin_level"`
	IsActive     bool            `json:"is_active"`
	CreatedAt    time.Time       `json:"created_at"`
	LastActiveAt *time.Time      `json:"last_active_at"`
}

// adminLevelToRoleName converts AdminLevel to the actual role name in the database
func (am *AdminManager) adminLevelToRoleName(level auth.AdminLevel) string {
	switch level {
	case auth.SystemAdmin:
		return "System Admin"
	case auth.SuperAdmin:
		return "Super Admin"
	case auth.RegularAdmin:
		return "Regular Admin"
	case auth.Moderator:
		return "Moderator"
	default:
		return "Moderator"
	}
}
