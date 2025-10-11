package auth

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// RBACService defines the role-based access control interface
type RBACService interface {
	// Authorization checks
	CanPerformAction(ctx context.Context, userID uuid.UUID, action string, resource string, resourceID *string) (bool, error)
	CanAccessTable(ctx context.Context, userID uuid.UUID, tableName string, operation TableOperation) (bool, error)
	CanManageUser(ctx context.Context, adminID uuid.UUID, targetUserID uuid.UUID) (bool, error)
	CanPromoteToLevel(ctx context.Context, promoterID uuid.UUID, targetLevel AdminLevel) (bool, error)

	// Capability checks
	HasCapability(ctx context.Context, userID uuid.UUID, capability string) (bool, error)
	GetUserCapabilities(ctx context.Context, userID uuid.UUID) (*AdminCapabilities, error)

	// Context-aware authorization
	CreateAuthContext(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*AuthContext, error)
	ValidateAuthContext(ctx context.Context, authCtx *AuthContext) error

	// Admin hierarchy
	GetAdminHierarchy(ctx context.Context, userID uuid.UUID) (*AdminHierarchy, error)
	IsHigherInHierarchy(ctx context.Context, adminID uuid.UUID, targetUserID uuid.UUID) (bool, error)

	// Cache management
	InvalidateUserCache(userID uuid.UUID)
	ClearCache()
}

// TableOperation represents database table operations
type TableOperation string

const (
	TableOperationRead   TableOperation = "read"
	TableOperationCreate TableOperation = "create"
	TableOperationUpdate TableOperation = "update"
	TableOperationDelete TableOperation = "delete"
)

// AuthContext represents the authorization context for a request
type AuthContext struct {
	UserID      uuid.UUID              `json:"user_id"`
	User        *UnifiedUser           `json:"user"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	SessionID   *uuid.UUID             `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Permissions map[string]interface{} `json:"permissions"`
}

// AdminHierarchy represents the admin hierarchy information
type AdminHierarchy struct {
	UserID       uuid.UUID   `json:"user_id"`
	AdminLevel   AdminLevel  `json:"admin_level"`
	HierarchyNum int         `json:"hierarchy_num"`
	CanManage    []uuid.UUID `json:"can_manage"`
	ManagedBy    []uuid.UUID `json:"managed_by"`
}

// CachedUserAuth represents cached user authorization data
type CachedUserAuth struct {
	User         *UnifiedUser       `json:"user"`
	Capabilities *AdminCapabilities `json:"capabilities"`
	CachedAt     time.Time          `json:"cached_at"`
	ExpiresAt    time.Time          `json:"expires_at"`
}

// rbacService implements the RBACService interface
type rbacService struct {
	repo      Repository
	cache     map[uuid.UUID]*CachedUserAuth
	cacheMux  sync.RWMutex
	cacheTime time.Duration
}

// NewRBACService creates a new RBAC service
func NewRBACService(repo Repository) RBACService {
	return &rbacService{
		repo:      repo,
		cache:     make(map[uuid.UUID]*CachedUserAuth),
		cacheTime: 5 * time.Minute, // Cache for 5 minutes
	}
}

// CanPerformAction checks if a user can perform a specific action on a resource
func (r *rbacService) CanPerformAction(ctx context.Context, userID uuid.UUID, action string, resource string, resourceID *string) (bool, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return false, err
	}

	// Non-admin users have limited permissions
	if !user.IsAdmin() {
		return r.checkNonAdminPermissions(action, resource, user, resourceID)
	}

	// Check admin capabilities based on action and resource
	return r.checkAdminPermissions(ctx, user, action, resource, resourceID)
}

// CanAccessTable checks if a user can access a specific table with the given operation
func (r *rbacService) CanAccessTable(ctx context.Context, userID uuid.UUID, tableName string, operation TableOperation) (bool, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return false, err
	}

	// Non-admin users cannot access admin tables
	if !user.IsAdmin() {
		return r.checkTableAccessForNonAdmin(tableName, operation)
	}

	// System and super admins can access all tables
	if user.IsSuperAdmin() {
		return true, nil
	}

	// Regular admins and moderators can only access assigned tables
	if user.IsRegularAdmin() {
		return user.CanAccessTable(tableName), nil
	}

	return false, nil
}

// CanManageUser checks if an admin can manage a specific user
func (r *rbacService) CanManageUser(ctx context.Context, adminID uuid.UUID, targetUserID uuid.UUID) (bool, error) {
	admin, err := r.getCachedUser(ctx, adminID)
	if err != nil {
		return false, err
	}

	targetUser, err := r.getCachedUser(ctx, targetUserID)
	if err != nil {
		return false, err
	}

	return admin.CanManageUser(targetUser), nil
}

// CanPromoteToLevel checks if a user can promote someone to a specific admin level
func (r *rbacService) CanPromoteToLevel(ctx context.Context, promoterID uuid.UUID, targetLevel AdminLevel) (bool, error) {
	promoter, err := r.getCachedUser(ctx, promoterID)
	if err != nil {
		return false, err
	}

	return ValidateAdminPromotion(promoter, targetLevel) == nil, nil
}

// HasCapability checks if a user has a specific capability
func (r *rbacService) HasCapability(ctx context.Context, userID uuid.UUID, capability string) (bool, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return false, err
	}

	return user.HasCapability(capability), nil
}

// GetUserCapabilities returns the capabilities for a user
func (r *rbacService) GetUserCapabilities(ctx context.Context, userID uuid.UUID) (*AdminCapabilities, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if user.Capabilities == nil {
		// Return empty capabilities for non-admin users
		return &AdminCapabilities{
			CanUpdateProfile: true,
		}, nil
	}

	return user.Capabilities, nil
}

// CreateAuthContext creates an authorization context for a request
func (r *rbacService) CreateAuthContext(ctx context.Context, userID uuid.UUID, ipAddress, userAgent string) (*AuthContext, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Generate request ID
	requestID := uuid.New().String()

	// Create permissions map based on user capabilities
	permissions := make(map[string]interface{})
	if user.Capabilities != nil {
		permissions["admin_level"] = user.AdminLevel
		permissions["capabilities"] = user.Capabilities
		permissions["assigned_tables"] = user.AssignedTables
	}

	authCtx := &AuthContext{
		UserID:      userID,
		User:        user,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		RequestID:   requestID,
		Timestamp:   time.Now().UTC(),
		Permissions: permissions,
	}

	return authCtx, nil
}

// ValidateAuthContext validates an authorization context
func (r *rbacService) ValidateAuthContext(ctx context.Context, authCtx *AuthContext) error {
	if authCtx == nil {
		return errors.NewAuthError("authorization context is required")
	}

	// Check if context is too old (prevent replay attacks)
	if time.Since(authCtx.Timestamp) > 5*time.Minute {
		return errors.NewAuthError("authorization context has expired")
	}

	// Validate user still exists and has same permissions
	currentUser, err := r.getCachedUser(ctx, authCtx.UserID)
	if err != nil {
		return errors.Wrap(err, "failed to validate user in auth context")
	}

	// Check if user's admin level has changed
	if authCtx.User.AdminLevel != currentUser.AdminLevel {
		return errors.NewAuthError("user admin level has changed, context invalid")
	}

	// Check if user is locked
	if currentUser.IsLocked() {
		return errors.NewAuthError("user account is locked")
	}

	return nil
}

// GetAdminHierarchy returns the admin hierarchy information for a user
func (r *rbacService) GetAdminHierarchy(ctx context.Context, userID uuid.UUID) (*AdminHierarchy, error) {
	user, err := r.getCachedUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, errors.NewAuthError("user is not an admin")
	}

	hierarchy := &AdminHierarchy{
		UserID:       userID,
		AdminLevel:   *user.AdminLevel,
		HierarchyNum: user.AdminLevel.GetHierarchy(),
		CanManage:    []uuid.UUID{},
		ManagedBy:    []uuid.UUID{},
	}

	// Get users this admin can manage
	canManage, err := r.getUsersCanManage(ctx, user)
	if err == nil {
		hierarchy.CanManage = canManage
	}

	// Get users who can manage this admin
	managedBy, err := r.getUsersWhoCanManage(ctx, user)
	if err == nil {
		hierarchy.ManagedBy = managedBy
	}

	return hierarchy, nil
}

// IsHigherInHierarchy checks if one admin is higher in hierarchy than another
func (r *rbacService) IsHigherInHierarchy(ctx context.Context, adminID uuid.UUID, targetUserID uuid.UUID) (bool, error) {
	admin, err := r.getCachedUser(ctx, adminID)
	if err != nil {
		return false, err
	}

	targetUser, err := r.getCachedUser(ctx, targetUserID)
	if err != nil {
		return false, err
	}

	// Non-admin cannot be higher than anyone
	if !admin.IsAdmin() {
		return false, nil
	}

	// If target is not admin, admin is higher
	if !targetUser.IsAdmin() {
		return true, nil
	}

	// Compare hierarchy levels
	return admin.AdminLevel.IsHigherThan(*targetUser.AdminLevel), nil
}

// InvalidateUserCache removes a user from the cache
func (r *rbacService) InvalidateUserCache(userID uuid.UUID) {
	r.cacheMux.Lock()
	defer r.cacheMux.Unlock()
	delete(r.cache, userID)
}

// ClearCache clears the entire cache
func (r *rbacService) ClearCache() {
	r.cacheMux.Lock()
	defer r.cacheMux.Unlock()
	r.cache = make(map[uuid.UUID]*CachedUserAuth)
}

// Helper methods

// getCachedUser retrieves a user from cache or database
func (r *rbacService) getCachedUser(ctx context.Context, userID uuid.UUID) (*UnifiedUser, error) {
	r.cacheMux.RLock()
	cached, exists := r.cache[userID]
	r.cacheMux.RUnlock()

	// Check if cached data is valid
	if exists && cached.ExpiresAt.After(time.Now()) {
		return cached.User, nil
	}

	// Fetch from database
	user, err := r.repo.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Cache the user
	r.cacheMux.Lock()
	r.cache[userID] = &CachedUserAuth{
		User:         user,
		Capabilities: user.Capabilities,
		CachedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(r.cacheTime),
	}
	r.cacheMux.Unlock()

	return user, nil
}

// checkNonAdminPermissions checks permissions for non-admin users
func (r *rbacService) checkNonAdminPermissions(action string, resource string, user *UnifiedUser, resourceID *string) (bool, error) {
	// Non-admin users can only perform limited actions
	switch action {
	case "read_profile", "update_profile":
		// Users can read/update their own profile
		if resourceID != nil && *resourceID == user.ID.String() {
			return true, nil
		}
		return false, nil
	case "read_public":
		// Users can read public resources
		return true, nil
	default:
		return false, nil
	}
}

// checkAdminPermissions checks permissions for admin users
func (r *rbacService) checkAdminPermissions(ctx context.Context, user *UnifiedUser, action string, resource string, resourceID *string) (bool, error) {
	if user.Capabilities == nil {
		return false, nil
	}

	// Map actions to capabilities
	switch {
	case strings.HasPrefix(action, "sql_"):
		return user.Capabilities.CanAccessSQL, nil
	case strings.HasPrefix(action, "database_"):
		return user.Capabilities.CanManageDatabase, nil
	case strings.HasPrefix(action, "system_"):
		return user.Capabilities.CanManageSystem, nil
	case strings.HasPrefix(action, "admin_"):
		return user.Capabilities.CanCreateAdmins, nil
	case strings.HasPrefix(action, "user_"):
		return user.Capabilities.CanManageUsers, nil
	case strings.HasPrefix(action, "table_"):
		return user.Capabilities.CanManageAllTables, nil
	case strings.HasPrefix(action, "storage_"):
		return user.Capabilities.CanManageStorage, nil
	case strings.HasPrefix(action, "template_"):
		return user.Capabilities.CanManageTemplates, nil
	case strings.HasPrefix(action, "cron_"):
		return user.Capabilities.CanManageCronJobs, nil
	case strings.HasPrefix(action, "audit_"):
		return user.Capabilities.CanViewAllLogs, nil
	case strings.HasPrefix(action, "security_"):
		return user.Capabilities.CanModifySecurityConfig, nil
	case strings.HasPrefix(action, "plugin_"):
		return user.Capabilities.CanInstallPlugins, nil
	default:
		// Default to basic dashboard access
		return user.Capabilities.CanViewDashboard, nil
	}
}

// checkTableAccessForNonAdmin checks table access for non-admin users
func (r *rbacService) checkTableAccessForNonAdmin(tableName string, operation TableOperation) (bool, error) {
	// Define public tables that non-admin users can access
	publicTables := map[string][]TableOperation{
		"public_content": {TableOperationRead},
		"user_profiles":  {TableOperationRead, TableOperationUpdate}, // Users can update their own profiles
	}

	allowedOps, exists := publicTables[tableName]
	if !exists {
		return false, nil
	}

	for _, allowedOp := range allowedOps {
		if allowedOp == operation {
			return true, nil
		}
	}

	return false, nil
}

// getUsersCanManage returns list of users this admin can manage
func (r *rbacService) getUsersCanManage(ctx context.Context, admin *UnifiedUser) ([]uuid.UUID, error) {
	var canManage []uuid.UUID

	// System admins can manage everyone
	if admin.IsSystemAdmin() {
		// For performance, we'll return a placeholder indicating "all users"
		// In a real implementation, you might want to paginate this
		return []uuid.UUID{}, nil // Empty slice indicates all users
	}

	// Get users based on admin level
	filter := &UserFilter{Limit: 1000} // Reasonable limit

	if admin.IsSuperAdmin() {
		// Super admins can manage non-system-admins
		users, err := r.repo.ListUsers(ctx, filter)
		if err != nil {
			return nil, err
		}

		for _, user := range users {
			if user.AdminLevel == nil || *user.AdminLevel != AdminLevelSystemAdmin {
				canManage = append(canManage, user.ID)
			}
		}
	} else if admin.IsRegularAdmin() {
		// Regular admins can manage non-admins and moderators
		users, err := r.repo.ListUsers(ctx, filter)
		if err != nil {
			return nil, err
		}

		for _, user := range users {
			if user.AdminLevel == nil || *user.AdminLevel == AdminLevelModerator {
				canManage = append(canManage, user.ID)
			}
		}
	}

	return canManage, nil
}

// getUsersWhoCanManage returns list of users who can manage this admin
func (r *rbacService) getUsersWhoCanManage(ctx context.Context, user *UnifiedUser) ([]uuid.UUID, error) {
	var managedBy []uuid.UUID

	if !user.IsAdmin() {
		// Non-admin users can be managed by all admins
		adminFilter := &AdminFilter{Limit: 1000}
		admins, err := r.repo.ListAdmins(ctx, adminFilter)
		if err != nil {
			return nil, err
		}

		for _, admin := range admins {
			managedBy = append(managedBy, admin.ID)
		}
		return managedBy, nil
	}

	// Get admins who can manage this admin based on hierarchy
	adminFilter := &AdminFilter{Limit: 1000}
	admins, err := r.repo.ListAdmins(ctx, adminFilter)
	if err != nil {
		return nil, err
	}

	for _, admin := range admins {
		if admin.CanManageUser(user) {
			managedBy = append(managedBy, admin.ID)
		}
	}

	return managedBy, nil
}

// AuthorizationMiddleware creates middleware for authorization checks
func (r *rbacService) AuthorizationMiddleware(requiredAction string, requiredResource string) func(ctx context.Context, userID uuid.UUID) error {
	return func(ctx context.Context, userID uuid.UUID) error {
		allowed, err := r.CanPerformAction(ctx, userID, requiredAction, requiredResource, nil)
		if err != nil {
			return err
		}

		if !allowed {
			return errors.NewAuthError(fmt.Sprintf("insufficient permissions for action: %s on resource: %s", requiredAction, requiredResource))
		}

		return nil
	}
}

// TableAuthorizationMiddleware creates middleware for table access authorization
func (r *rbacService) TableAuthorizationMiddleware(tableName string, operation TableOperation) func(ctx context.Context, userID uuid.UUID) error {
	return func(ctx context.Context, userID uuid.UUID) error {
		allowed, err := r.CanAccessTable(ctx, userID, tableName, operation)
		if err != nil {
			return err
		}

		if !allowed {
			return errors.NewAuthError(fmt.Sprintf("insufficient permissions for %s operation on table: %s", operation, tableName))
		}

		return nil
	}
}

// CapabilityMiddleware creates middleware for capability checks
func (r *rbacService) CapabilityMiddleware(requiredCapability string) func(ctx context.Context, userID uuid.UUID) error {
	return func(ctx context.Context, userID uuid.UUID) error {
		hasCapability, err := r.HasCapability(ctx, userID, requiredCapability)
		if err != nil {
			return err
		}

		if !hasCapability {
			return errors.NewAuthError(fmt.Sprintf("missing required capability: %s", requiredCapability))
		}

		return nil
	}
}
