package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AdminRole represents hierarchical admin roles
type AdminRole struct {
	ID           string            `json:"id" db:"id"`
	Name         string            `json:"name" db:"name"`
	Level        AdminLevel        `json:"level" db:"level"`
	Capabilities AdminCapabilities `json:"capabilities" db:"capabilities"`
	CreatedBy    string            `json:"created_by" db:"created_by"`
	CreatedAt    time.Time         `json:"created_at" db:"created_at"`
	IsSystemRole bool              `json:"is_system_role" db:"is_system_role"`
	Description  string            `json:"description" db:"description"`
}

// UserAdminRole represents the assignment of admin roles to users
type UserAdminRole struct {
	ID        string            `json:"id" db:"id"`
	UserID    string            `json:"user_id" db:"user_id"`
	RoleID    string            `json:"role_id" db:"role_id"`
	GrantedBy string            `json:"granted_by" db:"granted_by"`
	GrantedAt time.Time         `json:"granted_at" db:"granted_at"`
	ExpiresAt *time.Time        `json:"expires_at" db:"expires_at"`
	IsActive  bool              `json:"is_active" db:"is_active"`
	Metadata  map[string]string `json:"metadata" db:"metadata"`
}

// PermissionCache represents cached permission results
type PermissionCache struct {
	UserID    string    `json:"user_id"`
	Resource  string    `json:"resource"`
	Action    string    `json:"action"`
	Result    bool      `json:"result"`
	ExpiresAt time.Time `json:"expires_at"`
	Context   string    `json:"context"` // Hash of security context
}

// RBACEngine interface defines role-based access control operations
type RBACEngine interface {
	// Role management
	CreateRole(ctx context.Context, role AdminRole) error
	UpdateRole(ctx context.Context, roleID string, updates AdminRole) error
	DeleteRole(ctx context.Context, roleID string) error
	GetRole(ctx context.Context, roleID string) (*AdminRole, error)
	ListRoles(ctx context.Context) ([]*AdminRole, error)

	// Role assignment
	AssignRole(ctx context.Context, userID string, roleID string, grantedBy string) error
	RevokeRole(ctx context.Context, userID string, roleID string, revokedBy string) error
	GetUserRoles(ctx context.Context, userID string) ([]*AdminRole, error)
	GetRoleUsers(ctx context.Context, roleID string) ([]*User, error)

	// Permission evaluation
	CheckPermission(ctx context.Context, userID string, resource string, action string, context SecurityContext) (bool, error)
	GetUserCapabilities(ctx context.Context, userID string) (*AdminCapabilities, error)
	EvaluatePolicy(ctx context.Context, policy SecurityPolicy, context SecurityContext) (bool, error)

	// Hierarchy management
	GetRoleHierarchy(ctx context.Context) (map[AdminLevel][]*AdminRole, error)
	CanUserManageRole(ctx context.Context, userID string, targetRoleLevel AdminLevel) (bool, error)
	GetEffectivePermissions(ctx context.Context, userID string) (*AdminCapabilities, error)

	// Cache management
	InvalidateUserCache(ctx context.Context, userID string) error
	InvalidateResourceCache(ctx context.Context, resource string) error
	GetCacheStats(ctx context.Context) (map[string]interface{}, error)
}

// SecurityPolicy represents a security policy for evaluation
type SecurityPolicy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rules       []PolicyRule           `json:"rules"`
	Conditions  map[string]interface{} `json:"conditions"`
	Effect      PolicyEffect           `json:"effect"`
	Priority    int                    `json:"priority"`
	IsActive    bool                   `json:"is_active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// PolicyRule represents a rule within a security policy
type PolicyRule struct {
	Resource   string       `json:"resource"`
	Actions    []string     `json:"actions"`
	Conditions []string     `json:"conditions"`
	Effect     PolicyEffect `json:"effect"`
}

// PolicyEffect represents the effect of a policy rule
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// RBACEngineImpl implements the RBACEngine interface
type RBACEngineImpl struct {
	userRepo        UserRepositoryInterface
	adminRepo       *AdminRepository
	permissionCache *PermissionCacheImpl
	roleHierarchy   map[AdminLevel]int // Level priority for hierarchy
}

// NewRBACEngine creates a new RBAC engine
func NewRBACEngine(userRepo UserRepositoryInterface, adminRepo *AdminRepository) RBACEngine {
	return &RBACEngineImpl{
		userRepo:        userRepo,
		adminRepo:       adminRepo,
		permissionCache: NewPermissionCache(),
		roleHierarchy: map[AdminLevel]int{
			SystemAdmin:  4, // Highest priority
			SuperAdmin:   3,
			RegularAdmin: 2,
			Moderator:    1, // Lowest priority
		},
	}
}

// CreateRole creates a new admin role
func (rbac *RBACEngineImpl) CreateRole(ctx context.Context, role AdminRole) error {
	// Validate role data
	if role.Name == "" {
		return fmt.Errorf("role name is required")
	}

	// Set default values
	if role.ID == "" {
		role.ID = uuid.New().String()
	}
	role.CreatedAt = time.Now()

	// Create role using admin repository
	return rbac.adminRepo.CreateAdminRole(ctx, &role)
}

// UpdateRole updates an existing admin role
func (rbac *RBACEngineImpl) UpdateRole(ctx context.Context, roleID string, updates AdminRole) error {
	// TODO: Implement database update
	// This would update the role in admin_roles table
	return fmt.Errorf("role update not implemented")
}

// DeleteRole deletes an admin role
func (rbac *RBACEngineImpl) DeleteRole(ctx context.Context, roleID string) error {
	// TODO: Implement database deletion
	// This would:
	// 1. Check if role is in use
	// 2. Prevent deletion of system roles
	// 3. Delete from admin_roles table
	return fmt.Errorf("role deletion not implemented")
}

// GetRole retrieves a role by ID
func (rbac *RBACEngineImpl) GetRole(ctx context.Context, roleID string) (*AdminRole, error) {
	// For now, we'll implement a simple lookup by querying all roles
	// In a full implementation, this would be a direct database query
	roles, err := rbac.ListRoles(ctx)
	if err != nil {
		return nil, err
	}

	for _, role := range roles {
		if role.ID == roleID {
			return role, nil
		}
	}

	return nil, fmt.Errorf("role not found: %s", roleID)
}

// ListRoles lists all admin roles
func (rbac *RBACEngineImpl) ListRoles(ctx context.Context) ([]*AdminRole, error) {
	// Get roles for each level and combine them
	var allRoles []*AdminRole

	levels := []AdminLevel{SystemAdmin, SuperAdmin, RegularAdmin, Moderator}
	for _, level := range levels {
		roles, err := rbac.adminRepo.GetAdminRolesByLevel(ctx, level)
		if err != nil {
			return nil, fmt.Errorf("failed to get roles for level %s: %w", level, err)
		}
		allRoles = append(allRoles, roles...)
	}

	return allRoles, nil
}

// AssignRole assigns a role to a user
func (rbac *RBACEngineImpl) AssignRole(ctx context.Context, userID string, roleID string, grantedBy string) error {
	// Validate that user exists
	_, err := rbac.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Assign role using admin repository
	err = rbac.adminRepo.AssignAdminRole(ctx, userID, roleID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	// Invalidate user's permission cache
	rbac.InvalidateUserCache(ctx, userID)

	return nil
}

// RevokeRole revokes a role from a user
func (rbac *RBACEngineImpl) RevokeRole(ctx context.Context, userID string, roleID string, revokedBy string) error {
	// Revoke role using admin repository
	err := rbac.adminRepo.RevokeAdminRole(ctx, userID, roleID, revokedBy)
	if err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	// Invalidate user's permission cache
	rbac.InvalidateUserCache(ctx, userID)

	return nil
}

// GetUserRoles retrieves all roles assigned to a user
func (rbac *RBACEngineImpl) GetUserRoles(ctx context.Context, userID string) ([]*AdminRole, error) {
	return rbac.adminRepo.GetUserAdminRoles(ctx, userID)
}

// GetRoleUsers retrieves all users assigned to a role
func (rbac *RBACEngineImpl) GetRoleUsers(ctx context.Context, roleID string) ([]*User, error) {
	// TODO: Implement database query
	// This would join user_admin_roles with users
	return nil, fmt.Errorf("role users retrieval not implemented")
}

// CheckPermission checks if a user has permission to perform an action on a resource
func (rbac *RBACEngineImpl) CheckPermission(ctx context.Context, userID string, resource string, action string, securityContext SecurityContext) (bool, error) {
	// Check cache first
	contextHash := rbac.hashSecurityContext(securityContext)
	if cached := rbac.permissionCache.Get(userID, resource, action, contextHash); cached != nil {
		return cached.Result, nil
	}

	// Get user capabilities
	capabilities, err := rbac.GetUserCapabilities(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user capabilities: %w", err)
	}

	// Evaluate permission based on resource and action
	result := rbac.evaluatePermission(capabilities, resource, action, securityContext)

	// Cache the result
	rbac.permissionCache.Set(userID, resource, action, contextHash, result, 5*time.Minute)

	return result, nil
}

// GetUserCapabilities retrieves effective capabilities for a user
func (rbac *RBACEngineImpl) GetUserCapabilities(ctx context.Context, userID string) (*AdminCapabilities, error) {
	return rbac.adminRepo.GetUserAdminCapabilities(ctx, userID)
}

// EvaluatePolicy evaluates a security policy against a context
func (rbac *RBACEngineImpl) EvaluatePolicy(ctx context.Context, policy SecurityPolicy, securityContext SecurityContext) (bool, error) {
	if !policy.IsActive {
		return false, nil
	}

	// Evaluate each rule in the policy
	for _, rule := range policy.Rules {
		if rbac.evaluateRule(rule, securityContext) {
			return rule.Effect == PolicyEffectAllow, nil
		}
	}

	// Default deny if no rules match
	return false, nil
}

// GetRoleHierarchy returns the role hierarchy organized by level
func (rbac *RBACEngineImpl) GetRoleHierarchy(ctx context.Context) (map[AdminLevel][]*AdminRole, error) {
	hierarchy := make(map[AdminLevel][]*AdminRole)

	// Get roles for each level
	levels := []AdminLevel{SystemAdmin, SuperAdmin, RegularAdmin, Moderator}
	for _, level := range levels {
		roles, err := rbac.adminRepo.GetAdminRolesByLevel(ctx, level)
		if err != nil {
			return nil, fmt.Errorf("failed to get roles for level %s: %w", level, err)
		}
		hierarchy[level] = roles
	}

	return hierarchy, nil
}

// CanUserManageRole checks if a user can manage roles at a specific level
func (rbac *RBACEngineImpl) CanUserManageRole(ctx context.Context, userID string, targetRoleLevel AdminLevel) (bool, error) {
	capabilities, err := rbac.GetUserCapabilities(ctx, userID)
	if err != nil {
		return false, err
	}

	// System admins can manage all roles
	if capabilities.CanManageSystem {
		return true, nil
	}

	// Super admins can manage regular admins and moderators
	if capabilities.CanCreateAdmins {
		return targetRoleLevel == RegularAdmin || targetRoleLevel == Moderator, nil
	}

	// Regular admins cannot create other admin roles
	return false, nil
}

// GetEffectivePermissions gets the effective permissions for a user
func (rbac *RBACEngineImpl) GetEffectivePermissions(ctx context.Context, userID string) (*AdminCapabilities, error) {
	return rbac.GetUserCapabilities(ctx, userID)
}

// InvalidateUserCache invalidates all cached permissions for a user
func (rbac *RBACEngineImpl) InvalidateUserCache(ctx context.Context, userID string) error {
	rbac.permissionCache.InvalidateUser(userID)
	return nil
}

// InvalidateResourceCache invalidates all cached permissions for a resource
func (rbac *RBACEngineImpl) InvalidateResourceCache(ctx context.Context, resource string) error {
	rbac.permissionCache.InvalidateResource(resource)
	return nil
}

// GetCacheStats returns cache statistics
func (rbac *RBACEngineImpl) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	return rbac.permissionCache.GetStats(), nil
}

// Helper methods

// evaluatePermission evaluates if capabilities allow a specific action on a resource
func (rbac *RBACEngineImpl) evaluatePermission(capabilities *AdminCapabilities, resource string, action string, context SecurityContext) bool {
	// System-level permissions
	if strings.HasPrefix(resource, "system.") {
		switch action {
		case "read", "write", "execute":
			return capabilities.CanManageSystem
		case "sql.execute":
			return capabilities.CanAccessSQL
		case "database.manage":
			return capabilities.CanManageDatabase
		}
	}

	// Admin management permissions
	if strings.HasPrefix(resource, "admin.") {
		switch action {
		case "create", "update", "delete":
			return capabilities.CanCreateAdmins || capabilities.CanCreateSuperAdmin
		case "read":
			return capabilities.CanViewAllLogs || capabilities.CanViewBasicLogs
		}
	}

	// Table management permissions
	if strings.HasPrefix(resource, "table.") {
		tableName := strings.TrimPrefix(resource, "table.")
		switch action {
		case "read", "write", "configure":
			if capabilities.CanManageAllTables {
				return true
			}
			// Check if table is in assigned tables
			for _, assignedTable := range capabilities.AssignedTables {
				if assignedTable == tableName || assignedTable == "*" {
					return true
				}
			}
		}
	}

	// User management permissions
	if strings.HasPrefix(resource, "user.") {
		switch action {
		case "create", "update", "delete", "read":
			return capabilities.CanManageUsers
		}
	}

	// Storage permissions
	if strings.HasPrefix(resource, "storage.") {
		switch action {
		case "read", "write", "delete":
			return capabilities.CanManageStorage
		}
	}

	// Auth permissions
	if strings.HasPrefix(resource, "auth.") {
		switch action {
		case "configure", "manage":
			return capabilities.CanManageAuth
		}
	}

	// Dashboard and reporting
	if resource == "dashboard" {
		return capabilities.CanViewDashboard
	}

	if strings.HasPrefix(resource, "report.") {
		return capabilities.CanViewReports || capabilities.CanViewAllLogs
	}

	// Content moderation
	if strings.HasPrefix(resource, "content.") {
		switch action {
		case "moderate":
			return capabilities.CanModerateContent
		case "manage":
			return capabilities.CanManageContent
		}
	}

	// Export permissions
	if action == "export" {
		return capabilities.CanExportData
	}

	// Default deny
	return false
}

// evaluateRule evaluates a policy rule against a security context
func (rbac *RBACEngineImpl) evaluateRule(rule PolicyRule, context SecurityContext) bool {
	// Simple rule evaluation - in a full implementation, this would be more sophisticated
	// For now, just check if any conditions match
	for _, condition := range rule.Conditions {
		if rbac.evaluateCondition(condition, context) {
			return true
		}
	}
	return false
}

// evaluateCondition evaluates a condition against a security context
func (rbac *RBACEngineImpl) evaluateCondition(condition string, context SecurityContext) bool {
	// Simple condition evaluation
	// In a full implementation, this would parse and evaluate complex conditions
	switch condition {
	case "ip_whitelist":
		// Check if IP is in whitelist (placeholder)
		return true
	case "time_restriction":
		// Check time-based restrictions (placeholder)
		return true
	case "mfa_required":
		// Check if MFA is verified (placeholder)
		return true
	default:
		return false
	}
}

// mergeCapabilities merges capabilities from multiple roles
func (rbac *RBACEngineImpl) mergeCapabilities(base *AdminCapabilities, additional AdminCapabilities) {
	// Merge boolean capabilities (OR operation)
	base.CanAccessSQL = base.CanAccessSQL || additional.CanAccessSQL
	base.CanManageDatabase = base.CanManageDatabase || additional.CanManageDatabase
	base.CanManageSystem = base.CanManageSystem || additional.CanManageSystem
	base.CanCreateSuperAdmin = base.CanCreateSuperAdmin || additional.CanCreateSuperAdmin
	base.CanCreateAdmins = base.CanCreateAdmins || additional.CanCreateAdmins
	base.CanManageAllTables = base.CanManageAllTables || additional.CanManageAllTables
	base.CanManageAuth = base.CanManageAuth || additional.CanManageAuth
	base.CanManageStorage = base.CanManageStorage || additional.CanManageStorage
	base.CanViewAllLogs = base.CanViewAllLogs || additional.CanViewAllLogs
	base.CanManageUsers = base.CanManageUsers || additional.CanManageUsers
	base.CanManageContent = base.CanManageContent || additional.CanManageContent
	base.CanViewReports = base.CanViewReports || additional.CanViewReports
	base.CanModerateContent = base.CanModerateContent || additional.CanModerateContent
	base.CanViewBasicLogs = base.CanViewBasicLogs || additional.CanViewBasicLogs
	base.CanViewDashboard = base.CanViewDashboard || additional.CanViewDashboard
	base.CanExportData = base.CanExportData || additional.CanExportData

	// Merge arrays (union operation)
	base.AssignedTables = append(base.AssignedTables, additional.AssignedTables...)
	base.AssignedUserGroups = append(base.AssignedUserGroups, additional.AssignedUserGroups...)
}

// hashSecurityContext creates a hash of the security context for caching
func (rbac *RBACEngineImpl) hashSecurityContext(context SecurityContext) string {
	// Simple hash implementation - in production, use a proper hash function
	return fmt.Sprintf("%s:%s:%s", context.IPAddress, context.UserAgent, context.Environment)
}
