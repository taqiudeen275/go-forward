package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// AdminRepository handles admin-related database operations
type AdminRepository struct {
	db *database.DB
}

// NewAdminRepository creates a new admin repository
func NewAdminRepository(db *database.DB) *AdminRepository {
	return &AdminRepository{
		db: db,
	}
}

// GetUserAdminCapabilities retrieves effective admin capabilities for a user
func (r *AdminRepository) GetUserAdminCapabilities(ctx context.Context, userID string) (*AdminCapabilities, error) {
	query := `
		SELECT 
			ar.level,
			ac.capability_name,
			ac.capability_value,
			ac.resource_scope
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		JOIN admin_capabilities ac ON ar.id = ac.role_id
		WHERE uar.user_id = $1 
			AND uar.is_active = true 
			AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ar.level ASC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user admin capabilities: %w", err)
	}
	defer rows.Close()

	capabilities := &AdminCapabilities{}
	assignedTables := make(map[string]bool)
	assignedUserGroups := make(map[string]bool)
	highestLevel := 0

	for rows.Next() {
		var level int
		var capabilityName string
		var capabilityValue bool
		var resourceScopeJSON []byte

		err := rows.Scan(&level, &capabilityName, &capabilityValue, &resourceScopeJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability row: %w", err)
		}

		// Track highest level for hierarchy
		if level > highestLevel {
			highestLevel = level
		}

		// Set capability if it's true
		if capabilityValue {
			r.setCapability(capabilities, capabilityName, true)
		}

		// Handle resource scope for assigned tables/groups
		if len(resourceScopeJSON) > 0 {
			var resourceScope map[string]interface{}
			if err := json.Unmarshal(resourceScopeJSON, &resourceScope); err == nil {
				if tables, ok := resourceScope["assigned_tables"].([]interface{}); ok {
					for _, table := range tables {
						if tableStr, ok := table.(string); ok {
							assignedTables[tableStr] = true
						}
					}
				}
				if groups, ok := resourceScope["assigned_user_groups"].([]interface{}); ok {
					for _, group := range groups {
						if groupStr, ok := group.(string); ok {
							assignedUserGroups[groupStr] = true
						}
					}
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating capability rows: %w", err)
	}

	// Convert maps to slices
	for table := range assignedTables {
		capabilities.AssignedTables = append(capabilities.AssignedTables, table)
	}
	for group := range assignedUserGroups {
		capabilities.AssignedUserGroups = append(capabilities.AssignedUserGroups, group)
	}

	// If no capabilities found, user is not an admin
	if highestLevel == 0 {
		return nil, fmt.Errorf("user has no admin roles")
	}

	return capabilities, nil
}

// GetUserAdminLevel retrieves the highest admin level for a user
func (r *AdminRepository) GetUserAdminLevel(ctx context.Context, userID string) (AdminLevel, error) {
	query := `
		SELECT ar.level
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		WHERE uar.user_id = $1 
			AND uar.is_active = true 
			AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ar.level ASC
		LIMIT 1
	`

	var level int
	err := r.db.QueryRow(ctx, query, userID).Scan(&level)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("user has no admin roles")
		}
		return "", fmt.Errorf("failed to get user admin level: %w", err)
	}

	return r.levelToAdminLevel(level), nil
}

// AssignAdminRole assigns an admin role to a user
func (r *AdminRepository) AssignAdminRole(ctx context.Context, userID, roleID, grantedBy string) error {
	query := `
		INSERT INTO user_admin_roles (user_id, role_id, granted_by, granted_at, is_active)
		VALUES ($1, $2, $3, NOW(), true)
		ON CONFLICT (user_id, role_id, is_active) DO NOTHING
	`

	err := r.db.Exec(ctx, query, userID, roleID, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to assign admin role: %w", err)
	}

	return nil
}

// RevokeAdminRole revokes an admin role from a user
func (r *AdminRepository) RevokeAdminRole(ctx context.Context, userID, roleID, revokedBy string) error {
	query := `
		UPDATE user_admin_roles 
		SET is_active = false, metadata = jsonb_set(
			COALESCE(metadata, '{}'), 
			'{revoked_by}', 
			to_jsonb($4::text)
		)
		WHERE user_id = $1 AND role_id = $2 AND is_active = true
	`

	err := r.db.Exec(ctx, query, userID, roleID, revokedBy)
	if err != nil {
		return fmt.Errorf("failed to revoke admin role: %w", err)
	}

	return nil
}

// GetAdminRoleByName retrieves an admin role by name
func (r *AdminRepository) GetAdminRoleByName(ctx context.Context, name string) (*AdminRole, error) {
	query := `
		SELECT id, name, level, description, is_system_role, created_by, created_at
		FROM admin_roles
		WHERE name = $1
	`

	role := &AdminRole{}
	var levelInt int
	err := r.db.QueryRow(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&levelInt,
		&role.Description,
		&role.IsSystemRole,
		&role.CreatedBy,
		&role.CreatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("admin role not found: %s", name)
		}
		return nil, fmt.Errorf("failed to get admin role: %w", err)
	}

	// Convert level to AdminLevel
	role.Level = r.levelToAdminLevel(levelInt)

	// Get capabilities for this role
	capabilities, err := r.getRoleCapabilities(ctx, role.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role capabilities: %w", err)
	}
	role.Capabilities = *capabilities

	return role, nil
}

// GetUserAdminRoles retrieves all admin roles for a user
func (r *AdminRepository) GetUserAdminRoles(ctx context.Context, userID string) ([]*AdminRole, error) {
	query := `
		SELECT ar.id, ar.name, ar.level, ar.description, ar.is_system_role, ar.created_by, ar.created_at
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		WHERE uar.user_id = $1 
			AND uar.is_active = true 
			AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ar.level ASC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user admin roles: %w", err)
	}
	defer rows.Close()

	var roles []*AdminRole
	for rows.Next() {
		role := &AdminRole{}
		var levelInt int

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&levelInt,
			&role.Description,
			&role.IsSystemRole,
			&role.CreatedBy,
			&role.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan admin role row: %w", err)
		}

		// Convert level to AdminLevel
		role.Level = r.levelToAdminLevel(levelInt)

		// Get capabilities for this role
		capabilities, err := r.getRoleCapabilities(ctx, role.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role capabilities: %w", err)
		}
		role.Capabilities = *capabilities

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating admin role rows: %w", err)
	}

	return roles, nil
}

// CreateAdminRole creates a new admin role
func (r *AdminRepository) CreateAdminRole(ctx context.Context, role *AdminRole) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Insert role
	roleQuery := `
		INSERT INTO admin_roles (id, name, level, description, is_system_role, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err = tx.Exec(ctx, roleQuery,
		role.ID,
		role.Name,
		r.adminLevelToInt(role.Level),
		role.Description,
		role.IsSystemRole,
		role.CreatedBy,
		role.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create admin role: %w", err)
	}

	// Insert capabilities
	err = r.insertRoleCapabilities(ctx, tx, role.ID, &role.Capabilities)
	if err != nil {
		return fmt.Errorf("failed to insert role capabilities: %w", err)
	}

	return tx.Commit(ctx)
}

// Helper methods

// setCapability sets a capability field based on the capability name
func (r *AdminRepository) setCapability(capabilities *AdminCapabilities, name string, value bool) {
	switch name {
	case "can_access_sql":
		capabilities.CanAccessSQL = value
	case "can_manage_database":
		capabilities.CanManageDatabase = value
	case "can_manage_system":
		capabilities.CanManageSystem = value
	case "can_create_super_admin":
		capabilities.CanCreateSuperAdmin = value
	case "can_create_admins":
		capabilities.CanCreateAdmins = value
	case "can_manage_all_tables":
		capabilities.CanManageAllTables = value
	case "can_manage_auth":
		capabilities.CanManageAuth = value
	case "can_manage_storage":
		capabilities.CanManageStorage = value
	case "can_view_all_logs":
		capabilities.CanViewAllLogs = value
	case "can_manage_users":
		capabilities.CanManageUsers = value
	case "can_manage_content":
		capabilities.CanManageContent = value
	case "can_view_reports":
		capabilities.CanViewReports = value
	case "can_moderate_content":
		capabilities.CanModerateContent = value
	case "can_view_basic_logs":
		capabilities.CanViewBasicLogs = value
	case "can_view_dashboard":
		capabilities.CanViewDashboard = value
	case "can_export_data":
		capabilities.CanExportData = value
	}
}

// levelToAdminLevel converts integer level to AdminLevel
func (r *AdminRepository) levelToAdminLevel(level int) AdminLevel {
	switch level {
	case 1:
		return SystemAdmin
	case 2:
		return SuperAdmin
	case 3:
		return RegularAdmin
	case 4:
		return Moderator
	default:
		return Moderator
	}
}

// adminLevelToInt converts AdminLevel to integer
func (r *AdminRepository) adminLevelToInt(level AdminLevel) int {
	switch level {
	case SystemAdmin:
		return 1
	case SuperAdmin:
		return 2
	case RegularAdmin:
		return 3
	case Moderator:
		return 4
	default:
		return 4
	}
}

// getRoleCapabilities retrieves capabilities for a role
func (r *AdminRepository) getRoleCapabilities(ctx context.Context, roleID string) (*AdminCapabilities, error) {
	query := `
		SELECT capability_name, capability_value, resource_scope
		FROM admin_capabilities
		WHERE role_id = $1
	`

	rows, err := r.db.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role capabilities: %w", err)
	}
	defer rows.Close()

	capabilities := &AdminCapabilities{}
	assignedTables := make(map[string]bool)
	assignedUserGroups := make(map[string]bool)

	for rows.Next() {
		var capabilityName string
		var capabilityValue bool
		var resourceScopeJSON []byte

		err := rows.Scan(&capabilityName, &capabilityValue, &resourceScopeJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability row: %w", err)
		}

		// Set capability
		r.setCapability(capabilities, capabilityName, capabilityValue)

		// Handle resource scope
		if len(resourceScopeJSON) > 0 {
			var resourceScope map[string]interface{}
			if err := json.Unmarshal(resourceScopeJSON, &resourceScope); err == nil {
				if tables, ok := resourceScope["assigned_tables"].([]interface{}); ok {
					for _, table := range tables {
						if tableStr, ok := table.(string); ok {
							assignedTables[tableStr] = true
						}
					}
				}
				if groups, ok := resourceScope["assigned_user_groups"].([]interface{}); ok {
					for _, group := range groups {
						if groupStr, ok := group.(string); ok {
							assignedUserGroups[groupStr] = true
						}
					}
				}
			}
		}
	}

	// Convert maps to slices
	for table := range assignedTables {
		capabilities.AssignedTables = append(capabilities.AssignedTables, table)
	}
	for group := range assignedUserGroups {
		capabilities.AssignedUserGroups = append(capabilities.AssignedUserGroups, group)
	}

	return capabilities, nil
}

// insertRoleCapabilities inserts capabilities for a role
func (r *AdminRepository) insertRoleCapabilities(ctx context.Context, tx pgx.Tx, roleID string, capabilities *AdminCapabilities) error {
	capabilityMap := map[string]bool{
		"can_access_sql":         capabilities.CanAccessSQL,
		"can_manage_database":    capabilities.CanManageDatabase,
		"can_manage_system":      capabilities.CanManageSystem,
		"can_create_super_admin": capabilities.CanCreateSuperAdmin,
		"can_create_admins":      capabilities.CanCreateAdmins,
		"can_manage_all_tables":  capabilities.CanManageAllTables,
		"can_manage_auth":        capabilities.CanManageAuth,
		"can_manage_storage":     capabilities.CanManageStorage,
		"can_view_all_logs":      capabilities.CanViewAllLogs,
		"can_manage_users":       capabilities.CanManageUsers,
		"can_manage_content":     capabilities.CanManageContent,
		"can_view_reports":       capabilities.CanViewReports,
		"can_moderate_content":   capabilities.CanModerateContent,
		"can_view_basic_logs":    capabilities.CanViewBasicLogs,
		"can_view_dashboard":     capabilities.CanViewDashboard,
		"can_export_data":        capabilities.CanExportData,
	}

	// Prepare resource scope
	resourceScope := map[string]interface{}{
		"assigned_tables":      capabilities.AssignedTables,
		"assigned_user_groups": capabilities.AssignedUserGroups,
	}
	resourceScopeJSON, err := json.Marshal(resourceScope)
	if err != nil {
		return fmt.Errorf("failed to marshal resource scope: %w", err)
	}

	// Insert capabilities
	for capabilityName, capabilityValue := range capabilityMap {
		capQuery := `
			INSERT INTO admin_capabilities (role_id, capability_name, capability_value, resource_scope, created_at, updated_at)
			VALUES ($1, $2, $3, $4, NOW(), NOW())
		`

		_, err = tx.Exec(ctx, capQuery, roleID, capabilityName, capabilityValue, resourceScopeJSON)
		if err != nil {
			return fmt.Errorf("failed to insert capability %s: %w", capabilityName, err)
		}
	}

	return nil
}

// IsUserAdmin checks if a user has any admin role
func (r *AdminRepository) IsUserAdmin(ctx context.Context, userID string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM user_admin_roles uar
			JOIN admin_roles ar ON uar.role_id = ar.id
			WHERE uar.user_id = $1 
				AND uar.is_active = true 
				AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		)
	`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user is admin: %w", err)
	}

	return exists, nil
}

// GetAdminRolesByLevel retrieves all admin roles at a specific level
func (r *AdminRepository) GetAdminRolesByLevel(ctx context.Context, level AdminLevel) ([]*AdminRole, error) {
	query := `
		SELECT id, name, level, description, is_system_role, created_by, created_at
		FROM admin_roles
		WHERE level = $1
		ORDER BY name
	`

	rows, err := r.db.Query(ctx, query, r.adminLevelToInt(level))
	if err != nil {
		return nil, fmt.Errorf("failed to get admin roles by level: %w", err)
	}
	defer rows.Close()

	var roles []*AdminRole
	for rows.Next() {
		role := &AdminRole{}
		var levelInt int

		err := rows.Scan(
			&role.ID,
			&role.Name,
			&levelInt,
			&role.Description,
			&role.IsSystemRole,
			&role.CreatedBy,
			&role.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan admin role row: %w", err)
		}

		role.Level = r.levelToAdminLevel(levelInt)

		// Get capabilities for this role
		capabilities, err := r.getRoleCapabilities(ctx, role.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get role capabilities: %w", err)
		}
		role.Capabilities = *capabilities

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating admin role rows: %w", err)
	}

	return roles, nil
}
