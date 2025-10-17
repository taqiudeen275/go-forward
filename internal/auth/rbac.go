package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lib/pq"
)

// RBACEngine defines the interface for role-based access control operations
type RBACEngine interface {
	// Role management
	GetUserRoles(ctx context.Context, userID string) ([]UserAdminRole, error)
	HasRole(ctx context.Context, userID string, roleName string) (bool, error)
	GetHighestRole(ctx context.Context, userID string) (*AdminRole, error)
	GrantRole(ctx context.Context, userID string, roleID string, grantedBy string) error
	RevokeRole(ctx context.Context, userID string, roleID string, revokedBy string) error

	// Permission checking
	HasPermission(ctx context.Context, userID string, permission string) (bool, error)
	CanAccessTable(ctx context.Context, userID string, tableName string, operation string) (bool, error)
	GetTableFilters(ctx context.Context, userID string, tableName string) (map[string]interface{}, error)

	// Hierarchy checking
	CanManageUser(ctx context.Context, managerID string, targetUserID string) (bool, error)
	GetAccessibleTables(ctx context.Context, userID string) ([]string, error)
	GetUserAdminLevel(ctx context.Context, userID string) (int, error)

	// Capability checking
	HasCapability(ctx context.Context, userID string, capability string, resource string) (bool, error)
	GetUserCapabilities(ctx context.Context, userID string) ([]string, error)
}

// rbacEngine implements the RBACEngine interface
type rbacEngine struct {
	db *pgxpool.Pool
}

// NewRBACEngine creates a new RBAC engine instance
func NewRBACEngine(db *pgxpool.Pool) RBACEngine {
	return &rbacEngine{
		db: db,
	}
}

// GetUserRoles retrieves all active admin roles for a user
func (r *rbacEngine) GetUserRoles(ctx context.Context, userID string) ([]UserAdminRole, error) {
	query := `
		SELECT
			uar.id, uar.user_id, uar.role_id, uar.granted_by,
			uar.granted_at, uar.expires_at, uar.is_active,
			uar.metadata, uar.created_at, uar.updated_at,
			ar.id as "role.id", ar.name as "role.name",
			ar.level as "role.level", ar.description as "role.description",
			ar.permissions as "role.permissions", ar.is_active as "role.is_active",
			ar.created_at as "role.created_at", ar.updated_at as "role.updated_at"
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		WHERE uar.user_id = $1
		AND uar.is_active = TRUE
		AND ar.is_active = TRUE
		AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ar.level ASC
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []UserAdminRole
	for rows.Next() {
		var role UserAdminRole
		err := rows.Scan(
			&role.ID, &role.UserID, &role.RoleID, &role.GrantedBy,
			&role.GrantedAt, &role.ExpiresAt, &role.IsActive,
			&role.Metadata, &role.CreatedAt, &role.UpdatedAt,
			// Role fields would be scanned here but we'll handle them separately
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}
		roles = append(roles, role)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	// Map the nested role data
	for i := range roles {
		if roles[i].RoleID != "" {
			roles[i].Role = &AdminRole{
				ID:          roles[i].RoleID,
				Name:        "", // Will be populated by the select query
				Level:       0,  // Will be populated by the select query
				Description: "", // Will be populated by the select query
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return roles, nil
}

// HasRole checks if a user has a specific role
func (r *rbacEngine) HasRole(ctx context.Context, userID string, roleName string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM user_admin_roles uar
			JOIN admin_roles ar ON uar.role_id = ar.id
			WHERE uar.user_id = $1
			AND ar.name = $2
			AND uar.is_active = TRUE
			AND ar.is_active = TRUE
			AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		)
	`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID, roleName).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user role: %w", err)
	}

	return exists, nil
}

// GetHighestRole returns the user's highest privilege role (lowest level number)
func (r *rbacEngine) GetHighestRole(ctx context.Context, userID string) (*AdminRole, error) {
	query := `
		SELECT ar.id, ar.name, ar.level, ar.description,
			   ar.permissions, ar.is_active, ar.created_at, ar.updated_at
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		WHERE uar.user_id = $1
		AND uar.is_active = TRUE
		AND ar.is_active = TRUE
		AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ar.level ASC
		LIMIT 1
	`

	var role AdminRole
	err := r.db.QueryRow(ctx, query, userID).Scan(
		&role.ID, &role.Name, &role.Level, &role.Description,
		&role.Permissions, &role.IsActive, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil // User has no admin roles
		}
		return nil, fmt.Errorf("failed to get highest role: %w", err)
	}

	return &role, nil
}

// GrantRole assigns a role to a user
func (r *rbacEngine) GrantRole(ctx context.Context, userID string, roleID string, grantedBy string) error {
	// Check if the granter has permission to grant this role
	granterLevel, err := r.GetUserAdminLevel(ctx, grantedBy)
	if err != nil {
		return fmt.Errorf("failed to get granter admin level: %w", err)
	}

	// Get the role being granted
	var roleLevel int
	err = r.db.QueryRow(ctx, "SELECT level FROM admin_roles WHERE id = $1", roleID).Scan(&roleLevel)
	if err != nil {
		return fmt.Errorf("failed to get role level: %w", err)
	}

	// System admins can grant any role, others can only grant roles lower than their own
	if granterLevel > 1 && roleLevel <= granterLevel {
		return fmt.Errorf("insufficient privileges to grant this role")
	}

	// Check if user already has this role
	hasRole, err := r.HasRole(ctx, userID, "")
	if err != nil {
		return fmt.Errorf("failed to check existing role: %w", err)
	}

	if hasRole {
		// Update existing role assignment
		query := `
			UPDATE user_admin_roles
			SET is_active = TRUE, granted_by = $3, granted_at = NOW(), expires_at = NULL, updated_at = NOW()
			WHERE user_id = $1 AND role_id = $2
		`
		_, err = r.db.Exec(ctx, query, userID, roleID, grantedBy)
	} else {
		// Create new role assignment
		query := `
			INSERT INTO user_admin_roles (user_id, role_id, granted_by, is_active)
			VALUES ($1, $2, $3, TRUE)
		`
		_, err = r.db.Exec(ctx, query, userID, roleID, grantedBy)
	}

	if err != nil {
		return fmt.Errorf("failed to grant role: %w", err)
	}

	return nil
}

// RevokeRole removes a role from a user
func (r *rbacEngine) RevokeRole(ctx context.Context, userID string, roleID string, revokedBy string) error {
	// Check if the revoker has permission to revoke this role
	revokerLevel, err := r.GetUserAdminLevel(ctx, revokedBy)
	if err != nil {
		return fmt.Errorf("failed to get revoker admin level: %w", err)
	}

	// Get the role being revoked
	var roleLevel int
	err = r.db.QueryRow(ctx, "SELECT level FROM admin_roles WHERE id = $1", roleID).Scan(&roleLevel)
	if err != nil {
		return fmt.Errorf("failed to get role level: %w", err)
	}

	// System admins can revoke any role, others can only revoke roles lower than their own
	if revokerLevel > 1 && roleLevel <= revokerLevel {
		return fmt.Errorf("insufficient privileges to revoke this role")
	}

	// Deactivate the role assignment
	query := `
		UPDATE user_admin_roles
		SET is_active = FALSE, updated_at = NOW()
		WHERE user_id = $1 AND role_id = $2
	`

	result, err := r.db.Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to revoke role: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("role assignment not found or already inactive")
	}

	return nil
}

// HasPermission checks if a user has a specific permission
func (r *rbacEngine) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1
			FROM user_admin_roles uar
			JOIN admin_roles ar ON uar.role_id = ar.id
			WHERE uar.user_id = $1
			AND uar.is_active = TRUE
			AND ar.is_active = TRUE
			AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
			AND (
				ar.permissions ? $2
				OR ar.permissions ->> $2 = 'true'
				OR ar.name = 'system_admin'  -- System admins have all permissions
			)
		)
	`

	var exists bool
	err := r.db.QueryRow(ctx, query, userID, permission).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return exists, nil
}

// CanAccessTable checks if a user can access a specific table with the given operation
func (r *rbacEngine) CanAccessTable(ctx context.Context, userID string, tableName string, operation string) (bool, error) {
	// First check if user has admin role
	level, err := r.GetUserAdminLevel(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user admin level: %w", err)
	}

	if level == 999 {
		return false, nil // No admin role
	}

	// System admins can access any table
	if level == 1 {
		return true, nil
	}

	// Check table security configuration
	query := `
		SELECT auth_required, allowed_roles, api_permissions
		FROM table_security_config
		WHERE table_name = $1
		AND is_active = TRUE
	`

	var config struct {
		AuthRequired   bool                   `db:"auth_required"`
		AllowedRoles   pq.StringArray         `db:"allowed_roles"`
		APIPermissions map[string]interface{} `db:"api_permissions"`
	}

	err = r.db.QueryRow(ctx, query, tableName).Scan(&config.AuthRequired, &config.AllowedRoles, &config.APIPermissions)
	if err != nil {
		if err == pgx.ErrNoRows {
			// No specific config, use default permissions based on admin level
			return level <= 2, nil // Super admins and above can access
		}
		return false, fmt.Errorf("failed to get table config: %w", err)
	}

	// Get user's role name
	role, err := r.GetHighestRole(ctx, userID)
	if err != nil || role == nil {
		return false, fmt.Errorf("failed to get user role: %w", err)
	}

	// Check if role is in allowed roles
	roleAllowed := false
	for _, allowedRole := range config.AllowedRoles {
		if allowedRole == role.Name {
			roleAllowed = true
			break
		}
	}

	if !roleAllowed {
		return false, nil
	}

	// Check specific operation permission
	if rolePerms, ok := config.APIPermissions[role.Name]; ok {
		if permsMap, ok := rolePerms.(map[string]interface{}); ok {
			if perm, exists := permsMap[operation]; exists {
				if permBool, ok := perm.(bool); ok {
					return permBool, nil
				}
				if permStr, ok := perm.(string); ok {
					return permStr == "true" || permStr == "scoped", nil
				}
			}
		}
	}

	// Default to deny
	return false, nil
}

// GetTableFilters returns custom filters for a user accessing a specific table
func (r *rbacEngine) GetTableFilters(ctx context.Context, userID string, tableName string) (map[string]interface{}, error) {
	// Get user's role
	role, err := r.GetHighestRole(ctx, userID)
	if err != nil || role == nil {
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}

	// System admins have no filters
	if role.Level == 1 {
		return make(map[string]interface{}), nil
	}

	// Get table security configuration
	query := `
		SELECT custom_filters, ownership_column
		FROM table_security_config
		WHERE table_name = $1
		AND is_active = TRUE
	`

	var config struct {
		CustomFilters   map[string]interface{} `db:"custom_filters"`
		OwnershipColumn *string                `db:"ownership_column"`
	}

	err = r.db.QueryRow(ctx, query, tableName).Scan(&config.CustomFilters, &config.OwnershipColumn)
	if err != nil {
		if err == pgx.ErrNoRows {
			return make(map[string]interface{}), nil
		}
		return nil, fmt.Errorf("failed to get table config: %w", err)
	}

	filters := make(map[string]interface{})

	// Add ownership filter if specified
	if config.OwnershipColumn != nil {
		filters[*config.OwnershipColumn] = userID
	}

	// Add role-specific custom filters
	if roleFilters, ok := config.CustomFilters[role.Name]; ok {
		if filterMap, ok := roleFilters.(map[string]interface{}); ok {
			for key, value := range filterMap {
				filters[key] = value
			}
		}
	}

	return filters, nil
}

// CanManageUser checks if one user can manage another based on admin hierarchy
func (r *rbacEngine) CanManageUser(ctx context.Context, managerID string, targetUserID string) (bool, error) {
	// Users can always manage themselves
	if managerID == targetUserID {
		return true, nil
	}

	// Get both users' admin levels
	managerLevel, err := r.GetUserAdminLevel(ctx, managerID)
	if err != nil {
		return false, fmt.Errorf("failed to get manager admin level: %w", err)
	}

	targetLevel, err := r.GetUserAdminLevel(ctx, targetUserID)
	if err != nil {
		return false, fmt.Errorf("failed to get target admin level: %w", err)
	}

	// Manager must have higher privileges (lower level number) than target
	// or target must have no admin role (level 999)
	return managerLevel < targetLevel || targetLevel == 999, nil
}

// GetAccessibleTables returns list of tables the user can access
func (r *rbacEngine) GetAccessibleTables(ctx context.Context, userID string) ([]string, error) {
	level, err := r.GetUserAdminLevel(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user admin level: %w", err)
	}

	if level == 999 {
		return []string{}, nil // No admin role
	}

	// System admins can access all tables
	if level == 1 {
		query := `
			SELECT table_name
			FROM table_metadata
			WHERE table_type = 'BASE TABLE'
			ORDER BY table_name
		`
		rows, err := r.db.Query(ctx, query)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		var tables []string
		for rows.Next() {
			var table string
			if err := rows.Scan(&table); err != nil {
				return nil, err
			}
			tables = append(tables, table)
		}
		return tables, rows.Err()
	}

	// Get user's role name
	role, err := r.GetHighestRole(ctx, userID)
	if err != nil || role == nil {
		return []string{}, fmt.Errorf("failed to get user role: %w", err)
	}

	// Get tables where user's role is in allowed_roles
	query := `
		SELECT table_name
		FROM table_security_config
		WHERE $1 = ANY(allowed_roles)
		AND is_active = TRUE
		ORDER BY table_name
	`

	rows, err := r.db.Query(ctx, query, role.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get accessible tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, fmt.Errorf("failed to scan table: %w", err)
		}
		tables = append(tables, table)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get accessible tables: %w", err)
	}

	return tables, nil
}

// GetUserAdminLevel returns the user's highest admin level (lowest number)
func (r *rbacEngine) GetUserAdminLevel(ctx context.Context, userID string) (int, error) {
	query := `SELECT get_user_admin_level($1)`

	var level int
	err := r.db.QueryRow(ctx, query, userID).Scan(&level)
	if err != nil {
		return 999, fmt.Errorf("failed to get user admin level: %w", err)
	}

	return level, nil
}

// HasCapability checks if user has a specific capability for a resource
func (r *rbacEngine) HasCapability(ctx context.Context, userID string, capability string, resource string) (bool, error) {
	query := `SELECT user_has_admin_capability($1, $2, $3)`

	var hasCapability bool
	err := r.db.QueryRow(ctx, query, userID, capability, resource).Scan(&hasCapability)
	if err != nil {
		return false, fmt.Errorf("failed to check capability: %w", err)
	}

	return hasCapability, nil
}

// GetUserCapabilities returns all capabilities for a user
func (r *rbacEngine) GetUserCapabilities(ctx context.Context, userID string) ([]string, error) {
	query := `
		SELECT DISTINCT ac.capability
		FROM user_admin_roles uar
		JOIN admin_roles ar ON uar.role_id = ar.id
		JOIN admin_capabilities ac ON ac.role_id = ar.id
		WHERE uar.user_id = $1
		AND uar.is_active = TRUE
		AND ar.is_active = TRUE
		AND ac.is_active = TRUE
		AND (uar.expires_at IS NULL OR uar.expires_at > NOW())
		ORDER BY ac.capability
	`

	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []string
	for rows.Next() {
		var capability string
		if err := rows.Scan(&capability); err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, capability)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user capabilities: %w", err)
	}

	return capabilities, nil
}
