package auth

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/taqiudeen275/go-foward/internal/database"
)

// PolicyRepository handles policy and table configuration database operations
type PolicyRepository struct {
	db *database.DB
}

// NewPolicyRepository creates a new policy repository
func NewPolicyRepository(db *database.DB) *PolicyRepository {
	return &PolicyRepository{
		db: db,
	}
}

// CreateTableConfiguration creates a new table security configuration
func (r *PolicyRepository) CreateTableConfiguration(ctx context.Context, config *TableSecurityConfig) error {
	query := `
		INSERT INTO table_configurations (
			id, table_name, schema_name, display_name, description,
			require_auth, require_verified, allowed_roles, require_ownership, ownership_column,
			public_read, public_write, require_mfa, ip_whitelist, rate_limit_config,
			audit_actions, readable_fields, writable_fields, hidden_fields,
			custom_filters, time_based_access, created_by, created_at, updated_by, updated_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
	`

	// Convert JSON fields
	allowedRolesJSON, err := json.Marshal(config.APIConfig.AllowedRoles)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed roles: %w", err)
	}

	ipWhitelistJSON, err := json.Marshal(config.APIConfig.IPWhitelist)
	if err != nil {
		return fmt.Errorf("failed to marshal IP whitelist: %w", err)
	}

	rateLimitJSON, err := json.Marshal(config.APIConfig.RateLimit)
	if err != nil {
		return fmt.Errorf("failed to marshal rate limit config: %w", err)
	}

	readableFieldsJSON, err := json.Marshal(config.APIConfig.ReadableFields)
	if err != nil {
		return fmt.Errorf("failed to marshal readable fields: %w", err)
	}

	writableFieldsJSON, err := json.Marshal(config.APIConfig.WritableFields)
	if err != nil {
		return fmt.Errorf("failed to marshal writable fields: %w", err)
	}

	hiddenFieldsJSON, err := json.Marshal(config.APIConfig.HiddenFields)
	if err != nil {
		return fmt.Errorf("failed to marshal hidden fields: %w", err)
	}

	customFiltersJSON, err := json.Marshal(config.APIConfig.CustomFilters)
	if err != nil {
		return fmt.Errorf("failed to marshal custom filters: %w", err)
	}

	timeBasedAccessJSON, err := json.Marshal(config.APIConfig.TimeBasedAccess)
	if err != nil {
		return fmt.Errorf("failed to marshal time based access: %w", err)
	}

	err = r.db.Exec(ctx, query,
		config.ID,
		config.TableName,
		config.SchemaName,
		config.DisplayName,
		config.Description,
		config.APIConfig.RequireAuth,
		config.APIConfig.RequireVerified,
		allowedRolesJSON,
		config.APIConfig.RequireOwnership,
		config.APIConfig.OwnershipColumn,
		config.APIConfig.PublicRead,
		config.APIConfig.PublicWrite,
		config.APIConfig.RequireMFA,
		ipWhitelistJSON,
		rateLimitJSON,
		config.APIConfig.AuditActions,
		readableFieldsJSON,
		writableFieldsJSON,
		hiddenFieldsJSON,
		customFiltersJSON,
		timeBasedAccessJSON,
		config.CreatedBy,
		config.CreatedAt,
		config.UpdatedBy,
		config.UpdatedAt,
		config.IsActive,
	)

	if err != nil {
		return fmt.Errorf("failed to create table configuration: %w", err)
	}

	return nil
}

// GetTableConfiguration retrieves table configuration by table name
func (r *PolicyRepository) GetTableConfiguration(ctx context.Context, tableName, schemaName string) (*TableSecurityConfig, error) {
	query := `
		SELECT 
			id, table_name, schema_name, display_name, description,
			require_auth, require_verified, allowed_roles, require_ownership, ownership_column,
			public_read, public_write, require_mfa, ip_whitelist, rate_limit_config,
			audit_actions, readable_fields, writable_fields, hidden_fields,
			custom_filters, time_based_access, created_by, created_at, updated_by, updated_at, is_active
		FROM table_configurations
		WHERE table_name = $1 AND schema_name = $2 AND is_active = true
	`

	config := &TableSecurityConfig{}
	var allowedRolesJSON, ipWhitelistJSON, rateLimitJSON []byte
	var readableFieldsJSON, writableFieldsJSON, hiddenFieldsJSON []byte
	var customFiltersJSON, timeBasedAccessJSON []byte

	err := r.db.QueryRow(ctx, query, tableName, schemaName).Scan(
		&config.ID,
		&config.TableName,
		&config.SchemaName,
		&config.DisplayName,
		&config.Description,
		&config.APIConfig.RequireAuth,
		&config.APIConfig.RequireVerified,
		&allowedRolesJSON,
		&config.APIConfig.RequireOwnership,
		&config.APIConfig.OwnershipColumn,
		&config.APIConfig.PublicRead,
		&config.APIConfig.PublicWrite,
		&config.APIConfig.RequireMFA,
		&ipWhitelistJSON,
		&rateLimitJSON,
		&config.APIConfig.AuditActions,
		&readableFieldsJSON,
		&writableFieldsJSON,
		&hiddenFieldsJSON,
		&customFiltersJSON,
		&timeBasedAccessJSON,
		&config.CreatedBy,
		&config.CreatedAt,
		&config.UpdatedBy,
		&config.UpdatedAt,
		&config.IsActive,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("table configuration not found")
		}
		return nil, fmt.Errorf("failed to get table configuration: %w", err)
	}

	// Unmarshal JSON fields
	if len(allowedRolesJSON) > 0 {
		if err := json.Unmarshal(allowedRolesJSON, &config.APIConfig.AllowedRoles); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allowed roles: %w", err)
		}
	}

	if len(ipWhitelistJSON) > 0 {
		if err := json.Unmarshal(ipWhitelistJSON, &config.APIConfig.IPWhitelist); err != nil {
			return nil, fmt.Errorf("failed to unmarshal IP whitelist: %w", err)
		}
	}

	if len(rateLimitJSON) > 0 {
		if err := json.Unmarshal(rateLimitJSON, &config.APIConfig.RateLimit); err != nil {
			return nil, fmt.Errorf("failed to unmarshal rate limit config: %w", err)
		}
	}

	if len(readableFieldsJSON) > 0 {
		if err := json.Unmarshal(readableFieldsJSON, &config.APIConfig.ReadableFields); err != nil {
			return nil, fmt.Errorf("failed to unmarshal readable fields: %w", err)
		}
	}

	if len(writableFieldsJSON) > 0 {
		if err := json.Unmarshal(writableFieldsJSON, &config.APIConfig.WritableFields); err != nil {
			return nil, fmt.Errorf("failed to unmarshal writable fields: %w", err)
		}
	}

	if len(hiddenFieldsJSON) > 0 {
		if err := json.Unmarshal(hiddenFieldsJSON, &config.APIConfig.HiddenFields); err != nil {
			return nil, fmt.Errorf("failed to unmarshal hidden fields: %w", err)
		}
	}

	if len(customFiltersJSON) > 0 {
		if err := json.Unmarshal(customFiltersJSON, &config.APIConfig.CustomFilters); err != nil {
			return nil, fmt.Errorf("failed to unmarshal custom filters: %w", err)
		}
	}

	if len(timeBasedAccessJSON) > 0 {
		if err := json.Unmarshal(timeBasedAccessJSON, &config.APIConfig.TimeBasedAccess); err != nil {
			return nil, fmt.Errorf("failed to unmarshal time based access: %w", err)
		}
	}

	return config, nil
}

// UpdateTableConfiguration updates an existing table configuration
func (r *PolicyRepository) UpdateTableConfiguration(ctx context.Context, config *TableSecurityConfig) error {
	query := `
		UPDATE table_configurations SET
			display_name = $3, description = $4,
			require_auth = $5, require_verified = $6, allowed_roles = $7, require_ownership = $8, ownership_column = $9,
			public_read = $10, public_write = $11, require_mfa = $12, ip_whitelist = $13, rate_limit_config = $14,
			audit_actions = $15, readable_fields = $16, writable_fields = $17, hidden_fields = $18,
			custom_filters = $19, time_based_access = $20, updated_by = $21, updated_at = $22, is_active = $23
		WHERE id = $1
	`

	// Convert JSON fields
	allowedRolesJSON, err := json.Marshal(config.APIConfig.AllowedRoles)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed roles: %w", err)
	}

	ipWhitelistJSON, err := json.Marshal(config.APIConfig.IPWhitelist)
	if err != nil {
		return fmt.Errorf("failed to marshal IP whitelist: %w", err)
	}

	rateLimitJSON, err := json.Marshal(config.APIConfig.RateLimit)
	if err != nil {
		return fmt.Errorf("failed to marshal rate limit config: %w", err)
	}

	readableFieldsJSON, err := json.Marshal(config.APIConfig.ReadableFields)
	if err != nil {
		return fmt.Errorf("failed to marshal readable fields: %w", err)
	}

	writableFieldsJSON, err := json.Marshal(config.APIConfig.WritableFields)
	if err != nil {
		return fmt.Errorf("failed to marshal writable fields: %w", err)
	}

	hiddenFieldsJSON, err := json.Marshal(config.APIConfig.HiddenFields)
	if err != nil {
		return fmt.Errorf("failed to marshal hidden fields: %w", err)
	}

	customFiltersJSON, err := json.Marshal(config.APIConfig.CustomFilters)
	if err != nil {
		return fmt.Errorf("failed to marshal custom filters: %w", err)
	}

	timeBasedAccessJSON, err := json.Marshal(config.APIConfig.TimeBasedAccess)
	if err != nil {
		return fmt.Errorf("failed to marshal time based access: %w", err)
	}

	err = r.db.Exec(ctx, query,
		config.ID,
		config.TableName,
		config.DisplayName,
		config.Description,
		config.APIConfig.RequireAuth,
		config.APIConfig.RequireVerified,
		allowedRolesJSON,
		config.APIConfig.RequireOwnership,
		config.APIConfig.OwnershipColumn,
		config.APIConfig.PublicRead,
		config.APIConfig.PublicWrite,
		config.APIConfig.RequireMFA,
		ipWhitelistJSON,
		rateLimitJSON,
		config.APIConfig.AuditActions,
		readableFieldsJSON,
		writableFieldsJSON,
		hiddenFieldsJSON,
		customFiltersJSON,
		timeBasedAccessJSON,
		config.UpdatedBy,
		config.UpdatedAt,
		config.IsActive,
	)

	if err != nil {
		return fmt.Errorf("failed to update table configuration: %w", err)
	}

	return nil
}

// ListTableConfigurations lists all table configurations
func (r *PolicyRepository) ListTableConfigurations(ctx context.Context) ([]*TableSecurityConfig, error) {
	query := `
		SELECT 
			id, table_name, schema_name, display_name, description,
			require_auth, require_verified, allowed_roles, require_ownership, ownership_column,
			public_read, public_write, require_mfa, ip_whitelist, rate_limit_config,
			audit_actions, readable_fields, writable_fields, hidden_fields,
			custom_filters, time_based_access, created_by, created_at, updated_by, updated_at, is_active
		FROM table_configurations
		WHERE is_active = true
		ORDER BY table_name, schema_name
	`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list table configurations: %w", err)
	}
	defer rows.Close()

	var configs []*TableSecurityConfig
	for rows.Next() {
		config := &TableSecurityConfig{}
		var allowedRolesJSON, ipWhitelistJSON, rateLimitJSON []byte
		var readableFieldsJSON, writableFieldsJSON, hiddenFieldsJSON []byte
		var customFiltersJSON, timeBasedAccessJSON []byte

		err := rows.Scan(
			&config.ID,
			&config.TableName,
			&config.SchemaName,
			&config.DisplayName,
			&config.Description,
			&config.APIConfig.RequireAuth,
			&config.APIConfig.RequireVerified,
			&allowedRolesJSON,
			&config.APIConfig.RequireOwnership,
			&config.APIConfig.OwnershipColumn,
			&config.APIConfig.PublicRead,
			&config.APIConfig.PublicWrite,
			&config.APIConfig.RequireMFA,
			&ipWhitelistJSON,
			&rateLimitJSON,
			&config.APIConfig.AuditActions,
			&readableFieldsJSON,
			&writableFieldsJSON,
			&hiddenFieldsJSON,
			&customFiltersJSON,
			&timeBasedAccessJSON,
			&config.CreatedBy,
			&config.CreatedAt,
			&config.UpdatedBy,
			&config.UpdatedAt,
			&config.IsActive,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan table configuration row: %w", err)
		}

		// Unmarshal JSON fields (simplified for brevity)
		if len(allowedRolesJSON) > 0 {
			json.Unmarshal(allowedRolesJSON, &config.APIConfig.AllowedRoles)
		}
		if len(ipWhitelistJSON) > 0 {
			json.Unmarshal(ipWhitelistJSON, &config.APIConfig.IPWhitelist)
		}
		if len(rateLimitJSON) > 0 {
			json.Unmarshal(rateLimitJSON, &config.APIConfig.RateLimit)
		}
		if len(readableFieldsJSON) > 0 {
			json.Unmarshal(readableFieldsJSON, &config.APIConfig.ReadableFields)
		}
		if len(writableFieldsJSON) > 0 {
			json.Unmarshal(writableFieldsJSON, &config.APIConfig.WritableFields)
		}
		if len(hiddenFieldsJSON) > 0 {
			json.Unmarshal(hiddenFieldsJSON, &config.APIConfig.HiddenFields)
		}
		if len(customFiltersJSON) > 0 {
			json.Unmarshal(customFiltersJSON, &config.APIConfig.CustomFilters)
		}
		if len(timeBasedAccessJSON) > 0 {
			json.Unmarshal(timeBasedAccessJSON, &config.APIConfig.TimeBasedAccess)
		}

		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table configuration rows: %w", err)
	}

	return configs, nil
}

// DeleteTableConfiguration soft deletes a table configuration
func (r *PolicyRepository) DeleteTableConfiguration(ctx context.Context, configID string) error {
	query := `UPDATE table_configurations SET is_active = false, updated_at = NOW() WHERE id = $1`

	err := r.db.Exec(ctx, query, configID)
	if err != nil {
		return fmt.Errorf("failed to delete table configuration: %w", err)
	}

	return nil
}

// CreateSecurityPolicy creates a new security policy (in-memory for now)
func (r *PolicyRepository) CreateSecurityPolicy(ctx context.Context, policy *SecurityPolicy) error {
	// For now, this is a placeholder since we're storing policies in memory
	// In a full implementation, this would save to a security_policies table
	return nil
}

// GetSecurityPolicy retrieves a security policy by ID (in-memory for now)
func (r *PolicyRepository) GetSecurityPolicy(ctx context.Context, policyID string) (*SecurityPolicy, error) {
	// For now, this is a placeholder since we're storing policies in memory
	// In a full implementation, this would query a security_policies table
	return nil, fmt.Errorf("security policy not found")
}

// ListSecurityPolicies lists all security policies (in-memory for now)
func (r *PolicyRepository) ListSecurityPolicies(ctx context.Context) ([]*SecurityPolicy, error) {
	// For now, this is a placeholder since we're storing policies in memory
	// In a full implementation, this would query a security_policies table
	return []*SecurityPolicy{}, nil
}

// UpdateSecurityPolicy updates a security policy (in-memory for now)
func (r *PolicyRepository) UpdateSecurityPolicy(ctx context.Context, policy *SecurityPolicy) error {
	// For now, this is a placeholder since we're storing policies in memory
	// In a full implementation, this would update a security_policies table
	return nil
}

// DeleteSecurityPolicy deletes a security policy (in-memory for now)
func (r *PolicyRepository) DeleteSecurityPolicy(ctx context.Context, policyID string) error {
	// For now, this is a placeholder since we're storing policies in memory
	// In a full implementation, this would delete from a security_policies table
	return nil
}
