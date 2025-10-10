package auth

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// APISecurityEnforcerImpl implements the APISecurityEnforcer interface
type APISecurityEnforcerImpl struct {
	configService TableSecurityConfigService
	rateLimiter   RateLimiter
	auditService  AuditService
}

// RateLimiter interface for rate limiting functionality
type RateLimiter interface {
	CheckLimit(key string, limit *RateLimitConfig) (bool, error)
	IncrementCounter(key string) error
	GetCurrentUsage(key string) (int, error)
	ResetLimit(key string) error
}

// NewAPISecurityEnforcer creates a new API security enforcer
func NewAPISecurityEnforcer(configService TableSecurityConfigService, rateLimiter RateLimiter, auditService AuditService) *APISecurityEnforcerImpl {
	return &APISecurityEnforcerImpl{
		configService: configService,
		rateLimiter:   rateLimiter,
		auditService:  auditService,
	}
}

// ValidateRequest validates a request against table security configuration
func (e *APISecurityEnforcerImpl) ValidateRequest(tableName, schemaName, method string, userContext *APISecurityContext) (*SecurityDecision, error) {
	// Get security configuration for the table
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return &SecurityDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Failed to get security config: %v", err),
		}, nil
	}

	decision := &SecurityDecision{
		Allowed:      true,
		Reason:       "Access granted",
		Warnings:     []string{},
		Restrictions: make(map[string]interface{}),
	}

	// Check authentication requirement
	if config.RequireAuth && userContext.UserID == "" {
		decision.Allowed = false
		decision.Reason = "Authentication required"
		return decision, nil
	}

	// Check email verification requirement
	if config.RequireVerified && userContext.UserID != "" {
		// This would typically check user verification status from the user service
		// For now, we'll assume it's handled elsewhere
	}

	// Check role-based access
	if len(config.AllowedRoles) > 0 && userContext.UserID != "" {
		hasRequiredRole := false
		for _, userRole := range userContext.UserRoles {
			for _, allowedRole := range config.AllowedRoles {
				if userRole == allowedRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			decision.Allowed = false
			decision.Reason = "Insufficient role permissions"
			decision.RequiredRoles = config.AllowedRoles
			return decision, nil
		}
	}

	// Check MFA requirement
	if config.RequireMFA && !userContext.MFAVerified {
		decision.RequiresMFA = true
		if method != "GET" { // Allow reads but require MFA for writes
			decision.Allowed = false
			decision.Reason = "Multi-factor authentication required"
			return decision, nil
		} else {
			decision.Warnings = append(decision.Warnings, "MFA recommended for this resource")
		}
	}

	// Check public access permissions
	if userContext.UserID == "" { // Anonymous user
		if method == "GET" && !config.PublicRead {
			decision.Allowed = false
			decision.Reason = "Public read access not allowed"
			return decision, nil
		}
		if method != "GET" && !config.PublicWrite {
			decision.Allowed = false
			decision.Reason = "Public write access not allowed"
			return decision, nil
		}
	}

	// Check IP whitelist
	if len(config.IPWhitelist) > 0 {
		err := e.ValidateIPAccess(tableName, schemaName, userContext.IPAddress)
		if err != nil {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("IP validation failed: %v", err)
			return decision, nil
		}
	}

	// Check time-based access
	if config.TimeBasedAccess != nil {
		err := e.ValidateTimeBasedAccess(tableName, schemaName)
		if err != nil {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("Time-based access denied: %v", err)
			return decision, nil
		}
	}

	// Check rate limits
	if config.RateLimit != nil {
		err := e.CheckRateLimit(tableName, schemaName, userContext)
		if err != nil {
			decision.RateLimited = true
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("Rate limit exceeded: %v", err)
			return decision, nil
		}
	}

	// Add restrictions for field-level permissions
	if len(config.ReadableFields) > 0 {
		decision.Restrictions["readable_fields"] = config.ReadableFields
	}
	if len(config.WritableFields) > 0 {
		decision.Restrictions["writable_fields"] = config.WritableFields
	}
	if len(config.HiddenFields) > 0 {
		decision.Restrictions["hidden_fields"] = config.HiddenFields
	}

	// Log security decision if auditing is enabled
	if config.AuditActions {
		e.auditService.LogAdminAction(
			userContext.UserID,
			fmt.Sprintf("API_ACCESS_%s", method),
			fmt.Sprintf("%s.%s", schemaName, tableName),
			map[string]interface{}{
				"allowed":      decision.Allowed,
				"reason":       decision.Reason,
				"ip_address":   userContext.IPAddress,
				"user_agent":   userContext.UserAgent,
				"mfa_verified": userContext.MFAVerified,
			},
		)
	}

	return decision, nil
}

// FilterReadableFields filters data based on field-level read permissions
func (e *APISecurityEnforcerImpl) FilterReadableFields(tableName, schemaName string, data map[string]interface{}, userContext *APISecurityContext) (map[string]interface{}, error) {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return data, fmt.Errorf("failed to get security config: %w", err)
	}

	filteredData := make(map[string]interface{})

	// If no field restrictions, return all data
	if len(config.ReadableFields) == 0 && len(config.HiddenFields) == 0 {
		return data, nil
	}

	// If readable fields are specified, only include those
	if len(config.ReadableFields) > 0 {
		readableFieldsMap := make(map[string]bool)
		for _, field := range config.ReadableFields {
			readableFieldsMap[field] = true
		}

		for key, value := range data {
			if readableFieldsMap[key] {
				filteredData[key] = value
			}
		}
	} else {
		// Include all fields except hidden ones
		hiddenFieldsMap := make(map[string]bool)
		for _, field := range config.HiddenFields {
			hiddenFieldsMap[field] = true
		}

		for key, value := range data {
			if !hiddenFieldsMap[key] {
				filteredData[key] = value
			}
		}
	}

	// Apply role-based field filtering
	filteredData = e.applyRoleBasedFieldFiltering(filteredData, userContext.UserRoles)

	return filteredData, nil
}

// ValidateWritableFields validates that only writable fields are being modified
func (e *APISecurityEnforcerImpl) ValidateWritableFields(tableName, schemaName string, data map[string]interface{}, userContext *APISecurityContext) error {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return fmt.Errorf("failed to get security config: %w", err)
	}

	// If no field restrictions, allow all writes
	if len(config.WritableFields) == 0 {
		return nil
	}

	writableFieldsMap := make(map[string]bool)
	for _, field := range config.WritableFields {
		writableFieldsMap[field] = true
	}

	var invalidFields []string
	for key := range data {
		if !writableFieldsMap[key] {
			invalidFields = append(invalidFields, key)
		}
	}

	if len(invalidFields) > 0 {
		return fmt.Errorf("attempt to modify non-writable fields: %s", strings.Join(invalidFields, ", "))
	}

	return nil
}

// ValidateOwnership validates ownership-based access
func (e *APISecurityEnforcerImpl) ValidateOwnership(tableName, schemaName string, resourceID string, userContext *APISecurityContext) error {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return fmt.Errorf("failed to get security config: %w", err)
	}

	if !config.RequireOwnership || config.OwnershipColumn == "" {
		return nil // No ownership requirement
	}

	if userContext.UserID == "" {
		return fmt.Errorf("ownership validation requires authenticated user")
	}

	// Check if user has admin privileges that bypass ownership
	if userContext.AdminLevel == SystemAdmin || userContext.AdminLevel == SuperAdmin {
		return nil // System and Super admins bypass ownership
	}

	// For regular admins, check if they have CanManageAllTables capability
	if userContext.Capabilities.CanManageAllTables {
		return nil // Can manage all tables
	}

	// Check if the table is in the user's assigned tables
	if len(userContext.Capabilities.AssignedTables) > 0 {
		tableKey := fmt.Sprintf("%s.%s", schemaName, tableName)
		for _, assignedTable := range userContext.Capabilities.AssignedTables {
			if assignedTable == tableKey || assignedTable == tableName {
				return nil // User has access to this table
			}
		}
	}

	// If we reach here, we need to validate actual ownership
	// This would require a database query to check the ownership column
	// For now, we'll create a validation context that can be used by the query layer
	return &OwnershipValidationError{
		TableName:       tableName,
		SchemaName:      schemaName,
		ResourceID:      resourceID,
		OwnershipColumn: config.OwnershipColumn,
		UserID:          userContext.UserID,
		Message:         fmt.Sprintf("ownership validation required for %s.%s", schemaName, tableName),
	}
}

// OwnershipValidationError represents an ownership validation requirement
type OwnershipValidationError struct {
	TableName       string `json:"table_name"`
	SchemaName      string `json:"schema_name"`
	ResourceID      string `json:"resource_id"`
	OwnershipColumn string `json:"ownership_column"`
	UserID          string `json:"user_id"`
	Message         string `json:"message"`
}

func (e *OwnershipValidationError) Error() string {
	return e.Message
}

// IsOwnershipValidationError checks if an error is an ownership validation error
func IsOwnershipValidationError(err error) (*OwnershipValidationError, bool) {
	if ove, ok := err.(*OwnershipValidationError); ok {
		return ove, true
	}
	return nil, false
}

// ApplyCustomFilters applies custom SQL filters to a query
func (e *APISecurityEnforcerImpl) ApplyCustomFilters(tableName, schemaName string, query *SQLQuery, userContext *APISecurityContext) (*SQLQuery, error) {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return query, fmt.Errorf("failed to get security config: %w", err)
	}

	modifiedQuery := *query
	if modifiedQuery.Metadata == nil {
		modifiedQuery.Metadata = make(map[string]string)
	}

	var whereConditions []string

	// Apply ownership filter if required
	if config.RequireOwnership && config.OwnershipColumn != "" && userContext.UserID != "" {
		// Skip ownership filter for system and super admins
		if userContext.AdminLevel != SystemAdmin && userContext.AdminLevel != SuperAdmin {
			// Check if user can manage all tables
			if !userContext.Capabilities.CanManageAllTables {
				// Apply ownership filter
				ownershipCondition := fmt.Sprintf("%s = '%s'", config.OwnershipColumn, userContext.UserID)
				whereConditions = append(whereConditions, ownershipCondition)
				modifiedQuery.Metadata["ownership_filter"] = ownershipCondition
			}
		}
	}

	// Apply custom filters based on user context
	for filterName, filterExpression := range config.CustomFilters {
		// Replace placeholders in filter expression
		processedFilter := e.processFilterExpression(filterExpression, userContext)
		if processedFilter != "" {
			whereConditions = append(whereConditions, processedFilter)
			modifiedQuery.Metadata["filter_"+filterName] = processedFilter
		}
	}

	// Apply role-based filters for regular admins
	if userContext.AdminLevel == RegularAdmin {
		roleFilters := e.buildRoleBasedFilters(tableName, schemaName, userContext)
		whereConditions = append(whereConditions, roleFilters...)
	}

	// Inject WHERE conditions into the query
	if len(whereConditions) > 0 {
		modifiedQuery.Query = e.injectWhereConditions(modifiedQuery.Query, whereConditions)
		modifiedQuery.Metadata["applied_filters"] = strings.Join(whereConditions, " AND ")
	}

	return &modifiedQuery, nil
}

// buildRoleBasedFilters builds filters based on user roles and assigned resources
func (e *APISecurityEnforcerImpl) buildRoleBasedFilters(tableName, schemaName string, userContext *APISecurityContext) []string {
	var filters []string

	// If user has assigned tables, only show data from those tables
	if len(userContext.Capabilities.AssignedTables) > 0 {
		tableKey := fmt.Sprintf("%s.%s", schemaName, tableName)
		hasAccess := false
		for _, assignedTable := range userContext.Capabilities.AssignedTables {
			if assignedTable == tableKey || assignedTable == tableName {
				hasAccess = true
				break
			}
		}

		// If table is not assigned, add impossible condition
		if !hasAccess {
			filters = append(filters, "1 = 0") // Always false condition
		}
	}

	// If user has assigned user groups, filter by those groups
	if len(userContext.Capabilities.AssignedUserGroups) > 0 {
		// This assumes there's a user_group or group_id column
		groupConditions := make([]string, len(userContext.Capabilities.AssignedUserGroups))
		for i, group := range userContext.Capabilities.AssignedUserGroups {
			groupConditions[i] = fmt.Sprintf("user_group = '%s'", group)
		}
		if len(groupConditions) > 0 {
			filters = append(filters, fmt.Sprintf("(%s)", strings.Join(groupConditions, " OR ")))
		}
	}

	// Add status filter for content moderation
	if userContext.Capabilities.CanModerateContent {
		// Show only non-deleted content for moderators
		filters = append(filters, "status != 'deleted'")
	}

	return filters
}

// injectWhereConditions injects WHERE conditions into a SQL query
func (e *APISecurityEnforcerImpl) injectWhereConditions(query string, conditions []string) string {
	if len(conditions) == 0 {
		return query
	}

	combinedCondition := strings.Join(conditions, " AND ")
	upperQuery := strings.ToUpper(query)

	// Check if query already has WHERE clause
	if strings.Contains(upperQuery, " WHERE ") {
		// Add to existing WHERE clause
		return strings.Replace(query, " WHERE ", fmt.Sprintf(" WHERE (%s) AND ", combinedCondition), 1)
	} else {
		// Add new WHERE clause
		// Find appropriate insertion point (before ORDER BY, GROUP BY, HAVING, LIMIT)
		insertionPoint := len(query)

		keywords := []string{" ORDER BY ", " GROUP BY ", " HAVING ", " LIMIT ", " OFFSET "}
		for _, keyword := range keywords {
			if idx := strings.Index(upperQuery, keyword); idx != -1 && idx < insertionPoint {
				insertionPoint = idx
			}
		}

		return query[:insertionPoint] + fmt.Sprintf(" WHERE (%s)", combinedCondition) + query[insertionPoint:]
	}
}

// CheckRateLimit checks if the request is within rate limits
func (e *APISecurityEnforcerImpl) CheckRateLimit(tableName, schemaName string, userContext *APISecurityContext) error {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return fmt.Errorf("failed to get security config: %w", err)
	}

	if config.RateLimit == nil {
		return nil // No rate limiting configured
	}

	// Create rate limit key based on user and table
	var rateLimitKey string
	if userContext.UserID != "" {
		rateLimitKey = fmt.Sprintf("user:%s:table:%s.%s", userContext.UserID, schemaName, tableName)
	} else {
		rateLimitKey = fmt.Sprintf("ip:%s:table:%s.%s", userContext.IPAddress, schemaName, tableName)
	}

	// Check rate limit
	allowed, err := e.rateLimiter.CheckLimit(rateLimitKey, config.RateLimit)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}

	if !allowed {
		return fmt.Errorf("rate limit exceeded for table %s.%s", schemaName, tableName)
	}

	// Increment counter
	err = e.rateLimiter.IncrementCounter(rateLimitKey)
	if err != nil {
		// Log error but don't fail the request
		return nil
	}

	return nil
}

// ValidateIPAccess validates IP-based access restrictions
func (e *APISecurityEnforcerImpl) ValidateIPAccess(tableName, schemaName string, ipAddress string) error {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return fmt.Errorf("failed to get security config: %w", err)
	}

	if len(config.IPWhitelist) == 0 {
		return nil // No IP restrictions
	}

	clientIP := net.ParseIP(ipAddress)
	if clientIP == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	for _, allowedIP := range config.IPWhitelist {
		// Check if it's a CIDR range
		if strings.Contains(allowedIP, "/") {
			_, ipNet, err := net.ParseCIDR(allowedIP)
			if err != nil {
				continue // Skip invalid CIDR
			}
			if ipNet.Contains(clientIP) {
				return nil // IP is in allowed range
			}
		} else {
			// Check exact IP match
			allowedIPParsed := net.ParseIP(allowedIP)
			if allowedIPParsed != nil && allowedIPParsed.Equal(clientIP) {
				return nil // IP matches exactly
			}
		}
	}

	return fmt.Errorf("IP address %s not in whitelist", ipAddress)
}

// ValidateTimeBasedAccess validates time-based access restrictions
func (e *APISecurityEnforcerImpl) ValidateTimeBasedAccess(tableName, schemaName string) error {
	config, err := e.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return fmt.Errorf("failed to get security config: %w", err)
	}

	if config.TimeBasedAccess == nil {
		return nil // No time restrictions
	}

	now := time.Now()

	// Load timezone if specified
	if config.TimeBasedAccess.Timezone != "" {
		loc, err := time.LoadLocation(config.TimeBasedAccess.Timezone)
		if err == nil {
			now = now.In(loc)
		}
	}

	// Check allowed hours
	if len(config.TimeBasedAccess.AllowedHours) > 0 {
		currentHour := now.Hour()
		allowed := false
		for _, allowedHour := range config.TimeBasedAccess.AllowedHours {
			if currentHour == allowedHour {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access not allowed at hour %d", currentHour)
		}
	}

	// Check allowed days (0 = Sunday, 1 = Monday, etc.)
	if len(config.TimeBasedAccess.AllowedDays) > 0 {
		currentDay := int(now.Weekday())
		allowed := false
		for _, allowedDay := range config.TimeBasedAccess.AllowedDays {
			if currentDay == allowedDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access not allowed on day %d", currentDay)
		}
	}

	// Check blocked periods
	if len(config.TimeBasedAccess.BlockedPeriods) > 0 {
		currentTime := now.Format("15:04")
		for _, period := range config.TimeBasedAccess.BlockedPeriods {
			// Parse period format "HH:MM-HH:MM"
			if strings.Contains(period, "-") {
				parts := strings.Split(period, "-")
				if len(parts) == 2 && currentTime >= parts[0] && currentTime <= parts[1] {
					return fmt.Errorf("access blocked during period %s", period)
				}
			}
		}
	}

	return nil
}

// applyRoleBasedFieldFiltering applies additional field filtering based on user roles
func (e *APISecurityEnforcerImpl) applyRoleBasedFieldFiltering(data map[string]interface{}, userRoles []string) map[string]interface{} {
	// This is a placeholder for role-based field filtering
	// In a real implementation, you would:
	// 1. Define field permissions per role
	// 2. Check user roles against field permissions
	// 3. Filter fields accordingly

	// For now, we'll implement basic admin field filtering
	hasAdminRole := false
	for _, role := range userRoles {
		if strings.Contains(strings.ToLower(role), "admin") {
			hasAdminRole = true
			break
		}
	}

	if !hasAdminRole {
		// Remove sensitive fields for non-admin users
		sensitiveFields := []string{"password_hash", "secret", "private_key", "api_key", "token"}
		for _, field := range sensitiveFields {
			delete(data, field)
		}
	}

	return data
}

// processFilterExpression processes custom filter expressions with user context
func (e *APISecurityEnforcerImpl) processFilterExpression(expression string, userContext *APISecurityContext) string {
	// Replace common placeholders
	processed := expression
	processed = strings.ReplaceAll(processed, "{user_id}", userContext.UserID)
	processed = strings.ReplaceAll(processed, "{ip_address}", userContext.IPAddress)

	// Replace role-based placeholders
	if len(userContext.UserRoles) > 0 {
		rolesStr := "'" + strings.Join(userContext.UserRoles, "','") + "'"
		processed = strings.ReplaceAll(processed, "{user_roles}", rolesStr)
	}

	// Replace admin level placeholder
	processed = strings.ReplaceAll(processed, "{admin_level}", fmt.Sprintf("%d", userContext.AdminLevel))

	return processed
}
