package auth

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PolicyEngine interface defines rule evaluation and policy management
type PolicyEngine interface {
	CreatePolicy(ctx context.Context, policy SecurityPolicy) error
	UpdatePolicy(ctx context.Context, policyID string, updates SecurityPolicy) error
	DeletePolicy(ctx context.Context, policyID string) error
	GetPolicy(ctx context.Context, policyID string) (*SecurityPolicy, error)
	ListPolicies(ctx context.Context) ([]*SecurityPolicy, error)
	EvaluateAccess(ctx context.Context, request AccessRequest) (*AccessDecision, error)

	// RLS integration
	GenerateRLSPolicy(ctx context.Context, tableConfig TableSecurityConfig) (*RLSPolicy, error)
	ApplyRLSPolicies(ctx context.Context, userID string, query SQLQuery) (*SQLQuery, error)

	// Filter management
	ApplyCustomFilters(ctx context.Context, userID string, tableName string, baseQuery string) (string, error)
	EvaluateTimeBasedAccess(ctx context.Context, userID string, resource string) (bool, error)
	CheckIPWhitelist(ctx context.Context, ipAddress string, resource string) (bool, error)
}

// AccessRequest represents a request for access evaluation
type AccessRequest struct {
	UserID      string                 `json:"user_id"`
	Resource    string                 `json:"resource"`
	Action      string                 `json:"action"`
	Context     SecurityContext        `json:"context"`
	RequestData map[string]interface{} `json:"request_data"`
}

// AccessDecision represents the result of access evaluation
type AccessDecision struct {
	Allowed    bool                   `json:"allowed"`
	Reason     string                 `json:"reason"`
	Policies   []string               `json:"policies"`
	Conditions []string               `json:"conditions"`
	Filters    map[string]string      `json:"filters"`
	Metadata   map[string]interface{} `json:"metadata"`
	ExpiresAt  *time.Time             `json:"expires_at"`
}

// RLSPolicy represents a Row Level Security policy
type RLSPolicy struct {
	ID         string    `json:"id"`
	TableName  string    `json:"table_name"`
	PolicyName string    `json:"policy_name"`
	PolicyType string    `json:"policy_type"` // SELECT, INSERT, UPDATE, DELETE, ALL
	Expression string    `json:"expression"`
	Roles      []string  `json:"roles"`
	IsEnabled  bool      `json:"is_enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SQLQuery represents a SQL query with metadata
type SQLQuery struct {
	Query      string            `json:"query"`
	Parameters []interface{}     `json:"parameters"`
	Tables     []string          `json:"tables"`
	Operations []string          `json:"operations"`
	Metadata   map[string]string `json:"metadata"`
}

// TableSecurityConfig represents table-level security configuration
type TableSecurityConfig struct {
	ID          string `json:"id" db:"id"`
	TableName   string `json:"table_name" db:"table_name"`
	SchemaName  string `json:"schema_name" db:"schema_name"`
	DisplayName string `json:"display_name" db:"display_name"`
	Description string `json:"description" db:"description"`

	// API Security Configuration
	APIConfig APISecurityConfig `json:"api_config" db:"api_config"`

	// Admin Panel Configuration
	AdminConfig AdminPanelConfig `json:"admin_config" db:"admin_config"`

	// Field-level permissions
	FieldPermissions map[string]FieldPermission `json:"field_permissions" db:"field_permissions"`

	// Audit configuration
	AuditConfig AuditConfig `json:"audit_config" db:"audit_config"`

	// Metadata
	CreatedBy string    `json:"created_by" db:"created_by"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedBy string    `json:"updated_by" db:"updated_by"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
	IsActive  bool      `json:"is_active" db:"is_active"`
}

// APISecurityConfig defines API-level security settings
type APISecurityConfig struct {
	RequireAuth      bool     `json:"require_auth"`
	RequireVerified  bool     `json:"require_verified"`
	AllowedRoles     []string `json:"allowed_roles"`
	RequireOwnership bool     `json:"require_ownership"`
	OwnershipColumn  string   `json:"ownership_column"`
	PublicRead       bool     `json:"public_read"`
	PublicWrite      bool     `json:"public_write"`

	// Enhanced security features
	RequireMFA   bool             `json:"require_mfa"`
	IPWhitelist  []string         `json:"ip_whitelist"`
	RateLimit    *RateLimitConfig `json:"rate_limit"`
	AuditActions bool             `json:"audit_actions"`

	// Field-level controls
	ReadableFields []string `json:"readable_fields"`
	WritableFields []string `json:"writable_fields"`
	HiddenFields   []string `json:"hidden_fields"`

	// Advanced filters
	CustomFilters   map[string]string      `json:"custom_filters"`
	TimeBasedAccess *TimeBasedAccessConfig `json:"time_based_access"`
}

// AdminPanelConfig defines admin panel specific settings
type AdminPanelConfig struct {
	Visible          bool     `json:"visible"`
	ReadOnly         bool     `json:"read_only"`
	RequiredRoles    []string `json:"required_roles"`
	HiddenFields     []string `json:"hidden_fields"`
	SearchableFields []string `json:"searchable_fields"`
	SortableFields   []string `json:"sortable_fields"`
}

// FieldPermission defines field-level permissions
type FieldPermission struct {
	Read      bool     `json:"read"`
	Write     bool     `json:"write"`
	Roles     []string `json:"roles"`
	Condition string   `json:"condition"`
}

// AuditConfig defines audit settings
type AuditConfig struct {
	LogReads   bool `json:"log_reads"`
	LogWrites  bool `json:"log_writes"`
	LogDeletes bool `json:"log_deletes"`
}

// RateLimitConfig defines rate limiting settings
type RateLimitConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// TimeBasedAccessConfig defines time-based access restrictions
type TimeBasedAccessConfig struct {
	AllowedHours   []int    `json:"allowed_hours"` // 0-23
	AllowedDays    []int    `json:"allowed_days"`  // 0-6 (Sunday-Saturday)
	Timezone       string   `json:"timezone"`
	BlockedPeriods []string `json:"blocked_periods"` // "HH:MM-HH:MM"
}

// PolicyEngineImpl implements the PolicyEngine interface
type PolicyEngineImpl struct {
	policies    map[string]*SecurityPolicy
	rlsPolicies map[string]*RLSPolicy
	rbacEngine  RBACEngine
	adminRepo   *AdminRepository
	policyRepo  *PolicyRepository
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(rbacEngine RBACEngine, adminRepo *AdminRepository, policyRepo *PolicyRepository) PolicyEngine {
	return &PolicyEngineImpl{
		policies:    make(map[string]*SecurityPolicy),
		rlsPolicies: make(map[string]*RLSPolicy),
		rbacEngine:  rbacEngine,
		adminRepo:   adminRepo,
		policyRepo:  policyRepo,
	}
}

// CreatePolicy creates a new security policy
func (pe *PolicyEngineImpl) CreatePolicy(ctx context.Context, policy SecurityPolicy) error {
	if policy.ID == "" {
		policy.ID = uuid.New().String()
	}

	policy.CreatedAt = time.Now()
	policy.UpdatedAt = time.Now()

	// TODO: Validate policy rules and conditions
	if err := pe.validatePolicy(policy); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	// TODO: Save to database
	pe.policies[policy.ID] = &policy

	return nil
}

// UpdatePolicy updates an existing security policy
func (pe *PolicyEngineImpl) UpdatePolicy(ctx context.Context, policyID string, updates SecurityPolicy) error {
	existing, exists := pe.policies[policyID]
	if !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	// Preserve creation time and ID
	updates.ID = existing.ID
	updates.CreatedAt = existing.CreatedAt
	updates.UpdatedAt = time.Now()

	// TODO: Validate updated policy
	if err := pe.validatePolicy(updates); err != nil {
		return fmt.Errorf("invalid policy update: %w", err)
	}

	// TODO: Update in database
	pe.policies[policyID] = &updates

	return nil
}

// DeletePolicy deletes a security policy
func (pe *PolicyEngineImpl) DeletePolicy(ctx context.Context, policyID string) error {
	if _, exists := pe.policies[policyID]; !exists {
		return fmt.Errorf("policy not found: %s", policyID)
	}

	// TODO: Check if policy is in use
	// TODO: Delete from database
	delete(pe.policies, policyID)

	return nil
}

// GetPolicy retrieves a policy by ID
func (pe *PolicyEngineImpl) GetPolicy(ctx context.Context, policyID string) (*SecurityPolicy, error) {
	policy, exists := pe.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyID)
	}

	return policy, nil
}

// ListPolicies lists all security policies
func (pe *PolicyEngineImpl) ListPolicies(ctx context.Context) ([]*SecurityPolicy, error) {
	policies := make([]*SecurityPolicy, 0, len(pe.policies))
	for _, policy := range pe.policies {
		policies = append(policies, policy)
	}

	return policies, nil
}

// EvaluateAccess evaluates an access request against all applicable policies
func (pe *PolicyEngineImpl) EvaluateAccess(ctx context.Context, request AccessRequest) (*AccessDecision, error) {
	decision := &AccessDecision{
		Allowed:    false,
		Policies:   make([]string, 0),
		Conditions: make([]string, 0),
		Filters:    make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	// First check RBAC permissions
	rbacAllowed, err := pe.rbacEngine.CheckPermission(ctx, request.UserID, request.Resource, request.Action, request.Context)
	if err != nil {
		return decision, fmt.Errorf("RBAC check failed: %w", err)
	}

	if !rbacAllowed {
		decision.Reason = "RBAC permission denied"
		return decision, nil
	}

	// Evaluate applicable policies
	for _, policy := range pe.policies {
		if !policy.IsActive {
			continue
		}

		// Check if policy applies to this request
		if pe.policyApplies(policy, request) {
			decision.Policies = append(decision.Policies, policy.ID)

			// Evaluate policy rules
			allowed, conditions := pe.evaluatePolicyRules(policy, request)
			if !allowed && policy.Effect == PolicyEffectDeny {
				decision.Reason = fmt.Sprintf("Denied by policy: %s", policy.Name)
				return decision, nil
			}

			decision.Conditions = append(decision.Conditions, conditions...)
		}
	}

	// Apply additional security checks
	if err := pe.applySecurityChecks(ctx, request, decision); err != nil {
		decision.Reason = fmt.Sprintf("Security check failed: %v", err)
		return decision, nil
	}

	decision.Allowed = true
	decision.Reason = "Access granted"

	return decision, nil
}

// GenerateRLSPolicy generates a Row Level Security policy from table configuration
func (pe *PolicyEngineImpl) GenerateRLSPolicy(ctx context.Context, tableConfig TableSecurityConfig) (*RLSPolicy, error) {
	policy := &RLSPolicy{
		ID:         uuid.New().String(),
		TableName:  tableConfig.TableName,
		PolicyName: fmt.Sprintf("rls_%s_policy", tableConfig.TableName),
		PolicyType: "ALL",
		IsEnabled:  true,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Build RLS expression based on configuration
	var conditions []string

	// Add authentication requirement
	if tableConfig.APIConfig.RequireAuth {
		conditions = append(conditions, "current_user_id() IS NOT NULL")
	}

	// Add ownership requirement
	if tableConfig.APIConfig.RequireOwnership && tableConfig.APIConfig.OwnershipColumn != "" {
		conditions = append(conditions, fmt.Sprintf("%s = current_user_id()", tableConfig.APIConfig.OwnershipColumn))
	}

	// Add role-based access
	if len(tableConfig.APIConfig.AllowedRoles) > 0 {
		roleConditions := make([]string, len(tableConfig.APIConfig.AllowedRoles))
		for i, role := range tableConfig.APIConfig.AllowedRoles {
			roleConditions[i] = fmt.Sprintf("current_user_has_role('%s')", role)
		}
		conditions = append(conditions, fmt.Sprintf("(%s)", strings.Join(roleConditions, " OR ")))
	}

	// Combine conditions
	if len(conditions) > 0 {
		policy.Expression = strings.Join(conditions, " AND ")
	} else {
		policy.Expression = "true" // Allow all if no conditions
	}

	// TODO: Save to database
	pe.rlsPolicies[policy.ID] = policy

	return policy, nil
}

// ApplyRLSPolicies applies RLS policies to a SQL query
func (pe *PolicyEngineImpl) ApplyRLSPolicies(ctx context.Context, userID string, query SQLQuery) (*SQLQuery, error) {
	modifiedQuery := query

	// For each table in the query, apply relevant RLS policies
	for _, tableName := range query.Tables {
		// Find RLS policies for this table
		for _, rlsPolicy := range pe.rlsPolicies {
			if rlsPolicy.TableName == tableName && rlsPolicy.IsEnabled {
				// Modify query to include RLS conditions
				// This is a simplified implementation
				if strings.Contains(strings.ToUpper(modifiedQuery.Query), "SELECT") {
					modifiedQuery.Query = pe.injectRLSCondition(modifiedQuery.Query, tableName, rlsPolicy.Expression, userID)
				}
			}
		}
	}

	return &modifiedQuery, nil
}

// ApplyCustomFilters applies custom filters to a query based on user context
func (pe *PolicyEngineImpl) ApplyCustomFilters(ctx context.Context, userID string, tableName string, baseQuery string) (string, error) {
	// Get user capabilities to determine applicable filters
	capabilities, err := pe.rbacEngine.GetUserCapabilities(ctx, userID)
	if err != nil {
		return baseQuery, fmt.Errorf("failed to get user capabilities: %w", err)
	}

	modifiedQuery := baseQuery

	// Apply role-based filters
	if !capabilities.CanManageAllTables {
		// Add ownership filter for regular admins
		if capabilities.CanManageUsers {
			modifiedQuery = pe.addWhereCondition(modifiedQuery, "created_by = $user_id")
		}

		// Add table-specific filters for assigned tables
		for _, assignedTable := range capabilities.AssignedTables {
			if assignedTable == tableName {
				// Apply table-specific filters
				modifiedQuery = pe.addWhereCondition(modifiedQuery, "status != 'deleted'")
			}
		}
	}

	return modifiedQuery, nil
}

// EvaluateTimeBasedAccess checks if access is allowed based on time restrictions
func (pe *PolicyEngineImpl) EvaluateTimeBasedAccess(ctx context.Context, userID string, resource string) (bool, error) {
	// TODO: Get time-based access configuration for the resource
	// For now, implement basic time-based logic

	now := time.Now()

	// Example: Block access during maintenance hours (2-4 AM)
	if now.Hour() >= 2 && now.Hour() < 4 {
		// Check if user has system admin privileges to bypass time restrictions
		capabilities, err := pe.rbacEngine.GetUserCapabilities(ctx, userID)
		if err != nil {
			return false, err
		}

		if !capabilities.CanManageSystem {
			return false, nil
		}
	}

	return true, nil
}

// CheckIPWhitelist checks if an IP address is allowed for a resource
func (pe *PolicyEngineImpl) CheckIPWhitelist(ctx context.Context, ipAddress string, resource string) (bool, error) {
	// TODO: Get IP whitelist configuration for the resource
	// For now, implement basic IP checking logic

	// Parse IP address
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	// Allow local IPs by default
	if ip.IsLoopback() || ip.IsPrivate() {
		return true, nil
	}

	// TODO: Check against configured whitelist
	// For now, allow all external IPs (in production, this should be configurable)
	return true, nil
}

// Helper methods

// validatePolicy validates a security policy
func (pe *PolicyEngineImpl) validatePolicy(policy SecurityPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name is required")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("policy must have at least one rule")
	}

	// Validate each rule
	for i, rule := range policy.Rules {
		if rule.Resource == "" {
			return fmt.Errorf("rule %d: resource is required", i)
		}

		if len(rule.Actions) == 0 {
			return fmt.Errorf("rule %d: at least one action is required", i)
		}

		if rule.Effect != PolicyEffectAllow && rule.Effect != PolicyEffectDeny {
			return fmt.Errorf("rule %d: invalid effect, must be 'allow' or 'deny'", i)
		}
	}

	return nil
}

// policyApplies checks if a policy applies to a request
func (pe *PolicyEngineImpl) policyApplies(policy *SecurityPolicy, request AccessRequest) bool {
	for _, rule := range policy.Rules {
		if pe.resourceMatches(rule.Resource, request.Resource) {
			for _, action := range rule.Actions {
				if pe.actionMatches(action, request.Action) {
					return true
				}
			}
		}
	}

	return false
}

// resourceMatches checks if a resource pattern matches a request resource
func (pe *PolicyEngineImpl) resourceMatches(pattern, resource string) bool {
	// Simple pattern matching - in production, use more sophisticated matching
	if pattern == "*" || pattern == resource {
		return true
	}

	// Check for prefix matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}

	return false
}

// actionMatches checks if an action pattern matches a request action
func (pe *PolicyEngineImpl) actionMatches(pattern, action string) bool {
	return pattern == "*" || pattern == action
}

// evaluatePolicyRules evaluates the rules of a policy
func (pe *PolicyEngineImpl) evaluatePolicyRules(policy *SecurityPolicy, request AccessRequest) (bool, []string) {
	conditions := make([]string, 0)

	for _, rule := range policy.Rules {
		if pe.resourceMatches(rule.Resource, request.Resource) {
			for _, action := range rule.Actions {
				if pe.actionMatches(action, request.Action) {
					// Evaluate rule conditions
					for _, condition := range rule.Conditions {
						if pe.evaluateCondition(condition, request.Context) {
							conditions = append(conditions, condition)
						}
					}

					return rule.Effect == PolicyEffectAllow, conditions
				}
			}
		}
	}

	return true, conditions
}

// evaluateCondition evaluates a condition against a security context
func (pe *PolicyEngineImpl) evaluateCondition(condition string, context SecurityContext) bool {
	// Parse and evaluate conditions
	parts := strings.SplitN(condition, ":", 2)
	if len(parts) != 2 {
		return false
	}

	conditionType := parts[0]
	conditionValue := parts[1]

	switch conditionType {
	case "ip_range":
		return pe.evaluateIPRange(conditionValue, context.IPAddress)
	case "time_range":
		return pe.evaluateTimeRange(conditionValue)
	case "user_agent":
		return pe.evaluateUserAgent(conditionValue, context.UserAgent)
	case "environment":
		return conditionValue == context.Environment
	default:
		return false
	}
}

// evaluateIPRange checks if an IP is in a specified range
func (pe *PolicyEngineImpl) evaluateIPRange(rangeStr, ipStr string) bool {
	_, ipNet, err := net.ParseCIDR(rangeStr)
	if err != nil {
		// Try parsing as single IP
		if rangeStr == ipStr {
			return true
		}
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	return ipNet.Contains(ip)
}

// evaluateTimeRange checks if current time is in a specified range
func (pe *PolicyEngineImpl) evaluateTimeRange(rangeStr string) bool {
	// Parse time range (e.g., "09:00-17:00")
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return false
	}

	startTime, err := time.Parse("15:04", parts[0])
	if err != nil {
		return false
	}

	endTime, err := time.Parse("15:04", parts[1])
	if err != nil {
		return false
	}

	now := time.Now()
	currentTime := time.Date(0, 1, 1, now.Hour(), now.Minute(), 0, 0, time.UTC)

	return currentTime.After(startTime) && currentTime.Before(endTime)
}

// evaluateUserAgent checks if user agent matches a pattern
func (pe *PolicyEngineImpl) evaluateUserAgent(pattern, userAgent string) bool {
	matched, err := regexp.MatchString(pattern, userAgent)
	if err != nil {
		return false
	}

	return matched
}

// applySecurityChecks applies additional security checks
func (pe *PolicyEngineImpl) applySecurityChecks(ctx context.Context, request AccessRequest, decision *AccessDecision) error {
	// Check time-based access
	timeAllowed, err := pe.EvaluateTimeBasedAccess(ctx, request.UserID, request.Resource)
	if err != nil {
		return fmt.Errorf("time-based access check failed: %w", err)
	}

	if !timeAllowed {
		return fmt.Errorf("access denied due to time restrictions")
	}

	// Check IP whitelist
	ipAllowed, err := pe.CheckIPWhitelist(ctx, request.Context.IPAddress, request.Resource)
	if err != nil {
		return fmt.Errorf("IP whitelist check failed: %w", err)
	}

	if !ipAllowed {
		return fmt.Errorf("access denied due to IP restrictions")
	}

	return nil
}

// injectRLSCondition injects RLS conditions into a SQL query
func (pe *PolicyEngineImpl) injectRLSCondition(query, tableName, condition, userID string) string {
	// This is a simplified implementation
	// In production, you would use a proper SQL parser

	// Replace user context placeholders
	condition = strings.ReplaceAll(condition, "current_user_id()", fmt.Sprintf("'%s'", userID))

	// Add WHERE clause or extend existing one
	if strings.Contains(strings.ToUpper(query), "WHERE") {
		return strings.ReplaceAll(query, "WHERE", fmt.Sprintf("WHERE (%s) AND", condition))
	} else {
		// Find the position to insert WHERE clause
		fromIndex := strings.Index(strings.ToUpper(query), "FROM")
		if fromIndex != -1 {
			// Find the end of the FROM clause
			parts := strings.Fields(query[fromIndex:])
			if len(parts) >= 2 {
				tablePart := parts[1]
				insertPoint := fromIndex + len("FROM ") + len(tablePart)
				return query[:insertPoint] + fmt.Sprintf(" WHERE (%s)", condition) + query[insertPoint:]
			}
		}
	}

	return query
}

// addWhereCondition adds a WHERE condition to a query
func (pe *PolicyEngineImpl) addWhereCondition(query, condition string) string {
	if strings.Contains(strings.ToUpper(query), "WHERE") {
		return query + fmt.Sprintf(" AND (%s)", condition)
	} else {
		return query + fmt.Sprintf(" WHERE (%s)", condition)
	}
}
