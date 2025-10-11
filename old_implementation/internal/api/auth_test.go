package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/taqiudeen275/go-foward/internal/auth"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

func TestNewRLSPolicyManager(t *testing.T) {
	manager := NewRLSPolicyManager()

	assert.NotNil(t, manager)
	assert.NotNil(t, manager.policies)
	assert.Empty(t, manager.policies)
}

func TestRLSPolicyManager_AddPolicy(t *testing.T) {
	manager := NewRLSPolicyManager()

	policy := &RLSPolicy{
		TableName:  "products",
		PolicyName: "owner_policy",
		Operation:  "SELECT",
		Expression: "user_id = current_user_id()",
		Roles:      []string{"user"},
	}

	manager.AddPolicy(policy)

	assert.Len(t, manager.policies, 1)

	key := "products_SELECT_owner_policy"
	assert.Contains(t, manager.policies, key)
	assert.Equal(t, policy, manager.policies[key])
}

func TestRLSPolicyManager_GetPolicies(t *testing.T) {
	manager := NewRLSPolicyManager()

	// Add multiple policies
	policies := []*RLSPolicy{
		{
			TableName:  "products",
			PolicyName: "select_policy",
			Operation:  "SELECT",
			Expression: "user_id = current_user_id()",
		},
		{
			TableName:  "products",
			PolicyName: "update_policy",
			Operation:  "UPDATE",
			Expression: "user_id = current_user_id()",
		},
		{
			TableName:  "products",
			PolicyName: "all_policy",
			Operation:  "ALL",
			Expression: "role = 'admin'",
		},
		{
			TableName:  "orders",
			PolicyName: "select_policy",
			Operation:  "SELECT",
			Expression: "customer_id = current_user_id()",
		},
	}

	for _, policy := range policies {
		manager.AddPolicy(policy)
	}

	// Test getting SELECT policies for products
	selectPolicies := manager.GetPolicies("products", "SELECT")
	assert.Len(t, selectPolicies, 2) // select_policy and all_policy

	// Test getting UPDATE policies for products
	updatePolicies := manager.GetPolicies("products", "UPDATE")
	assert.Len(t, updatePolicies, 2) // update_policy and all_policy

	// Test getting policies for orders
	orderPolicies := manager.GetPolicies("orders", "SELECT")
	assert.Len(t, orderPolicies, 1) // only select_policy
}

func TestService_SetTableAuthConfig(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	config := &AuthConfig{
		RequireAuth:      true,
		RequireVerified:  true,
		AllowedRoles:     []string{"admin", "user"},
		RequireOwnership: true,
		OwnershipColumn:  "user_id",
		PublicRead:       false,
		PublicWrite:      false,
	}

	service.SetTableAuthConfig("products", config)

	assert.Contains(t, service.authConfigs, "products")
	assert.Equal(t, config, service.authConfigs["products"])
}

func TestService_GetTableAuthConfig(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	// Test getting config for table with custom config
	customConfig := &AuthConfig{
		RequireAuth:     true,
		RequireVerified: true,
	}
	service.SetTableAuthConfig("products", customConfig)

	retrievedConfig := service.GetTableAuthConfig("products")
	assert.Equal(t, customConfig, retrievedConfig)

	// Test getting config for table without custom config (should return default)
	defaultConfig := service.GetTableAuthConfig("orders")
	assert.NotNil(t, defaultConfig)
	assert.False(t, defaultConfig.RequireAuth)
	assert.False(t, defaultConfig.RequireVerified)
	assert.Empty(t, defaultConfig.AllowedRoles)
	assert.False(t, defaultConfig.RequireOwnership)
	assert.Equal(t, "", defaultConfig.OwnershipColumn)
	assert.True(t, defaultConfig.PublicRead)
	assert.False(t, defaultConfig.PublicWrite)
}

func TestService_AddRLSPolicy(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	policy := &RLSPolicy{
		TableName:  "products",
		PolicyName: "owner_policy",
		Operation:  "SELECT",
		Expression: "user_id = current_user_id()",
	}

	service.AddRLSPolicy(policy)

	// Verify policy was added to the manager
	policies := service.rlsPolicyMgr.GetPolicies("products", "SELECT")
	assert.Len(t, policies, 1)
	assert.Equal(t, policy, policies[0])
}

func TestAuthConfig_DefaultValues(t *testing.T) {
	config := &AuthConfig{}

	// Test default values
	assert.False(t, config.RequireAuth)
	assert.False(t, config.RequireVerified)
	assert.Empty(t, config.AllowedRoles)
	assert.False(t, config.RequireOwnership)
	assert.Equal(t, "", config.OwnershipColumn)
	assert.False(t, config.PublicRead)
	assert.False(t, config.PublicWrite)
}

func TestRLSPolicy_Structure(t *testing.T) {
	policy := &RLSPolicy{
		TableName:  "products",
		PolicyName: "owner_access",
		Operation:  "ALL",
		Expression: "user_id = current_user_id()",
		Roles:      []string{"user", "admin"},
		Conditions: map[string]string{"status": "active"},
	}

	assert.Equal(t, "products", policy.TableName)
	assert.Equal(t, "owner_access", policy.PolicyName)
	assert.Equal(t, "ALL", policy.Operation)
	assert.Equal(t, "user_id = current_user_id()", policy.Expression)
	assert.Equal(t, []string{"user", "admin"}, policy.Roles)
	assert.Equal(t, map[string]string{"status": "active"}, policy.Conditions)
}

func TestService_ApplyRLSPolicies_NoUser(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	originalQuery := interfaces.Query{
		SQL:  "SELECT * FROM products",
		Args: []interface{}{},
	}

	// Test with no user ID (should return query unchanged)
	result := service.ApplyRLSPolicies(nil, "", originalQuery)

	assert.Equal(t, originalQuery.SQL, result.SQL)
	assert.Equal(t, originalQuery.Args, result.Args)
}

func TestService_ApplyRLSPolicies_WithUser(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	originalQuery := interfaces.Query{
		SQL:  "SELECT * FROM products",
		Args: []interface{}{},
	}

	// Test with user ID (currently returns query unchanged, but structure is there for future implementation)
	result := service.ApplyRLSPolicies(nil, "user123", originalQuery)

	assert.Equal(t, originalQuery.SQL, result.SQL)
	assert.Equal(t, originalQuery.Args, result.Args)
}

// Mock auth middleware for testing
type MockAuthMiddleware struct {
	user *auth.User
}

func (m *MockAuthMiddleware) GetUserFromContext(c interface{}) *auth.User {
	return m.user
}

func (m *MockAuthMiddleware) RequireAuth() interface{} {
	return func(c interface{}) {
		// Mock implementation
	}
}

func (m *MockAuthMiddleware) OptionalAuth() interface{} {
	return func(c interface{}) {
		// Mock implementation
	}
}

func TestCreateAuthenticatedEndpoints_Integration(t *testing.T) {
	mockMeta := &MockMetaService{}
	service := NewService(mockMeta)

	// This would normally use a real auth middleware, but for testing we'll just verify the structure
	// service.CreateAuthenticatedEndpoints(table, mockAuthMiddleware, config)

	// Verify the service has the necessary components
	assert.NotNil(t, service.rlsPolicyMgr)
	assert.NotNil(t, service.authConfigs)
	assert.NotNil(t, service.endpoints)
}
