package interfaces

import (
	"context"
	"net/http"
)

// APIService defines the REST API service interface
type APIService interface {
	GenerateEndpoints(ctx context.Context, schema DatabaseSchema) error
	RegisterCustomEndpoint(path string, handler http.HandlerFunc)
	ApplyRLSPolicies(ctx context.Context, userID string, query Query) Query
	GetEndpoints() []EndpointInfo
}

// QueryBuilder defines interface for building database queries
type QueryBuilder interface {
	Select(columns ...string) QueryBuilder
	Where(condition string, args ...interface{}) QueryBuilder
	OrderBy(column string, direction string) QueryBuilder
	Limit(limit int) QueryBuilder
	Offset(offset int) QueryBuilder
	Execute(ctx context.Context) ([]map[string]interface{}, error)
	Count(ctx context.Context) (int64, error)
}

// Query represents a database query
type Query struct {
	SQL  string
	Args []interface{}
}

// EndpointInfo represents API endpoint information
type EndpointInfo struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Description string            `json:"description"`
	Parameters  map[string]string `json:"parameters"`
	IsGenerated bool              `json:"is_generated"`
}
