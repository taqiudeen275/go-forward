package docs

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/config"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = struct {
	Version     string
	Host        string
	BasePath    string
	Schemes     []string
	Title       string
	Description string
}{
	Version:     "1.0.0",
	Host:        "localhost:8080",
	BasePath:    "/api",
	Schemes:     []string{"http", "https"},
	Title:       "Unified Go Forward Framework API",
	Description: "A comprehensive Backend-as-a-Service (BaaS) framework with enterprise-grade security and administrative controls.",
}

// SwaggerSpec represents the Swagger specification
type SwaggerSpec struct {
	Swagger             string                `json:"swagger"`
	Info                Info                  `json:"info"`
	Host                string                `json:"host"`
	BasePath            string                `json:"basePath"`
	Schemes             []string              `json:"schemes"`
	Consumes            []string              `json:"consumes"`
	Produces            []string              `json:"produces"`
	Paths               map[string]PathItem   `json:"paths"`
	Definitions         map[string]Definition `json:"definitions"`
	SecurityDefinitions map[string]Security   `json:"securityDefinitions"`
	Security            []map[string][]string `json:"security"`
	Tags                []Tag                 `json:"tags"`
	ExternalDocs        *ExternalDocs         `json:"externalDocs,omitempty"`
}

// Info represents API information
type Info struct {
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Version        string  `json:"version"`
	TermsOfService string  `json:"termsOfService,omitempty"`
	Contact        Contact `json:"contact,omitempty"`
	License        License `json:"license,omitempty"`
}

// Contact represents contact information
type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// License represents license information
type License struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// PathItem represents a path item in the API
type PathItem struct {
	Get    *Operation `json:"get,omitempty"`
	Post   *Operation `json:"post,omitempty"`
	Put    *Operation `json:"put,omitempty"`
	Delete *Operation `json:"delete,omitempty"`
	Patch  *Operation `json:"patch,omitempty"`
}

// Operation represents an API operation
type Operation struct {
	Tags        []string              `json:"tags,omitempty"`
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	OperationID string                `json:"operationId,omitempty"`
	Consumes    []string              `json:"consumes,omitempty"`
	Produces    []string              `json:"produces,omitempty"`
	Parameters  []Parameter           `json:"parameters,omitempty"`
	Responses   map[string]Response   `json:"responses"`
	Security    []map[string][]string `json:"security,omitempty"`
}

// Parameter represents an operation parameter
type Parameter struct {
	Name        string      `json:"name"`
	In          string      `json:"in"`
	Description string      `json:"description,omitempty"`
	Required    bool        `json:"required,omitempty"`
	Type        string      `json:"type,omitempty"`
	Format      string      `json:"format,omitempty"`
	Schema      *Schema     `json:"schema,omitempty"`
	Example     interface{} `json:"example,omitempty"`
}

// Response represents an API response
type Response struct {
	Description string             `json:"description"`
	Schema      *Schema            `json:"schema,omitempty"`
	Headers     map[string]Header  `json:"headers,omitempty"`
	Examples    map[string]Example `json:"examples,omitempty"`
}

// Header represents a response header
type Header struct {
	Type        string `json:"type"`
	Format      string `json:"format,omitempty"`
	Description string `json:"description,omitempty"`
}

// Example represents an example value
type Example struct {
	Value interface{} `json:"value"`
}

// Schema represents a JSON schema
type Schema struct {
	Type                 string             `json:"type,omitempty"`
	Format               string             `json:"format,omitempty"`
	Title                string             `json:"title,omitempty"`
	Description          string             `json:"description,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	AdditionalProperties interface{}        `json:"additionalProperties,omitempty"`
	Ref                  string             `json:"$ref,omitempty"`
	Example              interface{}        `json:"example,omitempty"`
}

// Definition represents a model definition
type Definition struct {
	Type                 string             `json:"type"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	AdditionalProperties interface{}        `json:"additionalProperties,omitempty"`
	Description          string             `json:"description,omitempty"`
	Example              interface{}        `json:"example,omitempty"`
}

// Security represents a security definition
type Security struct {
	Type             string            `json:"type"`
	Description      string            `json:"description,omitempty"`
	Name             string            `json:"name,omitempty"`
	In               string            `json:"in,omitempty"`
	Flow             string            `json:"flow,omitempty"`
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	Scopes           map[string]string `json:"scopes,omitempty"`
}

// Tag represents an API tag
type Tag struct {
	Name         string        `json:"name"`
	Description  string        `json:"description,omitempty"`
	ExternalDocs *ExternalDocs `json:"externalDocs,omitempty"`
}

// ExternalDocs represents external documentation
type ExternalDocs struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

// SwaggerService manages Swagger documentation
type SwaggerService struct {
	spec   *SwaggerSpec
	config *config.Config
	logger *logger.Logger
}

// NewSwaggerService creates a new Swagger service
func NewSwaggerService(cfg *config.Config) *SwaggerService {
	return &SwaggerService{
		spec:   generateBaseSpec(cfg),
		config: cfg,
		logger: logger.GetLogger(),
	}
}

// generateBaseSpec creates the base Swagger specification
func generateBaseSpec(cfg *config.Config) *SwaggerSpec {
	spec := &SwaggerSpec{
		Swagger:  "2.0",
		Host:     fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		BasePath: "/api",
		Schemes:  []string{"http"},
		Consumes: []string{"application/json"},
		Produces: []string{"application/json"},
		Info: Info{
			Title:       "Unified Go Forward Framework API",
			Description: "A comprehensive Backend-as-a-Service (BaaS) framework with enterprise-grade security and administrative controls.",
			Version:     "1.0.0",
			Contact: Contact{
				Name:  "Go Forward Framework",
				Email: "support@goforward.dev",
			},
			License: License{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Paths:       make(map[string]PathItem),
		Definitions: make(map[string]Definition),
		SecurityDefinitions: map[string]Security{
			"BearerAuth": {
				Type:        "apiKey",
				Name:        "Authorization",
				In:          "header",
				Description: "JWT Bearer token authentication. Format: 'Bearer {token}'",
			},
			"CookieAuth": {
				Type:        "apiKey",
				Name:        "session",
				In:          "cookie",
				Description: "HTTP-only cookie authentication for admin dashboard",
			},
		},
		Security: []map[string][]string{
			{"BearerAuth": {}},
		},
		Tags: []Tag{
			{
				Name:        "Authentication",
				Description: "Authentication and authorization endpoints",
			},
			{
				Name:        "Admin",
				Description: "Administrative endpoints (requires admin privileges)",
			},
			{
				Name:        "Health",
				Description: "System health and monitoring endpoints",
			},
		},
	}

	// Add HTTPS if in production
	if cfg.IsProduction() {
		spec.Schemes = []string{"https", "http"}
	}

	// Add common definitions
	addCommonDefinitions(spec)

	// Add base endpoints
	addBaseEndpoints(spec, cfg)

	return spec
}

// addCommonDefinitions adds common model definitions
func addCommonDefinitions(spec *SwaggerSpec) {
	spec.Definitions["Error"] = Definition{
		Type: "object",
		Properties: map[string]*Schema{
			"error": {
				Type:        "string",
				Description: "Error message",
				Example:     "Invalid request",
			},
			"code": {
				Type:        "string",
				Description: "Error code",
				Example:     "INVALID_REQUEST",
			},
			"details": {
				Type:                 "object",
				Description:          "Additional error details",
				AdditionalProperties: true,
			},
			"request_id": {
				Type:        "string",
				Description: "Request ID for tracking",
				Example:     "req_123456789",
			},
			"timestamp": {
				Type:        "string",
				Format:      "date-time",
				Description: "Error timestamp",
				Example:     "2024-01-01T00:00:00Z",
			},
		},
		Required: []string{"error", "timestamp"},
	}

	spec.Definitions["Health"] = Definition{
		Type: "object",
		Properties: map[string]*Schema{
			"status": {
				Type:        "string",
				Description: "Overall system status",
				Example:     "healthy",
			},
			"timestamp": {
				Type:        "string",
				Format:      "date-time",
				Description: "Health check timestamp",
				Example:     "2024-01-01T00:00:00Z",
			},
			"version": {
				Type:        "string",
				Description: "Application version",
				Example:     "1.0.0",
			},
			"environment": {
				Type:        "string",
				Description: "Environment name",
				Example:     "production",
			},
			"database": {
				Type:                 "object",
				Description:          "Database health information",
				AdditionalProperties: true,
			},
		},
		Required: []string{"status", "timestamp", "version"},
	}
}

// addBaseEndpoints adds base API endpoints
func addBaseEndpoints(spec *SwaggerSpec, cfg *config.Config) {
	// Health endpoint
	spec.Paths["/health"] = PathItem{
		Get: &Operation{
			Tags:        []string{"Health"},
			Summary:     "Get system health status",
			Description: "Returns the current health status of the system including database connectivity",
			OperationID: "getHealth",
			Responses: map[string]Response{
				"200": {
					Description: "System health information",
					Schema: &Schema{
						Ref: "#/definitions/Health",
					},
				},
			},
		},
	}

	// API info endpoint
	spec.Paths["/"] = PathItem{
		Get: &Operation{
			Tags:        []string{"Health"},
			Summary:     "Get API information",
			Description: "Returns basic API information and version",
			OperationID: "getAPIInfo",
			Responses: map[string]Response{
				"200": {
					Description: "API information",
					Schema: &Schema{
						Type: "object",
						Properties: map[string]*Schema{
							"message": {
								Type:    "string",
								Example: "Unified Go Forward Framework API",
							},
							"version": {
								Type:    "string",
								Example: "1.0.0",
							},
							"environment": {
								Type:    "string",
								Example: cfg.Environment,
							},
						},
					},
				},
			},
		},
	}
}

// GetSpec returns the current Swagger specification
func (s *SwaggerService) GetSpec() *SwaggerSpec {
	return s.spec
}

// GetSpecJSON returns the Swagger specification as JSON
func (s *SwaggerService) GetSpecJSON() ([]byte, error) {
	return json.MarshalIndent(s.spec, "", "  ")
}

// AddEndpoint adds a new endpoint to the specification
func (s *SwaggerService) AddEndpoint(path, method string, operation *Operation) {
	if s.spec.Paths[path].Get == nil && s.spec.Paths[path].Post == nil &&
		s.spec.Paths[path].Put == nil && s.spec.Paths[path].Delete == nil &&
		s.spec.Paths[path].Patch == nil {
		s.spec.Paths[path] = PathItem{}
	}

	pathItem := s.spec.Paths[path]
	switch strings.ToUpper(method) {
	case "GET":
		pathItem.Get = operation
	case "POST":
		pathItem.Post = operation
	case "PUT":
		pathItem.Put = operation
	case "DELETE":
		pathItem.Delete = operation
	case "PATCH":
		pathItem.Patch = operation
	}
	s.spec.Paths[path] = pathItem
}

// AddDefinition adds a new model definition
func (s *SwaggerService) AddDefinition(name string, definition Definition) {
	s.spec.Definitions[name] = definition
}

// ServeSwaggerJSON serves the Swagger JSON specification
func (s *SwaggerService) ServeSwaggerJSON() gin.HandlerFunc {
	return func(c *gin.Context) {
		spec, err := s.GetSpecJSON()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to generate Swagger specification",
			})
			return
		}

		c.Header("Content-Type", "application/json")
		c.Data(http.StatusOK, "application/json", spec)
	}
}

// ServeSwaggerUI serves the Swagger UI interface
func (s *SwaggerService) ServeSwaggerUI() gin.HandlerFunc {
	return func(c *gin.Context) {
		swaggerUIHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Go Forward Framework API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.52.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/swagger.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>`

		c.Header("Content-Type", "text/html")
		c.String(http.StatusOK, swaggerUIHTML)
	}
}

// UpdateHost updates the host in the specification
func (s *SwaggerService) UpdateHost(host string) {
	s.spec.Host = host
}

// UpdateBasePath updates the base path in the specification
func (s *SwaggerService) UpdateBasePath(basePath string) {
	s.spec.BasePath = basePath
}
