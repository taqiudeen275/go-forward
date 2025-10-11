package docs

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
)

// EndpointDocumentation represents documentation for an endpoint
type EndpointDocumentation struct {
	Path        string
	Method      string
	Tags        []string
	Summary     string
	Description string
	Parameters  []ParameterDoc
	Responses   map[string]ResponseDoc
	Security    []string
}

// ParameterDoc represents parameter documentation
type ParameterDoc struct {
	Name        string
	Type        string
	In          string
	Required    bool
	Description string
	Example     interface{}
}

// ResponseDoc represents response documentation
type ResponseDoc struct {
	Description string
	Schema      interface{}
	Example     interface{}
}

// DocumentationGenerator helps generate Swagger documentation automatically
type DocumentationGenerator struct {
	service *SwaggerService
}

// NewDocumentationGenerator creates a new documentation generator
func NewDocumentationGenerator(service *SwaggerService) *DocumentationGenerator {
	return &DocumentationGenerator{
		service: service,
	}
}

// DocumentEndpoint automatically documents a Gin endpoint
func (g *DocumentationGenerator) DocumentEndpoint(doc EndpointDocumentation) {
	operation := &Operation{
		Tags:        doc.Tags,
		Summary:     doc.Summary,
		Description: doc.Description,
		OperationID: generateOperationID(doc.Method, doc.Path),
		Parameters:  convertParameters(doc.Parameters),
		Responses:   convertResponses(doc.Responses),
	}

	// Add security if specified
	if len(doc.Security) > 0 {
		security := make([]map[string][]string, len(doc.Security))
		for i, sec := range doc.Security {
			security[i] = map[string][]string{sec: {}}
		}
		operation.Security = security
	}

	g.service.AddEndpoint(doc.Path, doc.Method, operation)
}

// DocumentModel automatically documents a data model
func (g *DocumentationGenerator) DocumentModel(name string, model interface{}) {
	definition := generateDefinitionFromStruct(model)
	g.service.AddDefinition(name, definition)
}

// DocumentGinRoutes automatically documents Gin routes
func (g *DocumentationGenerator) DocumentGinRoutes(router *gin.Engine) {
	routes := router.Routes()

	for _, route := range routes {
		// Skip internal routes
		if strings.HasPrefix(route.Path, "/debug") ||
			strings.HasPrefix(route.Path, "/swagger") ||
			strings.HasPrefix(route.Path, "/docs") {
			continue
		}

		// Generate basic documentation for the route
		doc := EndpointDocumentation{
			Path:        route.Path,
			Method:      route.Method,
			Tags:        inferTags(route.Path),
			Summary:     generateSummary(route.Method, route.Path),
			Description: generateDescription(route.Method, route.Path),
			Responses:   generateDefaultResponses(),
		}

		// Add authentication requirement for admin routes
		if strings.HasPrefix(route.Path, "/_") {
			doc.Security = []string{"BearerAuth", "CookieAuth"}
		}

		g.DocumentEndpoint(doc)
	}
}

// generateOperationID creates a unique operation ID
func generateOperationID(method, path string) string {
	// Convert path to camelCase operation ID
	parts := strings.Split(path, "/")
	var operationParts []string

	operationParts = append(operationParts, strings.ToLower(method))

	for _, part := range parts {
		if part != "" && !strings.HasPrefix(part, ":") && !strings.HasPrefix(part, "*") {
			// Convert kebab-case to camelCase
			words := strings.Split(part, "-")
			for i, word := range words {
				if i == 0 {
					operationParts = append(operationParts, strings.ToLower(word))
				} else {
					operationParts = append(operationParts, strings.Title(word))
				}
			}
		}
	}

	return strings.Join(operationParts, "")
}

// convertParameters converts parameter documentation to Swagger parameters
func convertParameters(params []ParameterDoc) []Parameter {
	var swaggerParams []Parameter

	for _, param := range params {
		swaggerParam := Parameter{
			Name:        param.Name,
			In:          param.In,
			Description: param.Description,
			Required:    param.Required,
			Type:        param.Type,
			Example:     param.Example,
		}
		swaggerParams = append(swaggerParams, swaggerParam)
	}

	return swaggerParams
}

// convertResponses converts response documentation to Swagger responses
func convertResponses(responses map[string]ResponseDoc) map[string]Response {
	swaggerResponses := make(map[string]Response)

	for code, resp := range responses {
		swaggerResp := Response{
			Description: resp.Description,
		}

		if resp.Schema != nil {
			swaggerResp.Schema = convertSchemaFromInterface(resp.Schema)
		}

		if resp.Example != nil {
			swaggerResp.Examples = map[string]Example{
				"application/json": {Value: resp.Example},
			}
		}

		swaggerResponses[code] = swaggerResp
	}

	return swaggerResponses
}

// convertSchemaFromInterface converts an interface to a Swagger schema
func convertSchemaFromInterface(schema interface{}) *Schema {
	// This is a simplified conversion - in a full implementation,
	// you would use reflection to analyze the structure
	return &Schema{
		Type:                 "object",
		AdditionalProperties: true,
	}
}

// generateDefinitionFromStruct generates a Swagger definition from a struct
func generateDefinitionFromStruct(model interface{}) Definition {
	definition := Definition{
		Type:       "object",
		Properties: make(map[string]*Schema),
	}

	// Use reflection to analyze the struct
	modelType := reflect.TypeOf(model)
	if modelType.Kind() == reflect.Ptr {
		modelType = modelType.Elem()
	}

	if modelType.Kind() != reflect.Struct {
		return definition
	}

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get JSON tag or use field name
		jsonTag := field.Tag.Get("json")
		fieldName := field.Name
		if jsonTag != "" && jsonTag != "-" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		// Convert field type to Swagger type
		schema := &Schema{
			Type:        convertGoTypeToSwagger(field.Type),
			Description: field.Tag.Get("description"),
		}

		// Add example from tag if available
		if example := field.Tag.Get("example"); example != "" {
			schema.Example = example
		}

		definition.Properties[fieldName] = schema

		// Check if field is required (simplified check)
		if strings.Contains(jsonTag, "required") {
			definition.Required = append(definition.Required, fieldName)
		}
	}

	return definition
}

// convertGoTypeToSwagger converts Go types to Swagger types
func convertGoTypeToSwagger(goType reflect.Type) string {
	switch goType.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Array, reflect.Slice:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	case reflect.Ptr:
		return convertGoTypeToSwagger(goType.Elem())
	default:
		return "string"
	}
}

// inferTags infers tags from the path
func inferTags(path string) []string {
	if strings.HasPrefix(path, "/_") {
		return []string{"Admin"}
	}
	if strings.Contains(path, "auth") {
		return []string{"Authentication"}
	}
	if strings.Contains(path, "health") {
		return []string{"Health"}
	}
	return []string{"API"}
}

// generateSummary generates a summary from method and path
func generateSummary(method, path string) string {
	action := strings.Title(strings.ToLower(method))
	resource := extractResourceFromPath(path)
	return fmt.Sprintf("%s %s", action, resource)
}

// generateDescription generates a description from method and path
func generateDescription(method, path string) string {
	action := strings.ToLower(method)
	resource := extractResourceFromPath(path)

	switch action {
	case "get":
		return fmt.Sprintf("Retrieve %s information", resource)
	case "post":
		return fmt.Sprintf("Create new %s", resource)
	case "put":
		return fmt.Sprintf("Update %s", resource)
	case "delete":
		return fmt.Sprintf("Delete %s", resource)
	case "patch":
		return fmt.Sprintf("Partially update %s", resource)
	default:
		return fmt.Sprintf("Perform %s operation on %s", action, resource)
	}
}

// extractResourceFromPath extracts the main resource from a path
func extractResourceFromPath(path string) string {
	parts := strings.Split(path, "/")
	for _, part := range parts {
		if part != "" && !strings.HasPrefix(part, ":") && !strings.HasPrefix(part, "*") {
			return part
		}
	}
	return "resource"
}

// generateDefaultResponses generates default responses for an endpoint
func generateDefaultResponses() map[string]ResponseDoc {
	return map[string]ResponseDoc{
		"200": {
			Description: "Successful operation",
			Schema:      map[string]interface{}{"type": "object"},
		},
		"400": {
			Description: "Bad request",
			Schema:      "#/definitions/Error",
		},
		"401": {
			Description: "Unauthorized",
			Schema:      "#/definitions/Error",
		},
		"500": {
			Description: "Internal server error",
			Schema:      "#/definitions/Error",
		},
	}
}
