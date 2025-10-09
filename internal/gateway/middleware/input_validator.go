package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// InputValidator interface defines comprehensive input validation
type InputValidator interface {
	ValidateJSON(data []byte, schema ValidationSchema) error
	SanitizeInput(input string, rules SanitizationRules) (string, error)
	ValidateSQL(query string, userRoles []string) error
	CheckForInjection(input string) (bool, []string)
	ValidateFileUpload(file *multipart.FileHeader) error
	ValidateHeaders(headers http.Header) error
	ValidateQueryParams(params url.Values) error
}

// InputValidatorImpl implements the InputValidator interface
type InputValidatorImpl struct {
	logger          logger.Logger
	config          InputValidationConfig
	xssPatterns     []*regexp.Regexp
	sqlPatterns     []*regexp.Regexp
	commandPatterns []*regexp.Regexp
	pathPatterns    []*regexp.Regexp
}

// InputValidationConfig represents input validation configuration
type InputValidationConfig struct {
	Enabled                          bool            `json:"enabled"`
	MaxRequestSize                   int64           `json:"max_request_size"`
	MaxFieldLength                   int             `json:"max_field_length"`
	MaxArrayLength                   int             `json:"max_array_length"`
	MaxNestingDepth                  int             `json:"max_nesting_depth"`
	AllowedContentTypes              []string        `json:"allowed_content_types"`
	BlockedFileExtensions            []string        `json:"blocked_file_extensions"`
	AllowedFileExtensions            []string        `json:"allowed_file_extensions"`
	MaxFileSize                      int64           `json:"max_file_size"`
	ScanFileContent                  bool            `json:"scan_file_content"`
	StrictJSONValidation             bool            `json:"strict_json_validation"`
	EnableXSSProtection              bool            `json:"enable_xss_protection"`
	EnableSQLInjectionProtection     bool            `json:"enable_sql_injection_protection"`
	EnableCommandInjectionProtection bool            `json:"enable_command_injection_protection"`
	EnablePathTraversalProtection    bool            `json:"enable_path_traversal_protection"`
	CustomPatterns                   []CustomPattern `json:"custom_patterns"`
}

// ValidationSchema represents JSON schema for validation
type ValidationSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]ValidationRule `json:"properties"`
	Required   []string                  `json:"required"`
	MaxLength  int                       `json:"max_length"`
	MinLength  int                       `json:"min_length"`
	Pattern    string                    `json:"pattern"`
}

// ValidationRule represents validation rules for a field
type ValidationRule struct {
	Type      string   `json:"type"`
	Required  bool     `json:"required"`
	MinLength int      `json:"min_length"`
	MaxLength int      `json:"max_length"`
	Pattern   string   `json:"pattern"`
	Enum      []string `json:"enum"`
	Format    string   `json:"format"`
}

// SanitizationRules represents sanitization rules
type SanitizationRules struct {
	RemoveHTML        bool   `json:"remove_html"`
	EscapeHTML        bool   `json:"escape_html"`
	RemoveScripts     bool   `json:"remove_scripts"`
	NormalizeSpaces   bool   `json:"normalize_spaces"`
	TrimWhitespace    bool   `json:"trim_whitespace"`
	RemoveNullBytes   bool   `json:"remove_null_bytes"`
	MaxLength         int    `json:"max_length"`
	AllowedCharacters string `json:"allowed_characters"`
}

// CustomPattern represents custom validation patterns
type CustomPattern struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Value   string `json:"value,omitempty"`
}

// NewInputValidator creates a new input validator
func NewInputValidator(config InputValidationConfig, logger logger.Logger) InputValidator {
	validator := &InputValidatorImpl{
		logger: logger,
		config: config,
	}

	validator.initializePatterns()
	return validator
}

// InputValidationMiddleware creates input validation middleware
func InputValidationMiddleware(config InputValidationConfig, logger logger.Logger) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	validator := NewInputValidator(config, logger)

	return func(c *gin.Context) {
		// Validate request size
		if c.Request.ContentLength > config.MaxRequestSize {
			logger.Warn("Request size too large: %d bytes from %s", c.Request.ContentLength, c.ClientIP())
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":   "Request too large",
				"message": "Request body exceeds maximum allowed size",
				"code":    "REQUEST_TOO_LARGE",
			})
			c.Abort()
			return
		}

		// Validate content type
		contentType := c.GetHeader("Content-Type")
		if contentType != "" && !isAllowedContentType(contentType, config.AllowedContentTypes) {
			logger.Warn("Invalid content type: %s from %s", contentType, c.ClientIP())
			c.JSON(http.StatusUnsupportedMediaType, gin.H{
				"error":   "Unsupported content type",
				"message": "Content type not allowed",
				"code":    "UNSUPPORTED_CONTENT_TYPE",
			})
			c.Abort()
			return
		}

		// Validate headers
		if err := validator.ValidateHeaders(c.Request.Header); err != nil {
			logger.Warn("Invalid headers from %s: %v", c.ClientIP(), err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid headers",
				"message": err.Error(),
				"code":    "INVALID_HEADERS",
			})
			c.Abort()
			return
		}

		// Validate query parameters
		if err := validator.ValidateQueryParams(c.Request.URL.Query()); err != nil {
			logger.Warn("Invalid query parameters from %s: %v", c.ClientIP(), err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid query parameters",
				"message": err.Error(),
				"code":    "INVALID_QUERY_PARAMS",
			})
			c.Abort()
			return
		}

		// Validate and sanitize request body for POST/PUT/PATCH requests
		if c.Request.Method == "POST" || c.Request.Method == "PUT" || c.Request.Method == "PATCH" {
			if err := validateAndSanitizeBody(c, validator, config, logger); err != nil {
				logger.Warn("Invalid request body from %s: %v", c.ClientIP(), err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error":   "Invalid request body",
					"message": err.Error(),
					"code":    "INVALID_REQUEST_BODY",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// initializePatterns initializes security patterns
func (iv *InputValidatorImpl) initializePatterns() {
	// XSS patterns
	xssPatterns := []string{
		`<script[^>]*>.*?</script>`,
		`javascript:`,
		`on\w+\s*=`,
		`<iframe[^>]*>.*?</iframe>`,
		`<object[^>]*>.*?</object>`,
		`<embed[^>]*>`,
		`<link[^>]*>`,
		`<meta[^>]*>`,
		`vbscript:`,
		`data:text/html`,
		`expression\s*\(`,
		`@import`,
		`<svg[^>]*>.*?</svg>`,
	}

	for _, pattern := range xssPatterns {
		if compiled, err := regexp.Compile(`(?i)` + pattern); err == nil {
			iv.xssPatterns = append(iv.xssPatterns, compiled)
		}
	}

	// SQL injection patterns
	sqlPatterns := []string{
		`(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)`,
		`(\b(OR|AND)\s+\d+\s*=\s*\d+)`,
		`(\b(OR|AND)\s+['"]\w+['"]?\s*=\s*['"]\w+['"]?)`,
		`(--|#|/\*|\*/)`,
		`(\bxp_\w+)`,
		`(\bsp_\w+)`,
		`(\bUNION\s+(ALL\s+)?SELECT)`,
		`(\bINTO\s+(OUT|DUMP)FILE)`,
		`(\bLOAD_FILE\s*\()`,
		`(\bCHAR\s*\(\s*\d+)`,
		`(\bCONCAT\s*\()`,
		`(\bSUBSTRING\s*\()`,
		`(\bASCII\s*\()`,
		`(\bBENCHMARK\s*\()`,
		`(\bSLEEP\s*\()`,
	}

	for _, pattern := range sqlPatterns {
		if compiled, err := regexp.Compile(`(?i)` + pattern); err == nil {
			iv.sqlPatterns = append(iv.sqlPatterns, compiled)
		}
	}

	// Command injection patterns
	commandPatterns := []string{
		`[;&|` + "`" + `$(){}[\]\\]`,
		`\b(cat|ls|pwd|id|whoami|uname|ps|netstat|ifconfig|ping|nslookup|dig|curl|wget|nc|telnet|ssh|ftp|scp|rsync)\b`,
		`\b(rm|mv|cp|chmod|chown|kill|killall|pkill|sudo|su|passwd|mount|umount|fdisk|dd|tar|gzip|gunzip|zip|unzip)\b`,
		`\b(echo|printf|read|exec|eval|source|bash|sh|zsh|csh|tcsh|ksh|fish)\b`,
		`\b(python|perl|ruby|php|node|java|gcc|g\+\+|make|cmake|git|svn|hg)\b`,
	}

	for _, pattern := range commandPatterns {
		if compiled, err := regexp.Compile(`(?i)` + pattern); err == nil {
			iv.commandPatterns = append(iv.commandPatterns, compiled)
		}
	}

	// Path traversal patterns
	pathPatterns := []string{
		`\.\.[\\/]`,
		`[\\/]\.\.[\\/]`,
		`\.\.%2[fF]`,
		`%2[eE]%2[eE]%2[fF]`,
		`%2[eE]%2[eE][\\/]`,
		`\.\.%5[cC]`,
		`%5[cC]\.\.%5[cC]`,
		`%252[eE]%252[eE]%252[fF]`,
	}

	for _, pattern := range pathPatterns {
		if compiled, err := regexp.Compile(`(?i)` + pattern); err == nil {
			iv.pathPatterns = append(iv.pathPatterns, compiled)
		}
	}
}

// ValidateJSON validates JSON data against a schema
func (iv *InputValidatorImpl) ValidateJSON(data []byte, schema ValidationSchema) error {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	return iv.validateValue(jsonData, schema, "")
}

// validateValue validates a value against validation rules
func (iv *InputValidatorImpl) validateValue(value interface{}, schema ValidationSchema, fieldPath string) error {
	switch schema.Type {
	case "object":
		return iv.validateObject(value, schema, fieldPath)
	case "array":
		return iv.validateArray(value, schema, fieldPath)
	case "string":
		return iv.validateString(value, schema, fieldPath)
	case "number":
		return iv.validateNumber(value, schema, fieldPath)
	case "boolean":
		return iv.validateBoolean(value, schema, fieldPath)
	default:
		return nil
	}
}

// validateObject validates an object
func (iv *InputValidatorImpl) validateObject(value interface{}, schema ValidationSchema, fieldPath string) error {
	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("field %s: expected object, got %T", fieldPath, value)
	}

	// Check required fields
	for _, required := range schema.Required {
		if _, exists := obj[required]; !exists {
			return fmt.Errorf("field %s.%s: required field missing", fieldPath, required)
		}
	}

	// Validate each property
	for key, val := range obj {
		propertyPath := key
		if fieldPath != "" {
			propertyPath = fieldPath + "." + key
		}

		if rule, exists := schema.Properties[key]; exists {
			propertySchema := ValidationSchema{
				Type:      rule.Type,
				MaxLength: rule.MaxLength,
				MinLength: rule.MinLength,
				Pattern:   rule.Pattern,
			}
			if err := iv.validateValue(val, propertySchema, propertyPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateArray validates an array
func (iv *InputValidatorImpl) validateArray(value interface{}, schema ValidationSchema, fieldPath string) error {
	arr, ok := value.([]interface{})
	if !ok {
		return fmt.Errorf("field %s: expected array, got %T", fieldPath, value)
	}

	if len(arr) > iv.config.MaxArrayLength {
		return fmt.Errorf("field %s: array too long (%d > %d)", fieldPath, len(arr), iv.config.MaxArrayLength)
	}

	return nil
}

// validateString validates a string
func (iv *InputValidatorImpl) validateString(value interface{}, schema ValidationSchema, fieldPath string) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("field %s: expected string, got %T", fieldPath, value)
	}

	if len(str) > iv.config.MaxFieldLength {
		return fmt.Errorf("field %s: string too long (%d > %d)", fieldPath, len(str), iv.config.MaxFieldLength)
	}

	if schema.MaxLength > 0 && len(str) > schema.MaxLength {
		return fmt.Errorf("field %s: string exceeds maximum length (%d > %d)", fieldPath, len(str), schema.MaxLength)
	}

	if schema.MinLength > 0 && len(str) < schema.MinLength {
		return fmt.Errorf("field %s: string below minimum length (%d < %d)", fieldPath, len(str), schema.MinLength)
	}

	if schema.Pattern != "" {
		if matched, err := regexp.MatchString(schema.Pattern, str); err != nil {
			return fmt.Errorf("field %s: invalid pattern: %w", fieldPath, err)
		} else if !matched {
			return fmt.Errorf("field %s: does not match required pattern", fieldPath)
		}
	}

	// Check for security issues
	if found, issues := iv.CheckForInjection(str); found {
		return fmt.Errorf("field %s: security violation detected: %v", fieldPath, issues)
	}

	return nil
}

// validateNumber validates a number
func (iv *InputValidatorImpl) validateNumber(value interface{}, schema ValidationSchema, fieldPath string) error {
	switch value.(type) {
	case float64, int, int64, float32:
		return nil
	default:
		return fmt.Errorf("field %s: expected number, got %T", fieldPath, value)
	}
}

// validateBoolean validates a boolean
func (iv *InputValidatorImpl) validateBoolean(value interface{}, schema ValidationSchema, fieldPath string) error {
	if _, ok := value.(bool); !ok {
		return fmt.Errorf("field %s: expected boolean, got %T", fieldPath, value)
	}
	return nil
}

// SanitizeInput sanitizes input according to rules
func (iv *InputValidatorImpl) SanitizeInput(input string, rules SanitizationRules) (string, error) {
	result := input

	// Remove null bytes
	if rules.RemoveNullBytes {
		result = strings.ReplaceAll(result, "\x00", "")
	}

	// Trim whitespace
	if rules.TrimWhitespace {
		result = strings.TrimSpace(result)
	}

	// Normalize spaces
	if rules.NormalizeSpaces {
		spaceRegex := regexp.MustCompile(`\s+`)
		result = spaceRegex.ReplaceAllString(result, " ")
	}

	// Remove HTML tags
	if rules.RemoveHTML {
		htmlRegex := regexp.MustCompile(`<[^>]*>`)
		result = htmlRegex.ReplaceAllString(result, "")
	}

	// Escape HTML
	if rules.EscapeHTML {
		result = html.EscapeString(result)
	}

	// Remove scripts
	if rules.RemoveScripts {
		scriptRegex := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
		result = scriptRegex.ReplaceAllString(result, "")
	}

	// Apply character whitelist
	if rules.AllowedCharacters != "" {
		allowedRegex := regexp.MustCompile(`[^` + regexp.QuoteMeta(rules.AllowedCharacters) + `]`)
		result = allowedRegex.ReplaceAllString(result, "")
	}

	// Truncate to max length
	if rules.MaxLength > 0 && len(result) > rules.MaxLength {
		result = result[:rules.MaxLength]
	}

	return result, nil
}

// ValidateSQL validates SQL queries for security issues
func (iv *InputValidatorImpl) ValidateSQL(query string, userRoles []string) error {
	if !iv.config.EnableSQLInjectionProtection {
		return nil
	}

	// Check for SQL injection patterns
	for _, pattern := range iv.sqlPatterns {
		if pattern.MatchString(query) {
			return fmt.Errorf("potentially dangerous SQL pattern detected")
		}
	}

	// Additional SQL-specific validations can be added here
	return nil
}

// CheckForInjection checks for various injection attacks
func (iv *InputValidatorImpl) CheckForInjection(input string) (bool, []string) {
	var issues []string

	// Check for XSS
	if iv.config.EnableXSSProtection {
		for _, pattern := range iv.xssPatterns {
			if pattern.MatchString(input) {
				issues = append(issues, "XSS pattern detected")
				break
			}
		}
	}

	// Check for SQL injection
	if iv.config.EnableSQLInjectionProtection {
		for _, pattern := range iv.sqlPatterns {
			if pattern.MatchString(input) {
				issues = append(issues, "SQL injection pattern detected")
				break
			}
		}
	}

	// Check for command injection
	if iv.config.EnableCommandInjectionProtection {
		for _, pattern := range iv.commandPatterns {
			if pattern.MatchString(input) {
				issues = append(issues, "Command injection pattern detected")
				break
			}
		}
	}

	// Check for path traversal
	if iv.config.EnablePathTraversalProtection {
		for _, pattern := range iv.pathPatterns {
			if pattern.MatchString(input) {
				issues = append(issues, "Path traversal pattern detected")
				break
			}
		}
	}

	// Check custom patterns
	for _, customPattern := range iv.config.CustomPatterns {
		if matched, err := regexp.MatchString(customPattern.Pattern, input); err == nil && matched {
			issues = append(issues, fmt.Sprintf("Custom pattern violation: %s", customPattern.Description))
		}
	}

	return len(issues) > 0, issues
}

// ValidateFileUpload validates file uploads
func (iv *InputValidatorImpl) ValidateFileUpload(file *multipart.FileHeader) error {
	// Check file size
	if file.Size > iv.config.MaxFileSize {
		return fmt.Errorf("file too large: %d bytes (max: %d)", file.Size, iv.config.MaxFileSize)
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(file.Filename))

	// Check blocked extensions
	for _, blockedExt := range iv.config.BlockedFileExtensions {
		if ext == strings.ToLower(blockedExt) {
			return fmt.Errorf("file extension not allowed: %s", ext)
		}
	}

	// Check allowed extensions (if specified)
	if len(iv.config.AllowedFileExtensions) > 0 {
		allowed := false
		for _, allowedExt := range iv.config.AllowedFileExtensions {
			if ext == strings.ToLower(allowedExt) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("file extension not in allowed list: %s", ext)
		}
	}

	// Scan file content if enabled
	if iv.config.ScanFileContent {
		if err := iv.scanFileContent(file); err != nil {
			return fmt.Errorf("file content validation failed: %w", err)
		}
	}

	return nil
}

// scanFileContent scans file content for security issues
func (iv *InputValidatorImpl) scanFileContent(file *multipart.FileHeader) error {
	src, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer src.Close()

	// Read first 1KB for content analysis
	buffer := make([]byte, 1024)
	n, err := src.Read(buffer)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read file: %w", err)
	}

	content := string(buffer[:n])

	// Check for malicious content
	if found, issues := iv.CheckForInjection(content); found {
		return fmt.Errorf("malicious content detected: %v", issues)
	}

	return nil
}

// ValidateHeaders validates HTTP headers
func (iv *InputValidatorImpl) ValidateHeaders(headers http.Header) error {
	suspiciousHeaders := []string{
		"X-Forwarded-Host",
		"X-Original-URL",
		"X-Rewrite-URL",
		"X-Arbitrary-Header",
	}

	for _, header := range suspiciousHeaders {
		if value := headers.Get(header); value != "" {
			if found, _ := iv.CheckForInjection(value); found {
				return fmt.Errorf("suspicious content in header %s", header)
			}
		}
	}

	// Validate User-Agent
	userAgent := headers.Get("User-Agent")
	if userAgent != "" && len(userAgent) > 500 {
		return fmt.Errorf("user agent too long")
	}

	return nil
}

// ValidateQueryParams validates query parameters
func (iv *InputValidatorImpl) ValidateQueryParams(params url.Values) error {
	for key, values := range params {
		// Check parameter name
		if found, _ := iv.CheckForInjection(key); found {
			return fmt.Errorf("suspicious parameter name: %s", key)
		}

		// Check parameter values
		for _, value := range values {
			if len(value) > iv.config.MaxFieldLength {
				return fmt.Errorf("parameter value too long: %s", key)
			}

			if found, issues := iv.CheckForInjection(value); found {
				return fmt.Errorf("suspicious parameter value in %s: %v", key, issues)
			}
		}
	}

	return nil
}

// Helper functions

func validateAndSanitizeBody(c *gin.Context, validator InputValidator, config InputValidationConfig, logger logger.Logger) error {
	contentType := c.GetHeader("Content-Type")

	// Handle multipart form data (file uploads)
	if strings.HasPrefix(contentType, "multipart/form-data") {
		return validateMultipartForm(c, validator, config, logger)
	}

	// Handle JSON data
	if strings.HasPrefix(contentType, "application/json") {
		return validateJSONBody(c, validator, config, logger)
	}

	// Handle form data
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return validateFormBody(c, validator, config, logger)
	}

	return nil
}

func validateMultipartForm(c *gin.Context, validator InputValidator, config InputValidationConfig, logger logger.Logger) error {
	if err := c.Request.ParseMultipartForm(config.MaxRequestSize); err != nil {
		return fmt.Errorf("failed to parse multipart form: %w", err)
	}

	// Validate form fields
	for key, values := range c.Request.MultipartForm.Value {
		for _, value := range values {
			if found, issues := validator.CheckForInjection(value); found {
				return fmt.Errorf("suspicious content in form field %s: %v", key, issues)
			}
		}
	}

	// Validate uploaded files
	for _, files := range c.Request.MultipartForm.File {
		for _, file := range files {
			if err := validator.ValidateFileUpload(file); err != nil {
				return fmt.Errorf("file validation failed: %w", err)
			}
		}
	}

	return nil
}

func validateJSONBody(c *gin.Context, validator InputValidator, config InputValidationConfig, logger logger.Logger) error {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore body for further processing
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	// Basic JSON validation
	var jsonData interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	// Check for injection in JSON string values
	return validateJSONValues(jsonData, validator, "")
}

func validateJSONValues(data interface{}, validator InputValidator, path string) error {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			newPath := key
			if path != "" {
				newPath = path + "." + key
			}
			if err := validateJSONValues(value, validator, newPath); err != nil {
				return err
			}
		}
	case []interface{}:
		for i, value := range v {
			newPath := fmt.Sprintf("%s[%d]", path, i)
			if err := validateJSONValues(value, validator, newPath); err != nil {
				return err
			}
		}
	case string:
		if found, issues := validator.CheckForInjection(v); found {
			return fmt.Errorf("suspicious content in field %s: %v", path, issues)
		}
	}
	return nil
}

func validateFormBody(c *gin.Context, validator InputValidator, config InputValidationConfig, logger logger.Logger) error {
	if err := c.Request.ParseForm(); err != nil {
		return fmt.Errorf("failed to parse form: %w", err)
	}

	for key, values := range c.Request.Form {
		for _, value := range values {
			if found, issues := validator.CheckForInjection(value); found {
				return fmt.Errorf("suspicious content in form field %s: %v", key, issues)
			}
		}
	}

	return nil
}

func isAllowedContentType(contentType string, allowedTypes []string) bool {
	if len(allowedTypes) == 0 {
		return true // No restrictions
	}

	// Extract main content type (ignore charset, boundary, etc.)
	mainType := strings.Split(contentType, ";")[0]
	mainType = strings.TrimSpace(mainType)

	for _, allowed := range allowedTypes {
		if strings.EqualFold(mainType, allowed) {
			return true
		}
	}

	return false
}

// FileUploadSecurityMiddleware creates file upload security middleware
func FileUploadSecurityMiddleware(config InputValidationConfig, logger logger.Logger) gin.HandlerFunc {
	validator := NewInputValidator(config, logger)

	return func(c *gin.Context) {
		contentType := c.GetHeader("Content-Type")

		// Only process multipart form data
		if !strings.HasPrefix(contentType, "multipart/form-data") {
			c.Next()
			return
		}

		if err := c.Request.ParseMultipartForm(config.MaxRequestSize); err != nil {
			logger.Warn("Failed to parse multipart form from %s: %v", c.ClientIP(), err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid multipart form",
				"message": "Failed to parse uploaded files",
				"code":    "INVALID_MULTIPART_FORM",
			})
			c.Abort()
			return
		}

		// Validate all uploaded files
		for fieldName, files := range c.Request.MultipartForm.File {
			for _, file := range files {
				if err := validator.ValidateFileUpload(file); err != nil {
					logger.Warn("File upload validation failed for field %s from %s: %v", fieldName, c.ClientIP(), err)
					c.JSON(http.StatusBadRequest, gin.H{
						"error":   "File validation failed",
						"message": err.Error(),
						"code":    "FILE_VALIDATION_FAILED",
						"field":   fieldName,
					})
					c.Abort()
					return
				}
			}
		}

		c.Next()
	}
}
