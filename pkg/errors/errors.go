package errors

import (
	"fmt"
	"time"
)

// ErrorCode represents specific error types
type ErrorCode string

const (
	// Authentication errors
	ErrInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrForbidden          ErrorCode = "FORBIDDEN"

	// Database errors
	ErrDatabaseConnection ErrorCode = "DATABASE_CONNECTION"
	ErrRecordNotFound     ErrorCode = "RECORD_NOT_FOUND"
	ErrDuplicateRecord    ErrorCode = "DUPLICATE_RECORD"

	// Configuration errors
	ErrInvalidConfig ErrorCode = "INVALID_CONFIG"
	ErrMissingConfig ErrorCode = "MISSING_CONFIG"

	// Server errors
	ErrInternalServer     ErrorCode = "INTERNAL_SERVER_ERROR"
	ErrServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity string

const (
	SeverityLow      ErrorSeverity = "low"
	SeverityMedium   ErrorSeverity = "medium"
	SeverityHigh     ErrorSeverity = "high"
	SeverityCritical ErrorSeverity = "critical"
)

// ErrorCategory represents the category of an error
type ErrorCategory string

const (
	CategoryAuth     ErrorCategory = "authentication"
	CategoryDB       ErrorCategory = "database"
	CategoryConfig   ErrorCategory = "configuration"
	CategorySecurity ErrorCategory = "security"
	CategoryServer   ErrorCategory = "server"
)

// UnifiedError represents all types of framework errors
type UnifiedError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	Severity   ErrorSeverity          `json:"severity"`
	Category   ErrorCategory          `json:"category"`
	UserID     string                 `json:"user_id,omitempty"`
	Resource   string                 `json:"resource,omitempty"`
	Action     string                 `json:"action,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id,omitempty"`
	StackTrace string                 `json:"stack_trace,omitempty"`

	// Error handling flags
	ShouldAudit bool `json:"-"`
	ShouldAlert bool `json:"-"`
	ShouldRetry bool `json:"-"`
}

// Error implements the error interface
func (e *UnifiedError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Category, e.Message)
}

// New creates a new UnifiedError
func New(code ErrorCode, message string) *UnifiedError {
	return &UnifiedError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now().UTC(),
		Details:   make(map[string]interface{}),
	}
}

// WithSeverity sets the error severity
func (e *UnifiedError) WithSeverity(severity ErrorSeverity) *UnifiedError {
	e.Severity = severity
	return e
}

// WithCategory sets the error category
func (e *UnifiedError) WithCategory(category ErrorCategory) *UnifiedError {
	e.Category = category
	return e
}

// WithDetails adds details to the error
func (e *UnifiedError) WithDetails(key string, value interface{}) *UnifiedError {
	e.Details[key] = value
	return e
}

// WithUser sets the user ID
func (e *UnifiedError) WithUser(userID string) *UnifiedError {
	e.UserID = userID
	return e
}

// WithResource sets the resource
func (e *UnifiedError) WithResource(resource string) *UnifiedError {
	e.Resource = resource
	return e
}

// WithAction sets the action
func (e *UnifiedError) WithAction(action string) *UnifiedError {
	e.Action = action
	return e
}

// WithRequestID sets the request ID
func (e *UnifiedError) WithRequestID(requestID string) *UnifiedError {
	e.RequestID = requestID
	return e
}

// ShouldAuditLog marks the error for audit logging
func (e *UnifiedError) ShouldAuditLog() *UnifiedError {
	e.ShouldAudit = true
	return e
}

// ShouldSendAlert marks the error for alerting
func (e *UnifiedError) ShouldSendAlert() *UnifiedError {
	e.ShouldAlert = true
	return e
}

// CanRetry marks the error as retryable
func (e *UnifiedError) CanRetry() *UnifiedError {
	e.ShouldRetry = true
	return e
}

// Common error constructors
func NewAuthError(message string) *UnifiedError {
	return New(ErrUnauthorized, message).
		WithCategory(CategoryAuth).
		WithSeverity(SeverityMedium).
		ShouldAuditLog()
}

func NewDatabaseError(message string) *UnifiedError {
	return New(ErrDatabaseConnection, message).
		WithCategory(CategoryDB).
		WithSeverity(SeverityHigh).
		ShouldSendAlert()
}

func NewConfigError(message string) *UnifiedError {
	return New(ErrInvalidConfig, message).
		WithCategory(CategoryConfig).
		WithSeverity(SeverityHigh)
}

func NewSecurityError(message string) *UnifiedError {
	return New(ErrForbidden, message).
		WithCategory(CategorySecurity).
		WithSeverity(SeverityCritical).
		ShouldAuditLog().
		ShouldSendAlert()
}
