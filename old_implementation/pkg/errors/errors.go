package errors

import (
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"time"
)

// ErrorCode represents application error codes
type ErrorCode string

const (
	// Authentication errors
	ErrCodeUnauthorized       ErrorCode = "UNAUTHORIZED"
	ErrCodeInvalidToken       ErrorCode = "INVALID_TOKEN"
	ErrCodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeUserNotFound       ErrorCode = "USER_NOT_FOUND"
	ErrCodeUserExists         ErrorCode = "USER_EXISTS"
	ErrCodeOTPInvalid         ErrorCode = "OTP_INVALID"
	ErrCodeOTPExpired         ErrorCode = "OTP_EXPIRED"

	// Authorization errors
	ErrCodeForbidden               ErrorCode = "FORBIDDEN"
	ErrCodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"

	// Validation errors
	ErrCodeValidation    ErrorCode = "VALIDATION_ERROR"
	ErrCodeInvalidInput  ErrorCode = "INVALID_INPUT"
	ErrCodeMissingField  ErrorCode = "MISSING_FIELD"
	ErrCodeInvalidFormat ErrorCode = "INVALID_FORMAT"

	// Resource errors
	ErrCodeNotFound       ErrorCode = "NOT_FOUND"
	ErrCodeConflict       ErrorCode = "CONFLICT"
	ErrCodeResourceExists ErrorCode = "RESOURCE_EXISTS"
	ErrCodeResourceLocked ErrorCode = "RESOURCE_LOCKED"

	// Database errors
	ErrCodeDatabase          ErrorCode = "DATABASE_ERROR"
	ErrCodeConnectionFailed  ErrorCode = "CONNECTION_FAILED"
	ErrCodeQueryFailed       ErrorCode = "QUERY_FAILED"
	ErrCodeTransactionFailed ErrorCode = "TRANSACTION_FAILED"

	// Storage errors
	ErrCodeStorageError    ErrorCode = "STORAGE_ERROR"
	ErrCodeFileNotFound    ErrorCode = "FILE_NOT_FOUND"
	ErrCodeFileTooLarge    ErrorCode = "FILE_TOO_LARGE"
	ErrCodeInvalidFileType ErrorCode = "INVALID_FILE_TYPE"

	// Rate limiting errors
	ErrCodeRateLimited     ErrorCode = "RATE_LIMITED"
	ErrCodeTooManyRequests ErrorCode = "TOO_MANY_REQUESTS"

	// Internal errors
	ErrCodeInternal           ErrorCode = "INTERNAL_ERROR"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	ErrCodeTimeout            ErrorCode = "TIMEOUT"
	ErrCodeConfigError        ErrorCode = "CONFIG_ERROR"
)

// AppError represents application-specific errors
type AppError struct {
	Code      ErrorCode              `json:"code"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Cause     error                  `json:"-"`
	Status    int                    `json:"-"`
	Timestamp time.Time              `json:"timestamp"`
	RequestID string                 `json:"request_id,omitempty"`
	Stack     string                 `json:"stack,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause
func (e *AppError) Unwrap() error {
	return e.Cause
}

// MarshalJSON implements json.Marshaler
func (e *AppError) MarshalJSON() ([]byte, error) {
	type alias AppError
	return json.Marshal(&struct {
		*alias
		Error string `json:"error"`
	}{
		alias: (*alias)(e),
		Error: e.Error(),
	})
}

// New creates a new AppError
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Status:    getDefaultStatus(code),
		Timestamp: time.Now(),
		Stack:     getStack(),
	}
}

// Newf creates a new AppError with formatted message
func Newf(code ErrorCode, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Status:    getDefaultStatus(code),
		Timestamp: time.Now(),
		Stack:     getStack(),
	}
}

// Wrap wraps an existing error with AppError
func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:      code,
		Message:   message,
		Cause:     err,
		Status:    getDefaultStatus(code),
		Timestamp: time.Now(),
		Stack:     getStack(),
	}
}

// Wrapf wraps an existing error with AppError and formatted message
func Wrapf(err error, code ErrorCode, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:      code,
		Message:   fmt.Sprintf(format, args...),
		Cause:     err,
		Status:    getDefaultStatus(code),
		Timestamp: time.Now(),
		Stack:     getStack(),
	}
}

// WithDetails adds details to the error
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithDetail adds a single detail to the error
func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithStatus sets the HTTP status code
func (e *AppError) WithStatus(status int) *AppError {
	e.Status = status
	return e
}

// WithRequestID sets the request ID
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// GetStatus returns the HTTP status code
func (e *AppError) GetStatus() int {
	if e.Status == 0 {
		return getDefaultStatus(e.Code)
	}
	return e.Status
}

// IsCode checks if the error has the specified code
func (e *AppError) IsCode(code ErrorCode) bool {
	return e.Code == code
}

// getDefaultStatus returns the default HTTP status for an error code
func getDefaultStatus(code ErrorCode) int {
	switch code {
	case ErrCodeUnauthorized, ErrCodeInvalidToken, ErrCodeTokenExpired, ErrCodeInvalidCredentials:
		return http.StatusUnauthorized
	case ErrCodeForbidden, ErrCodeInsufficientPermissions:
		return http.StatusForbidden
	case ErrCodeNotFound, ErrCodeUserNotFound, ErrCodeFileNotFound:
		return http.StatusNotFound
	case ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingField, ErrCodeInvalidFormat:
		return http.StatusBadRequest
	case ErrCodeConflict, ErrCodeResourceExists, ErrCodeUserExists:
		return http.StatusConflict
	case ErrCodeResourceLocked:
		return http.StatusLocked
	case ErrCodeRateLimited, ErrCodeTooManyRequests:
		return http.StatusTooManyRequests
	case ErrCodeFileTooLarge:
		return http.StatusRequestEntityTooLarge
	case ErrCodeInvalidFileType:
		return http.StatusUnsupportedMediaType
	case ErrCodeServiceUnavailable:
		return http.StatusServiceUnavailable
	case ErrCodeTimeout:
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}

// getStack returns the current stack trace
func getStack() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// AsAppError converts an error to AppError if possible
func AsAppError(err error) (*AppError, bool) {
	if appErr, ok := err.(*AppError); ok {
		return appErr, true
	}
	return nil, false
}

// Common error constructors
func Unauthorized(message string) *AppError {
	return New(ErrCodeUnauthorized, message)
}

func Forbidden(message string) *AppError {
	return New(ErrCodeForbidden, message)
}

func NotFound(message string) *AppError {
	return New(ErrCodeNotFound, message)
}

func BadRequest(message string) *AppError {
	return New(ErrCodeValidation, message)
}

func Conflict(message string) *AppError {
	return New(ErrCodeConflict, message)
}

func Internal(message string) *AppError {
	return New(ErrCodeInternal, message)
}

func InternalWithCause(err error, message string) *AppError {
	return Wrap(err, ErrCodeInternal, message)
}

// Validation error constructors
func ValidationError(field string, message string) *AppError {
	return New(ErrCodeValidation, message).WithDetail("field", field)
}

func MissingField(field string) *AppError {
	return New(ErrCodeMissingField, fmt.Sprintf("Missing required field: %s", field)).WithDetail("field", field)
}

func InvalidFormat(field string, expected string) *AppError {
	return New(ErrCodeInvalidFormat, fmt.Sprintf("Invalid format for field %s, expected %s", field, expected)).
		WithDetails(map[string]interface{}{
			"field":    field,
			"expected": expected,
		})
}
