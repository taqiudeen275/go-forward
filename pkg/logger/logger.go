package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
}

// LogLevel represents logging levels
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
)

// AuditEvent represents an audit log entry
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id,omitempty"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
	Success   bool                   `json:"success"`
	ErrorCode string                 `json:"error_code,omitempty"`
}

// New creates a new logger instance
func New(level LogLevel) *Logger {
	var slogLevel slog.Level
	switch level {
	case LevelDebug:
		slogLevel = slog.LevelDebug
	case LevelInfo:
		slogLevel = slog.LevelInfo
	case LevelWarn:
		slogLevel = slog.LevelWarn
	case LevelError:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: slogLevel,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	return &Logger{
		Logger: slog.New(handler),
	}
}

// WithRequestID adds request ID to logger context
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.Logger.With("request_id", requestID),
	}
}

// WithUser adds user ID to logger context
func (l *Logger) WithUser(userID string) *Logger {
	return &Logger{
		Logger: l.Logger.With("user_id", userID),
	}
}

// LogError logs a UnifiedError with appropriate context
func (l *Logger) LogError(ctx context.Context, err *errors.UnifiedError) {
	l.Logger.ErrorContext(ctx, err.Message,
		"error_code", err.Code,
		"category", err.Category,
		"severity", err.Severity,
		"user_id", err.UserID,
		"resource", err.Resource,
		"action", err.Action,
		"request_id", err.RequestID,
		"details", err.Details,
	)
}

// LogAudit logs an audit event
func (l *Logger) LogAudit(ctx context.Context, event *AuditEvent) {
	l.Logger.InfoContext(ctx, "audit_event",
		"audit_timestamp", event.Timestamp,
		"audit_user_id", event.UserID,
		"audit_action", event.Action,
		"audit_resource", event.Resource,
		"audit_details", event.Details,
		"audit_ip_address", event.IPAddress,
		"audit_user_agent", event.UserAgent,
		"audit_request_id", event.RequestID,
		"audit_success", event.Success,
		"audit_error_code", event.ErrorCode,
	)
}

// LogPerformance logs performance metrics
func (l *Logger) LogPerformance(ctx context.Context, operation string, duration time.Duration, details map[string]interface{}) {
	l.Logger.InfoContext(ctx, "performance_metric",
		"operation", operation,
		"duration_ms", duration.Milliseconds(),
		"details", details,
	)
}

// LogSecurity logs security events
func (l *Logger) LogSecurity(ctx context.Context, event string, severity string, details map[string]interface{}) {
	l.Logger.WarnContext(ctx, "security_event",
		"security_event", event,
		"severity", severity,
		"details", details,
	)
}

// CreateAuditEvent creates a new audit event
func CreateAuditEvent(userID, action, resource string) *AuditEvent {
	return &AuditEvent{
		Timestamp: time.Now().UTC(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Details:   make(map[string]interface{}),
		Success:   true,
	}
}

// WithDetails adds details to audit event
func (ae *AuditEvent) WithDetails(key string, value interface{}) *AuditEvent {
	ae.Details[key] = value
	return ae
}

// WithIPAddress sets IP address
func (ae *AuditEvent) WithIPAddress(ip string) *AuditEvent {
	ae.IPAddress = ip
	return ae
}

// WithUserAgent sets user agent
func (ae *AuditEvent) WithUserAgent(ua string) *AuditEvent {
	ae.UserAgent = ua
	return ae
}

// WithRequestID sets request ID
func (ae *AuditEvent) WithRequestID(id string) *AuditEvent {
	ae.RequestID = id
	return ae
}

// WithError marks the event as failed
func (ae *AuditEvent) WithError(errorCode string) *AuditEvent {
	ae.Success = false
	ae.ErrorCode = errorCode
	return ae
}

// ToJSON converts audit event to JSON string
func (ae *AuditEvent) ToJSON() string {
	data, _ := json.Marshal(ae)
	return string(data)
}

// Global logger instance
var defaultLogger *Logger

// Init initializes the global logger
func Init(level LogLevel) {
	defaultLogger = New(level)
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if defaultLogger == nil {
		defaultLogger = New(LevelInfo)
	}
	return defaultLogger
}

// Convenience functions for global logger
func Info(msg string, args ...interface{}) {
	GetLogger().Info(fmt.Sprintf(msg, args...))
}

func Error(msg string, args ...interface{}) {
	GetLogger().Error(fmt.Sprintf(msg, args...))
}

func Debug(msg string, args ...interface{}) {
	GetLogger().Debug(fmt.Sprintf(msg, args...))
}

func Warn(msg string, args ...interface{}) {
	GetLogger().Warn(fmt.Sprintf(msg, args...))
}
