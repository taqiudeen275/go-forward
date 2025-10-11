package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// AuditLoggerImpl implements the AuditLogger interface
type AuditLoggerImpl struct {
	logger logger.Logger
	config AuditConfig
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(logger logger.Logger, config AuditConfig) AuditLogger {
	return &AuditLoggerImpl{
		logger: logger,
		config: config,
	}
}

// LogSecurityEvent logs a security event
func (al *AuditLoggerImpl) LogSecurityEvent(event SecurityEvent) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal security event: %w", err)
	}

	al.logger.Info("SECURITY_EVENT: %s", string(eventJSON))
	return nil
}

// LogRequest logs an HTTP request
func (al *AuditLoggerImpl) LogRequest(req *http.Request, context SecurityContext) error {
	if !al.config.LogRequests {
		return nil
	}

	requestLog := map[string]interface{}{
		"timestamp":  time.Now(),
		"type":       "REQUEST",
		"method":     req.Method,
		"url":        req.URL.String(),
		"user_id":    context.UserID,
		"session_id": context.SessionID,
		"request_id": context.RequestID,
	}

	if al.config.IncludeIP {
		requestLog["ip_address"] = context.IPAddress
	}

	if al.config.IncludeUserAgent {
		requestLog["user_agent"] = context.UserAgent
	}

	if al.config.LogHeaders {
		headers := make(map[string]string)
		for name, values := range req.Header {
			if !al.isSensitiveHeader(name) && len(values) > 0 {
				headers[name] = values[0]
			}
		}
		requestLog["headers"] = headers
	}

	logJSON, err := json.Marshal(requestLog)
	if err != nil {
		return fmt.Errorf("failed to marshal request log: %w", err)
	}

	al.logger.Info("REQUEST_LOG: %s", string(logJSON))
	return nil
}

// LogResponse logs an HTTP response
func (al *AuditLoggerImpl) LogResponse(resp *gin.ResponseWriter, context SecurityContext) error {
	if !al.config.LogResponses {
		return nil
	}

	responseLog := map[string]interface{}{
		"timestamp":   time.Now(),
		"type":        "RESPONSE",
		"status_code": (*resp).Status(),
		"size":        (*resp).Size(),
		"user_id":     context.UserID,
		"session_id":  context.SessionID,
		"request_id":  context.RequestID,
	}

	logJSON, err := json.Marshal(responseLog)
	if err != nil {
		return fmt.Errorf("failed to marshal response log: %w", err)
	}

	al.logger.Info("RESPONSE_LOG: %s", string(logJSON))
	return nil
}

// isSensitiveHeader checks if a header contains sensitive information
func (al *AuditLoggerImpl) isSensitiveHeader(headerName string) bool {
	for _, sensitive := range al.config.SensitiveHeaders {
		if headerName == sensitive {
			return true
		}
	}
	return false
}
