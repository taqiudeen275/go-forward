package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SQLSecurityMiddleware provides SQL execution security and audit logging
type SQLSecurityMiddleware struct {
	validator  SQLSecurityValidator
	rbacEngine RBACEngine
}

// NewSQLSecurityMiddleware creates a new SQL security middleware
func NewSQLSecurityMiddleware(validator SQLSecurityValidator, rbacEngine RBACEngine) *SQLSecurityMiddleware {
	return &SQLSecurityMiddleware{
		validator:  validator,
		rbacEngine: rbacEngine,
	}
}

// SQLExecutionRequest represents a request to execute SQL
type SQLExecutionRequest struct {
	Query          string                 `json:"query" binding:"required"`
	Parameters     []interface{}          `json:"parameters,omitempty"`
	QueryTimeout   int                    `json:"query_timeout,omitempty"`  // in milliseconds
	DryRun         bool                   `json:"dry_run,omitempty"`        // validate only, don't execute
	RequestReason  string                 `json:"request_reason,omitempty"` // reason for execution
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// SQLExecutionResponse represents the response from SQL execution
type SQLExecutionResponse struct {
	Success           bool                   `json:"success"`
	ValidationResult  *SQLValidationResult   `json:"validation_result,omitempty"`
	ExecutionResult   *SQLExecutionResult    `json:"execution_result,omitempty"`
	RequiresApproval  bool                   `json:"requires_approval"`
	ApprovalRequestID string                 `json:"approval_request_id,omitempty"`
	Message           string                 `json:"message,omitempty"`
	AdditionalData    map[string]interface{} `json:"additional_data,omitempty"`
}

// RequireAdminRole middleware that ensures user has admin role for SQL execution
func (m *SQLSecurityMiddleware) RequireAdminRole(minRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user ID from context (set by auth middleware)
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"message": "User ID not found in context",
			})
			c.Abort()
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid authentication",
				"message": "Invalid user ID format",
			})
			c.Abort()
			return
		}

		// Check if user has required admin role
		hasRole, err := m.rbacEngine.HasRole(c.Request.Context(), userIDStr, minRole)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization check failed",
				"message": fmt.Sprintf("Error checking admin role: %v", err),
			})
			c.Abort()
			return
		}

		if !hasRole {
			// Log unauthorized access attempt
			m.logSecurityEvent(c, "unauthorized_sql_access", map[string]interface{}{
				"user_id":       userIDStr,
				"required_role": minRole,
				"ip_address":    c.ClientIP(),
				"user_agent":    c.GetHeader("User-Agent"),
				"endpoint":      c.Request.URL.Path,
			})

			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient privileges",
				"message": fmt.Sprintf("Required admin role: %s", minRole),
			})
			c.Abort()
			return
		}

		// Get user's highest role for context
		highestRole, err := m.rbacEngine.GetHighestRole(c.Request.Context(), userIDStr)
		if err == nil && highestRole != nil {
			c.Set("admin_role", highestRole.Name)
			c.Set("admin_role_id", highestRole.ID)
		}

		c.Next()
	}
}

// ValidateAndExecuteSQL handles SQL validation and execution with security checks
func (m *SQLSecurityMiddleware) ValidateAndExecuteSQL() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request SQLExecutionRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Extract execution context
		execCtx, err := m.buildExecutionContext(c, &request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid execution context",
				"message": err.Error(),
			})
			return
		}

		// Validate the SQL query
		validationResult, err := m.validator.ValidateQuery(c.Request.Context(), request.Query, *execCtx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Validation failed",
				"message": err.Error(),
			})
			return
		}

		response := &SQLExecutionResponse{
			ValidationResult: validationResult,
			RequiresApproval: validationResult.RequiresApproval,
		}

		// If validation failed, return error
		if !validationResult.Valid {
			response.Success = false
			response.Message = fmt.Sprintf("Query validation failed: %s", strings.Join(validationResult.Errors, ", "))
			c.JSON(http.StatusBadRequest, response)
			return
		}

		// If it's a dry run, return validation results only
		if request.DryRun {
			response.Success = true
			response.Message = "Query validation successful (dry run)"
			c.JSON(http.StatusOK, response)
			return
		}

		// Check if approval is required
		if validationResult.RequiresApproval {
			// Check if query already has approval
			approval, err := m.validator.CheckQueryApproval(c.Request.Context(), validationResult.QueryHash)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":   "Approval check failed",
					"message": err.Error(),
				})
				return
			}

			if approval == nil || approval.Status != "approved" {
				// Request approval
				err := m.validator.RequestQueryApproval(c.Request.Context(), validationResult.QueryHash, request.Query, *execCtx)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{
						"error":   "Approval request failed",
						"message": err.Error(),
					})
					return
				}

				response.Success = false
				response.Message = "Query requires approval. Approval request has been submitted."
				response.ApprovalRequestID = validationResult.QueryHash
				c.JSON(http.StatusAccepted, response)
				return
			}
		}

		// Execute the query
		executionResult, err := m.validator.ExecuteQuery(c.Request.Context(), request.Query, *execCtx, !validationResult.RequiresApproval)
		if err != nil {
			response.Success = false
			response.ExecutionResult = executionResult
			response.Message = fmt.Sprintf("Query execution failed: %v", err)

			// Log failed execution
			m.logSecurityEvent(c, "sql_execution_failed", map[string]interface{}{
				"query_hash": validationResult.QueryHash,
				"query_type": validationResult.QueryType,
				"risk_level": validationResult.RiskLevel,
				"error":      err.Error(),
				"user_id":    execCtx.UserID,
				"session_id": execCtx.SessionID,
			})

			c.JSON(http.StatusInternalServerError, response)
			return
		}

		response.Success = true
		response.ExecutionResult = executionResult
		response.Message = "Query executed successfully"

		// Log successful execution
		m.logSecurityEvent(c, "sql_execution_success", map[string]interface{}{
			"query_hash":        validationResult.QueryHash,
			"query_type":        validationResult.QueryType,
			"risk_level":        validationResult.RiskLevel,
			"rows_affected":     executionResult.RowsAffected,
			"rows_returned":     executionResult.RowsReturned,
			"execution_time_ms": executionResult.ExecutionTimeMs,
			"user_id":           execCtx.UserID,
			"session_id":        execCtx.SessionID,
		})

		c.JSON(http.StatusOK, response)
	}
}

// GetExecutionHistory returns SQL execution history for the current user
func (m *SQLSecurityMiddleware) GetExecutionHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Parse limit parameter
		limit := 50 // default
		if limitStr := c.Query("limit"); limitStr != "" {
			if parsedLimit, err := parseLimit(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
				limit = parsedLimit
			}
		}

		// Get execution history
		history, err := m.validator.GetExecutionHistory(c.Request.Context(), userIDStr, limit)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to retrieve execution history",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    history,
			"count":   len(history),
		})
	}
}

// GetPendingApprovals returns pending query approvals (for approvers)
func (m *SQLSecurityMiddleware) GetPendingApprovals() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		userIDStr, ok := userID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// Check if user can approve queries (system admin or higher)
		canApprove, err := m.rbacEngine.HasRole(c.Request.Context(), userIDStr, "system_admin")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to check approval permissions",
			})
			return
		}

		if !canApprove {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient privileges to view pending approvals",
			})
			return
		}

		// This would need to be implemented in the validator
		// For now, return a placeholder
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"message": "Pending approvals endpoint not yet implemented",
		})
	}
}

// Helper methods

func (m *SQLSecurityMiddleware) buildExecutionContext(c *gin.Context, request *SQLExecutionRequest) (*SQLExecutionContext, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil, fmt.Errorf("user ID not found in context")
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return nil, fmt.Errorf("invalid user ID format")
	}

	adminRole := ""
	if role, exists := c.Get("admin_role"); exists {
		if roleStr, ok := role.(string); ok {
			adminRole = roleStr
		}
	}

	sessionID := ""
	if sid, exists := c.Get("session_id"); exists {
		if sidStr, ok := sid.(string); ok {
			sessionID = sidStr
		}
	}

	execCtx := &SQLExecutionContext{
		UserID:      userIDStr,
		SessionID:   sessionID,
		AdminRole:   adminRole,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
		RequestPath: c.Request.URL.Path,
		AdditionalData: map[string]interface{}{
			"request_reason": request.RequestReason,
			"parameters":     request.Parameters,
			"query_timeout":  request.QueryTimeout,
		},
	}

	// Add any additional data from the request
	for k, v := range request.AdditionalData {
		execCtx.AdditionalData[k] = v
	}

	return execCtx, nil
}

func (m *SQLSecurityMiddleware) logSecurityEvent(c *gin.Context, eventType string, details map[string]interface{}) {
	// This would integrate with the security event logging system
	// For now, we'll just log to stdout/stderr
	eventData := map[string]interface{}{
		"event_type":   eventType,
		"timestamp":    time.Now().UTC(),
		"ip_address":   c.ClientIP(),
		"user_agent":   c.GetHeader("User-Agent"),
		"request_path": c.Request.URL.Path,
		"details":      details,
	}

	if eventJSON, err := json.Marshal(eventData); err == nil {
		fmt.Printf("SECURITY_EVENT: %s\n", string(eventJSON))
	}
}

func parseLimit(limitStr string) (int, error) {
	var limit int
	if _, err := fmt.Sscanf(limitStr, "%d", &limit); err != nil {
		return 0, err
	}
	return limit, nil
}

// SecurityEventLogger can be used to log security events to the database
type SecurityEventLogger struct {
	// This would be implemented to write to the security_events table
	// Left as a placeholder for now
}

// LogSecurityEvent logs a security event to the database
func (sel *SecurityEventLogger) LogSecurityEvent(ctx context.Context, eventType, title, description string, details map[string]interface{}) error {
	// Implementation would write to security_events table
	return fmt.Errorf("not implemented")
}
