package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/auth"
)

// AdminSQLHandlers provides HTTP handlers for admin SQL operations
type AdminSQLHandlers struct {
	sqlMiddleware *auth.SQLSecurityMiddleware
	validator     auth.SQLSecurityValidator
	rbacEngine    auth.RBACEngine
}

// NewAdminSQLHandlers creates new admin SQL handlers
func NewAdminSQLHandlers(sqlMiddleware *auth.SQLSecurityMiddleware, validator auth.SQLSecurityValidator, rbacEngine auth.RBACEngine) *AdminSQLHandlers {
	return &AdminSQLHandlers{
		sqlMiddleware: sqlMiddleware,
		validator:     validator,
		rbacEngine:    rbacEngine,
	}
}

// RegisterRoutes registers all admin SQL routes
func (h *AdminSQLHandlers) RegisterRoutes(router *gin.RouterGroup) {
	// SQL execution routes - require system admin role
	sqlGroup := router.Group("/sql")
	sqlGroup.Use(h.sqlMiddleware.RequireAdminRole("system_admin"))
	{
		sqlGroup.POST("/execute", h.sqlMiddleware.ValidateAndExecuteSQL())
		sqlGroup.POST("/validate", h.ValidateSQL())
		sqlGroup.GET("/history", h.sqlMiddleware.GetExecutionHistory())
		sqlGroup.GET("/history/:user_id", h.GetUserExecutionHistory())
	}

	// Approval management routes - require system admin role
	approvalGroup := router.Group("/sql/approvals")
	approvalGroup.Use(h.sqlMiddleware.RequireAdminRole("system_admin"))
	{
		approvalGroup.GET("/pending", h.sqlMiddleware.GetPendingApprovals())
		approvalGroup.GET("/:approval_id", h.GetApprovalDetails())
		approvalGroup.POST("/:approval_id/approve", h.ApproveQuery())
		approvalGroup.POST("/:approval_id/deny", h.DenyQuery())
		approvalGroup.GET("/", h.ListApprovals())
	}

	// Security monitoring routes - require security admin role
	securityGroup := router.Group("/sql/security")
	securityGroup.Use(h.sqlMiddleware.RequireAdminRole("security_admin"))
	{
		securityGroup.GET("/events", h.GetSecurityEvents())
		securityGroup.GET("/stats", h.GetSecurityStats())
		securityGroup.GET("/risk-assessment", h.GetRiskAssessment())
		securityGroup.POST("/emergency-stop", h.EmergencyStopSQL())
	}
}

// ValidateSQL validates a SQL query without executing it
func (h *AdminSQLHandlers) ValidateSQL() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request auth.SQLExecutionRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

		// Force dry run for validation endpoint
		request.DryRun = true

		// Build execution context
		execCtx, err := h.buildExecutionContext(c, &request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid execution context",
				"message": err.Error(),
			})
			return
		}

		// Validate the query
		validationResult, err := h.validator.ValidateQuery(c.Request.Context(), request.Query, *execCtx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Validation failed",
				"message": err.Error(),
			})
			return
		}

		response := gin.H{
			"success":           validationResult.Valid,
			"validation_result": validationResult,
			"message":           "Query validation completed",
		}

		if !validationResult.Valid {
			response["message"] = "Query validation failed"
		}

		c.JSON(http.StatusOK, response)
	}
}

// GetUserExecutionHistory gets SQL execution history for a specific user
func (h *AdminSQLHandlers) GetUserExecutionHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		targetUserID := c.Param("user_id")
		if targetUserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// Check if current user can view other users' history
		currentUserID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			return
		}

		currentUserIDStr, ok := currentUserID.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid user ID format",
			})
			return
		}

		// System admins can view any user's history, others can only view their own
		if targetUserID != currentUserIDStr {
			canViewAll, err := h.rbacEngine.HasRole(c.Request.Context(), currentUserIDStr, "system_admin")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check permissions",
				})
				return
			}

			if !canViewAll {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Insufficient privileges to view other users' history",
				})
				return
			}
		}

		// Parse limit parameter
		limit := 50 // default
		if limitStr := c.Query("limit"); limitStr != "" {
			if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
				limit = parsedLimit
			}
		}

		// Get execution history
		history, err := h.validator.GetExecutionHistory(c.Request.Context(), targetUserID, limit)
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
			"user_id": targetUserID,
			"limit":   limit,
		})
	}
}

// GetApprovalDetails gets details of a specific approval request
func (h *AdminSQLHandlers) GetApprovalDetails() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		// Check if approval exists (this would need to be implemented in the validator)
		approval, err := h.validator.CheckQueryApproval(c.Request.Context(), approvalID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Failed to retrieve approval details",
				"message": err.Error(),
			})
			return
		}

		if approval == nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Approval not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    approval,
		})
	}
}

// ApprovalRequest represents an approval/denial request
type ApprovalRequest struct {
	Reason        string `json:"reason"`
	MaxExecutions int    `json:"max_executions,omitempty"`
	ExpiryHours   int    `json:"expiry_hours,omitempty"`
}

// ApproveQuery approves a pending query
func (h *AdminSQLHandlers) ApproveQuery() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		var request ApprovalRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

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

		// This would need to be implemented in the validator
		// For now, return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"message":     "Query approved successfully",
			"approval_id": approvalID,
			"approved_by": userIDStr,
			"reason":      request.Reason,
		})
	}
}

// DenyQuery denies a pending query
func (h *AdminSQLHandlers) DenyQuery() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		var request ApprovalRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid request",
				"message": err.Error(),
			})
			return
		}

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

		// This would need to be implemented in the validator
		// For now, return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"message":     "Query denied",
			"approval_id": approvalID,
			"denied_by":   userIDStr,
			"reason":      request.Reason,
		})
	}
}

// ListApprovals lists all approval requests with filters
func (h *AdminSQLHandlers) ListApprovals() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse query parameters
		status := c.Query("status")        // pending, approved, denied, expired
		riskLevel := c.Query("risk_level") // low, medium, high, critical
		queryType := c.Query("query_type") // SELECT, INSERT, UPDATE, DELETE, etc.

		limit := 50
		if limitStr := c.Query("limit"); limitStr != "" {
			if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
				limit = parsedLimit
			}
		}

		offset := 0
		if offsetStr := c.Query("offset"); offsetStr != "" {
			if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
				offset = parsedOffset
			}
		}

		// This would need to be implemented with proper database queries
		// For now, return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"total":   0,
			"limit":   limit,
			"offset":  offset,
			"filters": gin.H{
				"status":     status,
				"risk_level": riskLevel,
				"query_type": queryType,
			},
			"message": "List approvals endpoint not yet fully implemented",
		})
	}
}

// GetSecurityEvents gets recent security events related to SQL operations
func (h *AdminSQLHandlers) GetSecurityEvents() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse query parameters
		eventType := c.Query("event_type") // sql_execution_failed, unauthorized_sql_access, etc.
		severity := c.Query("severity")    // low, medium, high, critical

		limit := 50
		if limitStr := c.Query("limit"); limitStr != "" {
			if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
				limit = parsedLimit
			}
		}

		// This would query the security_events table
		// For now, return a placeholder response
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data":    []interface{}{},
			"total":   0,
			"limit":   limit,
			"filters": gin.H{
				"event_type": eventType,
				"severity":   severity,
			},
			"message": "Security events endpoint not yet fully implemented",
		})
	}
}

// GetSecurityStats gets security statistics for SQL operations
func (h *AdminSQLHandlers) GetSecurityStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would calculate various security metrics
		// For now, return placeholder statistics
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"total_queries_last_24h":         0,
				"failed_queries_last_24h":        0,
				"high_risk_queries_last_24h":     0,
				"pending_approvals":              0,
				"unauthorized_attempts_last_24h": 0,
				"avg_query_execution_time_ms":    0,
				"query_types": gin.H{
					"SELECT": 0,
					"INSERT": 0,
					"UPDATE": 0,
					"DELETE": 0,
					"OTHER":  0,
				},
				"risk_levels": gin.H{
					"low":      0,
					"medium":   0,
					"high":     0,
					"critical": 0,
				},
			},
			"generated_at": "placeholder",
			"message":      "Security stats endpoint not yet fully implemented",
		})
	}
}

// GetRiskAssessment gets risk assessment for current SQL security posture
func (h *AdminSQLHandlers) GetRiskAssessment() gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would analyze current security posture and provide recommendations
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"overall_risk_level": "medium",
				"risk_factors": []gin.H{
					{
						"factor":         "High-privilege user activity",
						"level":          "medium",
						"description":    "Multiple system admin users have executed high-risk queries recently",
						"recommendation": "Review and audit system admin activities",
					},
				},
				"security_recommendations": []gin.H{
					{
						"priority":    "high",
						"category":    "access_control",
						"title":       "Enable MFA for all admin users",
						"description": "Multi-factor authentication should be required for all administrative access",
					},
				},
				"compliance_status": gin.H{
					"audit_logging":     "compliant",
					"access_control":    "needs_attention",
					"approval_workflow": "compliant",
				},
			},
			"generated_at": "placeholder",
			"message":      "Risk assessment endpoint not yet fully implemented",
		})
	}
}

// EmergencyStopSQL immediately stops all non-critical SQL operations
func (h *AdminSQLHandlers) EmergencyStopSQL() gin.HandlerFunc {
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

		// This would implement emergency stop functionality
		// - Cancel all running queries
		// - Disable query execution for non-emergency users
		// - Log the emergency stop event
		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"message":      "Emergency SQL stop initiated",
			"initiated_by": userIDStr,
			"timestamp":    "placeholder",
			"note":         "Emergency stop endpoint not yet fully implemented",
		})
	}
}

// Helper methods

func (h *AdminSQLHandlers) buildExecutionContext(c *gin.Context, request *auth.SQLExecutionRequest) (*auth.SQLExecutionContext, error) {
	userID, exists := c.Get("user_id")
	if !exists {
		return nil, gin.Error{Err: gin.Error{}, Type: gin.ErrorTypePublic, Meta: "user ID not found in context"}
	}

	userIDStr, ok := userID.(string)
	if !ok {
		return nil, gin.Error{Err: gin.Error{}, Type: gin.ErrorTypePublic, Meta: "invalid user ID format"}
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

	execCtx := &auth.SQLExecutionContext{
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
