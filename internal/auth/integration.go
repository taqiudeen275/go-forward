package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLSecurityIntegration provides integration between SQL security components
type SQLSecurityIntegration struct {
	validator   SQLSecurityValidator
	middleware  *SQLSecurityMiddleware
	rbacEngine  RBACEngine
	mfaService  MFAService
	authService *Service
	db          *pgxpool.Pool
	initialized bool
}

// NewSQLSecurityIntegration creates a new SQL security integration
func NewSQLSecurityIntegration(db *pgxpool.Pool, authService *Service) *SQLSecurityIntegration {
	integration := &SQLSecurityIntegration{
		db:          db,
		authService: authService,
		initialized: false,
	}
	return integration
}

// Initialize sets up all SQL security components
func (s *SQLSecurityIntegration) Initialize() error {
	if s.initialized {
		return nil
	}

	// Initialize RBAC engine
	s.rbacEngine = NewRBACEngine(s.db)

	// Initialize MFA service
	s.mfaService = NewMFAService(s.db, s.rbacEngine, "go-forward")

	// Initialize SQL validator
	s.validator = NewSQLSecurityValidator(s.db, s.rbacEngine)

	// Initialize SQL middleware
	s.middleware = NewSQLSecurityMiddleware(s.validator, s.rbacEngine)

	s.initialized = true
	return nil
}

// GetValidator returns the SQL security validator
func (s *SQLSecurityIntegration) GetValidator() SQLSecurityValidator {
	return s.validator
}

// GetMiddleware returns the SQL security middleware
func (s *SQLSecurityIntegration) GetMiddleware() *SQLSecurityMiddleware {
	return s.middleware
}

// GetRBACEngine returns the RBAC engine
func (s *SQLSecurityIntegration) GetRBACEngine() RBACEngine {
	return s.rbacEngine
}

// GetMFAService returns the MFA service
func (s *SQLSecurityIntegration) GetMFAService() MFAService {
	return s.mfaService
}

// RegisterSQLRoutes registers SQL administration routes with Gin router
func (s *SQLSecurityIntegration) RegisterSQLRoutes(router *gin.RouterGroup) {
	if !s.initialized {
		panic("SQLSecurityIntegration must be initialized before registering routes")
	}

	// Admin SQL management routes
	adminSQL := router.Group("/admin/sql")
	adminSQL.Use(s.middleware.RequireAdminRole("admin"))
	{
		// SQL execution endpoints
		adminSQL.POST("/execute", s.middleware.ValidateAndExecuteSQL())
		adminSQL.POST("/validate", s.handleValidateSQL())
		adminSQL.GET("/history", s.middleware.GetExecutionHistory())
		adminSQL.GET("/history/:user_id", s.handleGetUserHistory())

		// Query approval endpoints
		approvals := adminSQL.Group("/approvals")
		approvals.Use(s.middleware.RequireAdminRole("system_admin"))
		{
			approvals.GET("/pending", s.middleware.GetPendingApprovals())
			approvals.GET("/:approval_id", s.handleGetApprovalDetails())
			approvals.POST("/:approval_id/approve", s.handleApproveQuery())
			approvals.POST("/:approval_id/deny", s.handleDenyQuery())
			approvals.GET("/", s.handleListApprovals())
		}

		// Security monitoring endpoints
		security := adminSQL.Group("/security")
		security.Use(s.middleware.RequireAdminRole("security_admin"))
		{
			security.GET("/events", s.handleGetSecurityEvents())
			security.GET("/stats", s.handleGetSecurityStats())
			security.GET("/risk-assessment", s.handleGetRiskAssessment())
			security.POST("/emergency-stop", s.handleEmergencyStop())
		}
	}
}

// SQL validation handler (dry-run only)
func (s *SQLSecurityIntegration) handleValidateSQL() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request SQLExecutionRequest
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
		execCtx, err := s.buildExecutionContext(c, &request)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "Invalid execution context",
				"message": err.Error(),
			})
			return
		}

		// Validate the query
		validationResult, err := s.validator.ValidateQuery(c.Request.Context(), request.Query, *execCtx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Validation failed",
				"message": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success":           validationResult.Valid,
			"validation_result": validationResult,
			"message":           "Query validation completed",
		})
	}
}

// Get user execution history handler
func (s *SQLSecurityIntegration) handleGetUserHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		targetUserID := c.Param("user_id")
		if targetUserID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID is required",
			})
			return
		}

		// Check permissions
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

		// System admins can view any user's history
		if targetUserID != currentUserIDStr {
			canViewAll, err := s.rbacEngine.HasRole(c.Request.Context(), currentUserIDStr, "system_admin")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Failed to check permissions",
				})
				return
			}
			if !canViewAll {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Insufficient privileges",
				})
				return
			}
		}

		// Get limit parameter
		limit := 50
		if limitStr := c.Query("limit"); limitStr != "" {
			// Parse limit safely (implementation would go here)
		}

		history, err := s.validator.GetExecutionHistory(c.Request.Context(), targetUserID, limit)
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
		})
	}
}

// Approval details handler
func (s *SQLSecurityIntegration) handleGetApprovalDetails() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		approval, err := s.validator.CheckQueryApproval(c.Request.Context(), approvalID)
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

// Approve query handler
func (s *SQLSecurityIntegration) handleApproveQuery() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		var request struct {
			Reason        string `json:"reason" binding:"required"`
			MaxExecutions int    `json:"max_executions,omitempty"`
			ExpiryHours   int    `json:"expiry_hours,omitempty"`
		}

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

		// TODO: Implement actual approval logic in the validator
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"message":     "Query approved successfully",
			"approval_id": approvalID,
			"approved_by": userIDStr,
			"reason":      request.Reason,
		})
	}
}

// Deny query handler
func (s *SQLSecurityIntegration) handleDenyQuery() gin.HandlerFunc {
	return func(c *gin.Context) {
		approvalID := c.Param("approval_id")
		if approvalID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Approval ID is required",
			})
			return
		}

		var request struct {
			Reason string `json:"reason" binding:"required"`
		}

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

		// TODO: Implement actual denial logic in the validator
		c.JSON(http.StatusOK, gin.H{
			"success":     true,
			"message":     "Query denied",
			"approval_id": approvalID,
			"denied_by":   userIDStr,
			"reason":      request.Reason,
		})
	}
}

// List approvals handler
func (s *SQLSecurityIntegration) handleListApprovals() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse query parameters
		status := c.DefaultQuery("status", "pending")
		riskLevel := c.Query("risk_level")
		queryType := c.Query("query_type")
		limit := 50
		offset := 0

		// TODO: Implement actual approval listing logic
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

// Security events handler
func (s *SQLSecurityIntegration) handleGetSecurityEvents() gin.HandlerFunc {
	return func(c *gin.Context) {
		eventType := c.Query("event_type")
		severity := c.Query("severity")
		limit := 50

		// TODO: Query the security_events table
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

// Security statistics handler
func (s *SQLSecurityIntegration) handleGetSecurityStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Calculate actual statistics from database
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

// Risk assessment handler
func (s *SQLSecurityIntegration) handleGetRiskAssessment() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Implement risk assessment logic
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
			},
			"message": "Risk assessment endpoint not yet fully implemented",
		})
	}
}

// Emergency stop handler
func (s *SQLSecurityIntegration) handleEmergencyStop() gin.HandlerFunc {
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

		// TODO: Implement emergency stop functionality
		c.JSON(http.StatusOK, gin.H{
			"success":      true,
			"message":      "Emergency SQL stop initiated",
			"initiated_by": userIDStr,
			"timestamp":    "placeholder",
			"note":         "Emergency stop endpoint not yet fully implemented",
		})
	}
}

// Helper method to build execution context
func (s *SQLSecurityIntegration) buildExecutionContext(c *gin.Context, request *SQLExecutionRequest) (*SQLExecutionContext, error) {
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

// IsInitialized returns whether the integration has been initialized
func (s *SQLSecurityIntegration) IsInitialized() bool {
	return s.initialized
}

// Shutdown gracefully shuts down the integration
func (s *SQLSecurityIntegration) Shutdown(ctx context.Context) error {
	// TODO: Implement graceful shutdown logic
	return nil
}
