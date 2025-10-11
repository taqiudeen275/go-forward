package template

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// Handler handles HTTP requests for template management
type Handler struct {
	service *Service
}

// NewHandler creates a new template handler
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
	}
}

// RegisterRoutes registers template routes
func (h *Handler) RegisterRoutes(router *gin.RouterGroup) {
	templates := router.Group("/templates")
	{
		templates.POST("", h.CreateTemplate)
		templates.GET("", h.ListTemplates)
		templates.GET("/:id", h.GetTemplate)
		templates.PUT("/:id", h.UpdateTemplate)
		templates.DELETE("/:id", h.DeleteTemplate)

		templates.POST("/render", h.RenderTemplate)
		templates.POST("/preview", h.PreviewTemplate)
		templates.POST("/:id/validate", h.ValidateTemplate)

		templates.GET("/:id/versions", h.GetTemplateVersions)
		templates.GET("/:id/versions/:version", h.GetTemplateVersion)
		templates.GET("/:id/stats", h.GetTemplateStats)

		templates.GET("/variables/:purpose", h.GetAvailableVariables)
		templates.GET("/help/:purpose", h.GetVariableHelp)

		templates.GET("/providers", h.GetProviderInfo)
		templates.POST("/providers/validate", h.ValidateProviders)

		// Communication endpoints
		templates.POST("/send/email", h.SendEmail)
		templates.POST("/send/sms", h.SendSMS)
	}
}

// CreateTemplate creates a new template
// @Summary Create a new template
// @Description Create a new email or SMS template with variable support
// @Tags templates
// @Accept json
// @Produce json
// @Param template body TemplateRequest true "Template data"
// @Success 201 {object} Template
// @Failure 400 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates [post]
func (h *Handler) CreateTemplate(c *gin.Context) {
	var req TemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, errors.NewAuthenticationError("User not authenticated"))
		return
	}

	template, err := h.service.CreateTemplate(c.Request.Context(), &req, userID.(string))
	if err != nil {
		if errors.IsValidationError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusCreated, template)
}

// ListTemplates lists templates with filtering
// @Summary List templates
// @Description List templates with optional filtering
// @Tags templates
// @Produce json
// @Param type query string false "Template type (email, sms)"
// @Param purpose query string false "Template purpose"
// @Param language query string false "Template language"
// @Param is_default query boolean false "Filter by default templates"
// @Param is_active query boolean false "Filter by active templates"
// @Param limit query int false "Limit results" default(50)
// @Param offset query int false "Offset results" default(0)
// @Success 200 {array} Template
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates [get]
func (h *Handler) ListTemplates(c *gin.Context) {
	filter := &TemplateFilter{}

	if templateType := c.Query("type"); templateType != "" {
		t := TemplateType(templateType)
		filter.Type = &t
	}

	if purpose := c.Query("purpose"); purpose != "" {
		p := TemplatePurpose(purpose)
		filter.Purpose = &p
	}

	if language := c.Query("language"); language != "" {
		filter.Language = &language
	}

	if isDefault := c.Query("is_default"); isDefault != "" {
		if val, err := strconv.ParseBool(isDefault); err == nil {
			filter.IsDefault = &val
		}
	}

	if isActive := c.Query("is_active"); isActive != "" {
		if val, err := strconv.ParseBool(isActive); err == nil {
			filter.IsActive = &val
		}
	}

	if limit := c.Query("limit"); limit != "" {
		if val, err := strconv.Atoi(limit); err == nil {
			filter.Limit = val
		}
	} else {
		filter.Limit = 50
	}

	if offset := c.Query("offset"); offset != "" {
		if val, err := strconv.Atoi(offset); err == nil {
			filter.Offset = val
		}
	}

	templates, err := h.service.ListTemplates(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, templates)
}

// GetTemplate retrieves a template by ID
// @Summary Get template by ID
// @Description Retrieve a specific template by its ID
// @Tags templates
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} Template
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id} [get]
func (h *Handler) GetTemplate(c *gin.Context) {
	id := c.Param("id")

	template, err := h.service.GetTemplate(c.Request.Context(), id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, template)
}

// UpdateTemplate updates an existing template
// @Summary Update template
// @Description Update an existing template
// @Tags templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param template body TemplateUpdateRequest true "Template update data"
// @Success 200 {object} Template
// @Failure 400 {object} errors.ErrorResponse
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id} [put]
func (h *Handler) UpdateTemplate(c *gin.Context) {
	id := c.Param("id")

	var req TemplateUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, errors.NewAuthenticationError("User not authenticated"))
		return
	}

	template, err := h.service.UpdateTemplate(c.Request.Context(), id, &req, userID.(string))
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else if errors.IsValidationError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, template)
}

// DeleteTemplate deletes a template
// @Summary Delete template
// @Description Delete a template by ID
// @Tags templates
// @Param id path string true "Template ID"
// @Success 204
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id} [delete]
func (h *Handler) DeleteTemplate(c *gin.Context) {
	id := c.Param("id")

	err := h.service.DeleteTemplate(c.Request.Context(), id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.Status(http.StatusNoContent)
}

// RenderTemplate renders a template with variables
// @Summary Render template
// @Description Render a template with provided variables
// @Tags templates
// @Accept json
// @Produce json
// @Param render body RenderRequest true "Render request"
// @Success 200 {object} RenderResult
// @Failure 400 {object} errors.ErrorResponse
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/render [post]
func (h *Handler) RenderTemplate(c *gin.Context) {
	var req RenderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	result, err := h.service.RenderTemplate(c.Request.Context(), &req)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else if errors.IsValidationError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// PreviewTemplate previews a template with sample data
// @Summary Preview template
// @Description Preview a template with sample data
// @Tags templates
// @Accept json
// @Produce json
// @Param preview body PreviewRequest true "Preview request"
// @Success 200 {object} RenderResult
// @Failure 400 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/preview [post]
func (h *Handler) PreviewTemplate(c *gin.Context) {
	var req PreviewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	result, err := h.service.PreviewTemplate(c.Request.Context(), &req)
	if err != nil {
		if errors.IsValidationError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

// ValidateTemplate validates a template
// @Summary Validate template
// @Description Validate template syntax and variables
// @Tags templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} ValidationResult
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id}/validate [post]
func (h *Handler) ValidateTemplate(c *gin.Context) {
	id := c.Param("id")

	template, err := h.service.GetTemplate(c.Request.Context(), id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	result := h.service.ValidateTemplate(c.Request.Context(), template)
	c.JSON(http.StatusOK, result)
}

// GetTemplateVersions retrieves template versions
// @Summary Get template versions
// @Description Get all versions of a template
// @Tags templates
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {array} TemplateVersion
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id}/versions [get]
func (h *Handler) GetTemplateVersions(c *gin.Context) {
	id := c.Param("id")

	versions, err := h.service.GetTemplateVersions(c.Request.Context(), id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, versions)
}

// GetTemplateVersion retrieves a specific template version
// @Summary Get template version
// @Description Get a specific version of a template
// @Tags templates
// @Produce json
// @Param id path string true "Template ID"
// @Param version path int true "Version number"
// @Success 200 {object} TemplateVersion
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id}/versions/{version} [get]
func (h *Handler) GetTemplateVersion(c *gin.Context) {
	id := c.Param("id")
	versionStr := c.Param("version")

	version, err := strconv.Atoi(versionStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError("Invalid version number"))
		return
	}

	templateVersion, err := h.service.GetTemplateVersion(c.Request.Context(), id, version)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, templateVersion)
}

// GetTemplateStats retrieves template usage statistics
// @Summary Get template statistics
// @Description Get usage statistics for a template
// @Tags templates
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} TemplateStats
// @Failure 404 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/{id}/stats [get]
func (h *Handler) GetTemplateStats(c *gin.Context) {
	id := c.Param("id")

	stats, err := h.service.GetTemplateStats(c.Request.Context(), id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			c.JSON(http.StatusNotFound, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, stats)
}

// GetAvailableVariables returns available variables for a purpose
// @Summary Get available variables
// @Description Get available variables for a specific template purpose
// @Tags templates
// @Produce json
// @Param purpose path string true "Template purpose"
// @Success 200 {array} TemplateVariable
// @Router /templates/variables/{purpose} [get]
func (h *Handler) GetAvailableVariables(c *gin.Context) {
	purpose := TemplatePurpose(c.Param("purpose"))
	variables := h.service.GetAvailableVariables(purpose)
	c.JSON(http.StatusOK, variables)
}

// GetVariableHelp returns help text for template variables
// @Summary Get variable help
// @Description Get help text for template variables for a specific purpose
// @Tags templates
// @Produce json
// @Param purpose path string true "Template purpose"
// @Success 200 {object} map[string]string
// @Router /templates/help/{purpose} [get]
func (h *Handler) GetVariableHelp(c *gin.Context) {
	purpose := TemplatePurpose(c.Param("purpose"))
	help := h.service.GetVariableHelp(purpose)
	c.JSON(http.StatusOK, map[string]string{"help": help})
}

// GetProviderInfo returns information about configured providers
// @Summary Get provider information
// @Description Get information about configured email and SMS providers
// @Tags templates
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /templates/providers [get]
func (h *Handler) GetProviderInfo(c *gin.Context) {
	info := h.service.GetProviderInfo()
	c.JSON(http.StatusOK, info)
}

// ValidateProviders validates provider configurations
// @Summary Validate providers
// @Description Validate email and SMS provider configurations
// @Tags templates
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /templates/providers/validate [post]
func (h *Handler) ValidateProviders(c *gin.Context) {
	results := h.service.ValidateProviders()

	response := map[string]interface{}{
		"valid":  len(results) == 0,
		"errors": results,
	}

	c.JSON(http.StatusOK, response)
}

// SendEmailRequest represents an email sending request
type SendEmailRequest struct {
	Purpose   TemplatePurpose        `json:"purpose" validate:"required"`
	Language  string                 `json:"language"`
	Variables map[string]interface{} `json:"variables" validate:"required"`
	To        []string               `json:"to" validate:"required,min=1"`
}

// SendSMSRequest represents an SMS sending request
type SendSMSRequest struct {
	Purpose   TemplatePurpose        `json:"purpose" validate:"required"`
	Language  string                 `json:"language"`
	Variables map[string]interface{} `json:"variables" validate:"required"`
	To        string                 `json:"to" validate:"required"`
}

// SendEmail sends an email using a template
// @Summary Send templated email
// @Description Send an email using a template
// @Tags templates
// @Accept json
// @Produce json
// @Param email body SendEmailRequest true "Email request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/send/email [post]
func (h *Handler) SendEmail(c *gin.Context) {
	var req SendEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	if req.Language == "" {
		req.Language = "en"
	}

	err := h.service.SendEmail(c.Request.Context(), TemplateTypeEmail, req.Purpose, req.Language, req.Variables, req.To)
	if err != nil {
		if errors.IsValidationError(err) || errors.IsNotFoundError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, map[string]string{"message": "Email sent successfully"})
}

// SendSMS sends an SMS using a template
// @Summary Send templated SMS
// @Description Send an SMS using a template
// @Tags templates
// @Accept json
// @Produce json
// @Param sms body SendSMSRequest true "SMS request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} errors.ErrorResponse
// @Failure 500 {object} errors.ErrorResponse
// @Router /templates/send/sms [post]
func (h *Handler) SendSMS(c *gin.Context) {
	var req SendSMSRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errors.NewValidationError(err.Error()))
		return
	}

	if req.Language == "" {
		req.Language = "en"
	}

	err := h.service.SendSMS(c.Request.Context(), req.Purpose, req.Language, req.Variables, req.To)
	if err != nil {
		if errors.IsValidationError(err) || errors.IsNotFoundError(err) {
			c.JSON(http.StatusBadRequest, err)
		} else {
			c.JSON(http.StatusInternalServerError, err)
		}
		return
	}

	c.JSON(http.StatusOK, map[string]string{"message": "SMS sent successfully"})
}
