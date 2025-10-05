package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/interfaces"
)

// Handlers provides HTTP handlers for storage operations
type Handlers struct {
	service       interfaces.StorageService
	accessControl interfaces.AccessControl
}

// NewHandlers creates new storage handlers
func NewHandlers(service interfaces.StorageService, accessControl interfaces.AccessControl) *Handlers {
	return &Handlers{
		service:       service,
		accessControl: accessControl,
	}
}

// UploadFile handles file upload requests
func (h *Handlers) UploadFile(c *gin.Context) {
	bucket := c.Param("bucket")
	if bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket name is required"})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Parse multipart form
	err := c.Request.ParseMultipartForm(32 << 20) // 32 MB max memory
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to parse multipart form"})
		return
	}

	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file is required"})
		return
	}
	defer file.Close()

	// Get file path from form or use filename
	path := c.Request.FormValue("path")
	if path == "" {
		path = header.Filename
	}

	// Check write permissions
	if h.accessControl != nil && !h.accessControl.CanWrite(c.Request.Context(), userID.(string), bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to upload file"})
		return
	}

	// Parse metadata from form
	metadata := interfaces.FileMetadata{
		Name:     header.Filename,
		MimeType: header.Header.Get("Content-Type"),
		Size:     header.Size,
		Metadata: make(map[string]string),
	}

	// Parse additional metadata from form
	if metadataStr := c.Request.FormValue("metadata"); metadataStr != "" {
		if err := json.Unmarshal([]byte(metadataStr), &metadata.Metadata); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid metadata format"})
			return
		}
	}

	// Parse permissions from form or create default permissions
	if permissionsStr := c.Request.FormValue("permissions"); permissionsStr != "" {
		permissions := &interfaces.FilePermissions{}
		if err := json.Unmarshal([]byte(permissionsStr), permissions); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permissions format"})
			return
		}
		metadata.Permissions = permissions
	} else if ac, ok := h.accessControl.(*AccessControlService); ok {
		// Create default permissions based on bucket configuration
		metadata.Permissions = ac.CreateDefaultPermissions(c.Request.Context(), bucket, userID.(string))
	}

	// Upload file
	fileInfo, err := h.service.Upload(c.Request.Context(), bucket, path, file, metadata)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, fileInfo)
}

// DownloadFile handles file download requests
func (h *Handlers) DownloadFile(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Param("path")

	if bucket == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket and path are required"})
		return
	}

	// Get user ID from context (may be empty for public files)
	userID, _ := c.Get("user_id")
	userIDStr := ""
	if userID != nil {
		userIDStr = userID.(string)
	}

	// Check read permissions
	if h.accessControl != nil && !h.accessControl.CanRead(c.Request.Context(), userIDStr, bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to download file"})
		return
	}

	// Get file info first to set proper headers
	fileInfo, err := h.service.GetFileInfo(c.Request.Context(), bucket, path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Download file
	reader, err := h.service.Download(c.Request.Context(), bucket, path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Set appropriate headers
	c.Header("Content-Type", fileInfo.MimeType)
	c.Header("Content-Length", fmt.Sprintf("%d", fileInfo.Size))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileInfo.Name))

	// Stream file content
	_, err = io.Copy(c.Writer, reader)
	if err != nil {
		// Log error but don't send JSON response as headers are already sent
		fmt.Printf("Error streaming file: %v\n", err)
	}
}

// DeleteFile handles file deletion requests
func (h *Handlers) DeleteFile(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Param("path")

	if bucket == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket and path are required"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Check delete permissions
	if h.accessControl != nil && !h.accessControl.CanDelete(c.Request.Context(), userID.(string), bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to delete file"})
		return
	}

	// Delete file
	err := h.service.Delete(c.Request.Context(), bucket, path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file deleted successfully"})
}

// GetFileInfo handles file info requests
func (h *Handlers) GetFileInfo(c *gin.Context) {
	bucket := c.Param("bucket")
	path := c.Param("path")

	if bucket == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket and path are required"})
		return
	}

	// Get user ID from context (may be empty for public files)
	userID, _ := c.Get("user_id")
	userIDStr := ""
	if userID != nil {
		userIDStr = userID.(string)
	}

	// Check read permissions
	if h.accessControl != nil && !h.accessControl.CanRead(c.Request.Context(), userIDStr, bucket, path) {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to access file info"})
		return
	}

	// Get file info
	fileInfo, err := h.service.GetFileInfo(c.Request.Context(), bucket, path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	c.JSON(http.StatusOK, fileInfo)
}

// ListFiles handles file listing requests
func (h *Handlers) ListFiles(c *gin.Context) {
	bucket := c.Param("bucket")
	if bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket name is required"})
		return
	}

	// Get query parameters
	prefix := c.Query("prefix")
	limitStr := c.DefaultQuery("limit", "100")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 100
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Get user ID from context (may be empty for public buckets)
	userID, _ := c.Get("user_id")
	userIDStr := ""
	if userID != nil {
		userIDStr = userID.(string)
	}

	// Check read permissions for bucket
	if h.accessControl != nil && !h.accessControl.CanRead(c.Request.Context(), userIDStr, bucket, "") {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to list files"})
		return
	}

	// List files
	files, err := h.service.ListFiles(c.Request.Context(), bucket, prefix, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filter files based on individual permissions if access control is enabled
	if h.accessControl != nil {
		var filteredFiles []*interfaces.FileInfo
		for _, file := range files {
			if h.accessControl.CanRead(c.Request.Context(), userIDStr, bucket, file.Path) {
				filteredFiles = append(filteredFiles, file)
			}
		}
		files = filteredFiles
	}

	c.JSON(http.StatusOK, gin.H{
		"files":  files,
		"limit":  limit,
		"offset": offset,
		"count":  len(files),
	})
}

// CreateBucket handles bucket creation requests
func (h *Handlers) CreateBucket(c *gin.Context) {
	bucket := c.Param("bucket")
	if bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket name is required"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// Parse bucket configuration
	var config interfaces.BucketConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bucket configuration"})
		return
	}

	// TODO: Check admin permissions for bucket creation
	_ = userID

	// Create bucket
	err := h.service.CreateBucket(c.Request.Context(), bucket, config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "bucket created successfully"})
}

// DeleteBucket handles bucket deletion requests
func (h *Handlers) DeleteBucket(c *gin.Context) {
	bucket := c.Param("bucket")
	if bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bucket name is required"})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// TODO: Check admin permissions for bucket deletion
	_ = userID

	// Delete bucket
	err := h.service.DeleteBucket(c.Request.Context(), bucket)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "bucket deleted successfully"})
}

// GetBuckets handles bucket listing requests
func (h *Handlers) GetBuckets(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	// TODO: Check admin permissions for bucket listing
	_ = userID

	// Get buckets
	buckets, err := h.service.GetBuckets(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"buckets": buckets})
}

// RegisterRoutes registers storage routes with the router
func (h *Handlers) RegisterRoutes(router *gin.RouterGroup) {
	storage := router.Group("/storage")
	{
		// Bucket operations
		storage.GET("/buckets", h.GetBuckets)
		storage.POST("/buckets/:bucket", h.CreateBucket)
		storage.DELETE("/buckets/:bucket", h.DeleteBucket)

		// File operations
		storage.POST("/files/:bucket/*path", h.UploadFile)
		storage.GET("/files/:bucket/*path", h.DownloadFile)
		storage.DELETE("/files/:bucket/*path", h.DeleteFile)
		storage.HEAD("/files/:bucket/*path", h.GetFileInfo)

		// File listing
		storage.GET("/files/:bucket", h.ListFiles)
	}

	// Public file access (no auth required)
	public := router.Group("/public")
	{
		public.GET("/:bucket/*path", func(c *gin.Context) {
			// Remove leading slash from path parameter
			path := strings.TrimPrefix(c.Param("path"), "/")
			c.Set("path", path)
			h.DownloadFile(c)
		})
	}
}
