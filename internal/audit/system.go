package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// auditSystem implements the AuditSystem interface
type auditSystem struct {
	db              *sql.DB
	config          *AuditConfig
	retentionPolicy *RetentionPolicy
	indexManager    *IndexManager
	compressionMgr  *CompressionManager
	mutex           sync.RWMutex

	// Statistics cache
	statsCache      map[string]*CachedStatistics
	statsCacheMutex sync.RWMutex
	statsCacheTTL   time.Duration
}

// AuditConfig contains configuration for the audit system
type AuditConfig struct {
	// Storage configuration
	MaxLogSize         int64 `json:"max_log_size"`
	CompressionEnabled bool  `json:"compression_enabled"`
	EncryptionEnabled  bool  `json:"encryption_enabled"`

	// Performance configuration
	BatchSize       int           `json:"batch_size"`
	FlushInterval   time.Duration `json:"flush_interval"`
	IndexingEnabled bool          `json:"indexing_enabled"`
	CacheEnabled    bool          `json:"cache_enabled"`
	CacheTTL        time.Duration `json:"cache_ttl"`

	// Retention configuration
	DefaultRetention time.Duration `json:"default_retention"`
	ArchiveEnabled   bool          `json:"archive_enabled"`
	ArchiveLocation  string        `json:"archive_location"`

	// Security configuration
	IntegrityChecks bool `json:"integrity_checks"`
	TamperDetection bool `json:"tamper_detection"`
	AccessLogging   bool `json:"access_logging"`

	// Categorization
	EventCategories map[EventType]CategoryConfig `json:"event_categories"`
}

// CategoryConfig defines configuration for event categories
type CategoryConfig struct {
	Retention       time.Duration    `json:"retention"`
	Severity        SecuritySeverity `json:"default_severity"`
	RequireApproval bool             `json:"require_approval"`
	Encryption      bool             `json:"encryption"`
	Compression     bool             `json:"compression"`
}

// RetentionPolicy defines how long different types of audit logs are kept
type RetentionPolicy struct {
	ID                 string                             `json:"id"`
	Name               string                             `json:"name"`
	Description        string                             `json:"description"`
	DefaultPeriod      time.Duration                      `json:"default_period"`
	CategoryPolicies   map[EventType]time.Duration        `json:"category_policies"`
	SeverityPolicies   map[SecuritySeverity]time.Duration `json:"severity_policies"`
	CompliancePolicies map[string]time.Duration           `json:"compliance_policies"`
	ArchiveAfter       time.Duration                      `json:"archive_after"`
	PurgeAfter         time.Duration                      `json:"purge_after"`
	CreatedAt          time.Time                          `json:"created_at"`
	UpdatedAt          time.Time                          `json:"updated_at"`
	CreatedBy          string                             `json:"created_by"`
}

// IndexManager and CompressionManager types are defined in index_manager.go

// CachedStatistics represents cached audit statistics
type CachedStatistics struct {
	Data      *AuditStatistics `json:"data"`
	CachedAt  time.Time        `json:"cached_at"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// AuditStatistics contains audit system statistics
type AuditStatistics struct {
	TotalEntries        int64                      `json:"total_entries"`
	EntriesByType       map[EventType]int64        `json:"entries_by_type"`
	EntriesBySeverity   map[SecuritySeverity]int64 `json:"entries_by_severity"`
	EntriesByRisk       map[RiskLevel]int64        `json:"entries_by_risk"`
	TopUsers            []UserActivityStats        `json:"top_users"`
	TopResources        []ResourceAccessStats      `json:"top_resources"`
	RecentActivity      []AuditEntry               `json:"recent_activity"`
	ErrorRate           float64                    `json:"error_rate"`
	AverageResponseTime time.Duration              `json:"average_response_time"`
	StorageUsage        StorageUsageStats          `json:"storage_usage"`
	RetentionStatus     RetentionStatus            `json:"retention_status"`
	GeneratedAt         time.Time                  `json:"generated_at"`
}

// UserActivityStats represents user activity statistics
type UserActivityStats struct {
	UserID       string    `json:"user_id"`
	AdminLevel   string    `json:"admin_level"`
	ActionCount  int64     `json:"action_count"`
	ErrorCount   int64     `json:"error_count"`
	LastActivity time.Time `json:"last_activity"`
	RiskScore    float64   `json:"risk_score"`
}

// ResourceAccessStats represents resource access statistics
type ResourceAccessStats struct {
	Resource    string    `json:"resource"`
	AccessCount int64     `json:"access_count"`
	UniqueUsers int64     `json:"unique_users"`
	LastAccess  time.Time `json:"last_access"`
	RiskScore   float64   `json:"risk_score"`
}

// StorageUsageStats represents storage usage statistics
type StorageUsageStats struct {
	TotalSize        int64     `json:"total_size"`
	CompressedSize   int64     `json:"compressed_size"`
	ArchivedSize     int64     `json:"archived_size"`
	CompressionRatio float64   `json:"compression_ratio"`
	GrowthRate       float64   `json:"growth_rate"`
	LastCleanup      time.Time `json:"last_cleanup"`
}

// RetentionStatus represents retention policy status
type RetentionStatus struct {
	EntriesEligibleForArchive int64     `json:"entries_eligible_for_archive"`
	EntriesEligibleForPurge   int64     `json:"entries_eligible_for_purge"`
	LastArchiveRun            time.Time `json:"last_archive_run"`
	LastPurgeRun              time.Time `json:"last_purge_run"`
	NextScheduledArchive      time.Time `json:"next_scheduled_archive"`
	NextScheduledPurge        time.Time `json:"next_scheduled_purge"`
}

// AuditSystemHealth represents the health status of the audit system
type AuditSystemHealth struct {
	Status             string             `json:"status"`
	DatabaseConnected  bool               `json:"database_connected"`
	IndexesHealthy     bool               `json:"indexes_healthy"`
	StorageAvailable   bool               `json:"storage_available"`
	RetentionUpToDate  bool               `json:"retention_up_to_date"`
	PerformanceMetrics PerformanceMetrics `json:"performance_metrics"`
	Errors             []HealthError      `json:"errors,omitempty"`
	Warnings           []HealthWarning    `json:"warnings,omitempty"`
	LastHealthCheck    time.Time          `json:"last_health_check"`
	Uptime             time.Duration      `json:"uptime"`
}

// PerformanceMetrics represents audit system performance metrics
type PerformanceMetrics struct {
	AverageWriteTime    time.Duration `json:"average_write_time"`
	AverageQueryTime    time.Duration `json:"average_query_time"`
	ThroughputPerSecond float64       `json:"throughput_per_second"`
	QueueDepth          int           `json:"queue_depth"`
	CacheHitRate        float64       `json:"cache_hit_rate"`
	IndexEfficiency     float64       `json:"index_efficiency"`
}

// HealthError represents a health check error
type HealthError struct {
	Component   string    `json:"component"`
	Error       string    `json:"error"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
	Recoverable bool      `json:"recoverable"`
}

// HealthWarning represents a health check warning
type HealthWarning struct {
	Component  string    `json:"component"`
	Warning    string    `json:"warning"`
	Timestamp  time.Time `json:"timestamp"`
	Actionable bool      `json:"actionable"`
}

// NewAuditSystem creates a new audit system instance
func NewAuditSystem(db *sql.DB, config *AuditConfig) (AuditSystem, error) {
	if config == nil {
		config = DefaultAuditConfig()
	}

	system := &auditSystem{
		db:              db,
		config:          config,
		retentionPolicy: DefaultRetentionPolicy(),
		indexManager:    NewIndexManager(db),
		compressionMgr:  NewCompressionManager(config.CompressionEnabled),
		statsCache:      make(map[string]*CachedStatistics),
		statsCacheTTL:   config.CacheTTL,
	}

	// Initialize database schema
	if err := system.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize audit schema: %w", err)
	}

	// Create default indexes
	if config.IndexingEnabled {
		if err := system.createDefaultIndexes(); err != nil {
			return nil, fmt.Errorf("failed to create default indexes: %w", err)
		}
	}

	return system, nil
}

// LogAdminAction logs an administrative action
func (as *auditSystem) LogAdminAction(action AdminAction) error {
	entry := AuditEntry{
		ID:           uuid.New().String(),
		EventType:    EventTypeAdminAction,
		Category:     action.Category,
		Action:       action.Type,
		Resource:     action.Resource,
		ResourceID:   action.ResourceID,
		UserID:       action.UserID,
		SessionID:    action.Context.SessionID,
		AdminLevel:   action.AdminLevel,
		IPAddress:    action.Context.IPAddress,
		UserAgent:    action.Context.UserAgent,
		RequestID:    action.Context.RequestID,
		Description:  action.Description,
		Success:      action.Success,
		ErrorMessage: action.Error,
		Severity:     as.calculateSeverity(action),
		RiskLevel:    action.RiskLevel,
		Timestamp:    action.Timestamp,
		Duration:     action.Duration,
	}

	// Set details from action parameters
	if err := entry.SetDetails(action.Parameters); err != nil {
		return fmt.Errorf("failed to set action details: %w", err)
	}

	// Add metadata from context
	entry.Metadata = action.Context.Metadata

	// Add compliance flags based on action type
	as.addComplianceFlags(&entry, action)

	// Set retention date based on policy
	as.setRetentionDate(&entry)

	return as.createAuditEntry(entry)
}

// LogSecurityEvent logs a security event
func (as *auditSystem) LogSecurityEvent(event SecurityEvent) error {
	entry := AuditEntry{
		ID:          uuid.New().String(),
		EventType:   EventTypeSecurityEvent,
		Category:    event.Category,
		Action:      event.Type,
		Resource:    event.Resource,
		UserID:      event.UserID,
		SessionID:   event.Context.SessionID,
		IPAddress:   event.Context.IPAddress,
		UserAgent:   event.Context.UserAgent,
		RequestID:   event.Context.RequestID,
		Description: event.Description,
		Success:     !event.Resolved, // Security events are "successful" if not resolved
		Severity:    event.Severity,
		RiskLevel:   event.RiskLevel,
		Timestamp:   event.Timestamp,
	}

	// Set details from event
	eventDetails := map[string]interface{}{
		"title":      event.Title,
		"indicators": event.Indicators,
		"resolved":   event.Resolved,
		"resolution": event.Resolution,
	}
	if err := entry.SetDetails(eventDetails); err != nil {
		return fmt.Errorf("failed to set event details: %w", err)
	}

	// Add metadata from context
	entry.Metadata = event.Context.Metadata

	// Add security-specific compliance flags
	entry.SetComplianceFlag("SECURITY_EVENT")
	if event.Severity == SeverityCritical {
		entry.SetComplianceFlag("CRITICAL_SECURITY")
	}

	// Set retention date based on policy
	as.setRetentionDate(&entry)

	return as.createAuditEntry(entry)
}

// LogDataAccess logs a data access event
func (as *auditSystem) LogDataAccess(access DataAccessEvent) error {
	entry := AuditEntry{
		ID:           uuid.New().String(),
		EventType:    EventTypeDataAccess,
		Category:     "DATA_ACCESS",
		Action:       access.Action,
		Resource:     access.Resource,
		ResourceID:   access.RecordID,
		UserID:       access.UserID,
		SessionID:    access.Context.SessionID,
		IPAddress:    access.Context.IPAddress,
		UserAgent:    access.Context.UserAgent,
		RequestID:    access.Context.RequestID,
		Description:  fmt.Sprintf("Data access: %s on %s", access.Action, access.Resource),
		Success:      access.Success,
		ErrorMessage: access.Error,
		Severity:     as.calculateDataAccessSeverity(access),
		RiskLevel:    as.calculateDataAccessRisk(access),
		Timestamp:    access.Timestamp,
		Duration:     access.Duration,
	}

	// Set details from access event
	accessDetails := map[string]interface{}{
		"resource_type":   access.ResourceType,
		"table_name":      access.TableName,
		"fields_accessed": access.FieldsAccessed,
		"query":           access.Query,
		"rows_affected":   access.RowsAffected,
		"data_size":       access.DataSize,
		"pii_accessed":    access.PIIAccessed,
		"authorized":      access.Authorized,
	}
	if err := entry.SetDetails(accessDetails); err != nil {
		return fmt.Errorf("failed to set access details: %w", err)
	}

	// Add metadata from context
	entry.Metadata = access.Context.Metadata

	// Add compliance flags for data access
	entry.SetComplianceFlag("DATA_ACCESS")
	if access.PIIAccessed {
		entry.SetComplianceFlag("PII_ACCESS")
		entry.SetComplianceFlag("GDPR_RELEVANT")
	}
	if !access.Authorized {
		entry.SetComplianceFlag("UNAUTHORIZED_ACCESS")
	}

	// Set retention date based on policy
	as.setRetentionDate(&entry)

	return as.createAuditEntry(entry)
}

// LogSystemChange logs a system configuration change
func (as *auditSystem) LogSystemChange(change SystemChangeEvent) error {
	entry := AuditEntry{
		ID:           uuid.New().String(),
		EventType:    EventTypeSystemChange,
		Category:     change.ChangeType,
		Action:       change.Action,
		Resource:     change.Resource,
		UserID:       change.UserID,
		SessionID:    change.Context.SessionID,
		IPAddress:    change.Context.IPAddress,
		UserAgent:    change.Context.UserAgent,
		RequestID:    change.Context.RequestID,
		Description:  fmt.Sprintf("System change: %s %s", change.Action, change.Component),
		Success:      change.Success,
		ErrorMessage: change.Error,
		Severity:     as.calculateSystemChangeSeverity(change),
		RiskLevel:    change.RiskLevel,
		Timestamp:    change.Timestamp,
	}

	// Set details from change event
	changeDetails := map[string]interface{}{
		"component":        change.Component,
		"old_value":        change.OldValue,
		"new_value":        change.NewValue,
		"changes":          change.Changes,
		"requires_restart": change.RequiresRestart,
		"reversible":       change.Reversible,
	}
	if err := entry.SetDetails(changeDetails); err != nil {
		return fmt.Errorf("failed to set change details: %w", err)
	}

	// Add metadata from context
	entry.Metadata = change.Context.Metadata

	// Add compliance flags for system changes
	entry.SetComplianceFlag("SYSTEM_CHANGE")
	if change.RiskLevel == RiskLevelHigh || change.RiskLevel == RiskLevelCritical {
		entry.SetComplianceFlag("HIGH_RISK_CHANGE")
	}

	// Set retention date based on policy
	as.setRetentionDate(&entry)

	return as.createAuditEntry(entry)
}

// QueryAuditLogs queries audit logs with filtering
func (as *auditSystem) QueryAuditLogs(filter AuditFilter) ([]AuditEntry, error) {
	as.mutex.RLock()
	defer as.mutex.RUnlock()

	query, args := as.buildAuditQuery(filter)

	rows, err := as.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var entry AuditEntry
		var detailsJSON, metadataJSON, complianceFlagsJSON, tagsJSON string
		var durationNs sql.NullInt64
		var retentionDate sql.NullTime

		err := rows.Scan(
			&entry.ID, &entry.EventType, &entry.Category, &entry.Action,
			&entry.Resource, &entry.ResourceID, &entry.UserID, &entry.SessionID,
			&entry.AdminLevel, &entry.IPAddress, &entry.UserAgent, &entry.RequestID,
			&entry.Description, &detailsJSON, &metadataJSON, &entry.Success,
			&entry.ErrorCode, &entry.ErrorMessage, &entry.Severity, &entry.RiskLevel,
			&entry.Timestamp, &durationNs, &retentionDate, &complianceFlagsJSON,
			&tagsJSON, &entry.SearchText,
		)
		if err != nil {
			continue // Skip invalid entries
		}

		// Parse JSON fields
		if detailsJSON != "" {
			json.Unmarshal([]byte(detailsJSON), &entry.Details)
		}
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &entry.Metadata)
		}
		if complianceFlagsJSON != "" {
			json.Unmarshal([]byte(complianceFlagsJSON), &entry.ComplianceFlags)
		}
		if tagsJSON != "" {
			json.Unmarshal([]byte(tagsJSON), &entry.Tags)
		}

		// Handle nullable fields
		if durationNs.Valid {
			entry.Duration = time.Duration(durationNs.Int64)
		}
		if retentionDate.Valid {
			entry.RetentionDate = &retentionDate.Time
		}

		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// Helper methods

func (as *auditSystem) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_entries (
		id TEXT PRIMARY KEY,
		event_type TEXT NOT NULL,
		category TEXT NOT NULL,
		action TEXT NOT NULL,
		resource TEXT NOT NULL,
		resource_id TEXT,
		user_id TEXT NOT NULL,
		session_id TEXT,
		admin_level TEXT,
		ip_address TEXT NOT NULL,
		user_agent TEXT,
		request_id TEXT,
		description TEXT NOT NULL,
		details TEXT,
		metadata TEXT,
		success BOOLEAN NOT NULL,
		error_code TEXT,
		error_message TEXT,
		severity TEXT NOT NULL,
		risk_level TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		duration BIGINT,
		retention_date DATETIME,
		compliance_flags TEXT,
		tags TEXT,
		search_text TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS audit_retention_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		default_period BIGINT NOT NULL,
		category_policies TEXT,
		severity_policies TEXT,
		compliance_policies TEXT,
		archive_after BIGINT,
		purge_after BIGINT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT
	);

	CREATE TABLE IF NOT EXISTS audit_statistics_cache (
		cache_key TEXT PRIMARY KEY,
		data TEXT NOT NULL,
		cached_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL
	);`

	_, err := as.db.Exec(schema)
	return err
}

func (as *auditSystem) createDefaultIndexes() error {
	indexes := []IndexConfig{
		{
			Name:    "idx_audit_timestamp",
			Table:   "audit_entries",
			Columns: []string{"timestamp"},
			Type:    "btree",
		},
		{
			Name:    "idx_audit_user_id",
			Table:   "audit_entries",
			Columns: []string{"user_id"},
			Type:    "btree",
		},
		{
			Name:    "idx_audit_event_type",
			Table:   "audit_entries",
			Columns: []string{"event_type"},
			Type:    "btree",
		},
		{
			Name:    "idx_audit_severity",
			Table:   "audit_entries",
			Columns: []string{"severity"},
			Type:    "btree",
		},
		{
			Name:    "idx_audit_resource",
			Table:   "audit_entries",
			Columns: []string{"resource"},
			Type:    "btree",
		},
		{
			Name:    "idx_audit_search",
			Table:   "audit_entries",
			Columns: []string{"search_text"},
			Type:    "gin",
		},
	}

	for _, idx := range indexes {
		if err := as.indexManager.CreateIndex(idx); err != nil {
			return fmt.Errorf("failed to create index %s: %w", idx.Name, err)
		}
	}

	return nil
}

func (as *auditSystem) createAuditEntry(entry AuditEntry) error {
	// Generate search text for full-text search
	entry.SearchText = as.generateSearchText(entry)

	// Serialize JSON fields
	detailsJSON, _ := json.Marshal(entry.Details)
	metadataJSON, _ := json.Marshal(entry.Metadata)
	complianceFlagsJSON, _ := json.Marshal(entry.ComplianceFlags)
	tagsJSON, _ := json.Marshal(entry.Tags)

	query := `
		INSERT INTO audit_entries (
			id, event_type, category, action, resource, resource_id,
			user_id, session_id, admin_level, ip_address, user_agent,
			request_id, description, details, metadata, success,
			error_code, error_message, severity, risk_level, timestamp,
			duration, retention_date, compliance_flags, tags, search_text
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var durationNs sql.NullInt64
	if entry.Duration > 0 {
		durationNs.Valid = true
		durationNs.Int64 = int64(entry.Duration)
	}

	var retentionDate sql.NullTime
	if entry.RetentionDate != nil {
		retentionDate.Valid = true
		retentionDate.Time = *entry.RetentionDate
	}

	_, err := as.db.Exec(query,
		entry.ID, entry.EventType, entry.Category, entry.Action,
		entry.Resource, entry.ResourceID, entry.UserID, entry.SessionID,
		entry.AdminLevel, entry.IPAddress, entry.UserAgent, entry.RequestID,
		entry.Description, string(detailsJSON), string(metadataJSON),
		entry.Success, entry.ErrorCode, entry.ErrorMessage, entry.Severity,
		entry.RiskLevel, entry.Timestamp, durationNs, retentionDate,
		string(complianceFlagsJSON), string(tagsJSON), entry.SearchText,
	)

	return err
}

func (as *auditSystem) buildAuditQuery(filter AuditFilter) (string, []interface{}) {
	query := "SELECT * FROM audit_entries WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	// Time range filtering
	if filter.StartTime != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, *filter.StartTime)
		argIndex++
	}
	if filter.EndTime != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, *filter.EndTime)
		argIndex++
	}

	// Event type filtering
	if len(filter.EventTypes) > 0 {
		placeholders := make([]string, len(filter.EventTypes))
		for i, eventType := range filter.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, eventType)
			argIndex++
		}
		query += fmt.Sprintf(" AND event_type IN (%s)", strings.Join(placeholders, ","))
	}

	// User filtering
	if len(filter.UserIDs) > 0 {
		placeholders := make([]string, len(filter.UserIDs))
		for i, userID := range filter.UserIDs {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, userID)
			argIndex++
		}
		query += fmt.Sprintf(" AND user_id IN (%s)", strings.Join(placeholders, ","))
	}

	// Success filtering
	if filter.Success != nil {
		query += fmt.Sprintf(" AND success = $%d", argIndex)
		args = append(args, *filter.Success)
		argIndex++
	}

	// Severity filtering
	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, severity := range filter.Severities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, severity)
			argIndex++
		}
		query += fmt.Sprintf(" AND severity IN (%s)", strings.Join(placeholders, ","))
	}

	// Search text filtering
	if filter.SearchText != "" {
		query += fmt.Sprintf(" AND search_text LIKE $%d", argIndex)
		args = append(args, "%"+filter.SearchText+"%")
		argIndex++
	}

	// Sorting
	if filter.SortBy != "" {
		order := "ASC"
		if filter.SortOrder == "desc" {
			order = "DESC"
		}
		query += fmt.Sprintf(" ORDER BY %s %s", filter.SortBy, order)
	} else {
		query += " ORDER BY timestamp DESC"
	}

	// Pagination
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
		argIndex++
	}

	return query, args
}

func (as *auditSystem) generateSearchText(entry AuditEntry) string {
	var parts []string

	parts = append(parts, entry.Description)
	parts = append(parts, entry.Action)
	parts = append(parts, entry.Resource)
	parts = append(parts, entry.Category)

	if entry.ErrorMessage != "" {
		parts = append(parts, entry.ErrorMessage)
	}

	// Add details as searchable text
	if entry.Details != nil {
		for key, value := range entry.Details {
			parts = append(parts, fmt.Sprintf("%s:%v", key, value))
		}
	}

	return strings.Join(parts, " ")
}

// Severity calculation methods
func (as *auditSystem) calculateSeverity(action AdminAction) SecuritySeverity {
	// High-risk actions get higher severity
	highRiskActions := []string{
		"DELETE_USER", "DELETE_TABLE", "EXECUTE_SQL", "MODIFY_PERMISSIONS",
		"CREATE_ADMIN", "DELETE_ADMIN", "MODIFY_SYSTEM_CONFIG",
	}

	for _, riskAction := range highRiskActions {
		if action.Type == riskAction {
			return SeverityHigh
		}
	}

	if !action.Success {
		return SeverityMedium
	}

	return SeverityLow
}

func (as *auditSystem) calculateDataAccessSeverity(access DataAccessEvent) SecuritySeverity {
	if access.PIIAccessed {
		return SeverityHigh
	}
	if !access.Authorized {
		return SeverityCritical
	}
	if !access.Success {
		return SeverityMedium
	}
	return SeverityLow
}

func (as *auditSystem) calculateDataAccessRisk(access DataAccessEvent) RiskLevel {
	if !access.Authorized {
		return RiskLevelCritical
	}
	if access.PIIAccessed && access.Action == "EXPORT" {
		return RiskLevelHigh
	}
	if access.PIIAccessed {
		return RiskLevelMedium
	}
	return RiskLevelLow
}

func (as *auditSystem) calculateSystemChangeSeverity(change SystemChangeEvent) SecuritySeverity {
	if change.RiskLevel == RiskLevelCritical {
		return SeverityCritical
	}
	if change.RiskLevel == RiskLevelHigh {
		return SeverityHigh
	}
	if !change.Success {
		return SeverityMedium
	}
	return SeverityLow
}

func (as *auditSystem) addComplianceFlags(entry *AuditEntry, action AdminAction) {
	// Add compliance flags based on action type
	adminActions := []string{"CREATE_ADMIN", "DELETE_ADMIN", "MODIFY_PERMISSIONS"}
	for _, adminAction := range adminActions {
		if action.Type == adminAction {
			entry.SetComplianceFlag("ADMIN_MANAGEMENT")
			break
		}
	}

	if action.Type == "EXECUTE_SQL" {
		entry.SetComplianceFlag("SQL_EXECUTION")
	}

	if action.RiskLevel == RiskLevelHigh || action.RiskLevel == RiskLevelCritical {
		entry.SetComplianceFlag("HIGH_RISK_ACTION")
	}
}

func (as *auditSystem) setRetentionDate(entry *AuditEntry) {
	retention := as.retentionPolicy.DefaultPeriod

	// Check for category-specific retention
	if categoryRetention, exists := as.retentionPolicy.CategoryPolicies[entry.EventType]; exists {
		retention = categoryRetention
	}

	// Check for severity-specific retention
	if severityRetention, exists := as.retentionPolicy.SeverityPolicies[entry.Severity]; exists {
		if severityRetention > retention {
			retention = severityRetention
		}
	}

	retentionDate := entry.Timestamp.Add(retention)
	entry.RetentionDate = &retentionDate
}

// Default configuration functions
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		MaxLogSize:         100 * 1024 * 1024, // 100MB
		CompressionEnabled: true,
		EncryptionEnabled:  false,
		BatchSize:          1000,
		FlushInterval:      5 * time.Second,
		IndexingEnabled:    true,
		CacheEnabled:       true,
		CacheTTL:           5 * time.Minute,
		DefaultRetention:   365 * 24 * time.Hour, // 1 year
		ArchiveEnabled:     true,
		ArchiveLocation:    "/var/audit/archive",
		IntegrityChecks:    true,
		TamperDetection:    true,
		AccessLogging:      true,
		EventCategories: map[EventType]CategoryConfig{
			EventTypeSecurityEvent: {
				Retention:       2 * 365 * 24 * time.Hour, // 2 years
				Severity:        SeverityHigh,
				RequireApproval: false,
				Encryption:      true,
				Compression:     true,
			},
			EventTypeAdminAction: {
				Retention:       365 * 24 * time.Hour, // 1 year
				Severity:        SeverityMedium,
				RequireApproval: false,
				Encryption:      false,
				Compression:     true,
			},
		},
	}
}

func DefaultRetentionPolicy() *RetentionPolicy {
	return &RetentionPolicy{
		ID:            uuid.New().String(),
		Name:          "Default Retention Policy",
		Description:   "Default audit log retention policy",
		DefaultPeriod: 365 * 24 * time.Hour, // 1 year
		CategoryPolicies: map[EventType]time.Duration{
			EventTypeSecurityEvent: 2 * 365 * 24 * time.Hour, // 2 years
			EventTypeAdminAction:   365 * 24 * time.Hour,     // 1 year
			EventTypeDataAccess:    90 * 24 * time.Hour,      // 90 days
			EventTypeSystemChange:  2 * 365 * 24 * time.Hour, // 2 years
		},
		SeverityPolicies: map[SecuritySeverity]time.Duration{
			SeverityCritical: 3 * 365 * 24 * time.Hour, // 3 years
			SeverityHigh:     2 * 365 * 24 * time.Hour, // 2 years
			SeverityMedium:   365 * 24 * time.Hour,     // 1 year
			SeverityLow:      90 * 24 * time.Hour,      // 90 days
		},
		CompliancePolicies: map[string]time.Duration{
			"SOX":     7 * 365 * 24 * time.Hour, // 7 years
			"GDPR":    6 * 365 * 24 * time.Hour, // 6 years
			"HIPAA":   6 * 365 * 24 * time.Hour, // 6 years
			"PCI_DSS": 365 * 24 * time.Hour,     // 1 year
		},
		ArchiveAfter: 365 * 24 * time.Hour,     // 1 year
		PurgeAfter:   7 * 365 * 24 * time.Hour, // 7 years
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// Additional methods will be implemented in separate files for better organization
