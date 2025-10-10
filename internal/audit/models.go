package audit

import (
	"encoding/json"
	"time"
)

// Core audit event types
type EventType string

const (
	EventTypeAdminAction    EventType = "ADMIN_ACTION"
	EventTypeSecurityEvent  EventType = "SECURITY_EVENT"
	EventTypeDataAccess     EventType = "DATA_ACCESS"
	EventTypeSystemChange   EventType = "SYSTEM_CHANGE"
	EventTypeAuthentication EventType = "AUTHENTICATION"
	EventTypeAuthorization  EventType = "AUTHORIZATION"
	EventTypeConfiguration  EventType = "CONFIGURATION"
	EventTypeUserManagement EventType = "USER_MANAGEMENT"
)

// Security severity levels
type SecuritySeverity string

const (
	SeverityLow      SecuritySeverity = "LOW"
	SeverityMedium   SecuritySeverity = "MEDIUM"
	SeverityHigh     SecuritySeverity = "HIGH"
	SeverityCritical SecuritySeverity = "CRITICAL"
)

// Risk levels for actions and events
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "LOW"
	RiskLevelMedium   RiskLevel = "MEDIUM"
	RiskLevelHigh     RiskLevel = "HIGH"
	RiskLevelCritical RiskLevel = "CRITICAL"
)

// Alert types
type AlertType string

const (
	AlertTypeHighQueryVolume     AlertType = "HIGH_QUERY_VOLUME"
	AlertTypeDangerousOperation  AlertType = "DANGEROUS_OPERATION"
	AlertTypeSecurityViolation   AlertType = "SECURITY_VIOLATION"
	AlertTypePerformanceIssue    AlertType = "PERFORMANCE_ISSUE"
	AlertTypeSuspiciousActivity  AlertType = "SUSPICIOUS_ACTIVITY"
	AlertTypeAnomalyDetected     AlertType = "ANOMALY_DETECTED"
	AlertTypeComplianceViolation AlertType = "COMPLIANCE_VIOLATION"
)

// Alert status
type AlertStatus string

const (
	AlertStatusActive       AlertStatus = "ACTIVE"
	AlertStatusAcknowledged AlertStatus = "ACKNOWLEDGED"
	AlertStatusResolved     AlertStatus = "RESOLVED"
	AlertStatusExpired      AlertStatus = "EXPIRED"
)

// SecurityNotification represents a security notification
type SecurityNotification struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	Recipients []string               `json:"recipients"`
	Channel    string                 `json:"channel"`
	Priority   string                 `json:"priority"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID         string    `json:"id" db:"id"`
	EventType  EventType `json:"event_type" db:"event_type"`
	Category   string    `json:"category" db:"category"`
	Action     string    `json:"action" db:"action"`
	Resource   string    `json:"resource" db:"resource"`
	ResourceID string    `json:"resource_id,omitempty" db:"resource_id"`

	// User and session information
	UserID     string `json:"user_id" db:"user_id"`
	SessionID  string `json:"session_id,omitempty" db:"session_id"`
	AdminLevel string `json:"admin_level,omitempty" db:"admin_level"`

	// Request context
	IPAddress string `json:"ip_address" db:"ip_address"`
	UserAgent string `json:"user_agent" db:"user_agent"`
	RequestID string `json:"request_id,omitempty" db:"request_id"`

	// Event details
	Description string                 `json:"description" db:"description"`
	Details     map[string]interface{} `json:"details" db:"details"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Outcome and impact
	Success      bool   `json:"success" db:"success"`
	ErrorCode    string `json:"error_code,omitempty" db:"error_code"`
	ErrorMessage string `json:"error_message,omitempty" db:"error_message"`

	// Security classification
	Severity  SecuritySeverity `json:"severity" db:"severity"`
	RiskLevel RiskLevel        `json:"risk_level" db:"risk_level"`

	// Timing
	Timestamp time.Time     `json:"timestamp" db:"timestamp"`
	Duration  time.Duration `json:"duration,omitempty" db:"duration"`

	// Compliance and retention
	RetentionDate   *time.Time `json:"retention_date,omitempty" db:"retention_date"`
	ComplianceFlags []string   `json:"compliance_flags,omitempty" db:"compliance_flags"`

	// Indexing and search
	Tags       []string `json:"tags,omitempty" db:"tags"`
	SearchText string   `json:"search_text,omitempty" db:"search_text"`
}

// AdminAction represents an administrative action
type AdminAction struct {
	ActionID    string                 `json:"action_id"`
	Type        string                 `json:"type"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id"`
	AdminLevel  string                 `json:"admin_level"`
	Resource    string                 `json:"resource"`
	ResourceID  string                 `json:"resource_id,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Context     ActionContext          `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	RiskLevel   RiskLevel              `json:"risk_level"`
}

// ActionContext provides context for admin actions
type ActionContext struct {
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	SessionID     string                 `json:"session_id"`
	RequestID     string                 `json:"request_id"`
	MFAVerified   bool                   `json:"mfa_verified"`
	APIKey        string                 `json:"api_key,omitempty"`
	Environment   string                 `json:"environment"`
	ClientVersion string                 `json:"client_version,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	EventID     string               `json:"event_id"`
	Type        string               `json:"type"`
	Category    string               `json:"category"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	UserID      string               `json:"user_id,omitempty"`
	Resource    string               `json:"resource,omitempty"`
	Action      string               `json:"action,omitempty"`
	Severity    SecuritySeverity     `json:"severity"`
	RiskLevel   RiskLevel            `json:"risk_level"`
	Context     SecurityEventContext `json:"context"`
	Indicators  []ThreatIndicator    `json:"indicators,omitempty"`
	Timestamp   time.Time            `json:"timestamp"`
	Resolved    bool                 `json:"resolved"`
	Resolution  string               `json:"resolution,omitempty"`
}

// SecurityEventContext provides context for security events
type SecurityEventContext struct {
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	SessionID     string                 `json:"session_id"`
	RequestID     string                 `json:"request_id"`
	Geolocation   *GeolocationInfo       `json:"geolocation,omitempty"`
	DeviceInfo    *DeviceInfo            `json:"device_info,omitempty"`
	NetworkInfo   *NetworkInfo           `json:"network_info,omitempty"`
	AttackVectors []string               `json:"attack_vectors,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// DataAccessEvent represents data access events
type DataAccessEvent struct {
	EventID        string            `json:"event_id"`
	UserID         string            `json:"user_id"`
	Action         string            `json:"action"` // READ, WRITE, DELETE, EXPORT
	Resource       string            `json:"resource"`
	ResourceType   string            `json:"resource_type"`
	TableName      string            `json:"table_name,omitempty"`
	RecordID       string            `json:"record_id,omitempty"`
	FieldsAccessed []string          `json:"fields_accessed,omitempty"`
	Query          string            `json:"query,omitempty"`
	RowsAffected   int64             `json:"rows_affected,omitempty"`
	DataSize       int64             `json:"data_size,omitempty"`
	Context        DataAccessContext `json:"context"`
	Timestamp      time.Time         `json:"timestamp"`
	Duration       time.Duration     `json:"duration,omitempty"`
	Success        bool              `json:"success"`
	Error          string            `json:"error,omitempty"`
	PIIAccessed    bool              `json:"pii_accessed"`
	Authorized     bool              `json:"authorized"`
}

// DataAccessContext provides context for data access events
type DataAccessContext struct {
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	SessionID   string                 `json:"session_id"`
	RequestID   string                 `json:"request_id"`
	APIEndpoint string                 `json:"api_endpoint,omitempty"`
	HTTPMethod  string                 `json:"http_method,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	LegalBasis  string                 `json:"legal_basis,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SystemChangeEvent represents system configuration changes
type SystemChangeEvent struct {
	EventID         string              `json:"event_id"`
	UserID          string              `json:"user_id"`
	ChangeType      string              `json:"change_type"`
	Component       string              `json:"component"`
	Resource        string              `json:"resource"`
	Action          string              `json:"action"`
	OldValue        interface{}         `json:"old_value,omitempty"`
	NewValue        interface{}         `json:"new_value,omitempty"`
	Changes         []FieldChange       `json:"changes,omitempty"`
	Context         SystemChangeContext `json:"context"`
	Timestamp       time.Time           `json:"timestamp"`
	Success         bool                `json:"success"`
	Error           string              `json:"error,omitempty"`
	RiskLevel       RiskLevel           `json:"risk_level"`
	RequiresRestart bool                `json:"requires_restart"`
	Reversible      bool                `json:"reversible"`
}

// FieldChange represents a change to a specific field
type FieldChange struct {
	Field    string      `json:"field"`
	OldValue interface{} `json:"old_value"`
	NewValue interface{} `json:"new_value"`
	Type     string      `json:"type"`
}

// SystemChangeContext provides context for system changes
type SystemChangeContext struct {
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	SessionID    string                 `json:"session_id"`
	RequestID    string                 `json:"request_id"`
	ChangeReason string                 `json:"change_reason,omitempty"`
	ApprovalID   string                 `json:"approval_id,omitempty"`
	Environment  string                 `json:"environment"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Supporting types for security monitoring

// SecurityAnomaly represents detected anomalous behavior
type SecurityAnomaly struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	UserID      string                 `json:"user_id"`
	Severity    SecuritySeverity       `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Evidence    []AnomalyEvidence      `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AnomalyEvidence provides evidence for detected anomalies
type AnomalyEvidence struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Threshold   interface{} `json:"threshold,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// BehaviorAnalysis represents user behavior analysis results
type BehaviorAnalysis struct {
	UserID          string              `json:"user_id"`
	AnalysisPeriod  TimePeriod          `json:"analysis_period"`
	BaselineProfile UserBehaviorProfile `json:"baseline_profile"`
	CurrentProfile  UserBehaviorProfile `json:"current_profile"`
	Deviations      []BehaviorDeviation `json:"deviations"`
	RiskScore       float64             `json:"risk_score"`
	Recommendations []string            `json:"recommendations"`
	Timestamp       time.Time           `json:"timestamp"`
}

// UserBehaviorProfile represents a user's behavior profile
type UserBehaviorProfile struct {
	LoginPatterns    LoginPattern           `json:"login_patterns"`
	ActivityPatterns ActivityPattern        `json:"activity_patterns"`
	AccessPatterns   AccessPattern          `json:"access_patterns"`
	GeographicInfo   GeographicPattern      `json:"geographic_info"`
	DeviceInfo       DevicePattern          `json:"device_info"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// Pattern types for behavior analysis
type LoginPattern struct {
	TypicalHours     []int         `json:"typical_hours"`
	TypicalDays      []string      `json:"typical_days"`
	AverageFrequency float64       `json:"average_frequency"`
	SessionDuration  time.Duration `json:"session_duration"`
}

type ActivityPattern struct {
	CommonActions   []string           `json:"common_actions"`
	ActionFrequency map[string]float64 `json:"action_frequency"`
	PeakHours       []int              `json:"peak_hours"`
	ActivityVolume  float64            `json:"activity_volume"`
}

type AccessPattern struct {
	CommonResources []string           `json:"common_resources"`
	AccessMethods   map[string]float64 `json:"access_methods"`
	DataVolume      float64            `json:"data_volume"`
	QueryComplexity float64            `json:"query_complexity"`
}

type GeographicPattern struct {
	CommonLocations []string `json:"common_locations"`
	CountryCodes    []string `json:"country_codes"`
	TimeZones       []string `json:"time_zones"`
	TravelPatterns  []string `json:"travel_patterns"`
}

type DevicePattern struct {
	CommonDevices    []string           `json:"common_devices"`
	OperatingSystems map[string]float64 `json:"operating_systems"`
	Browsers         map[string]float64 `json:"browsers"`
	NetworkTypes     []string           `json:"network_types"`
}

// BehaviorDeviation represents a deviation from normal behavior
type BehaviorDeviation struct {
	Type        string           `json:"type"`
	Description string           `json:"description"`
	Severity    SecuritySeverity `json:"severity"`
	Confidence  float64          `json:"confidence"`
	Expected    interface{}      `json:"expected"`
	Actual      interface{}      `json:"actual"`
	Timestamp   time.Time        `json:"timestamp"`
}

// SuspiciousPattern represents detected suspicious patterns
type SuspiciousPattern struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Pattern     string                 `json:"pattern"`
	Confidence  float64                `json:"confidence"`
	Events      []SecurityEvent        `json:"events"`
	Indicators  []ThreatIndicator      `json:"indicators"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ThreatIndicator represents indicators of potential threats
type ThreatIndicator struct {
	Type        string    `json:"type"`
	Value       string    `json:"value"`
	Confidence  float64   `json:"confidence"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// UserRiskProfile represents a user's risk profile
type UserRiskProfile struct {
	UserID         string                 `json:"user_id"`
	OverallRisk    float64                `json:"overall_risk"`
	RiskFactors    []RiskFactor           `json:"risk_factors"`
	RecentActivity []AdminAction          `json:"recent_activity"`
	SecurityEvents []SecurityEvent        `json:"security_events"`
	LastUpdated    time.Time              `json:"last_updated"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// RiskFactor represents individual risk factors
type RiskFactor struct {
	Type        string    `json:"type"`
	Description string    `json:"description"`
	Score       float64   `json:"score"`
	Weight      float64   `json:"weight"`
	Evidence    []string  `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// Supporting information types
type GeolocationInfo struct {
	Country      string  `json:"country"`
	Region       string  `json:"region"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ISP          string  `json:"isp"`
	Organization string  `json:"organization"`
}

type DeviceInfo struct {
	DeviceType     string `json:"device_type"`
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browser_version"`
	DeviceID       string `json:"device_id,omitempty"`
}

type NetworkInfo struct {
	IPAddress   string `json:"ip_address"`
	ISP         string `json:"isp"`
	ASN         string `json:"asn"`
	NetworkType string `json:"network_type"`
	VPN         bool   `json:"vpn"`
	Proxy       bool   `json:"proxy"`
	TOR         bool   `json:"tor"`
}

// Filter and query types
type AuditFilter struct {
	// Time range
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// Event filtering
	EventTypes []EventType `json:"event_types,omitempty"`
	Categories []string    `json:"categories,omitempty"`
	Actions    []string    `json:"actions,omitempty"`

	// User and session filtering
	UserIDs     []string `json:"user_ids,omitempty"`
	AdminLevels []string `json:"admin_levels,omitempty"`
	SessionIDs  []string `json:"session_ids,omitempty"`

	// Resource filtering
	Resources   []string `json:"resources,omitempty"`
	ResourceIDs []string `json:"resource_ids,omitempty"`

	// Context filtering
	IPAddresses []string `json:"ip_addresses,omitempty"`
	UserAgents  []string `json:"user_agents,omitempty"`

	// Outcome filtering
	Success    *bool              `json:"success,omitempty"`
	Severities []SecuritySeverity `json:"severities,omitempty"`
	RiskLevels []RiskLevel        `json:"risk_levels,omitempty"`

	// Search and tags
	SearchText string   `json:"search_text,omitempty"`
	Tags       []string `json:"tags,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Sorting
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

// TimePeriod represents a time period for reports
type TimePeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Label string    `json:"label,omitempty"`
}

// Dashboard-related types
type DashboardConfig struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Layout      string                 `json:"layout"`
	Widgets     []DashboardWidget      `json:"widgets"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type Dashboard struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Layout      string            `json:"layout"`
	Widgets     []DashboardWidget `json:"widgets"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CreatedBy   string            `json:"created_by"`
}

type DashboardUpdates struct {
	Name        *string                `json:"name,omitempty"`
	Description *string                `json:"description,omitempty"`
	Layout      *string                `json:"layout,omitempty"`
	Widgets     []DashboardWidget      `json:"widgets,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type DashboardWidget struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"`
	Title    string                 `json:"title"`
	Config   map[string]interface{} `json:"config"`
	Position WidgetPosition         `json:"position"`
}

type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

type WidgetUpdates struct {
	Title    *string                `json:"title,omitempty"`
	Config   map[string]interface{} `json:"config,omitempty"`
	Position *WidgetPosition        `json:"position,omitempty"`
}

type RealTimeMetrics struct {
	Timestamp time.Time              `json:"timestamp"`
	Metrics   map[string]interface{} `json:"metrics"`
}

type MetricUpdate struct {
	MetricName string      `json:"metric_name"`
	Value      interface{} `json:"value"`
	Timestamp  time.Time   `json:"timestamp"`
}

type AlertConfiguration struct {
	Enabled  bool                   `json:"enabled"`
	Rules    []AlertRule            `json:"rules"`
	Channels []string               `json:"channels"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type AuditEntryUpdates struct {
	Description *string                `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// Utility methods for AuditEntry
func (ae *AuditEntry) SetDetails(details interface{}) error {
	if ae.Details == nil {
		ae.Details = make(map[string]interface{})
	}

	// Convert struct to map
	data, err := json.Marshal(details)
	if err != nil {
		return err
	}

	var detailsMap map[string]interface{}
	if err := json.Unmarshal(data, &detailsMap); err != nil {
		return err
	}

	for k, v := range detailsMap {
		ae.Details[k] = v
	}

	return nil
}

func (ae *AuditEntry) AddTag(tag string) {
	if ae.Tags == nil {
		ae.Tags = make([]string, 0)
	}

	// Check if tag already exists
	for _, existingTag := range ae.Tags {
		if existingTag == tag {
			return
		}
	}

	ae.Tags = append(ae.Tags, tag)
}

func (ae *AuditEntry) SetComplianceFlag(flag string) {
	if ae.ComplianceFlags == nil {
		ae.ComplianceFlags = make([]string, 0)
	}

	// Check if flag already exists
	for _, existingFlag := range ae.ComplianceFlags {
		if existingFlag == flag {
			return
		}
	}

	ae.ComplianceFlags = append(ae.ComplianceFlags, flag)
}
