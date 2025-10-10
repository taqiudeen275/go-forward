package audit

import (
	"io"
	"time"
)

// AuditSystem provides comprehensive audit logging and monitoring
type AuditSystem interface {
	// Audit logging
	LogAdminAction(action AdminAction) error
	LogSecurityEvent(event SecurityEvent) error
	LogDataAccess(access DataAccessEvent) error
	LogSystemChange(change SystemChangeEvent) error

	// Query and reporting
	QueryAuditLogs(filter AuditFilter) ([]AuditEntry, error)
	GenerateComplianceReport(period TimePeriod, format ReportFormat) (*ComplianceReport, error)
	ExportAuditLogs(filter AuditFilter, format ExportFormat) (io.Reader, error)

	// Configuration and management
	SetRetentionPolicy(policy RetentionPolicy) error
	GetRetentionPolicy() (*RetentionPolicy, error)
	ArchiveLogs(beforeDate time.Time) error
	PurgeLogs(beforeDate time.Time) error

	// Statistics and monitoring
	GetAuditStatistics(filter StatisticsFilter) (*AuditStatistics, error)
	GetSystemHealth() (*AuditSystemHealth, error)
}

// SecurityMonitor provides security event detection and analysis
type SecurityMonitor interface {
	// Anomaly detection
	DetectAnomalies(userID string, timeWindow time.Duration) ([]SecurityAnomaly, error)
	AnalyzeBehavior(userID string, actions []AdminAction) (*BehaviorAnalysis, error)

	// Pattern detection
	DetectSuspiciousPatterns(events []SecurityEvent) ([]SuspiciousPattern, error)
	CheckThreatIndicators(event SecurityEvent) ([]ThreatIndicator, error)

	// Risk assessment
	CalculateRiskScore(userID string, action AdminAction) (float64, error)
	GetUserRiskProfile(userID string) (*UserRiskProfile, error)

	// Real-time monitoring
	StartMonitoring() error
	StopMonitoring() error
	IsMonitoring() bool

	// Configuration
	SetDetectionRules(rules []DetectionRule) error
	GetDetectionRules() ([]DetectionRule, error)
	UpdateThresholds(thresholds SecurityThresholds) error
}

// AlertManager handles security alerts and notifications
type AlertManager interface {
	// Alert management
	CreateAlert(alert SecurityAlert) error
	ProcessAlert(alertID string) error
	AcknowledgeAlert(alertID string, acknowledgedBy string) error
	ResolveAlert(alertID string, resolvedBy string, resolution string) error

	// Alert querying
	GetActiveAlerts(filter AlertFilter) ([]SecurityAlert, error)
	GetAlertHistory(filter AlertFilter) ([]SecurityAlert, error)
	GetAlert(alertID string) (*SecurityAlert, error)

	// Alert rules and configuration
	ConfigureAlertRules(rules []AlertRule) error
	GetAlertRules() ([]AlertRule, error)
	UpdateAlertRule(ruleID string, updates AlertRuleUpdates) error
	DeleteAlertRule(ruleID string) error

	// Notification management
	SendNotification(notification SecurityNotification) error
	ConfigureNotificationChannels(channels []NotificationChannel) error
	GetNotificationChannels() ([]NotificationChannel, error)
	TestNotificationChannel(channelID string) error

	// Escalation
	ConfigureEscalationPolicies(policies []EscalationPolicy) error
	GetEscalationPolicies() ([]EscalationPolicy, error)
	TriggerEscalation(alertID string, level EscalationLevel) error
}

// ComplianceReporter generates compliance reports and audit trails
type ComplianceReporter interface {
	// Report generation
	GenerateSOC2Report(period TimePeriod) (*ComplianceReport, error)
	GenerateGDPRReport(period TimePeriod) (*ComplianceReport, error)
	GenerateHIPAAReport(period TimePeriod) (*ComplianceReport, error)
	GenerateCustomReport(template ReportTemplate, period TimePeriod) (*ComplianceReport, error)

	// Audit trail export
	ExportAuditTrail(filter AuditFilter, format ExportFormat) (io.Reader, error)
	ExportSecurityEvents(filter SecurityEventFilter, format ExportFormat) (io.Reader, error)

	// Compliance validation
	ValidateCompliance(standard ComplianceStandard, period TimePeriod) (*ComplianceValidation, error)
	GetComplianceGaps(standard ComplianceStandard) ([]ComplianceGap, error)

	// Report templates
	CreateReportTemplate(template ReportTemplate) error
	GetReportTemplates() ([]ReportTemplate, error)
	UpdateReportTemplate(templateID string, updates ReportTemplateUpdates) error
	DeleteReportTemplate(templateID string) error
}

// MonitoringDashboard provides real-time monitoring and visualization
type MonitoringDashboard interface {
	// Dashboard management
	CreateDashboard(config DashboardConfig) (*Dashboard, error)
	GetDashboard(dashboardID string) (*Dashboard, error)
	UpdateDashboard(dashboardID string, updates DashboardUpdates) error
	DeleteDashboard(dashboardID string) error

	// Widget management
	AddWidget(dashboardID string, widget DashboardWidget) error
	UpdateWidget(dashboardID string, widgetID string, updates WidgetUpdates) error
	RemoveWidget(dashboardID string, widgetID string) error

	// Real-time data
	GetRealTimeMetrics(dashboardID string) (*RealTimeMetrics, error)
	StreamMetrics(dashboardID string) (<-chan MetricUpdate, error)

	// Alerts integration
	GetDashboardAlerts(dashboardID string) ([]SecurityAlert, error)
	ConfigureDashboardAlerts(dashboardID string, alertConfig AlertConfiguration) error
}

// AuditRepository provides data access for audit logs
type AuditRepository interface {
	// CRUD operations
	CreateAuditEntry(entry AuditEntry) error
	GetAuditEntry(entryID string) (*AuditEntry, error)
	UpdateAuditEntry(entryID string, updates AuditEntryUpdates) error
	DeleteAuditEntry(entryID string) error

	// Batch operations
	CreateAuditEntries(entries []AuditEntry) error
	BulkUpdateAuditEntries(filter AuditFilter, updates AuditEntryUpdates) error
	BulkDeleteAuditEntries(filter AuditFilter) error

	// Querying
	QueryAuditEntries(filter AuditFilter) ([]AuditEntry, error)
	CountAuditEntries(filter AuditFilter) (int64, error)
	GetAuditEntriesByTimeRange(start, end time.Time) ([]AuditEntry, error)

	// Indexing and optimization
	CreateIndex(indexConfig IndexConfig) error
	OptimizeQueries() error
	GetQueryPerformance() (*QueryPerformanceStats, error)

	// Archival and retention
	ArchiveEntries(beforeDate time.Time, archiveLocation string) error
	PurgeEntries(beforeDate time.Time) error
	GetArchiveInfo() (*ArchiveInfo, error)
}
