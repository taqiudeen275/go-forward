# Audit and Monitoring System API Documentation

## Table of Contents
- [Core Interfaces](#core-interfaces)
- [Data Models](#data-models)
- [Audit System API](#audit-system-api)
- [Security Monitor API](#security-monitor-api)
- [Alert Manager API](#alert-manager-api)
- [Compliance Reporter API](#compliance-reporter-api)
- [Error Handling](#error-handling)
- [Examples](#examples)

## Core Interfaces

### AuditSystem Interface

The main interface for audit logging functionality.

```go
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
```

### SecurityMonitor Interface

Interface for security event detection and monitoring.

```go
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
```

### AlertManager Interface

Interface for alert management and notifications.

```go
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
```

### ComplianceReporter Interface

Interface for compliance reporting and validation.

```go
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
```

## Data Models

### Core Event Types

#### AdminAction
```go
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
```

#### SecurityEvent
```go
type SecurityEvent struct {
    EventID     string                 `json:"event_id"`
    Type        string                 `json:"type"`
    Category    string                 `json:"category"`
    Title       string                 `json:"title"`
    Description string                 `json:"description"`
    UserID      string                 `json:"user_id,omitempty"`
    Resource    string                 `json:"resource,omitempty"`
    Action      string                 `json:"action,omitempty"`
    Severity    SecuritySeverity       `json:"severity"`
    RiskLevel   RiskLevel              `json:"risk_level"`
    Context     SecurityEventContext   `json:"context"`
    Indicators  []ThreatIndicator      `json:"indicators,omitempty"`
    Timestamp   time.Time              `json:"timestamp"`
    Resolved    bool                   `json:"resolved"`
    Resolution  string                 `json:"resolution,omitempty"`
}
```

#### AuditEntry
```go
type AuditEntry struct {
    ID          string                 `json:"id"`
    EventType   EventType              `json:"event_type"`
    Category    string                 `json:"category"`
    Action      string                 `json:"action"`
    Resource    string                 `json:"resource"`
    ResourceID  string                 `json:"resource_id,omitempty"`
    UserID      string                 `json:"user_id"`
    SessionID   string                 `json:"session_id,omitempty"`
    AdminLevel  string                 `json:"admin_level,omitempty"`
    IPAddress   string                 `json:"ip_address"`
    UserAgent   string                 `json:"user_agent"`
    RequestID   string                 `json:"request_id,omitempty"`
    Description string                 `json:"description"`
    Details     map[string]interface{} `json:"details"`
    Metadata    map[string]interface{} `json:"metadata,omitempty"`
    Success     bool                   `json:"success"`
    ErrorCode   string                 `json:"error_code,omitempty"`
    ErrorMessage string                `json:"error_message,omitempty"`
    Severity    SecuritySeverity       `json:"severity"`
    RiskLevel   RiskLevel              `json:"risk_level"`
    Timestamp   time.Time              `json:"timestamp"`
    Duration    time.Duration          `json:"duration,omitempty"`
    RetentionDate *time.Time           `json:"retention_date,omitempty"`
    ComplianceFlags []string           `json:"compliance_flags,omitempty"`
    Tags        []string               `json:"tags,omitempty"`
    SearchText  string                 `json:"search_text,omitempty"`
}
```

### Filter Types

#### AuditFilter
```go
type AuditFilter struct {
    // Time range
    StartTime *time.Time `json:"start_time,omitempty"`
    EndTime   *time.Time `json:"end_time,omitempty"`
    
    // Event filtering
    EventTypes []EventType `json:"event_types,omitempty"`
    Categories []string    `json:"categories,omitempty"`
    Actions    []string    `json:"actions,omitempty"`
    
    // User and session filtering
    UserIDs    []string `json:"user_ids,omitempty"`
    AdminLevels []string `json:"admin_levels,omitempty"`
    SessionIDs []string `json:"session_ids,omitempty"`
    
    // Resource filtering
    Resources   []string `json:"resources,omitempty"`
    ResourceIDs []string `json:"resource_ids,omitempty"`
    
    // Context filtering
    IPAddresses []string `json:"ip_addresses,omitempty"`
    UserAgents  []string `json:"user_agents,omitempty"`
    
    // Outcome filtering
    Success    *bool             `json:"success,omitempty"`
    Severities []SecuritySeverity `json:"severities,omitempty"`
    RiskLevels []RiskLevel       `json:"risk_levels,omitempty"`
    
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
```

## Audit System API

### Constructor

```go
func NewAuditSystem(db *sql.DB, config *AuditConfig) (AuditSystem, error)
```

Creates a new audit system instance with the provided database connection and configuration.

**Parameters:**
- `db`: Database connection
- `config`: Audit system configuration (nil for defaults)

**Returns:**
- `AuditSystem`: Initialized audit system
- `error`: Error if initialization fails

### Logging Methods

#### LogAdminAction

```go
func LogAdminAction(action AdminAction) error
```

Logs an administrative action to the audit trail.

**Parameters:**
- `action`: AdminAction struct containing action details

**Returns:**
- `error`: Error if logging fails

**Example:**
```go
action := AdminAction{
    ActionID:    uuid.New().String(),
    Type:        "DELETE_USER",
    Category:    "USER_MANAGEMENT",
    Description: "User account deleted",
    UserID:      "admin123",
    AdminLevel:  "SUPER_ADMIN",
    Resource:    "users",
    ResourceID:  "user456",
    Context: ActionContext{
        IPAddress: "192.168.1.100",
        UserAgent: "Mozilla/5.0...",
        SessionID: "session789",
    },
    Timestamp: time.Now(),
    Success:   true,
    RiskLevel: RiskLevelHigh,
}

err := auditSystem.LogAdminAction(action)
```

#### LogSecurityEvent

```go
func LogSecurityEvent(event SecurityEvent) error
```

Logs a security event to the audit trail.

**Parameters:**
- `event`: SecurityEvent struct containing event details

**Returns:**
- `error`: Error if logging fails

#### LogDataAccess

```go
func LogDataAccess(access DataAccessEvent) error
```

Logs a data access event to the audit trail.

**Parameters:**
- `access`: DataAccessEvent struct containing access details

**Returns:**
- `error`: Error if logging fails

#### LogSystemChange

```go
func LogSystemChange(change SystemChangeEvent) error
```

Logs a system configuration change to the audit trail.

**Parameters:**
- `change`: SystemChangeEvent struct containing change details

**Returns:**
- `error`: Error if logging fails

### Query Methods

#### QueryAuditLogs

```go
func QueryAuditLogs(filter AuditFilter) ([]AuditEntry, error)
```

Queries audit logs with optional filtering, sorting, and pagination.

**Parameters:**
- `filter`: AuditFilter struct specifying query criteria

**Returns:**
- `[]AuditEntry`: Array of matching audit entries
- `error`: Error if query fails

**Example:**
```go
filter := AuditFilter{
    StartTime:  &startTime,
    EndTime:    &endTime,
    UserIDs:    []string{"user123"},
    EventTypes: []EventType{EventTypeAdminAction},
    Limit:      100,
    SortBy:     "timestamp",
    SortOrder:  "desc",
}

entries, err := auditSystem.QueryAuditLogs(filter)
```

#### GetAuditStatistics

```go
func GetAuditStatistics(filter StatisticsFilter) (*AuditStatistics, error)
```

Retrieves aggregated audit statistics for the specified time period and filters.

**Parameters:**
- `filter`: StatisticsFilter struct specifying criteria

**Returns:**
- `*AuditStatistics`: Aggregated statistics
- `error`: Error if retrieval fails

### Management Methods

#### SetRetentionPolicy

```go
func SetRetentionPolicy(policy RetentionPolicy) error
```

Sets the retention policy for audit logs.

**Parameters:**
- `policy`: RetentionPolicy struct defining retention rules

**Returns:**
- `error`: Error if setting fails

#### ArchiveLogs

```go
func ArchiveLogs(beforeDate time.Time) error
```

Archives audit logs older than the specified date.

**Parameters:**
- `beforeDate`: Date threshold for archival

**Returns:**
- `error`: Error if archival fails

#### PurgeLogs

```go
func PurgeLogs(beforeDate time.Time) error
```

Permanently deletes audit logs older than the specified date.

**Parameters:**
- `beforeDate`: Date threshold for purging

**Returns:**
- `error`: Error if purging fails

## Security Monitor API

### Constructor

```go
func NewSecurityMonitor(db *sql.DB, config *SecurityMonitorConfig) (SecurityMonitor, error)
```

Creates a new security monitor instance.

**Parameters:**
- `db`: Database connection
- `config`: Security monitor configuration

**Returns:**
- `SecurityMonitor`: Initialized security monitor
- `error`: Error if initialization fails

### Detection Methods

#### DetectAnomalies

```go
func DetectAnomalies(userID string, timeWindow time.Duration) ([]SecurityAnomaly, error)
```

Detects anomalies in user behavior within the specified time window.

**Parameters:**
- `userID`: User identifier
- `timeWindow`: Time window for analysis

**Returns:**
- `[]SecurityAnomaly`: Array of detected anomalies
- `error`: Error if detection fails

**Example:**
```go
anomalies, err := securityMonitor.DetectAnomalies("user123", 24*time.Hour)
if err != nil {
    log.Printf("Failed to detect anomalies: %v", err)
    return
}

for _, anomaly := range anomalies {
    log.Printf("Anomaly: %s (confidence: %.2f)", 
        anomaly.Description, anomaly.Confidence)
}
```

#### AnalyzeBehavior

```go
func AnalyzeBehavior(userID string, actions []AdminAction) (*BehaviorAnalysis, error)
```

Analyzes user behavior patterns and identifies deviations from baseline.

**Parameters:**
- `userID`: User identifier
- `actions`: Array of user actions to analyze

**Returns:**
- `*BehaviorAnalysis`: Behavior analysis results
- `error`: Error if analysis fails

#### DetectSuspiciousPatterns

```go
func DetectSuspiciousPatterns(events []SecurityEvent) ([]SuspiciousPattern, error)
```

Detects suspicious patterns in security events using built-in threat patterns.

**Parameters:**
- `events`: Array of security events to analyze

**Returns:**
- `[]SuspiciousPattern`: Array of detected suspicious patterns
- `error`: Error if detection fails

#### CalculateRiskScore

```go
func CalculateRiskScore(userID string, action AdminAction) (float64, error)
```

Calculates risk score for a specific user action.

**Parameters:**
- `userID`: User identifier
- `action`: Admin action to assess

**Returns:**
- `float64`: Risk score (0.0 to 1.0)
- `error`: Error if calculation fails

### Monitoring Control

#### StartMonitoring

```go
func StartMonitoring() error
```

Starts real-time security monitoring.

**Returns:**
- `error`: Error if start fails

#### StopMonitoring

```go
func StopMonitoring() error
```

Stops real-time security monitoring.

**Returns:**
- `error`: Error if stop fails

#### IsMonitoring

```go
func IsMonitoring() bool
```

Returns whether monitoring is currently active.

**Returns:**
- `bool`: True if monitoring is active

## Alert Manager API

### Constructor

```go
func NewAlertManager(db *sql.DB, config *AlertManagerConfig) (AlertManager, error)
```

Creates a new alert manager instance.

**Parameters:**
- `db`: Database connection
- `config`: Alert manager configuration

**Returns:**
- `AlertManager`: Initialized alert manager
- `error`: Error if initialization fails

### Alert Management

#### CreateAlert

```go
func CreateAlert(alert SecurityAlert) error
```

Creates a new security alert.

**Parameters:**
- `alert`: SecurityAlert struct containing alert details

**Returns:**
- `error`: Error if creation fails

**Example:**
```go
alert := SecurityAlert{
    ID:          uuid.New().String(),
    Type:        AlertTypeSecurityViolation,
    Severity:    SeverityHigh,
    Title:       "Suspicious Login Activity",
    Description: "Multiple failed login attempts detected",
    UserID:      "user123",
    Timestamp:   time.Now(),
    Status:      AlertStatusActive,
}

err := alertManager.CreateAlert(alert)
```

#### AcknowledgeAlert

```go
func AcknowledgeAlert(alertID string, acknowledgedBy string) error
```

Acknowledges an active alert.

**Parameters:**
- `alertID`: Alert identifier
- `acknowledgedBy`: User who acknowledged the alert

**Returns:**
- `error`: Error if acknowledgment fails

#### ResolveAlert

```go
func ResolveAlert(alertID string, resolvedBy string, resolution string) error
```

Resolves an alert with a resolution description.

**Parameters:**
- `alertID`: Alert identifier
- `resolvedBy`: User who resolved the alert
- `resolution`: Resolution description

**Returns:**
- `error`: Error if resolution fails

### Alert Querying

#### GetActiveAlerts

```go
func GetActiveAlerts(filter AlertFilter) ([]SecurityAlert, error)
```

Retrieves active alerts with optional filtering.

**Parameters:**
- `filter`: AlertFilter struct specifying criteria

**Returns:**
- `[]SecurityAlert`: Array of active alerts
- `error`: Error if retrieval fails

#### GetAlert

```go
func GetAlert(alertID string) (*SecurityAlert, error)
```

Retrieves a specific alert by ID.

**Parameters:**
- `alertID`: Alert identifier

**Returns:**
- `*SecurityAlert`: Alert details
- `error`: Error if retrieval fails

### Configuration

#### ConfigureAlertRules

```go
func ConfigureAlertRules(rules []AlertRule) error
```

Configures alert rules for automatic alert generation.

**Parameters:**
- `rules`: Array of AlertRule structs

**Returns:**
- `error`: Error if configuration fails

#### ConfigureNotificationChannels

```go
func ConfigureNotificationChannels(channels []NotificationChannel) error
```

Configures notification channels for alert delivery.

**Parameters:**
- `channels`: Array of NotificationChannel structs

**Returns:**
- `error`: Error if configuration fails

**Example:**
```go
emailChannel := NotificationChannel{
    ID:      "email-security",
    Type:    ChannelTypeEmail,
    Name:    "Security Team Email",
    Enabled: true,
    Recipients: []string{"security@company.com"},
    Config: map[string]interface{}{
        "smtp_server": "smtp.company.com",
        "smtp_port":   587,
        "username":    "alerts@company.com",
    },
}

err := alertManager.ConfigureNotificationChannels([]NotificationChannel{emailChannel})
```

## Compliance Reporter API

### Constructor

```go
func NewComplianceReporter(db *sql.DB, auditSystem AuditSystem, config *ComplianceReporterConfig) (ComplianceReporter, error)
```

Creates a new compliance reporter instance.

**Parameters:**
- `db`: Database connection
- `auditSystem`: Audit system instance
- `config`: Compliance reporter configuration

**Returns:**
- `ComplianceReporter`: Initialized compliance reporter
- `error`: Error if initialization fails

### Report Generation

#### GenerateSOC2Report

```go
func GenerateSOC2Report(period TimePeriod) (*ComplianceReport, error)
```

Generates a SOC 2 compliance report for the specified period.

**Parameters:**
- `period`: Time period for the report

**Returns:**
- `*ComplianceReport`: Generated compliance report
- `error`: Error if generation fails

**Example:**
```go
period := TimePeriod{
    Start: time.Now().Add(-90 * 24 * time.Hour),
    End:   time.Now(),
    Label: "Q1 2024",
}

report, err := complianceReporter.GenerateSOC2Report(period)
if err != nil {
    log.Printf("Failed to generate SOC 2 report: %v", err)
    return
}

log.Printf("Generated report with compliance score: %.2f%%", 
    report.Summary.ComplianceScore)
```

#### GenerateCustomReport

```go
func GenerateCustomReport(template ReportTemplate, period TimePeriod) (*ComplianceReport, error)
```

Generates a custom compliance report using the specified template.

**Parameters:**
- `template`: Report template defining structure and content
- `period`: Time period for the report

**Returns:**
- `*ComplianceReport`: Generated compliance report
- `error`: Error if generation fails

### Export Methods

#### ExportAuditTrail

```go
func ExportAuditTrail(filter AuditFilter, format ExportFormat) (io.Reader, error)
```

Exports audit trail data in the specified format.

**Parameters:**
- `filter`: Filter criteria for audit data
- `format`: Export format (JSON, CSV, XML)

**Returns:**
- `io.Reader`: Exported data stream
- `error`: Error if export fails

**Example:**
```go
filter := AuditFilter{
    StartTime: &startTime,
    EndTime:   &endTime,
    EventTypes: []EventType{EventTypeAdminAction},
}

reader, err := complianceReporter.ExportAuditTrail(filter, ExportFormatCSV)
if err != nil {
    log.Printf("Failed to export audit trail: %v", err)
    return
}

// Write to file or send as response
data, err := io.ReadAll(reader)
```

### Validation Methods

#### ValidateCompliance

```go
func ValidateCompliance(standard ComplianceStandard, period TimePeriod) (*ComplianceValidation, error)
```

Validates compliance against a specific standard for the given period.

**Parameters:**
- `standard`: Compliance standard to validate against
- `period`: Time period for validation

**Returns:**
- `*ComplianceValidation`: Validation results
- `error`: Error if validation fails

#### GetComplianceGaps

```go
func GetComplianceGaps(standard ComplianceStandard) ([]ComplianceGap, error)
```

Identifies compliance gaps for the specified standard.

**Parameters:**
- `standard`: Compliance standard to check

**Returns:**
- `[]ComplianceGap`: Array of identified gaps
- `error`: Error if gap analysis fails

## Error Handling

### Common Error Types

The system uses structured error handling with specific error types:

```go
// AuditError represents audit system errors
type AuditError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
    Details string `json:"details,omitempty"`
}

func (e *AuditError) Error() string {
    return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
}
```

### Error Codes

- `AUDIT_001`: Database connection error
- `AUDIT_002`: Invalid configuration
- `AUDIT_003`: Logging failure
- `AUDIT_004`: Query execution error
- `AUDIT_005`: Retention policy error
- `SECURITY_001`: Monitoring not started
- `SECURITY_002`: Detection rule error
- `SECURITY_003`: Anomaly detection failure
- `ALERT_001`: Alert creation failure
- `ALERT_002`: Notification delivery failure
- `ALERT_003`: Escalation policy error
- `COMPLIANCE_001`: Report generation failure
- `COMPLIANCE_002`: Validation error
- `COMPLIANCE_003`: Export failure

### Error Handling Best Practices

```go
// Check for specific error types
if err != nil {
    if auditErr, ok := err.(*AuditError); ok {
        switch auditErr.Code {
        case "AUDIT_001":
            // Handle database errors
            log.Printf("Database error: %v", auditErr)
            // Implement retry logic
        case "AUDIT_003":
            // Handle logging failures
            log.Printf("Logging failed: %v", auditErr)
            // Queue for retry
        default:
            log.Printf("Unknown audit error: %v", auditErr)
        }
    } else {
        log.Printf("General error: %v", err)
    }
}
```

## Examples

### Complete Integration Example

```go
package main

import (
    "database/sql"
    "log"
    "time"
    
    "your-project/internal/audit"
    _ "github.com/mattn/go-sqlite3"
)

func main() {
    // Initialize database
    db, err := sql.Open("sqlite3", "audit.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Create audit system
    auditSystem, err := audit.NewAuditSystem(db, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Create security monitor
    securityMonitor, err := audit.NewSecurityMonitor(db, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Create alert manager
    alertManager, err := audit.NewAlertManager(db, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Create compliance reporter
    complianceReporter, err := audit.NewComplianceReporter(db, auditSystem, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Configure notification channel
    emailChannel := audit.NotificationChannel{
        ID:      "email-alerts",
        Type:    audit.ChannelTypeEmail,
        Name:    "Email Alerts",
        Enabled: true,
        Recipients: []string{"admin@company.com"},
        Config: map[string]interface{}{
            "smtp_server": "smtp.company.com",
            "smtp_port":   587,
        },
    }

    err = alertManager.ConfigureNotificationChannels([]audit.NotificationChannel{emailChannel})
    if err != nil {
        log.Fatal(err)
    }

    // Start monitoring
    err = securityMonitor.StartMonitoring()
    if err != nil {
        log.Fatal(err)
    }

    err = alertManager.Start()
    if err != nil {
        log.Fatal(err)
    }

    // Example: Log an admin action
    action := audit.AdminAction{
        ActionID:    "action-123",
        Type:        "CREATE_USER",
        Category:    "USER_MANAGEMENT",
        Description: "New user account created",
        UserID:      "admin123",
        AdminLevel:  "ADMIN",
        Resource:    "users",
        ResourceID:  "user456",
        Context: audit.ActionContext{
            IPAddress: "192.168.1.100",
            UserAgent: "Admin Dashboard v1.0",
            SessionID: "session789",
        },
        Timestamp: time.Now(),
        Success:   true,
        RiskLevel: audit.RiskLevelMedium,
    }

    err = auditSystem.LogAdminAction(action)
    if err != nil {
        log.Printf("Failed to log action: %v", err)
    }

    // Example: Detect anomalies
    anomalies, err := securityMonitor.DetectAnomalies("admin123", 24*time.Hour)
    if err != nil {
        log.Printf("Failed to detect anomalies: %v", err)
    } else {
        log.Printf("Detected %d anomalies", len(anomalies))
    }

    // Example: Generate compliance report
    period := audit.TimePeriod{
        Start: time.Now().Add(-30 * 24 * time.Hour),
        End:   time.Now(),
        Label: "Last 30 Days",
    }

    report, err := complianceReporter.GenerateSOC2Report(period)
    if err != nil {
        log.Printf("Failed to generate report: %v", err)
    } else {
        log.Printf("Generated report with score: %.2f%%", report.Summary.ComplianceScore)
    }

    log.Println("Audit and Monitoring System is running...")
    
    // Keep running
    select {}
}
```

This API documentation provides comprehensive coverage of all interfaces, methods, and usage patterns for the Audit and Monitoring System.