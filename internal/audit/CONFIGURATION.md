# Audit and Monitoring System Configuration Guide

## Overview

This guide provides comprehensive configuration options for the Audit and Monitoring System. The system supports extensive customization through configuration structures that control behavior, performance, security, and compliance aspects.

## Configuration Structure

### Main Configuration Files

The system uses four main configuration structures:

1. **AuditConfig** - Core audit logging configuration
2. **SecurityMonitorConfig** - Security monitoring and detection configuration  
3. **AlertManagerConfig** - Alert management and notification configuration
4. **ComplianceReporterConfig** - Compliance reporting configuration

## Audit System Configuration

### AuditConfig Structure

```go
type AuditConfig struct {
    // Storage configuration
    MaxLogSize          int64         `json:"max_log_size"`
    CompressionEnabled  bool          `json:"compression_enabled"`
    EncryptionEnabled   bool          `json:"encryption_enabled"`
    
    // Performance configuration
    BatchSize           int           `json:"batch_size"`
    FlushInterval       time.Duration `json:"flush_interval"`
    IndexingEnabled     bool          `json:"indexing_enabled"`
    CacheEnabled        bool          `json:"cache_enabled"`
    CacheTTL            time.Duration `json:"cache_ttl"`
    
    // Retention configuration
    DefaultRetention    time.Duration `json:"default_retention"`
    ArchiveEnabled      bool          `json:"archive_enabled"`
    ArchiveLocation     string        `json:"archive_location"`
    
    // Security configuration
    IntegrityChecks     bool          `json:"integrity_checks"`
    TamperDetection     bool          `json:"tamper_detection"`
    AccessLogging       bool          `json:"access_logging"`
    
    // Categorization
    EventCategories     map[EventType]CategoryConfig `json:"event_categories"`
}
```

### Default Configuration

```go
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
```

### Configuration Options Explained

#### Storage Configuration

- **MaxLogSize**: Maximum size of individual log files before rotation
- **CompressionEnabled**: Enable compression for stored audit logs
- **EncryptionEnabled**: Enable encryption for sensitive audit data

#### Performance Configuration

- **BatchSize**: Number of log entries to process in a single batch
- **FlushInterval**: How often to flush pending log entries to storage
- **IndexingEnabled**: Enable database indexing for faster queries
- **CacheEnabled**: Enable caching of frequently accessed data
- **CacheTTL**: Time-to-live for cached data

#### Retention Configuration

- **DefaultRetention**: Default retention period for audit logs
- **ArchiveEnabled**: Enable automatic archiving of old logs
- **ArchiveLocation**: File system path for archived logs

#### Security Configuration

- **IntegrityChecks**: Enable integrity verification of audit logs
- **TamperDetection**: Enable tamper detection mechanisms
- **AccessLogging**: Log access to the audit system itself

### Custom Configuration Example

```go
config := &audit.AuditConfig{
    MaxLogSize:         500 * 1024 * 1024, // 500MB
    CompressionEnabled: true,
    EncryptionEnabled:  true, // Enable encryption for sensitive data
    BatchSize:          2000, // Larger batches for high-volume environments
    FlushInterval:      3 * time.Second, // More frequent flushing
    IndexingEnabled:    true,
    CacheEnabled:       true,
    CacheTTL:           10 * time.Minute, // Longer cache TTL
    DefaultRetention:   2 * 365 * 24 * time.Hour, // 2 years default
    ArchiveEnabled:     true,
    ArchiveLocation:    "/mnt/audit-archive",
    IntegrityChecks:    true,
    TamperDetection:    true,
    AccessLogging:      true,
    EventCategories: map[audit.EventType]audit.CategoryConfig{
        audit.EventTypeSecurityEvent: {
            Retention:       7 * 365 * 24 * time.Hour, // 7 years for security events
            Severity:        audit.SeverityHigh,
            RequireApproval: true, // Require approval for security event modifications
            Encryption:      true,
            Compression:     true,
        },
        audit.EventTypeAdminAction: {
            Retention:       3 * 365 * 24 * time.Hour, // 3 years for admin actions
            Severity:        audit.SeverityMedium,
            RequireApproval: false,
            Encryption:      true, // Encrypt admin actions too
            Compression:     true,
        },
        audit.EventTypeDataAccess: {
            Retention:       90 * 24 * time.Hour, // 90 days for data access
            Severity:        audit.SeverityLow,
            RequireApproval: false,
            Encryption:      false,
            Compression:     true,
        },
    },
}

auditSystem, err := audit.NewAuditSystem(db, config)
```

## Security Monitor Configuration

### SecurityMonitorConfig Structure

```go
type SecurityMonitorConfig struct {
    // Detection settings
    EnableAnomalyDetection    bool          `json:"enable_anomaly_detection"`
    EnablePatternDetection    bool          `json:"enable_pattern_detection"`
    EnableBehaviorAnalysis    bool          `json:"enable_behavior_analysis"`
    EnableMLDetection         bool          `json:"enable_ml_detection"`
    
    // Analysis windows
    ShortTermWindow           time.Duration `json:"short_term_window"`
    MediumTermWindow          time.Duration `json:"medium_term_window"`
    LongTermWindow            time.Duration `json:"long_term_window"`
    
    // Thresholds
    AnomalyThreshold          float64       `json:"anomaly_threshold"`
    RiskThreshold             float64       `json:"risk_threshold"`
    PatternConfidenceThreshold float64      `json:"pattern_confidence_threshold"`
    
    // Performance settings
    AnalysisInterval          time.Duration `json:"analysis_interval"`
    BatchSize                 int           `json:"batch_size"`
    MaxConcurrentAnalysis     int           `json:"max_concurrent_analysis"`
    
    // Storage settings
    RetainAnalysisResults     time.Duration `json:"retain_analysis_results"`
    CompressAnalysisData      bool          `json:"compress_analysis_data"`
}
```

### Security Thresholds Configuration

```go
type SecurityThresholds struct {
    // Authentication thresholds
    MaxFailedLogins           int           `json:"max_failed_logins"`
    LoginFailureWindow        time.Duration `json:"login_failure_window"`
    SuspiciousLoginThreshold  float64       `json:"suspicious_login_threshold"`
    
    // Activity thresholds
    MaxActionsPerMinute       int           `json:"max_actions_per_minute"`
    MaxActionsPerHour         int           `json:"max_actions_per_hour"`
    UnusualActivityThreshold  float64       `json:"unusual_activity_threshold"`
    
    // Data access thresholds
    MaxDataAccessPerHour      int64         `json:"max_data_access_per_hour"`
    PIIAccessThreshold        int           `json:"pii_access_threshold"`
    BulkDataThreshold         int64         `json:"bulk_data_threshold"`
    
    // Risk thresholds
    LowRiskThreshold          float64       `json:"low_risk_threshold"`
    MediumRiskThreshold       float64       `json:"medium_risk_threshold"`
    HighRiskThreshold         float64       `json:"high_risk_threshold"`
    CriticalRiskThreshold     float64       `json:"critical_risk_threshold"`
    
    // Geographic thresholds
    MaxLocationChangesPerDay  int           `json:"max_location_changes_per_day"`
    SuspiciousLocationRadius  float64       `json:"suspicious_location_radius"`
    
    // Time-based thresholds
    OffHoursActivityThreshold float64       `json:"off_hours_activity_threshold"`
    WeekendActivityThreshold  float64       `json:"weekend_activity_threshold"`
}
```

### Default Security Monitor Configuration

```go
func DefaultSecurityMonitorConfig() *SecurityMonitorConfig {
    return &SecurityMonitorConfig{
        EnableAnomalyDetection:     true,
        EnablePatternDetection:     true,
        EnableBehaviorAnalysis:     true,
        EnableMLDetection:          false, // Disabled by default
        ShortTermWindow:            1 * time.Hour,
        MediumTermWindow:           24 * time.Hour,
        LongTermWindow:             7 * 24 * time.Hour,
        AnomalyThreshold:           0.8,
        RiskThreshold:              0.7,
        PatternConfidenceThreshold: 0.75,
        AnalysisInterval:           5 * time.Minute,
        BatchSize:                  1000,
        MaxConcurrentAnalysis:      5,
        RetainAnalysisResults:      30 * 24 * time.Hour,
        CompressAnalysisData:       true,
    }
}
```

### Custom Security Monitor Configuration

```go
config := &audit.SecurityMonitorConfig{
    EnableAnomalyDetection:     true,
    EnablePatternDetection:     true,
    EnableBehaviorAnalysis:     true,
    EnableMLDetection:          true, // Enable ML detection
    ShortTermWindow:            30 * time.Minute, // Shorter window for faster detection
    MediumTermWindow:           12 * time.Hour,
    LongTermWindow:             3 * 24 * time.Hour,
    AnomalyThreshold:           0.9, // Higher threshold for fewer false positives
    RiskThreshold:              0.8,
    PatternConfidenceThreshold: 0.85, // Higher confidence required
    AnalysisInterval:           2 * time.Minute, // More frequent analysis
    BatchSize:                  2000,
    MaxConcurrentAnalysis:      10, // More concurrent analysis threads
    RetainAnalysisResults:      60 * 24 * time.Hour, // Retain for 60 days
    CompressAnalysisData:       true,
}

// Custom thresholds
thresholds := audit.SecurityThresholds{
    MaxFailedLogins:           3, // Stricter login failure threshold
    LoginFailureWindow:        10 * time.Minute,
    SuspiciousLoginThreshold:  0.9,
    MaxActionsPerMinute:       30, // Lower action rate limit
    MaxActionsPerHour:         500,
    UnusualActivityThreshold:  0.8,
    MaxDataAccessPerHour:      5000,
    PIIAccessThreshold:        50,
    BulkDataThreshold:         500000, // 500KB
    LowRiskThreshold:          0.2,
    MediumRiskThreshold:       0.5,
    HighRiskThreshold:         0.7,
    CriticalRiskThreshold:     0.85,
    MaxLocationChangesPerDay:  2,
    SuspiciousLocationRadius:  500.0, // 500m
    OffHoursActivityThreshold: 0.3,
    WeekendActivityThreshold:  0.2,
}

securityMonitor, err := audit.NewSecurityMonitor(db, config)
if err != nil {
    log.Fatal(err)
}

err = securityMonitor.UpdateThresholds(thresholds)
if err != nil {
    log.Fatal(err)
}
```

## Alert Manager Configuration

### AlertManagerConfig Structure

```go
type AlertManagerConfig struct {
    // Processing settings
    MaxConcurrentNotifications int           `json:"max_concurrent_notifications"`
    NotificationTimeout        time.Duration `json:"notification_timeout"`
    RetryAttempts              int           `json:"retry_attempts"`
    RetryDelay                 time.Duration `json:"retry_delay"`
    
    // Queue settings
    NotificationQueueSize      int           `json:"notification_queue_size"`
    EscalationQueueSize        int           `json:"escalation_queue_size"`
    
    // Alert settings
    DefaultAlertTTL            time.Duration `json:"default_alert_ttl"`
    AutoAcknowledgeTimeout     time.Duration `json:"auto_acknowledge_timeout"`
    AutoResolveTimeout         time.Duration `json:"auto_resolve_timeout"`
    
    // Escalation settings
    DefaultEscalationDelay     time.Duration `json:"default_escalation_delay"`
    MaxEscalationLevel         int           `json:"max_escalation_level"`
    
    // Notification settings
    EnableEmailNotifications   bool          `json:"enable_email_notifications"`
    EnableSlackNotifications   bool          `json:"enable_slack_notifications"`
    EnableWebhookNotifications bool          `json:"enable_webhook_notifications"`
    EnableSMSNotifications     bool          `json:"enable_sms_notifications"`
}
```

### Notification Channel Configuration

```go
type NotificationChannel struct {
    ID          string                 `json:"id"`
    Type        NotificationChannelType `json:"type"`
    Name        string                 `json:"name"`
    Config      map[string]interface{} `json:"config"`
    Enabled     bool                   `json:"enabled"`
    Description string                 `json:"description,omitempty"`
    Recipients  []string               `json:"recipients"`
    Filters     []NotificationFilter   `json:"filters,omitempty"`
    RateLimits  NotificationRateLimit  `json:"rate_limits"`
}
```

### Email Channel Configuration

```go
emailChannel := audit.NotificationChannel{
    ID:      "email-security-team",
    Type:    audit.ChannelTypeEmail,
    Name:    "Security Team Email",
    Enabled: true,
    Recipients: []string{
        "security@company.com",
        "admin@company.com",
    },
    Config: map[string]interface{}{
        "smtp_server":   "smtp.company.com",
        "smtp_port":     587,
        "username":      "alerts@company.com",
        "password":      "smtp_password",
        "use_tls":       true,
        "from_address":  "alerts@company.com",
        "from_name":     "Security Alert System",
    },
    RateLimits: audit.NotificationRateLimit{
        MaxPerMinute: 10,
        MaxPerHour:   100,
        MaxPerDay:    500,
        BurstLimit:   5,
        Window:       1 * time.Minute,
    },
}
```

### Slack Channel Configuration

```go
slackChannel := audit.NotificationChannel{
    ID:      "slack-security",
    Type:    audit.ChannelTypeSlack,
    Name:    "Security Slack Channel",
    Enabled: true,
    Config: map[string]interface{}{
        "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        "channel":     "#security-alerts",
        "username":    "SecurityBot",
        "icon_emoji":  ":warning:",
    },
    RateLimits: audit.NotificationRateLimit{
        MaxPerMinute: 5,
        MaxPerHour:   50,
        MaxPerDay:    200,
        BurstLimit:   3,
        Window:       1 * time.Minute,
    },
}
```

### Webhook Channel Configuration

```go
webhookChannel := audit.NotificationChannel{
    ID:      "webhook-external-system",
    Type:    audit.ChannelTypeWebhook,
    Name:    "External System Webhook",
    Enabled: true,
    Config: map[string]interface{}{
        "webhook_url": "https://external-system.com/api/alerts",
        "method":      "POST",
        "headers": map[string]string{
            "Authorization": "Bearer your-api-token",
            "Content-Type":  "application/json",
        },
        "timeout": 30, // seconds
        "retry_on_failure": true,
    },
    RateLimits: audit.NotificationRateLimit{
        MaxPerMinute: 20,
        MaxPerHour:   200,
        MaxPerDay:    1000,
        BurstLimit:   10,
        Window:       1 * time.Minute,
    },
}
```

### Alert Rules Configuration

```go
// High-severity security events
securityRule := audit.AlertRule{
    ID:          "security-high-severity",
    Name:        "High Severity Security Events",
    Description: "Alert on high and critical severity security events",
    Condition:   "severity IN ('HIGH', 'CRITICAL') AND event_type = 'SECURITY_EVENT'",
    Severity:    audit.SeverityHigh,
    Enabled:     true,
    NotificationChannels: []string{
        "email-security-team",
        "slack-security",
    },
    EscalationPolicy: "security-escalation",
    Cooldown:        5 * time.Minute,
}

// Failed login attempts
loginRule := audit.AlertRule{
    ID:          "failed-login-attempts",
    Name:        "Multiple Failed Login Attempts",
    Description: "Alert on multiple failed login attempts",
    Condition:   "action = 'LOGIN_FAILED' AND count >= 5 AND time_window <= 15m",
    Threshold:   5,
    Severity:    audit.SeverityMedium,
    Enabled:     true,
    NotificationChannels: []string{
        "email-security-team",
    },
    Cooldown: 10 * time.Minute,
}

rules := []audit.AlertRule{securityRule, loginRule}
err := alertManager.ConfigureAlertRules(rules)
```

### Escalation Policy Configuration

```go
escalationPolicy := audit.EscalationPolicy{
    ID:          "security-escalation",
    Name:        "Security Team Escalation",
    Description: "Escalation policy for security events",
    Enabled:     true,
    Steps: []audit.EscalationStep{
        {
            Level: 1,
            Delay: 15 * time.Minute,
            NotificationChannels: []string{
                "email-security-team",
                "slack-security",
            },
            RequireAcknowledgment: true,
            AutoResolve:          false,
        },
        {
            Level: 2,
            Delay: 30 * time.Minute,
            NotificationChannels: []string{
                "email-security-manager",
                "sms-security-manager",
            },
            RequireAcknowledgment: true,
            AutoResolve:          false,
        },
        {
            Level: 3,
            Delay: 60 * time.Minute,
            NotificationChannels: []string{
                "email-ciso",
                "sms-ciso",
            },
            RequireAcknowledgment: false,
            AutoResolve:          true,
        },
    },
}

err := alertManager.ConfigureEscalationPolicies([]audit.EscalationPolicy{escalationPolicy})
```

## Compliance Reporter Configuration

### ComplianceReporterConfig Structure

```go
type ComplianceReporterConfig struct {
    // Report generation settings
    DefaultReportFormat    ReportFormat      `json:"default_report_format"`
    MaxReportSize          int64             `json:"max_report_size"`
    ReportTimeout          time.Duration     `json:"report_timeout"`
    
    // Data retention for compliance
    ComplianceDataRetention map[ComplianceStandard]time.Duration `json:"compliance_data_retention"`
    
    // Export settings
    EnableEncryption       bool              `json:"enable_encryption"`
    CompressionEnabled     bool              `json:"compression_enabled"`
    DigitalSignatures      bool              `json:"digital_signatures"`
    
    // Template settings
    CustomTemplatesEnabled bool              `json:"custom_templates_enabled"`
    TemplateValidation     bool              `json:"template_validation"`
    
    // Performance settings
    MaxConcurrentReports   int               `json:"max_concurrent_reports"`
    CacheReports           bool              `json:"cache_reports"`
    CacheTTL               time.Duration     `json:"cache_ttl"`
}
```

### Default Compliance Configuration

```go
func DefaultComplianceReporterConfig() *ComplianceReporterConfig {
    return &ComplianceReporterConfig{
        DefaultReportFormat: ReportFormatPDF,
        MaxReportSize:       100 * 1024 * 1024, // 100MB
        ReportTimeout:       30 * time.Minute,
        ComplianceDataRetention: map[ComplianceStandard]time.Duration{
            ComplianceSOC2:  7 * 365 * 24 * time.Hour, // 7 years
            ComplianceGDPR:  6 * 365 * 24 * time.Hour, // 6 years
            ComplianceHIPAA: 6 * 365 * 24 * time.Hour, // 6 years
            CompliancePCI:   365 * 24 * time.Hour,     // 1 year
        },
        EnableEncryption:       true,
        CompressionEnabled:     true,
        DigitalSignatures:      false,
        CustomTemplatesEnabled: true,
        TemplateValidation:     true,
        MaxConcurrentReports:   5,
        CacheReports:           true,
        CacheTTL:               1 * time.Hour,
    }
}
```

### Custom Report Template Configuration

```go
// SOC 2 Custom Template
soc2Template := audit.ReportTemplate{
    ID:          "custom-soc2-template",
    Name:        "Custom SOC 2 Report",
    Description: "Customized SOC 2 compliance report for our organization",
    Standard:    audit.ComplianceSOC2,
    Version:     "2.0",
    Format:      audit.ReportFormatPDF,
    Sections: []audit.ReportTemplateSection{
        {
            ID:          "executive_summary",
            Title:       "Executive Summary",
            Description: "High-level overview of SOC 2 compliance status",
            Type:        audit.SectionTypeExecutiveSummary,
            Required:    true,
            Order:       1,
        },
        {
            ID:          "security_controls",
            Title:       "Security Controls Assessment",
            Description: "Detailed assessment of security controls",
            Type:        audit.SectionTypeCompliance,
            Required:    true,
            Order:       2,
            Filters: []audit.ReportFilter{
                {
                    Field:    "event_type",
                    Operator: "IN",
                    Value:    []string{"SECURITY_EVENT", "ADMIN_ACTION"},
                    Type:     "array",
                },
                {
                    Field:    "severity",
                    Operator: ">=",
                    Value:    "MEDIUM",
                    Type:     "string",
                },
            },
        },
        {
            ID:          "availability_metrics",
            Title:       "System Availability Metrics",
            Description: "System uptime and availability analysis",
            Type:        audit.SectionTypeMetrics,
            Required:    true,
            Order:       3,
            Aggregations: []audit.ReportAggregation{
                {
                    Field:    "success",
                    Function: "COUNT",
                    GroupBy:  "DATE(timestamp)",
                },
                {
                    Field:    "duration",
                    Function: "AVG",
                    GroupBy:  "event_type",
                },
            },
            Visualizations: []audit.ReportVisualization{
                {
                    Type: "LINE_CHART",
                    Config: map[string]interface{}{
                        "title":  "System Availability Over Time",
                        "x_axis": "Date",
                        "y_axis": "Availability %",
                    },
                    Data: "availability_data",
                },
            },
        },
        {
            ID:          "audit_trail_analysis",
            Title:       "Audit Trail Analysis",
            Description: "Comprehensive audit trail review",
            Type:        audit.SectionTypeAuditTrail,
            Required:    true,
            Order:       4,
            Query:       "SELECT * FROM audit_entries WHERE event_type IN ('ADMIN_ACTION', 'DATA_ACCESS') AND timestamp >= ? AND timestamp <= ?",
        },
        {
            ID:          "findings_recommendations",
            Title:       "Findings and Recommendations",
            Description: "Compliance findings and improvement recommendations",
            Type:        audit.SectionTypeFindings,
            Required:    true,
            Order:       5,
        },
    },
    Metadata: map[string]interface{}{
        "organization": "Your Company Name",
        "auditor":      "Internal Audit Team",
        "scope":        "SOC 2 Type II",
    },
    CreatedBy: "admin@company.com",
    IsActive:  true,
}

err := complianceReporter.CreateReportTemplate(soc2Template)
```

## Environment-Specific Configurations

### Development Environment

```go
// Development configuration with verbose logging and relaxed thresholds
devConfig := &audit.AuditConfig{
    MaxLogSize:         10 * 1024 * 1024, // 10MB for dev
    CompressionEnabled: false, // Disable compression for easier debugging
    EncryptionEnabled:  false, // Disable encryption for dev
    BatchSize:          100,   // Smaller batches
    FlushInterval:      1 * time.Second, // Frequent flushing
    IndexingEnabled:    true,
    CacheEnabled:       false, // Disable cache for real-time data
    DefaultRetention:   7 * 24 * time.Hour, // 7 days retention
    ArchiveEnabled:     false, // No archiving in dev
    IntegrityChecks:    false, // Disable for performance
    TamperDetection:    false,
    AccessLogging:      true,
}

devSecurityConfig := &audit.SecurityMonitorConfig{
    EnableAnomalyDetection:     true,
    EnablePatternDetection:     true,
    EnableBehaviorAnalysis:     false, // Disable for dev
    EnableMLDetection:          false,
    AnomalyThreshold:           0.5, // Lower threshold for testing
    RiskThreshold:              0.5,
    PatternConfidenceThreshold: 0.5,
    AnalysisInterval:           30 * time.Second, // Frequent analysis
    BatchSize:                  100,
    MaxConcurrentAnalysis:      2,
    RetainAnalysisResults:      24 * time.Hour,
    CompressAnalysisData:       false,
}
```

### Production Environment

```go
// Production configuration with high performance and security
prodConfig := &audit.AuditConfig{
    MaxLogSize:         1024 * 1024 * 1024, // 1GB
    CompressionEnabled: true,
    EncryptionEnabled:  true, // Enable encryption in production
    BatchSize:          5000, // Large batches for performance
    FlushInterval:      10 * time.Second,
    IndexingEnabled:    true,
    CacheEnabled:       true,
    CacheTTL:           15 * time.Minute,
    DefaultRetention:   3 * 365 * 24 * time.Hour, // 3 years
    ArchiveEnabled:     true,
    ArchiveLocation:    "/mnt/audit-archive",
    IntegrityChecks:    true,
    TamperDetection:    true,
    AccessLogging:      true,
}

prodSecurityConfig := &audit.SecurityMonitorConfig{
    EnableAnomalyDetection:     true,
    EnablePatternDetection:     true,
    EnableBehaviorAnalysis:     true,
    EnableMLDetection:          true, // Enable ML in production
    AnomalyThreshold:           0.85, // Higher threshold for fewer false positives
    RiskThreshold:              0.8,
    PatternConfidenceThreshold: 0.9,
    AnalysisInterval:           5 * time.Minute,
    BatchSize:                  2000,
    MaxConcurrentAnalysis:      10,
    RetainAnalysisResults:      90 * 24 * time.Hour,
    CompressAnalysisData:       true,
}

prodAlertConfig := &audit.AlertManagerConfig{
    MaxConcurrentNotifications: 20,
    NotificationTimeout:        60 * time.Second,
    RetryAttempts:              5,
    RetryDelay:                 10 * time.Second,
    NotificationQueueSize:      5000,
    EscalationQueueSize:        1000,
    DefaultAlertTTL:            48 * time.Hour,
    AutoAcknowledgeTimeout:     2 * time.Hour,
    AutoResolveTimeout:         24 * time.Hour,
    DefaultEscalationDelay:     30 * time.Minute,
    MaxEscalationLevel:         4,
    EnableEmailNotifications:   true,
    EnableSlackNotifications:   true,
    EnableWebhookNotifications: true,
    EnableSMSNotifications:     true,
}
```

## Configuration Validation

### Validation Functions

```go
func ValidateAuditConfig(config *AuditConfig) error {
    if config.MaxLogSize <= 0 {
        return fmt.Errorf("max_log_size must be positive")
    }
    if config.BatchSize <= 0 {
        return fmt.Errorf("batch_size must be positive")
    }
    if config.FlushInterval <= 0 {
        return fmt.Errorf("flush_interval must be positive")
    }
    if config.DefaultRetention <= 0 {
        return fmt.Errorf("default_retention must be positive")
    }
    if config.ArchiveEnabled && config.ArchiveLocation == "" {
        return fmt.Errorf("archive_location required when archiving is enabled")
    }
    return nil
}

func ValidateSecurityConfig(config *SecurityMonitorConfig) error {
    if config.AnomalyThreshold < 0 || config.AnomalyThreshold > 1 {
        return fmt.Errorf("anomaly_threshold must be between 0 and 1")
    }
    if config.RiskThreshold < 0 || config.RiskThreshold > 1 {
        return fmt.Errorf("risk_threshold must be between 0 and 1")
    }
    if config.AnalysisInterval <= 0 {
        return fmt.Errorf("analysis_interval must be positive")
    }
    if config.BatchSize <= 0 {
        return fmt.Errorf("batch_size must be positive")
    }
    return nil
}
```

### Configuration Loading

```go
func LoadConfigFromFile(filename string) (*AuditConfig, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    
    var config AuditConfig
    err = json.Unmarshal(data, &config)
    if err != nil {
        return nil, err
    }
    
    err = ValidateAuditConfig(&config)
    if err != nil {
        return nil, fmt.Errorf("invalid configuration: %w", err)
    }
    
    return &config, nil
}

func LoadConfigFromEnv() *AuditConfig {
    config := DefaultAuditConfig()
    
    if maxLogSize := os.Getenv("AUDIT_MAX_LOG_SIZE"); maxLogSize != "" {
        if size, err := strconv.ParseInt(maxLogSize, 10, 64); err == nil {
            config.MaxLogSize = size
        }
    }
    
    if compression := os.Getenv("AUDIT_COMPRESSION_ENABLED"); compression != "" {
        config.CompressionEnabled = compression == "true"
    }
    
    if encryption := os.Getenv("AUDIT_ENCRYPTION_ENABLED"); encryption != "" {
        config.EncryptionEnabled = encryption == "true"
    }
    
    if batchSize := os.Getenv("AUDIT_BATCH_SIZE"); batchSize != "" {
        if size, err := strconv.Atoi(batchSize); err == nil {
            config.BatchSize = size
        }
    }
    
    if archiveLocation := os.Getenv("AUDIT_ARCHIVE_LOCATION"); archiveLocation != "" {
        config.ArchiveLocation = archiveLocation
    }
    
    return config
}
```

## Best Practices

### Configuration Management

1. **Environment-Specific Configs**: Use different configurations for development, staging, and production
2. **Validation**: Always validate configuration before using
3. **Secrets Management**: Store sensitive configuration (passwords, API keys) in secure secret management systems
4. **Version Control**: Keep configuration templates in version control, but not sensitive values
5. **Documentation**: Document all configuration options and their impact

### Performance Tuning

1. **Batch Sizes**: Larger batch sizes improve throughput but increase memory usage
2. **Cache Settings**: Tune cache TTL based on query patterns and data freshness requirements
3. **Index Strategy**: Enable indexing for production, consider disabling for development
4. **Compression**: Enable compression for storage efficiency, disable for debugging
5. **Concurrent Processing**: Adjust concurrent processing limits based on system resources

### Security Considerations

1. **Encryption**: Enable encryption for sensitive audit data in production
2. **Access Control**: Implement proper access controls for configuration files
3. **Integrity Checks**: Enable integrity checks and tamper detection in production
4. **Retention Policies**: Set appropriate retention periods based on compliance requirements
5. **Alert Thresholds**: Tune alert thresholds to minimize false positives while maintaining security

This configuration guide provides comprehensive coverage of all configuration options and best practices for the Audit and Monitoring System.