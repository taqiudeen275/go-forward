package audit

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// alertManager implements the AlertManager interface
type alertManager struct {
	db                   *sql.DB
	config               *AlertManagerConfig
	alertRules           []AlertRule
	notificationChannels []NotificationChannel
	escalationPolicies   []EscalationPolicy
	activeAlerts         map[string]*SecurityAlert
	notificationQueue    chan NotificationTask
	escalationQueue      chan EscalationTask
	isRunning            bool
	stopChan             chan bool
	mutex                sync.RWMutex
}

// AlertManagerConfig contains configuration for the alert manager
type AlertManagerConfig struct {
	// Processing settings
	MaxConcurrentNotifications int           `json:"max_concurrent_notifications"`
	NotificationTimeout        time.Duration `json:"notification_timeout"`
	RetryAttempts              int           `json:"retry_attempts"`
	RetryDelay                 time.Duration `json:"retry_delay"`

	// Queue settings
	NotificationQueueSize int `json:"notification_queue_size"`
	EscalationQueueSize   int `json:"escalation_queue_size"`

	// Alert settings
	DefaultAlertTTL        time.Duration `json:"default_alert_ttl"`
	AutoAcknowledgeTimeout time.Duration `json:"auto_acknowledge_timeout"`
	AutoResolveTimeout     time.Duration `json:"auto_resolve_timeout"`

	// Escalation settings
	DefaultEscalationDelay time.Duration `json:"default_escalation_delay"`
	MaxEscalationLevel     int           `json:"max_escalation_level"`

	// Notification settings
	EnableEmailNotifications   bool `json:"enable_email_notifications"`
	EnableSlackNotifications   bool `json:"enable_slack_notifications"`
	EnableWebhookNotifications bool `json:"enable_webhook_notifications"`
	EnableSMSNotifications     bool `json:"enable_sms_notifications"`
}

// SecurityAlert represents a security alert (extended from models.go)
type SecurityAlert struct {
	ID          string                 `json:"id" db:"id"`
	Type        AlertType              `json:"type" db:"type"`
	Severity    SecuritySeverity       `json:"severity" db:"severity"`
	Title       string                 `json:"title" db:"title"`
	Description string                 `json:"description" db:"description"`
	UserID      string                 `json:"user_id,omitempty" db:"user_id"`
	Resource    string                 `json:"resource,omitempty" db:"resource"`
	Query       string                 `json:"query,omitempty" db:"query"`
	Timestamp   time.Time              `json:"timestamp" db:"timestamp"`
	Status      AlertStatus            `json:"status" db:"status"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Extended fields for alert management
	AcknowledgedBy    string               `json:"acknowledged_by,omitempty" db:"acknowledged_by"`
	AcknowledgedAt    *time.Time           `json:"acknowledged_at,omitempty" db:"acknowledged_at"`
	ResolvedBy        string               `json:"resolved_by,omitempty" db:"resolved_by"`
	ResolvedAt        *time.Time           `json:"resolved_at,omitempty" db:"resolved_at"`
	Resolution        string               `json:"resolution,omitempty" db:"resolution"`
	EscalationLevel   int                  `json:"escalation_level" db:"escalation_level"`
	LastEscalated     *time.Time           `json:"last_escalated,omitempty" db:"last_escalated"`
	NotificationsSent []NotificationRecord `json:"notifications_sent,omitempty" db:"notifications_sent"`
	TTL               time.Duration        `json:"ttl" db:"ttl"`
	ExpiresAt         *time.Time           `json:"expires_at,omitempty" db:"expires_at"`
}

// AlertRule represents an alert rule (extended from models.go)
type AlertRule struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Condition   string                 `json:"condition" db:"condition"`
	Threshold   interface{}            `json:"threshold" db:"threshold"`
	Severity    SecuritySeverity       `json:"severity" db:"severity"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`

	// Extended fields for rule management
	NotificationChannels []string      `json:"notification_channels" db:"notification_channels"`
	EscalationPolicy     string        `json:"escalation_policy,omitempty" db:"escalation_policy"`
	Cooldown             time.Duration `json:"cooldown" db:"cooldown"`
	LastTriggered        *time.Time    `json:"last_triggered,omitempty" db:"last_triggered"`
	TriggerCount         int64         `json:"trigger_count" db:"trigger_count"`
	CreatedAt            time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt            time.Time     `json:"updated_at" db:"updated_at"`
	CreatedBy            string        `json:"created_by" db:"created_by"`
}

// AlertRuleUpdates represents updates to an alert rule
type AlertRuleUpdates struct {
	Name                 *string                `json:"name,omitempty"`
	Description          *string                `json:"description,omitempty"`
	Condition            *string                `json:"condition,omitempty"`
	Threshold            interface{}            `json:"threshold,omitempty"`
	Severity             *SecuritySeverity      `json:"severity,omitempty"`
	Enabled              *bool                  `json:"enabled,omitempty"`
	NotificationChannels []string               `json:"notification_channels,omitempty"`
	EscalationPolicy     *string                `json:"escalation_policy,omitempty"`
	Cooldown             *time.Duration         `json:"cooldown,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

// NotificationChannel represents a notification channel (extended from models.go)
type NotificationChannel struct {
	ID      string                  `json:"id" db:"id"`
	Type    NotificationChannelType `json:"type" db:"type"`
	Name    string                  `json:"name" db:"name"`
	Config  map[string]interface{}  `json:"config" db:"config"`
	Enabled bool                    `json:"enabled" db:"enabled"`

	// Extended fields
	Description  string                `json:"description,omitempty" db:"description"`
	Recipients   []string              `json:"recipients" db:"recipients"`
	Filters      []NotificationFilter  `json:"filters,omitempty" db:"filters"`
	RateLimits   NotificationRateLimit `json:"rate_limits" db:"rate_limits"`
	LastUsed     *time.Time            `json:"last_used,omitempty" db:"last_used"`
	SuccessCount int64                 `json:"success_count" db:"success_count"`
	FailureCount int64                 `json:"failure_count" db:"failure_count"`
	CreatedAt    time.Time             `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time             `json:"updated_at" db:"updated_at"`
}

// NotificationChannelType represents the type of notification channel
type NotificationChannelType string

const (
	ChannelTypeEmail   NotificationChannelType = "EMAIL"
	ChannelTypeSlack   NotificationChannelType = "SLACK"
	ChannelTypeWebhook NotificationChannelType = "WEBHOOK"
	ChannelTypeSMS     NotificationChannelType = "SMS"
	ChannelTypePush    NotificationChannelType = "PUSH"
	ChannelTypeTeams   NotificationChannelType = "TEAMS"
)

// NotificationFilter represents a filter for notifications
type NotificationFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// NotificationRateLimit represents rate limiting for notifications
type NotificationRateLimit struct {
	MaxPerMinute int           `json:"max_per_minute"`
	MaxPerHour   int           `json:"max_per_hour"`
	MaxPerDay    int           `json:"max_per_day"`
	BurstLimit   int           `json:"burst_limit"`
	Window       time.Duration `json:"window"`
}

// EscalationPolicy represents an escalation policy
type EscalationPolicy struct {
	ID          string                 `json:"id" db:"id"`
	Name        string                 `json:"name" db:"name"`
	Description string                 `json:"description" db:"description"`
	Steps       []EscalationStep       `json:"steps" db:"steps"`
	Enabled     bool                   `json:"enabled" db:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty" db:"metadata"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy   string                 `json:"created_by" db:"created_by"`
}

// EscalationStep represents a step in an escalation policy
type EscalationStep struct {
	Level                 int                   `json:"level"`
	Delay                 time.Duration         `json:"delay"`
	NotificationChannels  []string              `json:"notification_channels"`
	RequireAcknowledgment bool                  `json:"require_acknowledgment"`
	AutoResolve           bool                  `json:"auto_resolve"`
	Conditions            []EscalationCondition `json:"conditions,omitempty"`
}

// EscalationCondition represents a condition for escalation
type EscalationCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// EscalationLevel represents escalation levels
type EscalationLevel int

const (
	EscalationLevelNone      EscalationLevel = 0
	EscalationLevelL1        EscalationLevel = 1
	EscalationLevelL2        EscalationLevel = 2
	EscalationLevelL3        EscalationLevel = 3
	EscalationLevelExecutive EscalationLevel = 4
)

// NotificationRecord represents a record of sent notifications
type NotificationRecord struct {
	ID          string                  `json:"id"`
	ChannelID   string                  `json:"channel_id"`
	ChannelType NotificationChannelType `json:"channel_type"`
	Recipients  []string                `json:"recipients"`
	SentAt      time.Time               `json:"sent_at"`
	Status      NotificationStatus      `json:"status"`
	Error       string                  `json:"error,omitempty"`
	RetryCount  int                     `json:"retry_count"`
}

// NotificationStatus represents the status of a notification
type NotificationStatus string

const (
	NotificationStatusPending NotificationStatus = "PENDING"
	NotificationStatusSent    NotificationStatus = "SENT"
	NotificationStatusFailed  NotificationStatus = "FAILED"
	NotificationStatusRetry   NotificationStatus = "RETRY"
)

// NotificationTask represents a notification task
type NotificationTask struct {
	AlertID     string               `json:"alert_id"`
	Alert       SecurityAlert        `json:"alert"`
	ChannelID   string               `json:"channel_id"`
	Channel     NotificationChannel  `json:"channel"`
	Recipients  []string             `json:"recipients"`
	Priority    NotificationPriority `json:"priority"`
	RetryCount  int                  `json:"retry_count"`
	ScheduledAt time.Time            `json:"scheduled_at"`
}

// NotificationPriority represents notification priority
type NotificationPriority int

const (
	PriorityLow      NotificationPriority = 1
	PriorityMedium   NotificationPriority = 2
	PriorityHigh     NotificationPriority = 3
	PriorityCritical NotificationPriority = 4
)

// EscalationTask represents an escalation task
type EscalationTask struct {
	AlertID     string           `json:"alert_id"`
	Alert       SecurityAlert    `json:"alert"`
	PolicyID    string           `json:"policy_id"`
	Policy      EscalationPolicy `json:"policy"`
	Level       int              `json:"level"`
	ScheduledAt time.Time        `json:"scheduled_at"`
}

// AlertFilter represents filters for querying alerts (extended from models.go)
type AlertFilter struct {
	// Basic filters
	Types      []AlertType        `json:"types,omitempty"`
	Severities []SecuritySeverity `json:"severities,omitempty"`
	Statuses   []AlertStatus      `json:"statuses,omitempty"`
	UserIDs    []string           `json:"user_ids,omitempty"`

	// Time filters
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`

	// Escalation filters
	EscalationLevels []int `json:"escalation_levels,omitempty"`

	// Acknowledgment filters
	Acknowledged   *bool   `json:"acknowledged,omitempty"`
	AcknowledgedBy *string `json:"acknowledged_by,omitempty"`

	// Resolution filters
	Resolved   *bool   `json:"resolved,omitempty"`
	ResolvedBy *string `json:"resolved_by,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Sorting
	SortBy    string `json:"sort_by,omitempty"`
	SortOrder string `json:"sort_order,omitempty"`
}

// NewAlertManager creates a new alert manager
func NewAlertManager(db *sql.DB, config *AlertManagerConfig) (AlertManager, error) {
	if config == nil {
		config = DefaultAlertManagerConfig()
	}

	manager := &alertManager{
		db:                   db,
		config:               config,
		alertRules:           make([]AlertRule, 0),
		notificationChannels: make([]NotificationChannel, 0),
		escalationPolicies:   make([]EscalationPolicy, 0),
		activeAlerts:         make(map[string]*SecurityAlert),
		notificationQueue:    make(chan NotificationTask, config.NotificationQueueSize),
		escalationQueue:      make(chan EscalationTask, config.EscalationQueueSize),
		stopChan:             make(chan bool),
	}

	// Initialize database schema
	if err := manager.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize alert manager schema: %w", err)
	}

	// Load configuration from database
	if err := manager.loadConfiguration(); err != nil {
		return nil, fmt.Errorf("failed to load alert manager configuration: %w", err)
	}

	return manager, nil
}

// CreateAlert creates a new security alert
func (am *alertManager) CreateAlert(alert SecurityAlert) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Set default values
	if alert.ID == "" {
		alert.ID = uuid.New().String()
	}
	if alert.Status == "" {
		alert.Status = AlertStatusActive
	}
	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}
	if alert.TTL == 0 {
		alert.TTL = am.config.DefaultAlertTTL
	}
	if alert.TTL > 0 {
		expiresAt := alert.Timestamp.Add(alert.TTL)
		alert.ExpiresAt = &expiresAt
	}

	// Store alert in database
	if err := am.storeAlert(alert); err != nil {
		return fmt.Errorf("failed to store alert: %w", err)
	}

	// Add to active alerts
	am.activeAlerts[alert.ID] = &alert

	// Process alert rules
	if err := am.processAlertRules(alert); err != nil {
		fmt.Printf("Warning: failed to process alert rules for alert %s: %v\n", alert.ID, err)
	}

	// Send notifications
	if err := am.sendNotifications(alert); err != nil {
		fmt.Printf("Warning: failed to send notifications for alert %s: %v\n", alert.ID, err)
	}

	// Schedule escalation if needed
	if err := am.scheduleEscalation(alert); err != nil {
		fmt.Printf("Warning: failed to schedule escalation for alert %s: %v\n", alert.ID, err)
	}

	return nil
}

// ProcessAlert processes an existing alert
func (am *alertManager) ProcessAlert(alertID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		// Try to load from database
		var err error
		alert, err = am.loadAlert(alertID)
		if err != nil {
			return fmt.Errorf("alert not found: %s", alertID)
		}
		am.activeAlerts[alertID] = alert
	}

	// Check if alert has expired
	if alert.ExpiresAt != nil && time.Now().After(*alert.ExpiresAt) {
		return am.expireAlert(alertID)
	}

	// Process based on current status
	switch alert.Status {
	case AlertStatusActive:
		return am.processActiveAlert(*alert)
	case AlertStatusAcknowledged:
		return am.processAcknowledgedAlert(*alert)
	case AlertStatusResolved:
		return am.processResolvedAlert(*alert)
	default:
		return fmt.Errorf("unknown alert status: %s", alert.Status)
	}
}

// AcknowledgeAlert acknowledges an alert
func (am *alertManager) AcknowledgeAlert(alertID string, acknowledgedBy string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Status != AlertStatusActive {
		return fmt.Errorf("alert is not in active status: %s", alert.Status)
	}

	// Update alert
	now := time.Now()
	alert.Status = AlertStatusAcknowledged
	alert.AcknowledgedBy = acknowledgedBy
	alert.AcknowledgedAt = &now

	// Update in database
	if err := am.updateAlert(*alert); err != nil {
		return fmt.Errorf("failed to update alert: %w", err)
	}

	// Send acknowledgment notifications
	if err := am.sendAcknowledgmentNotifications(*alert); err != nil {
		fmt.Printf("Warning: failed to send acknowledgment notifications: %v\n", err)
	}

	return nil
}

// ResolveAlert resolves an alert
func (am *alertManager) ResolveAlert(alertID string, resolvedBy string, resolution string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	if alert.Status == AlertStatusResolved {
		return fmt.Errorf("alert is already resolved")
	}

	// Update alert
	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.ResolvedBy = resolvedBy
	alert.ResolvedAt = &now
	alert.Resolution = resolution

	// Update in database
	if err := am.updateAlert(*alert); err != nil {
		return fmt.Errorf("failed to update alert: %w", err)
	}

	// Send resolution notifications
	if err := am.sendResolutionNotifications(*alert); err != nil {
		fmt.Printf("Warning: failed to send resolution notifications: %v\n", err)
	}

	// Remove from active alerts
	delete(am.activeAlerts, alertID)

	return nil
}

// GetActiveAlerts returns active alerts with filtering
func (am *alertManager) GetActiveAlerts(filter AlertFilter) ([]SecurityAlert, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	return am.queryAlerts(filter)
}

// GetAlertHistory returns alert history with filtering
func (am *alertManager) GetAlertHistory(filter AlertFilter) ([]SecurityAlert, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Include resolved alerts in history
	if filter.Statuses == nil {
		filter.Statuses = []AlertStatus{AlertStatusActive, AlertStatusAcknowledged, AlertStatusResolved}
	}

	return am.queryAlerts(filter)
}

// GetAlert returns a specific alert
func (am *alertManager) GetAlert(alertID string) (*SecurityAlert, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Check active alerts first
	if alert, exists := am.activeAlerts[alertID]; exists {
		return alert, nil
	}

	// Load from database
	return am.loadAlert(alertID)
}

// ConfigureAlertRules configures alert rules
func (am *alertManager) ConfigureAlertRules(rules []AlertRule) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Validate rules
	for _, rule := range rules {
		if err := am.validateAlertRule(rule); err != nil {
			return fmt.Errorf("invalid alert rule %s: %w", rule.ID, err)
		}
	}

	// Store rules in database
	if err := am.storeAlertRules(rules); err != nil {
		return fmt.Errorf("failed to store alert rules: %w", err)
	}

	am.alertRules = rules
	return nil
}

// GetAlertRules returns current alert rules
func (am *alertManager) GetAlertRules() ([]AlertRule, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Return a copy to prevent external modification
	rules := make([]AlertRule, len(am.alertRules))
	copy(rules, am.alertRules)

	return rules, nil
}

// UpdateAlertRule updates an alert rule
func (am *alertManager) UpdateAlertRule(ruleID string, updates AlertRuleUpdates) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Find the rule
	ruleIndex := -1
	for i, rule := range am.alertRules {
		if rule.ID == ruleID {
			ruleIndex = i
			break
		}
	}

	if ruleIndex == -1 {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}

	// Apply updates
	rule := &am.alertRules[ruleIndex]
	if updates.Name != nil {
		rule.Name = *updates.Name
	}
	if updates.Description != nil {
		rule.Description = *updates.Description
	}
	if updates.Condition != nil {
		rule.Condition = *updates.Condition
	}
	if updates.Threshold != nil {
		rule.Threshold = updates.Threshold
	}
	if updates.Severity != nil {
		rule.Severity = *updates.Severity
	}
	if updates.Enabled != nil {
		rule.Enabled = *updates.Enabled
	}
	if updates.NotificationChannels != nil {
		rule.NotificationChannels = updates.NotificationChannels
	}
	if updates.EscalationPolicy != nil {
		rule.EscalationPolicy = *updates.EscalationPolicy
	}
	if updates.Cooldown != nil {
		rule.Cooldown = *updates.Cooldown
	}
	if updates.Metadata != nil {
		rule.Metadata = updates.Metadata
	}

	rule.UpdatedAt = time.Now()

	// Validate updated rule
	if err := am.validateAlertRule(*rule); err != nil {
		return fmt.Errorf("invalid updated rule: %w", err)
	}

	// Update in database
	if err := am.updateAlertRule(*rule); err != nil {
		return fmt.Errorf("failed to update alert rule: %w", err)
	}

	return nil
}

// DeleteAlertRule deletes an alert rule
func (am *alertManager) DeleteAlertRule(ruleID string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Find and remove the rule
	ruleIndex := -1
	for i, rule := range am.alertRules {
		if rule.ID == ruleID {
			ruleIndex = i
			break
		}
	}

	if ruleIndex == -1 {
		return fmt.Errorf("alert rule not found: %s", ruleID)
	}

	// Remove from slice
	am.alertRules = append(am.alertRules[:ruleIndex], am.alertRules[ruleIndex+1:]...)

	// Delete from database
	if err := am.deleteAlertRule(ruleID); err != nil {
		return fmt.Errorf("failed to delete alert rule: %w", err)
	}

	return nil
}

// SendNotification sends a notification
func (am *alertManager) SendNotification(notification SecurityNotification) error {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Find the notification channel
	var channel *NotificationChannel
	for _, ch := range am.notificationChannels {
		if ch.ID == notification.Channel {
			channel = &ch
			break
		}
	}

	if channel == nil {
		return fmt.Errorf("notification channel not found: %s", notification.Channel)
	}

	// Send notification based on channel type
	return am.sendNotificationToChannel(notification, *channel)
}

// ConfigureNotificationChannels configures notification channels
func (am *alertManager) ConfigureNotificationChannels(channels []NotificationChannel) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Validate channels
	for _, channel := range channels {
		if err := am.validateNotificationChannel(channel); err != nil {
			return fmt.Errorf("invalid notification channel %s: %w", channel.ID, err)
		}
	}

	// Store channels in database
	if err := am.storeNotificationChannels(channels); err != nil {
		return fmt.Errorf("failed to store notification channels: %w", err)
	}

	am.notificationChannels = channels
	return nil
}

// GetNotificationChannels returns current notification channels
func (am *alertManager) GetNotificationChannels() ([]NotificationChannel, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Return a copy to prevent external modification
	channels := make([]NotificationChannel, len(am.notificationChannels))
	copy(channels, am.notificationChannels)

	return channels, nil
}

// TestNotificationChannel tests a notification channel
func (am *alertManager) TestNotificationChannel(channelID string) error {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Find the channel
	var channel *NotificationChannel
	for _, ch := range am.notificationChannels {
		if ch.ID == channelID {
			channel = &ch
			break
		}
	}

	if channel == nil {
		return fmt.Errorf("notification channel not found: %s", channelID)
	}

	// Create test notification
	testNotification := SecurityNotification{
		ID:       uuid.New().String(),
		Type:     "TEST",
		Title:    "Test Notification",
		Message:  "This is a test notification from the Alert Manager",
		Channel:  channelID,
		Priority: "LOW",
	}

	// Send test notification
	return am.sendNotificationToChannel(testNotification, *channel)
}

// ConfigureEscalationPolicies configures escalation policies
func (am *alertManager) ConfigureEscalationPolicies(policies []EscalationPolicy) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	// Validate policies
	for _, policy := range policies {
		if err := am.validateEscalationPolicy(policy); err != nil {
			return fmt.Errorf("invalid escalation policy %s: %w", policy.ID, err)
		}
	}

	// Store policies in database
	if err := am.storeEscalationPolicies(policies); err != nil {
		return fmt.Errorf("failed to store escalation policies: %w", err)
	}

	am.escalationPolicies = policies
	return nil
}

// GetEscalationPolicies returns current escalation policies
func (am *alertManager) GetEscalationPolicies() ([]EscalationPolicy, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Return a copy to prevent external modification
	policies := make([]EscalationPolicy, len(am.escalationPolicies))
	copy(policies, am.escalationPolicies)

	return policies, nil
}

// TriggerEscalation triggers escalation for an alert
func (am *alertManager) TriggerEscalation(alertID string, level EscalationLevel) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	// Update escalation level
	alert.EscalationLevel = int(level)
	now := time.Now()
	alert.LastEscalated = &now

	// Update in database
	if err := am.updateAlert(*alert); err != nil {
		return fmt.Errorf("failed to update alert escalation: %w", err)
	}

	// Process escalation
	return am.processEscalation(*alert, int(level))
}

// Start starts the alert manager
func (am *alertManager) Start() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if am.isRunning {
		return fmt.Errorf("alert manager is already running")
	}

	am.isRunning = true

	// Start notification workers
	for i := 0; i < am.config.MaxConcurrentNotifications; i++ {
		go am.notificationWorker()
	}

	// Start escalation worker
	go am.escalationWorker()

	// Start maintenance worker
	go am.maintenanceWorker()

	return nil
}

// Stop stops the alert manager
func (am *alertManager) Stop() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if !am.isRunning {
		return fmt.Errorf("alert manager is not running")
	}

	// Signal workers to stop
	close(am.stopChan)
	am.isRunning = false

	return nil
}

// Helper methods will be implemented in a separate file for better organization
// This includes database operations, notification sending, escalation processing, etc.

// DefaultAlertManagerConfig returns default configuration for alert manager
func DefaultAlertManagerConfig() *AlertManagerConfig {
	return &AlertManagerConfig{
		MaxConcurrentNotifications: 10,
		NotificationTimeout:        30 * time.Second,
		RetryAttempts:              3,
		RetryDelay:                 5 * time.Second,
		NotificationQueueSize:      1000,
		EscalationQueueSize:        100,
		DefaultAlertTTL:            24 * time.Hour,
		AutoAcknowledgeTimeout:     1 * time.Hour,
		AutoResolveTimeout:         24 * time.Hour,
		DefaultEscalationDelay:     15 * time.Minute,
		MaxEscalationLevel:         4,
		EnableEmailNotifications:   true,
		EnableSlackNotifications:   true,
		EnableWebhookNotifications: true,
		EnableSMSNotifications:     false,
	}
}
