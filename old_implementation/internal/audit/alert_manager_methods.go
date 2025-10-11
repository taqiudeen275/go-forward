package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Database operations

func (am *alertManager) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS security_alerts (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		user_id TEXT,
		resource TEXT,
		query TEXT,
		timestamp DATETIME NOT NULL,
		status TEXT NOT NULL,
		metadata TEXT,
		acknowledged_by TEXT,
		acknowledged_at DATETIME,
		resolved_by TEXT,
		resolved_at DATETIME,
		resolution TEXT,
		escalation_level INTEGER DEFAULT 0,
		last_escalated DATETIME,
		notifications_sent TEXT,
		ttl BIGINT,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS alert_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		condition TEXT NOT NULL,
		threshold TEXT,
		severity TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT true,
		metadata TEXT,
		notification_channels TEXT,
		escalation_policy TEXT,
		cooldown BIGINT,
		last_triggered DATETIME,
		trigger_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT
	);

	CREATE TABLE IF NOT EXISTS notification_channels (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		name TEXT NOT NULL,
		config TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT true,
		description TEXT,
		recipients TEXT,
		filters TEXT,
		rate_limits TEXT,
		last_used DATETIME,
		success_count INTEGER DEFAULT 0,
		failure_count INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS escalation_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		steps TEXT NOT NULL,
		enabled BOOLEAN NOT NULL DEFAULT true,
		metadata TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT
	);

	CREATE TABLE IF NOT EXISTS notification_history (
		id TEXT PRIMARY KEY,
		alert_id TEXT NOT NULL,
		channel_id TEXT NOT NULL,
		channel_type TEXT NOT NULL,
		recipients TEXT,
		sent_at DATETIME NOT NULL,
		status TEXT NOT NULL,
		error TEXT,
		retry_count INTEGER DEFAULT 0,
		FOREIGN KEY (alert_id) REFERENCES security_alerts(id)
	);`

	_, err := am.db.Exec(schema)
	return err
}

func (am *alertManager) loadConfiguration() error {
	// Load alert rules
	if err := am.loadAlertRules(); err != nil {
		return fmt.Errorf("failed to load alert rules: %w", err)
	}

	// Load notification channels
	if err := am.loadNotificationChannels(); err != nil {
		return fmt.Errorf("failed to load notification channels: %w", err)
	}

	// Load escalation policies
	if err := am.loadEscalationPolicies(); err != nil {
		return fmt.Errorf("failed to load escalation policies: %w", err)
	}

	// Load active alerts
	if err := am.loadActiveAlerts(); err != nil {
		return fmt.Errorf("failed to load active alerts: %w", err)
	}

	return nil
}

func (am *alertManager) loadAlertRules() error {
	query := `
		SELECT id, name, description, condition, threshold, severity, enabled,
			   metadata, notification_channels, escalation_policy, cooldown,
			   last_triggered, trigger_count, created_at, updated_at, created_by
		FROM alert_rules WHERE enabled = true`

	rows, err := am.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var rules []AlertRule
	for rows.Next() {
		var rule AlertRule
		var metadataJSON, notificationChannelsJSON, thresholdJSON string
		var cooldownNs sql.NullInt64
		var lastTriggered sql.NullTime

		err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.Condition,
			&thresholdJSON, &rule.Severity, &rule.Enabled, &metadataJSON,
			&notificationChannelsJSON, &rule.EscalationPolicy, &cooldownNs,
			&lastTriggered, &rule.TriggerCount, &rule.CreatedAt, &rule.UpdatedAt,
			&rule.CreatedBy)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &rule.Metadata)
		}
		if notificationChannelsJSON != "" {
			json.Unmarshal([]byte(notificationChannelsJSON), &rule.NotificationChannels)
		}
		if thresholdJSON != "" {
			json.Unmarshal([]byte(thresholdJSON), &rule.Threshold)
		}

		// Handle nullable fields
		if cooldownNs.Valid {
			rule.Cooldown = time.Duration(cooldownNs.Int64)
		}
		if lastTriggered.Valid {
			rule.LastTriggered = &lastTriggered.Time
		}

		rules = append(rules, rule)
	}

	am.alertRules = rules
	return nil
}

func (am *alertManager) loadNotificationChannels() error {
	query := `
		SELECT id, type, name, config, enabled, description, recipients,
			   filters, rate_limits, last_used, success_count, failure_count,
			   created_at, updated_at
		FROM notification_channels WHERE enabled = true`

	rows, err := am.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var channels []NotificationChannel
	for rows.Next() {
		var channel NotificationChannel
		var configJSON, recipientsJSON, filtersJSON, rateLimitsJSON string
		var lastUsed sql.NullTime

		err := rows.Scan(&channel.ID, &channel.Type, &channel.Name, &configJSON,
			&channel.Enabled, &channel.Description, &recipientsJSON, &filtersJSON,
			&rateLimitsJSON, &lastUsed, &channel.SuccessCount, &channel.FailureCount,
			&channel.CreatedAt, &channel.UpdatedAt)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if configJSON != "" {
			json.Unmarshal([]byte(configJSON), &channel.Config)
		}
		if recipientsJSON != "" {
			json.Unmarshal([]byte(recipientsJSON), &channel.Recipients)
		}
		if filtersJSON != "" {
			json.Unmarshal([]byte(filtersJSON), &channel.Filters)
		}
		if rateLimitsJSON != "" {
			json.Unmarshal([]byte(rateLimitsJSON), &channel.RateLimits)
		}

		// Handle nullable fields
		if lastUsed.Valid {
			channel.LastUsed = &lastUsed.Time
		}

		channels = append(channels, channel)
	}

	am.notificationChannels = channels
	return nil
}

func (am *alertManager) loadEscalationPolicies() error {
	query := `
		SELECT id, name, description, steps, enabled, metadata,
			   created_at, updated_at, created_by
		FROM escalation_policies WHERE enabled = true`

	rows, err := am.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	var policies []EscalationPolicy
	for rows.Next() {
		var policy EscalationPolicy
		var stepsJSON, metadataJSON string

		err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &stepsJSON,
			&policy.Enabled, &metadataJSON, &policy.CreatedAt, &policy.UpdatedAt,
			&policy.CreatedBy)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if stepsJSON != "" {
			json.Unmarshal([]byte(stepsJSON), &policy.Steps)
		}
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &policy.Metadata)
		}

		policies = append(policies, policy)
	}

	am.escalationPolicies = policies
	return nil
}

func (am *alertManager) loadActiveAlerts() error {
	query := `
		SELECT id, type, severity, title, description, user_id, resource, query,
			   timestamp, status, metadata, acknowledged_by, acknowledged_at,
			   resolved_by, resolved_at, resolution, escalation_level,
			   last_escalated, notifications_sent, ttl, expires_at
		FROM security_alerts 
		WHERE status IN ('ACTIVE', 'ACKNOWLEDGED') 
		AND (expires_at IS NULL OR expires_at > datetime('now'))`

	rows, err := am.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var alert SecurityAlert
		var metadataJSON, notificationsJSON string
		var acknowledgedAt, resolvedAt, lastEscalated, expiresAt sql.NullTime
		var ttlNs sql.NullInt64

		err := rows.Scan(&alert.ID, &alert.Type, &alert.Severity, &alert.Title,
			&alert.Description, &alert.UserID, &alert.Resource, &alert.Query,
			&alert.Timestamp, &alert.Status, &metadataJSON, &alert.AcknowledgedBy,
			&acknowledgedAt, &alert.ResolvedBy, &resolvedAt, &alert.Resolution,
			&alert.EscalationLevel, &lastEscalated, &notificationsJSON, &ttlNs,
			&expiresAt)
		if err != nil {
			continue
		}

		// Parse JSON fields
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &alert.Metadata)
		}
		if notificationsJSON != "" {
			json.Unmarshal([]byte(notificationsJSON), &alert.NotificationsSent)
		}

		// Handle nullable fields
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}
		if lastEscalated.Valid {
			alert.LastEscalated = &lastEscalated.Time
		}
		if expiresAt.Valid {
			alert.ExpiresAt = &expiresAt.Time
		}
		if ttlNs.Valid {
			alert.TTL = time.Duration(ttlNs.Int64)
		}

		am.activeAlerts[alert.ID] = &alert
	}

	return nil
}

func (am *alertManager) storeAlert(alert SecurityAlert) error {
	metadataJSON, _ := json.Marshal(alert.Metadata)
	notificationsJSON, _ := json.Marshal(alert.NotificationsSent)

	query := `
		INSERT INTO security_alerts (
			id, type, severity, title, description, user_id, resource, query,
			timestamp, status, metadata, acknowledged_by, acknowledged_at,
			resolved_by, resolved_at, resolution, escalation_level,
			last_escalated, notifications_sent, ttl, expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var acknowledgedAt, resolvedAt, lastEscalated, expiresAt sql.NullTime
	var ttlNs sql.NullInt64

	if alert.AcknowledgedAt != nil {
		acknowledgedAt.Valid = true
		acknowledgedAt.Time = *alert.AcknowledgedAt
	}
	if alert.ResolvedAt != nil {
		resolvedAt.Valid = true
		resolvedAt.Time = *alert.ResolvedAt
	}
	if alert.LastEscalated != nil {
		lastEscalated.Valid = true
		lastEscalated.Time = *alert.LastEscalated
	}
	if alert.ExpiresAt != nil {
		expiresAt.Valid = true
		expiresAt.Time = *alert.ExpiresAt
	}
	if alert.TTL > 0 {
		ttlNs.Valid = true
		ttlNs.Int64 = int64(alert.TTL)
	}

	_, err := am.db.Exec(query, alert.ID, alert.Type, alert.Severity, alert.Title,
		alert.Description, alert.UserID, alert.Resource, alert.Query,
		alert.Timestamp, alert.Status, string(metadataJSON), alert.AcknowledgedBy,
		acknowledgedAt, alert.ResolvedBy, resolvedAt, alert.Resolution,
		alert.EscalationLevel, lastEscalated, string(notificationsJSON), ttlNs,
		expiresAt)

	return err
}

func (am *alertManager) updateAlert(alert SecurityAlert) error {
	metadataJSON, _ := json.Marshal(alert.Metadata)
	notificationsJSON, _ := json.Marshal(alert.NotificationsSent)

	query := `
		UPDATE security_alerts SET
			status = ?, metadata = ?, acknowledged_by = ?, acknowledged_at = ?,
			resolved_by = ?, resolved_at = ?, resolution = ?, escalation_level = ?,
			last_escalated = ?, notifications_sent = ?, updated_at = datetime('now')
		WHERE id = ?`

	var acknowledgedAt, resolvedAt, lastEscalated sql.NullTime

	if alert.AcknowledgedAt != nil {
		acknowledgedAt.Valid = true
		acknowledgedAt.Time = *alert.AcknowledgedAt
	}
	if alert.ResolvedAt != nil {
		resolvedAt.Valid = true
		resolvedAt.Time = *alert.ResolvedAt
	}
	if alert.LastEscalated != nil {
		lastEscalated.Valid = true
		lastEscalated.Time = *alert.LastEscalated
	}

	_, err := am.db.Exec(query, alert.Status, string(metadataJSON),
		alert.AcknowledgedBy, acknowledgedAt, alert.ResolvedBy, resolvedAt,
		alert.Resolution, alert.EscalationLevel, lastEscalated,
		string(notificationsJSON), alert.ID)

	return err
}

func (am *alertManager) loadAlert(alertID string) (*SecurityAlert, error) {
	query := `
		SELECT id, type, severity, title, description, user_id, resource, query,
			   timestamp, status, metadata, acknowledged_by, acknowledged_at,
			   resolved_by, resolved_at, resolution, escalation_level,
			   last_escalated, notifications_sent, ttl, expires_at
		FROM security_alerts WHERE id = ?`

	var alert SecurityAlert
	var metadataJSON, notificationsJSON string
	var acknowledgedAt, resolvedAt, lastEscalated, expiresAt sql.NullTime
	var ttlNs sql.NullInt64

	err := am.db.QueryRow(query, alertID).Scan(&alert.ID, &alert.Type,
		&alert.Severity, &alert.Title, &alert.Description, &alert.UserID,
		&alert.Resource, &alert.Query, &alert.Timestamp, &alert.Status,
		&metadataJSON, &alert.AcknowledgedBy, &acknowledgedAt, &alert.ResolvedBy,
		&resolvedAt, &alert.Resolution, &alert.EscalationLevel, &lastEscalated,
		&notificationsJSON, &ttlNs, &expiresAt)

	if err != nil {
		return nil, err
	}

	// Parse JSON fields
	if metadataJSON != "" {
		json.Unmarshal([]byte(metadataJSON), &alert.Metadata)
	}
	if notificationsJSON != "" {
		json.Unmarshal([]byte(notificationsJSON), &alert.NotificationsSent)
	}

	// Handle nullable fields
	if acknowledgedAt.Valid {
		alert.AcknowledgedAt = &acknowledgedAt.Time
	}
	if resolvedAt.Valid {
		alert.ResolvedAt = &resolvedAt.Time
	}
	if lastEscalated.Valid {
		alert.LastEscalated = &lastEscalated.Time
	}
	if expiresAt.Valid {
		alert.ExpiresAt = &expiresAt.Time
	}
	if ttlNs.Valid {
		alert.TTL = time.Duration(ttlNs.Int64)
	}

	return &alert, nil
}

func (am *alertManager) queryAlerts(filter AlertFilter) ([]SecurityAlert, error) {
	query := "SELECT * FROM security_alerts WHERE 1=1"
	args := []interface{}{}

	// Apply filters
	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, alertType := range filter.Types {
			placeholders[i] = "?"
			args = append(args, alertType)
		}
		query += fmt.Sprintf(" AND type IN (%s)", strings.Join(placeholders, ","))
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, severity := range filter.Severities {
			placeholders[i] = "?"
			args = append(args, severity)
		}
		query += fmt.Sprintf(" AND severity IN (%s)", strings.Join(placeholders, ","))
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, status := range filter.Statuses {
			placeholders[i] = "?"
			args = append(args, status)
		}
		query += fmt.Sprintf(" AND status IN (%s)", strings.Join(placeholders, ","))
	}

	if filter.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, *filter.EndTime)
	}

	if filter.Acknowledged != nil {
		if *filter.Acknowledged {
			query += " AND acknowledged_at IS NOT NULL"
		} else {
			query += " AND acknowledged_at IS NULL"
		}
	}

	if filter.Resolved != nil {
		if *filter.Resolved {
			query += " AND resolved_at IS NOT NULL"
		} else {
			query += " AND resolved_at IS NULL"
		}
	}

	// Add sorting
	if filter.SortBy != "" {
		order := "ASC"
		if filter.SortOrder == "desc" {
			order = "DESC"
		}
		query += fmt.Sprintf(" ORDER BY %s %s", filter.SortBy, order)
	} else {
		query += " ORDER BY timestamp DESC"
	}

	// Add pagination
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := am.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []SecurityAlert
	for rows.Next() {
		var alert SecurityAlert
		var metadataJSON, notificationsJSON string
		var acknowledgedAt, resolvedAt, lastEscalated, expiresAt sql.NullTime
		var ttlNs sql.NullInt64

		err := rows.Scan(&alert.ID, &alert.Type, &alert.Severity, &alert.Title,
			&alert.Description, &alert.UserID, &alert.Resource, &alert.Query,
			&alert.Timestamp, &alert.Status, &metadataJSON, &alert.AcknowledgedBy,
			&acknowledgedAt, &alert.ResolvedBy, &resolvedAt, &alert.Resolution,
			&alert.EscalationLevel, &lastEscalated, &notificationsJSON, &ttlNs,
			&expiresAt)
		if err != nil {
			continue
		}

		// Parse JSON fields and handle nullable fields (same as loadAlert)
		if metadataJSON != "" {
			json.Unmarshal([]byte(metadataJSON), &alert.Metadata)
		}
		if notificationsJSON != "" {
			json.Unmarshal([]byte(notificationsJSON), &alert.NotificationsSent)
		}
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}
		if lastEscalated.Valid {
			alert.LastEscalated = &lastEscalated.Time
		}
		if expiresAt.Valid {
			alert.ExpiresAt = &expiresAt.Time
		}
		if ttlNs.Valid {
			alert.TTL = time.Duration(ttlNs.Int64)
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// Alert processing methods

func (am *alertManager) processAlertRules(alert SecurityAlert) error {
	for _, rule := range am.alertRules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown
		if rule.LastTriggered != nil && rule.Cooldown > 0 {
			if time.Since(*rule.LastTriggered) < rule.Cooldown {
				continue
			}
		}

		// Evaluate rule condition
		if am.evaluateRuleCondition(rule, alert) {
			// Update rule trigger info
			now := time.Now()
			rule.LastTriggered = &now
			rule.TriggerCount++
			am.updateAlertRule(rule)

			// Process rule actions (notifications, escalations, etc.)
			if err := am.processRuleActions(rule, alert); err != nil {
				fmt.Printf("Warning: failed to process rule actions for rule %s: %v\n", rule.ID, err)
			}
		}
	}

	return nil
}

func (am *alertManager) evaluateRuleCondition(rule AlertRule, alert SecurityAlert) bool {
	// This is a simplified rule evaluation
	// In a real implementation, this would parse and evaluate complex conditions

	condition := strings.ToLower(rule.Condition)

	// Check severity condition
	if strings.Contains(condition, "severity") {
		if strings.Contains(condition, strings.ToLower(string(alert.Severity))) {
			return true
		}
	}

	// Check type condition
	if strings.Contains(condition, "type") {
		if strings.Contains(condition, strings.ToLower(string(alert.Type))) {
			return true
		}
	}

	// Check user condition
	if strings.Contains(condition, "user") && alert.UserID != "" {
		if strings.Contains(condition, alert.UserID) {
			return true
		}
	}

	return false
}

func (am *alertManager) processRuleActions(rule AlertRule, alert SecurityAlert) error {
	// Send notifications to configured channels
	for _, channelID := range rule.NotificationChannels {
		task := NotificationTask{
			AlertID:     alert.ID,
			Alert:       alert,
			ChannelID:   channelID,
			Priority:    am.severityToPriority(alert.Severity),
			RetryCount:  0,
			ScheduledAt: time.Now(),
		}

		// Find the channel
		for _, channel := range am.notificationChannels {
			if channel.ID == channelID {
				task.Channel = channel
				task.Recipients = channel.Recipients
				break
			}
		}

		// Queue notification
		select {
		case am.notificationQueue <- task:
		default:
			fmt.Printf("Warning: notification queue is full, dropping notification for alert %s\n", alert.ID)
		}
	}

	// Schedule escalation if policy is configured
	if rule.EscalationPolicy != "" {
		escalationTask := EscalationTask{
			AlertID:     alert.ID,
			Alert:       alert,
			PolicyID:    rule.EscalationPolicy,
			Level:       1,
			ScheduledAt: time.Now().Add(am.config.DefaultEscalationDelay),
		}

		// Find the escalation policy
		for _, policy := range am.escalationPolicies {
			if policy.ID == rule.EscalationPolicy {
				escalationTask.Policy = policy
				break
			}
		}

		// Queue escalation
		select {
		case am.escalationQueue <- escalationTask:
		default:
			fmt.Printf("Warning: escalation queue is full, dropping escalation for alert %s\n", alert.ID)
		}
	}

	return nil
}

func (am *alertManager) severityToPriority(severity SecuritySeverity) NotificationPriority {
	switch severity {
	case SeverityCritical:
		return PriorityCritical
	case SeverityHigh:
		return PriorityHigh
	case SeverityMedium:
		return PriorityMedium
	case SeverityLow:
		return PriorityLow
	default:
		return PriorityMedium
	}
}

// Notification methods

func (am *alertManager) sendNotifications(alert SecurityAlert) error {
	// This would be called when an alert is created
	// For now, just log that notifications would be sent
	fmt.Printf("Sending notifications for alert %s (severity: %s)\n", alert.ID, alert.Severity)
	return nil
}

func (am *alertManager) sendNotificationToChannel(notification SecurityNotification, channel NotificationChannel) error {
	switch channel.Type {
	case ChannelTypeEmail:
		return am.sendEmailNotification(notification, channel)
	case ChannelTypeSlack:
		return am.sendSlackNotification(notification, channel)
	case ChannelTypeWebhook:
		return am.sendWebhookNotification(notification, channel)
	case ChannelTypeSMS:
		return am.sendSMSNotification(notification, channel)
	default:
		return fmt.Errorf("unsupported notification channel type: %s", channel.Type)
	}
}

func (am *alertManager) sendEmailNotification(notification SecurityNotification, channel NotificationChannel) error {
	// Placeholder for email notification implementation
	fmt.Printf("Sending email notification: %s to %v\n", notification.Title, channel.Recipients)
	return nil
}

func (am *alertManager) sendSlackNotification(notification SecurityNotification, channel NotificationChannel) error {
	// Placeholder for Slack notification implementation
	fmt.Printf("Sending Slack notification: %s\n", notification.Title)
	return nil
}

func (am *alertManager) sendWebhookNotification(notification SecurityNotification, channel NotificationChannel) error {
	// Placeholder for webhook notification implementation
	webhookURL, exists := channel.Config["webhook_url"]
	if !exists {
		return fmt.Errorf("webhook URL not configured")
	}

	// In a real implementation, this would make an HTTP POST request
	fmt.Printf("Sending webhook notification to %s: %s\n", webhookURL, notification.Title)
	return nil
}

func (am *alertManager) sendSMSNotification(notification SecurityNotification, channel NotificationChannel) error {
	// Placeholder for SMS notification implementation
	fmt.Printf("Sending SMS notification: %s to %v\n", notification.Title, channel.Recipients)
	return nil
}

func (am *alertManager) sendAcknowledgmentNotifications(alert SecurityAlert) error {
	// Send notifications about alert acknowledgment
	fmt.Printf("Alert %s acknowledged by %s\n", alert.ID, alert.AcknowledgedBy)
	return nil
}

func (am *alertManager) sendResolutionNotifications(alert SecurityAlert) error {
	// Send notifications about alert resolution
	fmt.Printf("Alert %s resolved by %s: %s\n", alert.ID, alert.ResolvedBy, alert.Resolution)
	return nil
}

// Worker methods

func (am *alertManager) notificationWorker() {
	for {
		select {
		case <-am.stopChan:
			return
		case task := <-am.notificationQueue:
			am.processNotificationTask(task)
		}
	}
}

func (am *alertManager) processNotificationTask(task NotificationTask) {
	// Create notification
	notification := SecurityNotification{
		ID:       uuid.New().String(),
		Type:     string(task.Alert.Type),
		Title:    task.Alert.Title,
		Message:  task.Alert.Description,
		Channel:  task.ChannelID,
		Priority: task.Priority.String(),
	}

	// Send notification
	err := am.sendNotificationToChannel(notification, task.Channel)

	// Record notification attempt
	record := NotificationRecord{
		ID:          uuid.New().String(),
		ChannelID:   task.ChannelID,
		ChannelType: task.Channel.Type,
		Recipients:  task.Recipients,
		SentAt:      time.Now(),
		RetryCount:  task.RetryCount,
	}

	if err != nil {
		record.Status = NotificationStatusFailed
		record.Error = err.Error()

		// Retry if under retry limit
		if task.RetryCount < am.config.RetryAttempts {
			task.RetryCount++
			task.ScheduledAt = time.Now().Add(am.config.RetryDelay)

			// Re-queue for retry
			go func() {
				time.Sleep(am.config.RetryDelay)
				select {
				case am.notificationQueue <- task:
				default:
					fmt.Printf("Failed to re-queue notification for retry\n")
				}
			}()
		}
	} else {
		record.Status = NotificationStatusSent
	}

	// Store notification record
	am.storeNotificationRecord(task.AlertID, record)
}

func (am *alertManager) escalationWorker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopChan:
			return
		case <-ticker.C:
			am.processScheduledEscalations()
		case task := <-am.escalationQueue:
			am.processEscalationTask(task)
		}
	}
}

func (am *alertManager) processEscalationTask(task EscalationTask) {
	// Check if alert still needs escalation
	alert, exists := am.activeAlerts[task.AlertID]
	if !exists || alert.Status == AlertStatusResolved {
		return
	}

	// Process escalation based on policy
	if err := am.processEscalation(*alert, task.Level); err != nil {
		fmt.Printf("Failed to process escalation for alert %s: %v\n", task.AlertID, err)
	}
}

func (am *alertManager) processScheduledEscalations() {
	// Check for alerts that need escalation
	for _, alert := range am.activeAlerts {
		if alert.Status == AlertStatusActive {
			// Check if escalation is due
			if am.shouldEscalateAlert(*alert) {
				am.processEscalation(*alert, alert.EscalationLevel+1)
			}
		}
	}
}

func (am *alertManager) shouldEscalateAlert(alert SecurityAlert) bool {
	// Check if enough time has passed for escalation
	timeSinceLastEscalation := time.Since(alert.Timestamp)

	if alert.LastEscalated != nil {
		timeSinceLastEscalation = time.Since(*alert.LastEscalated)
	}

	// Escalate if alert has been active for escalation delay
	return timeSinceLastEscalation >= am.config.DefaultEscalationDelay &&
		alert.EscalationLevel < am.config.MaxEscalationLevel
}

func (am *alertManager) processEscalation(alert SecurityAlert, level int) error {
	// Find escalation policy
	var policy *EscalationPolicy
	for _, rule := range am.alertRules {
		if rule.EscalationPolicy != "" {
			for _, p := range am.escalationPolicies {
				if p.ID == rule.EscalationPolicy {
					policy = &p
					break
				}
			}
		}
	}

	if policy == nil {
		return fmt.Errorf("no escalation policy found for alert %s", alert.ID)
	}

	// Find escalation step
	var step *EscalationStep
	for _, s := range policy.Steps {
		if s.Level == level {
			step = &s
			break
		}
	}

	if step == nil {
		return fmt.Errorf("no escalation step found for level %d", level)
	}

	// Send notifications to escalation channels
	for _, channelID := range step.NotificationChannels {
		task := NotificationTask{
			AlertID:     alert.ID,
			Alert:       alert,
			ChannelID:   channelID,
			Priority:    PriorityCritical, // Escalated alerts are high priority
			RetryCount:  0,
			ScheduledAt: time.Now(),
		}

		// Find the channel
		for _, channel := range am.notificationChannels {
			if channel.ID == channelID {
				task.Channel = channel
				task.Recipients = channel.Recipients
				break
			}
		}

		// Queue notification
		select {
		case am.notificationQueue <- task:
		default:
			fmt.Printf("Warning: notification queue is full during escalation\n")
		}
	}

	return nil
}

func (am *alertManager) maintenanceWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-am.stopChan:
			return
		case <-ticker.C:
			am.performMaintenance()
		}
	}
}

func (am *alertManager) performMaintenance() {
	// Clean up expired alerts
	am.cleanupExpiredAlerts()

	// Auto-acknowledge old alerts if configured
	am.autoAcknowledgeAlerts()

	// Auto-resolve old alerts if configured
	am.autoResolveAlerts()

	// Clean up old notification records
	am.cleanupNotificationHistory()
}

func (am *alertManager) cleanupExpiredAlerts() {
	now := time.Now()
	for alertID, alert := range am.activeAlerts {
		if alert.ExpiresAt != nil && now.After(*alert.ExpiresAt) {
			am.expireAlert(alertID)
		}
	}
}

func (am *alertManager) expireAlert(alertID string) error {
	alert, exists := am.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	// Mark as resolved with expiration
	now := time.Now()
	alert.Status = AlertStatusResolved
	alert.ResolvedBy = "SYSTEM"
	alert.ResolvedAt = &now
	alert.Resolution = "Alert expired"

	// Update in database
	if err := am.updateAlert(*alert); err != nil {
		return fmt.Errorf("failed to update expired alert: %w", err)
	}

	// Remove from active alerts
	delete(am.activeAlerts, alertID)

	return nil
}

func (am *alertManager) autoAcknowledgeAlerts() {
	if am.config.AutoAcknowledgeTimeout == 0 {
		return
	}

	threshold := time.Now().Add(-am.config.AutoAcknowledgeTimeout)
	for _, alert := range am.activeAlerts {
		if alert.Status == AlertStatusActive && alert.Timestamp.Before(threshold) {
			am.AcknowledgeAlert(alert.ID, "SYSTEM")
		}
	}
}

func (am *alertManager) autoResolveAlerts() {
	if am.config.AutoResolveTimeout == 0 {
		return
	}

	threshold := time.Now().Add(-am.config.AutoResolveTimeout)
	for _, alert := range am.activeAlerts {
		if alert.Status == AlertStatusAcknowledged && alert.Timestamp.Before(threshold) {
			am.ResolveAlert(alert.ID, "SYSTEM", "Auto-resolved due to timeout")
		}
	}
}

func (am *alertManager) cleanupNotificationHistory() {
	// Clean up notification history older than 30 days
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	query := "DELETE FROM notification_history WHERE sent_at < ?"
	am.db.Exec(query, cutoff)
}

// Validation and helper methods

func (am *alertManager) validateAlertRule(rule AlertRule) error {
	if rule.ID == "" || rule.Name == "" {
		return fmt.Errorf("rule ID and name are required")
	}
	if rule.Condition == "" {
		return fmt.Errorf("rule condition is required")
	}
	return nil
}

func (am *alertManager) validateNotificationChannel(channel NotificationChannel) error {
	if channel.ID == "" || channel.Name == "" {
		return fmt.Errorf("channel ID and name are required")
	}
	if channel.Type == "" {
		return fmt.Errorf("channel type is required")
	}
	return nil
}

func (am *alertManager) validateEscalationPolicy(policy EscalationPolicy) error {
	if policy.ID == "" || policy.Name == "" {
		return fmt.Errorf("policy ID and name are required")
	}
	if len(policy.Steps) == 0 {
		return fmt.Errorf("policy must have at least one step")
	}
	return nil
}

// Additional database operations

func (am *alertManager) storeAlertRules(rules []AlertRule) error {
	// This would implement bulk storage of alert rules
	return nil
}

func (am *alertManager) updateAlertRule(rule AlertRule) error {
	// This would implement alert rule updates
	return nil
}

func (am *alertManager) deleteAlertRule(ruleID string) error {
	query := "DELETE FROM alert_rules WHERE id = ?"
	_, err := am.db.Exec(query, ruleID)
	return err
}

func (am *alertManager) storeNotificationChannels(channels []NotificationChannel) error {
	// This would implement bulk storage of notification channels
	return nil
}

func (am *alertManager) storeEscalationPolicies(policies []EscalationPolicy) error {
	// This would implement bulk storage of escalation policies
	return nil
}

func (am *alertManager) storeNotificationRecord(alertID string, record NotificationRecord) error {
	query := `
		INSERT INTO notification_history (
			id, alert_id, channel_id, channel_type, recipients,
			sent_at, status, error, retry_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	recipientsJSON, _ := json.Marshal(record.Recipients)

	_, err := am.db.Exec(query, record.ID, alertID, record.ChannelID,
		record.ChannelType, string(recipientsJSON), record.SentAt,
		record.Status, record.Error, record.RetryCount)

	return err
}

// Process methods for different alert states

func (am *alertManager) processActiveAlert(alert SecurityAlert) error {
	// Process active alert (check for escalation, etc.)
	return nil
}

func (am *alertManager) processAcknowledgedAlert(alert SecurityAlert) error {
	// Process acknowledged alert (check for auto-resolution, etc.)
	return nil
}

func (am *alertManager) processResolvedAlert(alert SecurityAlert) error {
	// Process resolved alert (cleanup, archival, etc.)
	return nil
}

func (am *alertManager) scheduleEscalation(alert SecurityAlert) error {
	// Schedule escalation for the alert if needed
	return nil
}
