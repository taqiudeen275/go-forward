package audit

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// NewPatternDetector creates a new pattern detector
func NewPatternDetector(config *PatternDetectorConfig) *PatternDetector {
	detector := &PatternDetector{
		config:         config,
		knownPatterns:  make([]ThreatPattern, 0),
		customPatterns: make([]ThreatPattern, 0),
	}

	// Load built-in patterns if enabled
	if config.EnableBuiltinPatterns {
		detector.loadBuiltinPatterns()
	}

	return detector
}

// DetectPatterns detects suspicious patterns in security events
func (pd *PatternDetector) DetectPatterns(events []SecurityEvent) ([]SuspiciousPattern, error) {
	pd.mutex.RLock()
	defer pd.mutex.RUnlock()

	var suspiciousPatterns []SuspiciousPattern

	// Combine all patterns
	allPatterns := append(pd.knownPatterns, pd.customPatterns...)

	// Check each pattern against the events
	for _, pattern := range allPatterns {
		matches := pd.findPatternMatches(pattern, events)
		if len(matches) > 0 {
			suspiciousPattern := SuspiciousPattern{
				ID:          uuid.New().String(),
				Type:        string(pattern.Type),
				Description: pattern.Description,
				Pattern:     pattern.Pattern,
				Confidence:  pattern.Confidence,
				Events:      matches,
				Indicators:  pd.extractIndicators(pattern, matches),
				Timestamp:   time.Now(),
			}
			suspiciousPatterns = append(suspiciousPatterns, suspiciousPattern)
		}
	}

	// Detect correlation patterns
	correlationPatterns := pd.detectCorrelationPatterns(events)
	suspiciousPatterns = append(suspiciousPatterns, correlationPatterns...)

	// Detect sequence patterns
	sequencePatterns := pd.detectSequencePatterns(events)
	suspiciousPatterns = append(suspiciousPatterns, sequencePatterns...)

	return suspiciousPatterns, nil
}

// GetKnownPatterns returns all known threat patterns
func (pd *PatternDetector) GetKnownPatterns() []ThreatPattern {
	pd.mutex.RLock()
	defer pd.mutex.RUnlock()

	// Return a copy to prevent external modification
	patterns := make([]ThreatPattern, 0, len(pd.knownPatterns)+len(pd.customPatterns))
	patterns = append(patterns, pd.knownPatterns...)
	patterns = append(patterns, pd.customPatterns...)

	return patterns
}

// AddCustomPattern adds a custom threat pattern
func (pd *PatternDetector) AddCustomPattern(pattern ThreatPattern) error {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()

	// Validate pattern
	if err := pd.validatePattern(pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	// Set timestamps
	pattern.ID = uuid.New().String()
	pattern.CreatedAt = time.Now()
	pattern.UpdatedAt = time.Now()

	pd.customPatterns = append(pd.customPatterns, pattern)
	return nil
}

// RemoveCustomPattern removes a custom threat pattern
func (pd *PatternDetector) RemoveCustomPattern(patternID string) error {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()

	for i, pattern := range pd.customPatterns {
		if pattern.ID == patternID {
			// Remove pattern from slice
			pd.customPatterns = append(pd.customPatterns[:i], pd.customPatterns[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("pattern not found: %s", patternID)
}

// Helper methods

func (pd *PatternDetector) loadBuiltinPatterns() {
	// Brute force attack patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_brute_force_1",
		Name:        "Multiple Failed Login Attempts",
		Description: "Multiple failed login attempts from the same IP or user",
		Pattern:     "failed_login_attempts >= 5 AND time_window <= 15m",
		Type:        PatternTypeBruteForce,
		Severity:    SeverityHigh,
		Confidence:  0.9,
		Indicators:  []string{"failed_login", "multiple_attempts", "short_timeframe"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Privilege escalation patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_priv_esc_1",
		Name:        "Rapid Permission Changes",
		Description: "Rapid succession of permission or role changes",
		Pattern:     "permission_changes >= 3 AND time_window <= 5m",
		Type:        PatternTypePrivEscalation,
		Severity:    SeverityCritical,
		Confidence:  0.85,
		Indicators:  []string{"permission_change", "role_modification", "rapid_succession"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Data exfiltration patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_data_exfil_1",
		Name:        "Large Data Export",
		Description: "Unusually large data export operations",
		Pattern:     "data_export_size >= 100MB OR export_count >= 10",
		Type:        PatternTypeDataExfiltration,
		Severity:    SeverityHigh,
		Confidence:  0.8,
		Indicators:  []string{"large_export", "bulk_data", "unusual_volume"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Anomalous access patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_anomalous_1",
		Name:        "Off-Hours Access",
		Description: "Access during unusual hours or from unusual locations",
		Pattern:     "access_time NOT IN business_hours OR location_change > 1000km",
		Type:        PatternTypeAnomalousAccess,
		Severity:    SeverityMedium,
		Confidence:  0.7,
		Indicators:  []string{"off_hours", "unusual_location", "geographic_anomaly"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// SQL injection patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_sql_injection_1",
		Name:        "SQL Injection Attempt",
		Description: "Potential SQL injection in queries or parameters",
		Pattern:     "query CONTAINS ('OR 1=1' OR 'UNION SELECT' OR 'DROP TABLE')",
		Type:        PatternTypeInjection,
		Severity:    SeverityCritical,
		Confidence:  0.95,
		Indicators:  []string{"sql_injection", "malicious_query", "injection_attempt"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Reconnaissance patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_recon_1",
		Name:        "System Enumeration",
		Description: "Systematic enumeration of system resources",
		Pattern:     "list_operations >= 20 AND unique_resources >= 10 AND time_window <= 30m",
		Type:        PatternTypeReconnaissance,
		Severity:    SeverityMedium,
		Confidence:  0.75,
		Indicators:  []string{"enumeration", "systematic_access", "information_gathering"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})

	// Insider threat patterns
	pd.knownPatterns = append(pd.knownPatterns, ThreatPattern{
		ID:          "builtin_insider_1",
		Name:        "Unusual Data Access Pattern",
		Description: "Access to data outside normal job function",
		Pattern:     "data_access_outside_role = true AND access_volume > baseline * 3",
		Type:        PatternTypeInsiderThreat,
		Severity:    SeverityHigh,
		Confidence:  0.8,
		Indicators:  []string{"role_deviation", "excessive_access", "insider_behavior"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	})
}

func (pd *PatternDetector) findPatternMatches(pattern ThreatPattern, events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	switch pattern.Type {
	case PatternTypeBruteForce:
		matches = pd.detectBruteForcePattern(events)
	case PatternTypePrivEscalation:
		matches = pd.detectPrivilegeEscalationPattern(events)
	case PatternTypeDataExfiltration:
		matches = pd.detectDataExfiltrationPattern(events)
	case PatternTypeAnomalousAccess:
		matches = pd.detectAnomalousAccessPattern(events)
	case PatternTypeInjection:
		matches = pd.detectInjectionPattern(events)
	case PatternTypeReconnaissance:
		matches = pd.detectReconnaissancePattern(events)
	case PatternTypeInsiderThreat:
		matches = pd.detectInsiderThreatPattern(events)
	}

	return matches
}

func (pd *PatternDetector) detectBruteForcePattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	// Group events by user and IP
	userIPEvents := make(map[string][]SecurityEvent)

	for _, event := range events {
		if strings.Contains(event.Type, "LOGIN_FAILED") || strings.Contains(event.Type, "AUTH_FAILED") {
			key := fmt.Sprintf("%s_%s", event.UserID, event.Context.IPAddress)
			userIPEvents[key] = append(userIPEvents[key], event)
		}
	}

	// Check for brute force patterns
	for _, eventGroup := range userIPEvents {
		if len(eventGroup) >= 5 { // 5 or more failed attempts
			// Check if they occurred within 15 minutes
			if pd.eventsWithinTimeWindow(eventGroup, 15*time.Minute) {
				matches = append(matches, eventGroup...)
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectPrivilegeEscalationPattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	// Look for rapid permission changes
	permissionEvents := make([]SecurityEvent, 0)

	for _, event := range events {
		if strings.Contains(event.Type, "PERMISSION") || strings.Contains(event.Type, "ROLE") {
			permissionEvents = append(permissionEvents, event)
		}
	}

	// Group by user
	userEvents := make(map[string][]SecurityEvent)
	for _, event := range permissionEvents {
		userEvents[event.UserID] = append(userEvents[event.UserID], event)
	}

	// Check for rapid changes
	for _, eventGroup := range userEvents {
		if len(eventGroup) >= 3 { // 3 or more permission changes
			if pd.eventsWithinTimeWindow(eventGroup, 5*time.Minute) {
				matches = append(matches, eventGroup...)
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectDataExfiltrationPattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	for _, event := range events {
		if strings.Contains(event.Type, "EXPORT") || strings.Contains(event.Type, "DOWNLOAD") {
			// Check for large data exports (simplified)
			if event.Context.Metadata != nil {
				if size, exists := event.Context.Metadata["data_size"]; exists {
					if sizeFloat, ok := size.(float64); ok && sizeFloat > 100*1024*1024 { // 100MB
						matches = append(matches, event)
					}
				}
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectAnomalousAccessPattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	for _, event := range events {
		// Check for off-hours access (simplified - outside 9-17 hours)
		hour := event.Timestamp.Hour()
		if hour < 9 || hour > 17 {
			matches = append(matches, event)
		}

		// Check for unusual geographic locations (would need geolocation data)
		// This is a simplified check
		if event.Context.Geolocation != nil {
			// If country is different from usual, flag as anomalous
			// This would require baseline data in a real implementation
		}
	}

	return matches
}

func (pd *PatternDetector) detectInjectionPattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	// SQL injection patterns
	sqlInjectionPatterns := []string{
		`(?i)(union\s+select)`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(drop\s+table)`,
		`(?i)(insert\s+into)`,
		`(?i)(delete\s+from)`,
		`(?i)(';\s*drop)`,
		`(?i)(exec\s*\()`,
		`(?i)(script\s*>)`,
	}

	for _, event := range events {
		// Check event description and metadata for injection patterns
		textToCheck := event.Description
		if event.Context.Metadata != nil {
			if query, exists := event.Context.Metadata["query"]; exists {
				if queryStr, ok := query.(string); ok {
					textToCheck += " " + queryStr
				}
			}
		}

		for _, pattern := range sqlInjectionPatterns {
			if matched, _ := regexp.MatchString(pattern, textToCheck); matched {
				matches = append(matches, event)
				break
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectReconnaissancePattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	// Group events by user
	userEvents := make(map[string][]SecurityEvent)

	for _, event := range events {
		if strings.Contains(event.Type, "LIST") || strings.Contains(event.Type, "READ") {
			userEvents[event.UserID] = append(userEvents[event.UserID], event)
		}
	}

	// Check for systematic enumeration
	for _, eventGroup := range userEvents {
		if len(eventGroup) >= 20 { // 20 or more list/read operations
			// Check if they accessed many different resources
			uniqueResources := make(map[string]bool)
			for _, event := range eventGroup {
				uniqueResources[event.Resource] = true
			}

			if len(uniqueResources) >= 10 && pd.eventsWithinTimeWindow(eventGroup, 30*time.Minute) {
				matches = append(matches, eventGroup...)
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectInsiderThreatPattern(events []SecurityEvent) []SecurityEvent {
	var matches []SecurityEvent

	// This would require baseline data about normal user behavior
	// For now, implement a simplified version

	for _, event := range events {
		// Check for access to sensitive data outside normal hours
		if strings.Contains(event.Resource, "sensitive") || strings.Contains(event.Resource, "confidential") {
			hour := event.Timestamp.Hour()
			if hour < 8 || hour > 18 { // Outside normal business hours
				matches = append(matches, event)
			}
		}
	}

	return matches
}

func (pd *PatternDetector) detectCorrelationPatterns(events []SecurityEvent) []SuspiciousPattern {
	var patterns []SuspiciousPattern

	// Detect correlated events (events that often occur together)
	// This is a simplified implementation

	// Group events by time windows
	timeWindows := pd.groupEventsByTimeWindow(events, 5*time.Minute)

	for _, windowEvents := range timeWindows {
		if len(windowEvents) >= 3 {
			// Check for suspicious combinations
			eventTypes := make(map[string]int)
			for _, event := range windowEvents {
				eventTypes[event.Type]++
			}

			// Look for suspicious combinations
			if eventTypes["LOGIN_FAILED"] > 0 && eventTypes["PERMISSION_CHANGE"] > 0 {
				pattern := SuspiciousPattern{
					ID:          uuid.New().String(),
					Type:        "CORRELATION",
					Description: "Failed login followed by permission changes",
					Pattern:     "LOGIN_FAILED + PERMISSION_CHANGE",
					Confidence:  0.8,
					Events:      windowEvents,
					Timestamp:   time.Now(),
				}
				patterns = append(patterns, pattern)
			}
		}
	}

	return patterns
}

func (pd *PatternDetector) detectSequencePatterns(events []SecurityEvent) []SuspiciousPattern {
	var patterns []SuspiciousPattern

	// Detect suspicious sequences of events
	// This is a simplified implementation

	if len(events) < 3 {
		return patterns
	}

	// Sort events by timestamp
	sortedEvents := make([]SecurityEvent, len(events))
	copy(sortedEvents, events)

	// Look for suspicious sequences
	for i := 0; i < len(sortedEvents)-2; i++ {
		sequence := sortedEvents[i : i+3]

		// Check for attack sequences
		if pd.isAttackSequence(sequence) {
			pattern := SuspiciousPattern{
				ID:          uuid.New().String(),
				Type:        "SEQUENCE",
				Description: "Suspicious sequence of events detected",
				Pattern:     pd.describeSequence(sequence),
				Confidence:  0.75,
				Events:      sequence,
				Timestamp:   time.Now(),
			}
			patterns = append(patterns, pattern)
		}
	}

	return patterns
}

// Helper methods

func (pd *PatternDetector) eventsWithinTimeWindow(events []SecurityEvent, window time.Duration) bool {
	if len(events) < 2 {
		return false
	}

	// Find earliest and latest timestamps
	earliest := events[0].Timestamp
	latest := events[0].Timestamp

	for _, event := range events {
		if event.Timestamp.Before(earliest) {
			earliest = event.Timestamp
		}
		if event.Timestamp.After(latest) {
			latest = event.Timestamp
		}
	}

	return latest.Sub(earliest) <= window
}

func (pd *PatternDetector) groupEventsByTimeWindow(events []SecurityEvent, window time.Duration) [][]SecurityEvent {
	var groups [][]SecurityEvent

	if len(events) == 0 {
		return groups
	}

	// Sort events by timestamp
	sortedEvents := make([]SecurityEvent, len(events))
	copy(sortedEvents, events)

	// Group events within time windows
	currentGroup := []SecurityEvent{sortedEvents[0]}
	windowStart := sortedEvents[0].Timestamp

	for i := 1; i < len(sortedEvents); i++ {
		if sortedEvents[i].Timestamp.Sub(windowStart) <= window {
			currentGroup = append(currentGroup, sortedEvents[i])
		} else {
			if len(currentGroup) > 1 {
				groups = append(groups, currentGroup)
			}
			currentGroup = []SecurityEvent{sortedEvents[i]}
			windowStart = sortedEvents[i].Timestamp
		}
	}

	if len(currentGroup) > 1 {
		groups = append(groups, currentGroup)
	}

	return groups
}

func (pd *PatternDetector) isAttackSequence(events []SecurityEvent) bool {
	if len(events) != 3 {
		return false
	}

	// Check for common attack sequences
	types := make([]string, len(events))
	for i, event := range events {
		types[i] = event.Type
	}

	// Example: reconnaissance -> privilege escalation -> data access
	if strings.Contains(types[0], "LIST") &&
		strings.Contains(types[1], "PERMISSION") &&
		strings.Contains(types[2], "DATA_ACCESS") {
		return true
	}

	return false
}

func (pd *PatternDetector) describeSequence(events []SecurityEvent) string {
	types := make([]string, len(events))
	for i, event := range events {
		types[i] = event.Type
	}
	return strings.Join(types, " -> ")
}

func (pd *PatternDetector) extractIndicators(pattern ThreatPattern, events []SecurityEvent) []ThreatIndicator {
	var indicators []ThreatIndicator

	for _, indicatorType := range pattern.Indicators {
		indicator := ThreatIndicator{
			Type:        indicatorType,
			Value:       pattern.Pattern,
			Confidence:  pattern.Confidence,
			Source:      "PATTERN_DETECTION",
			Description: fmt.Sprintf("Indicator from pattern: %s", pattern.Name),
			Timestamp:   time.Now(),
		}
		indicators = append(indicators, indicator)
	}

	return indicators
}

func (pd *PatternDetector) validatePattern(pattern ThreatPattern) error {
	if pattern.Name == "" {
		return fmt.Errorf("pattern name is required")
	}
	if pattern.Pattern == "" {
		return fmt.Errorf("pattern definition is required")
	}
	if pattern.Confidence < 0 || pattern.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	return nil
}

// DefaultPatternDetectorConfig returns default configuration for pattern detection
func DefaultPatternDetectorConfig() *PatternDetectorConfig {
	return &PatternDetectorConfig{
		EnableBuiltinPatterns: true,
		EnableCustomPatterns:  true,
		PatternUpdateInterval: 1 * time.Hour,
		MaxPatternAge:         30 * 24 * time.Hour, // 30 days
		PatternCacheSize:      1000,
	}
}
