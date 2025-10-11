package audit

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// NewRiskCalculator creates a new risk calculator
func NewRiskCalculator(config *RiskCalculatorConfig) *RiskCalculator {
	return &RiskCalculator{
		config:      config,
		riskFactors: make(map[string]RiskFactor),
		weights:     config.RiskFactorWeights,
	}
}

// CalculateActionRiskScore calculates the risk score for a specific action
func (rc *RiskCalculator) CalculateActionRiskScore(userID string, action AdminAction) (float64, error) {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	baseScore := rc.config.BaseRiskScore

	// Calculate risk factors
	factors := rc.calculateActionRiskFactors(action)

	// Apply weights and calculate total score
	totalScore := baseScore
	for _, factor := range factors {
		weight := rc.getFactorWeight(factor.Type)
		totalScore += factor.Score * weight
	}

	// Apply time-based weighting (recent actions have higher impact)
	timeWeight := rc.calculateTimeWeight(action.Timestamp)
	totalScore *= timeWeight

	// Normalize to 0-1 range
	normalizedScore := math.Min(totalScore/rc.config.MaxRiskScore, 1.0)

	return normalizedScore, nil
}

// CalculateUserRiskScore calculates risk score based on user behavior analysis
func (rc *RiskCalculator) CalculateUserRiskScore(userID string, actions []AdminAction, deviations []BehaviorDeviation) (float64, error) {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	if len(actions) == 0 {
		return rc.config.BaseRiskScore, nil
	}

	// Calculate base risk from actions
	actionRisks := make([]float64, 0, len(actions))
	for _, action := range actions {
		risk, err := rc.CalculateActionRiskScore(userID, action)
		if err != nil {
			continue
		}
		actionRisks = append(actionRisks, risk)
	}

	// Calculate average action risk
	avgActionRisk := rc.calculateAverage(actionRisks)

	// Calculate deviation risk
	deviationRisk := rc.calculateDeviationRisk(deviations)

	// Combine risks with weights
	actionWeight := 0.6
	deviationWeight := 0.4

	totalRisk := (avgActionRisk * actionWeight) + (deviationRisk * deviationWeight)

	// Apply risk decay for older activities
	decayFactor := rc.calculateRiskDecay(actions)
	totalRisk *= decayFactor

	return math.Min(totalRisk, 1.0), nil
}

// CalculateOverallRiskScore calculates overall risk score for a user
func (rc *RiskCalculator) CalculateOverallRiskScore(userID string, activities []AdminAction, securityEvents []SecurityEvent) (float64, error) {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	// Calculate activity-based risk
	activityRisk := rc.calculateActivityRisk(activities)

	// Calculate security event-based risk
	eventRisk := rc.calculateSecurityEventRisk(securityEvents)

	// Calculate historical risk (would need historical data)
	historicalRisk := rc.calculateHistoricalRisk(userID)

	// Combine different risk components
	weights := map[string]float64{
		"activity":   0.4,
		"events":     0.4,
		"historical": 0.2,
	}

	overallRisk := (activityRisk * weights["activity"]) +
		(eventRisk * weights["events"]) +
		(historicalRisk * weights["historical"])

	return math.Min(overallRisk, 1.0), nil
}

// GetUserRiskFactors returns the risk factors for a user
func (rc *RiskCalculator) GetUserRiskFactors(userID string, activities []AdminAction, securityEvents []SecurityEvent) []RiskFactor {
	rc.mutex.RLock()
	defer rc.mutex.RUnlock()

	var factors []RiskFactor

	// Analyze activities for risk factors
	activityFactors := rc.analyzeActivityRiskFactors(activities)
	factors = append(factors, activityFactors...)

	// Analyze security events for risk factors
	eventFactors := rc.analyzeSecurityEventRiskFactors(securityEvents)
	factors = append(factors, eventFactors...)

	// Analyze behavioral patterns
	behaviorFactors := rc.analyzeBehaviorRiskFactors(userID, activities)
	factors = append(factors, behaviorFactors...)

	return factors
}

// Helper methods for risk calculation

func (rc *RiskCalculator) calculateActionRiskFactors(action AdminAction) []RiskFactor {
	var factors []RiskFactor

	// Action type risk
	actionTypeRisk := rc.getActionTypeRisk(action.Type)
	if actionTypeRisk > 0 {
		factors = append(factors, RiskFactor{
			Type:        "ACTION_TYPE",
			Description: fmt.Sprintf("Risk from action type: %s", action.Type),
			Score:       actionTypeRisk,
			Weight:      1.0,
			Evidence:    []string{action.Type},
			Timestamp:   action.Timestamp,
		})
	}

	// Resource sensitivity risk
	resourceRisk := rc.getResourceRisk(action.Resource)
	if resourceRisk > 0 {
		factors = append(factors, RiskFactor{
			Type:        "RESOURCE_SENSITIVITY",
			Description: fmt.Sprintf("Risk from accessing resource: %s", action.Resource),
			Score:       resourceRisk,
			Weight:      1.0,
			Evidence:    []string{action.Resource},
			Timestamp:   action.Timestamp,
		})
	}

	// Timing risk (off-hours activity)
	timingRisk := rc.getTimingRisk(action.Timestamp)
	if timingRisk > 0 {
		factors = append(factors, RiskFactor{
			Type:        "TIMING",
			Description: "Off-hours activity detected",
			Score:       timingRisk,
			Weight:      0.5,
			Evidence:    []string{fmt.Sprintf("Hour: %d", action.Timestamp.Hour())},
			Timestamp:   action.Timestamp,
		})
	}

	// Failure risk
	if !action.Success {
		factors = append(factors, RiskFactor{
			Type:        "FAILURE",
			Description: "Failed action increases risk",
			Score:       0.3,
			Weight:      0.8,
			Evidence:    []string{action.Error},
			Timestamp:   action.Timestamp,
		})
	}

	// Geographic risk (would need geolocation data)
	geoRisk := rc.getGeographicRisk(action.Context)
	if geoRisk > 0 {
		factors = append(factors, RiskFactor{
			Type:        "GEOGRAPHIC",
			Description: "Unusual geographic location",
			Score:       geoRisk,
			Weight:      0.7,
			Evidence:    []string{action.Context.IPAddress},
			Timestamp:   action.Timestamp,
		})
	}

	return factors
}

func (rc *RiskCalculator) getActionTypeRisk(actionType string) float64 {
	// Define risk scores for different action types
	riskScores := map[string]float64{
		"DELETE_USER":          0.9,
		"DELETE_TABLE":         0.95,
		"EXECUTE_SQL":          0.8,
		"MODIFY_PERMISSIONS":   0.85,
		"CREATE_ADMIN":         0.7,
		"DELETE_ADMIN":         0.9,
		"MODIFY_SYSTEM_CONFIG": 0.8,
		"EXPORT_DATA":          0.6,
		"BULK_DELETE":          0.85,
		"PRIVILEGE_ESCALATION": 0.95,
		"CREATE_USER":          0.3,
		"READ_DATA":            0.1,
		"UPDATE_DATA":          0.3,
		"LOGIN":                0.05,
		"LOGOUT":               0.0,
	}

	if score, exists := riskScores[actionType]; exists {
		return score
	}

	// Default risk for unknown actions
	return 0.2
}

func (rc *RiskCalculator) getResourceRisk(resource string) float64 {
	// Define risk scores for different resources
	sensitiveResources := []string{
		"users", "admins", "permissions", "system_config",
		"audit_logs", "security_settings", "api_keys",
		"sensitive_data", "financial_data", "personal_data",
	}

	resourceLower := strings.ToLower(resource)
	for _, sensitive := range sensitiveResources {
		if strings.Contains(resourceLower, sensitive) {
			return 0.7
		}
	}

	return 0.1
}

func (rc *RiskCalculator) getTimingRisk(timestamp time.Time) float64 {
	hour := timestamp.Hour()
	weekday := timestamp.Weekday()

	// Higher risk for off-hours activity
	if hour < 8 || hour > 18 {
		return 0.4
	}

	// Higher risk for weekend activity
	if weekday == time.Saturday || weekday == time.Sunday {
		return 0.3
	}

	return 0.0
}

func (rc *RiskCalculator) getGeographicRisk(context ActionContext) float64 {
	// This would implement geographic risk assessment
	// For now, return a placeholder value
	return 0.0
}

func (rc *RiskCalculator) calculateDeviationRisk(deviations []BehaviorDeviation) float64 {
	if len(deviations) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	for _, deviation := range deviations {
		switch deviation.Severity {
		case SeverityCritical:
			totalRisk += 0.9 * deviation.Confidence
		case SeverityHigh:
			totalRisk += 0.7 * deviation.Confidence
		case SeverityMedium:
			totalRisk += 0.5 * deviation.Confidence
		case SeverityLow:
			totalRisk += 0.3 * deviation.Confidence
		}
	}

	// Normalize by number of deviations
	avgRisk := totalRisk / float64(len(deviations))

	// Apply scaling factor based on number of deviations
	scalingFactor := math.Min(1.0+(float64(len(deviations))-1)*0.1, 2.0)

	return math.Min(avgRisk*scalingFactor, 1.0)
}

func (rc *RiskCalculator) calculateActivityRisk(activities []AdminAction) float64 {
	if len(activities) == 0 {
		return rc.config.BaseRiskScore
	}

	totalRisk := 0.0
	for _, activity := range activities {
		actionRisk, _ := rc.CalculateActionRiskScore("", activity)
		totalRisk += actionRisk
	}

	avgRisk := totalRisk / float64(len(activities))

	// Apply volume factor (more activities = higher risk)
	volumeFactor := math.Min(1.0+math.Log10(float64(len(activities)))*0.1, 2.0)

	return math.Min(avgRisk*volumeFactor, 1.0)
}

func (rc *RiskCalculator) calculateSecurityEventRisk(events []SecurityEvent) float64 {
	if len(events) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	for _, event := range events {
		eventRisk := rc.getSecurityEventRisk(event)
		totalRisk += eventRisk
	}

	avgRisk := totalRisk / float64(len(events))

	// Apply recency factor (recent events have higher impact)
	recencyFactor := rc.calculateEventRecencyFactor(events)

	return math.Min(avgRisk*recencyFactor, 1.0)
}

func (rc *RiskCalculator) getSecurityEventRisk(event SecurityEvent) float64 {
	switch event.Severity {
	case SeverityCritical:
		return 0.9
	case SeverityHigh:
		return 0.7
	case SeverityMedium:
		return 0.5
	case SeverityLow:
		return 0.3
	default:
		return 0.2
	}
}

func (rc *RiskCalculator) calculateEventRecencyFactor(events []SecurityEvent) float64 {
	if len(events) == 0 {
		return 1.0
	}

	now := time.Now()
	totalWeight := 0.0
	weightedSum := 0.0

	for _, event := range events {
		// Calculate time-based weight (more recent = higher weight)
		hoursSince := now.Sub(event.Timestamp).Hours()
		weight := math.Exp(-hoursSince / 24.0) // Exponential decay over 24 hours

		totalWeight += weight
		weightedSum += weight
	}

	if totalWeight == 0 {
		return 1.0
	}

	// Normalize and scale
	recencyFactor := (weightedSum / totalWeight) * 2.0
	return math.Min(recencyFactor, 2.0)
}

func (rc *RiskCalculator) calculateHistoricalRisk(userID string) float64 {
	// This would analyze historical risk patterns for the user
	// For now, return a baseline value
	return rc.config.BaseRiskScore
}

func (rc *RiskCalculator) analyzeActivityRiskFactors(activities []AdminAction) []RiskFactor {
	var factors []RiskFactor

	if len(activities) == 0 {
		return factors
	}

	// Analyze activity volume
	if len(activities) > 100 {
		factors = append(factors, RiskFactor{
			Type:        "HIGH_ACTIVITY_VOLUME",
			Description: fmt.Sprintf("High activity volume: %d actions", len(activities)),
			Score:       0.6,
			Weight:      0.7,
			Evidence:    []string{fmt.Sprintf("Activity count: %d", len(activities))},
			Timestamp:   time.Now(),
		})
	}

	// Analyze failure rate
	failureCount := 0
	for _, activity := range activities {
		if !activity.Success {
			failureCount++
		}
	}

	failureRate := float64(failureCount) / float64(len(activities))
	if failureRate > 0.2 { // More than 20% failure rate
		factors = append(factors, RiskFactor{
			Type:        "HIGH_FAILURE_RATE",
			Description: fmt.Sprintf("High failure rate: %.1f%%", failureRate*100),
			Score:       failureRate,
			Weight:      0.8,
			Evidence:    []string{fmt.Sprintf("Failures: %d/%d", failureCount, len(activities))},
			Timestamp:   time.Now(),
		})
	}

	// Analyze action diversity
	actionTypes := make(map[string]int)
	for _, activity := range activities {
		actionTypes[activity.Type]++
	}

	diversity := float64(len(actionTypes)) / float64(len(activities))
	if diversity < 0.1 { // Very low diversity (repetitive actions)
		factors = append(factors, RiskFactor{
			Type:        "LOW_ACTION_DIVERSITY",
			Description: "Low action diversity - repetitive behavior",
			Score:       0.4,
			Weight:      0.5,
			Evidence:    []string{fmt.Sprintf("Diversity: %.2f", diversity)},
			Timestamp:   time.Now(),
		})
	}

	return factors
}

func (rc *RiskCalculator) analyzeSecurityEventRiskFactors(events []SecurityEvent) []RiskFactor {
	var factors []RiskFactor

	if len(events) == 0 {
		return factors
	}

	// Count events by severity
	severityCounts := make(map[SecuritySeverity]int)
	for _, event := range events {
		severityCounts[event.Severity]++
	}

	// High-severity events increase risk
	if severityCounts[SeverityCritical] > 0 {
		factors = append(factors, RiskFactor{
			Type:        "CRITICAL_SECURITY_EVENTS",
			Description: fmt.Sprintf("Critical security events: %d", severityCounts[SeverityCritical]),
			Score:       0.9,
			Weight:      1.0,
			Evidence:    []string{fmt.Sprintf("Critical events: %d", severityCounts[SeverityCritical])},
			Timestamp:   time.Now(),
		})
	}

	if severityCounts[SeverityHigh] > 2 {
		factors = append(factors, RiskFactor{
			Type:        "MULTIPLE_HIGH_SEVERITY_EVENTS",
			Description: fmt.Sprintf("Multiple high-severity events: %d", severityCounts[SeverityHigh]),
			Score:       0.7,
			Weight:      0.8,
			Evidence:    []string{fmt.Sprintf("High-severity events: %d", severityCounts[SeverityHigh])},
			Timestamp:   time.Now(),
		})
	}

	return factors
}

func (rc *RiskCalculator) analyzeBehaviorRiskFactors(userID string, activities []AdminAction) []RiskFactor {
	var factors []RiskFactor

	// This would analyze behavioral patterns for risk factors
	// For now, implement basic checks

	if len(activities) == 0 {
		return factors
	}

	// Check for unusual timing patterns
	offHoursCount := 0
	for _, activity := range activities {
		hour := activity.Timestamp.Hour()
		if hour < 8 || hour > 18 {
			offHoursCount++
		}
	}

	offHoursRate := float64(offHoursCount) / float64(len(activities))
	if offHoursRate > 0.3 { // More than 30% off-hours activity
		factors = append(factors, RiskFactor{
			Type:        "OFF_HOURS_ACTIVITY",
			Description: fmt.Sprintf("High off-hours activity: %.1f%%", offHoursRate*100),
			Score:       offHoursRate,
			Weight:      0.6,
			Evidence:    []string{fmt.Sprintf("Off-hours actions: %d/%d", offHoursCount, len(activities))},
			Timestamp:   time.Now(),
		})
	}

	return factors
}

// Utility methods

func (rc *RiskCalculator) calculateTimeWeight(timestamp time.Time) float64 {
	hoursSince := time.Since(timestamp).Hours()

	// Apply exponential decay based on time weighting factor
	weight := math.Exp(-hoursSince * rc.config.TimeWeightingFactor)

	// Ensure minimum weight
	return math.Max(weight, 0.1)
}

func (rc *RiskCalculator) calculateRiskDecay(actions []AdminAction) float64 {
	if len(actions) == 0 {
		return 1.0
	}

	// Calculate average age of actions
	now := time.Now()
	totalAge := 0.0
	for _, action := range actions {
		age := now.Sub(action.Timestamp).Hours()
		totalAge += age
	}
	avgAge := totalAge / float64(len(actions))

	// Apply decay based on average age
	decayFactor := math.Exp(-avgAge * rc.config.RiskDecayRate)

	return math.Max(decayFactor, 0.1)
}

func (rc *RiskCalculator) getFactorWeight(factorType string) float64 {
	if weight, exists := rc.weights[factorType]; exists {
		return weight
	}
	return 1.0 // Default weight
}

func (rc *RiskCalculator) calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}

	return sum / float64(len(values))
}

// DefaultRiskCalculatorConfig returns default configuration for risk calculation
func DefaultRiskCalculatorConfig() *RiskCalculatorConfig {
	return &RiskCalculatorConfig{
		BaseRiskScore:       0.1,
		RiskDecayRate:       0.01, // 1% decay per hour
		MaxRiskScore:        1.0,
		TimeWeightingFactor: 0.02, // 2% weight decay per hour
		RiskFactorWeights: map[string]float64{
			"ACTION_TYPE":          1.0,
			"RESOURCE_SENSITIVITY": 0.8,
			"TIMING":               0.6,
			"FAILURE":              0.7,
			"GEOGRAPHIC":           0.5,
			"HIGH_ACTIVITY_VOLUME": 0.6,
			"HIGH_FAILURE_RATE":    0.8,
			"LOW_ACTION_DIVERSITY": 0.4,
		},
	}
}
