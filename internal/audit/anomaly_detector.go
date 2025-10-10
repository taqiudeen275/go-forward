package audit

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"
)

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(config *AnomalyDetectorConfig) *AnomalyDetector {
	return &AnomalyDetector{
		config:           config,
		statisticalModel: &StatisticalModel{},
		mlModel:          &MLModel{},
	}
}

// DetectStatisticalAnomalies detects statistical anomalies in user activities
func (ad *AnomalyDetector) DetectStatisticalAnomalies(userID string, activities []AdminAction) ([]SecurityAnomaly, error) {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()

	var anomalies []SecurityAnomaly

	// Analyze activity frequency
	frequencyAnomalies := ad.detectFrequencyAnomalies(userID, activities)
	anomalies = append(anomalies, frequencyAnomalies...)

	// Analyze timing patterns
	timingAnomalies := ad.detectTimingAnomalies(userID, activities)
	anomalies = append(anomalies, timingAnomalies...)

	// Analyze action types
	actionAnomalies := ad.detectActionTypeAnomalies(userID, activities)
	anomalies = append(anomalies, actionAnomalies...)

	// Analyze resource access patterns
	resourceAnomalies := ad.detectResourceAccessAnomalies(userID, activities)
	anomalies = append(anomalies, resourceAnomalies...)

	return anomalies, nil
}

// DetectMLAnomalies detects anomalies using machine learning models
func (ad *AnomalyDetector) DetectMLAnomalies(userID string, activities []AdminAction) ([]SecurityAnomaly, error) {
	ad.mutex.RLock()
	defer ad.mutex.RUnlock()

	// This would implement ML-based anomaly detection
	// For now, return empty slice as ML models are complex to implement
	return []SecurityAnomaly{}, nil
}

// UpdateModel updates the anomaly detection model with new data
func (ad *AnomalyDetector) UpdateModel(userID string, activities []AdminAction) error {
	ad.mutex.Lock()
	defer ad.mutex.Unlock()

	// Update statistical model
	if err := ad.updateStatisticalModel(userID, activities); err != nil {
		return fmt.Errorf("failed to update statistical model: %w", err)
	}

	// Update ML model if enabled
	if ad.config.Algorithm == "ml" {
		if err := ad.updateMLModel(userID, activities); err != nil {
			return fmt.Errorf("failed to update ML model: %w", err)
		}
	}

	return nil
}

// Helper methods for statistical anomaly detection

func (ad *AnomalyDetector) detectFrequencyAnomalies(userID string, activities []AdminAction) []SecurityAnomaly {
	var anomalies []SecurityAnomaly

	if len(activities) == 0 {
		return anomalies
	}

	// Calculate activity frequency per hour
	hourlyFrequency := make(map[int]int)
	for _, activity := range activities {
		hour := activity.Timestamp.Hour()
		hourlyFrequency[hour]++
	}

	// Calculate statistics
	frequencies := make([]float64, 0, len(hourlyFrequency))
	for _, freq := range hourlyFrequency {
		frequencies = append(frequencies, float64(freq))
	}

	if len(frequencies) < 2 {
		return anomalies
	}

	mean, stdDev := ad.calculateMeanAndStdDev(frequencies)
	threshold := mean + (ad.config.SensitivityLevel * stdDev)

	// Detect anomalies
	for hour, freq := range hourlyFrequency {
		if float64(freq) > threshold {
			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "FREQUENCY_ANOMALY",
				Description: fmt.Sprintf("Unusual activity frequency detected at hour %d: %d actions (threshold: %.2f)", hour, freq, threshold),
				UserID:      userID,
				Severity:    ad.calculateSeverity(float64(freq), threshold),
				Confidence:  ad.calculateConfidence(float64(freq), mean, stdDev),
				Evidence: []AnomalyEvidence{
					{
						Type:        "FREQUENCY",
						Description: "Activity frequency per hour",
						Value:       freq,
						Threshold:   threshold,
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ad *AnomalyDetector) detectTimingAnomalies(userID string, activities []AdminAction) []SecurityAnomaly {
	var anomalies []SecurityAnomaly

	if len(activities) < 2 {
		return anomalies
	}

	// Analyze time intervals between activities
	intervals := make([]float64, 0, len(activities)-1)
	for i := 1; i < len(activities); i++ {
		interval := activities[i].Timestamp.Sub(activities[i-1].Timestamp)
		intervals = append(intervals, interval.Seconds())
	}

	mean, stdDev := ad.calculateMeanAndStdDev(intervals)

	// Detect unusually short intervals (potential automation/bot activity)
	shortThreshold := mean - (2.0 * stdDev)
	if shortThreshold < 1.0 {
		shortThreshold = 1.0 // Minimum 1 second
	}

	// Detect unusually long intervals (potential session hijacking)
	longThreshold := mean + (3.0 * stdDev)

	for i, interval := range intervals {
		if interval < shortThreshold {
			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "TIMING_ANOMALY",
				Description: fmt.Sprintf("Unusually short interval between actions: %.2f seconds (threshold: %.2f)", interval, shortThreshold),
				UserID:      userID,
				Severity:    SeverityMedium,
				Confidence:  ad.calculateConfidence(interval, mean, stdDev),
				Evidence: []AnomalyEvidence{
					{
						Type:        "TIMING",
						Description: "Time interval between actions",
						Value:       interval,
						Threshold:   shortThreshold,
						Timestamp:   activities[i+1].Timestamp,
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		} else if interval > longThreshold {
			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "TIMING_ANOMALY",
				Description: fmt.Sprintf("Unusually long interval between actions: %.2f seconds (threshold: %.2f)", interval, longThreshold),
				UserID:      userID,
				Severity:    SeverityLow,
				Confidence:  ad.calculateConfidence(interval, mean, stdDev),
				Evidence: []AnomalyEvidence{
					{
						Type:        "TIMING",
						Description: "Time interval between actions",
						Value:       interval,
						Threshold:   longThreshold,
						Timestamp:   activities[i+1].Timestamp,
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ad *AnomalyDetector) detectActionTypeAnomalies(userID string, activities []AdminAction) []SecurityAnomaly {
	var anomalies []SecurityAnomaly

	if len(activities) == 0 {
		return anomalies
	}

	// Count action types
	actionCounts := make(map[string]int)
	for _, activity := range activities {
		actionCounts[activity.Type]++
	}

	// Detect unusual action types or frequencies
	totalActions := len(activities)
	for actionType, count := range actionCounts {
		frequency := float64(count) / float64(totalActions)

		// Check for high-risk actions
		if ad.isHighRiskAction(actionType) && count > 0 {
			severity := SeverityMedium
			if count > 5 {
				severity = SeverityHigh
			}

			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "ACTION_TYPE_ANOMALY",
				Description: fmt.Sprintf("High-risk action detected: %s performed %d times", actionType, count),
				UserID:      userID,
				Severity:    severity,
				Confidence:  0.8,
				Evidence: []AnomalyEvidence{
					{
						Type:        "ACTION_TYPE",
						Description: "High-risk action frequency",
						Value:       count,
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		}

		// Check for unusual frequency of any action type
		if frequency > 0.7 { // More than 70% of actions are the same type
			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "ACTION_FREQUENCY_ANOMALY",
				Description: fmt.Sprintf("Unusual concentration of action type: %s (%.1f%% of all actions)", actionType, frequency*100),
				UserID:      userID,
				Severity:    SeverityLow,
				Confidence:  0.6,
				Evidence: []AnomalyEvidence{
					{
						Type:        "ACTION_FREQUENCY",
						Description: "Action type frequency",
						Value:       frequency,
						Threshold:   0.7,
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

func (ad *AnomalyDetector) detectResourceAccessAnomalies(userID string, activities []AdminAction) []SecurityAnomaly {
	var anomalies []SecurityAnomaly

	if len(activities) == 0 {
		return anomalies
	}

	// Count resource access
	resourceCounts := make(map[string]int)
	for _, activity := range activities {
		if activity.Resource != "" {
			resourceCounts[activity.Resource]++
		}
	}

	// Detect unusual resource access patterns
	for resource, count := range resourceCounts {
		// Check for excessive access to a single resource
		if count > 50 { // Threshold for excessive access
			severity := SeverityMedium
			if count > 100 {
				severity = SeverityHigh
			}

			anomaly := SecurityAnomaly{
				ID:          uuid.New().String(),
				Type:        "RESOURCE_ACCESS_ANOMALY",
				Description: fmt.Sprintf("Excessive access to resource: %s (%d times)", resource, count),
				UserID:      userID,
				Severity:    severity,
				Confidence:  0.7,
				Evidence: []AnomalyEvidence{
					{
						Type:        "RESOURCE_ACCESS",
						Description: "Resource access frequency",
						Value:       count,
						Threshold:   50,
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Status:    "DETECTED",
			}
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

// Statistical helper methods

func (ad *AnomalyDetector) calculateMeanAndStdDev(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}

	// Calculate mean
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))

	// Calculate standard deviation
	sumSquaredDiff := 0.0
	for _, value := range values {
		diff := value - mean
		sumSquaredDiff += diff * diff
	}
	variance := sumSquaredDiff / float64(len(values))
	stdDev := math.Sqrt(variance)

	return mean, stdDev
}

func (ad *AnomalyDetector) calculateSeverity(value, threshold float64) SecuritySeverity {
	ratio := value / threshold
	if ratio > 3.0 {
		return SeverityCritical
	} else if ratio > 2.0 {
		return SeverityHigh
	} else if ratio > 1.5 {
		return SeverityMedium
	}
	return SeverityLow
}

func (ad *AnomalyDetector) calculateConfidence(value, mean, stdDev float64) float64 {
	if stdDev == 0 {
		return 0.5
	}

	// Calculate z-score
	zScore := math.Abs((value - mean) / stdDev)

	// Convert z-score to confidence (0-1)
	// Higher z-score = higher confidence
	confidence := math.Min(zScore/3.0, 1.0)

	return confidence
}

func (ad *AnomalyDetector) isHighRiskAction(actionType string) bool {
	highRiskActions := []string{
		"DELETE_USER",
		"DELETE_TABLE",
		"EXECUTE_SQL",
		"MODIFY_PERMISSIONS",
		"CREATE_ADMIN",
		"DELETE_ADMIN",
		"MODIFY_SYSTEM_CONFIG",
		"EXPORT_DATA",
		"BULK_DELETE",
		"PRIVILEGE_ESCALATION",
	}

	for _, riskAction := range highRiskActions {
		if actionType == riskAction {
			return true
		}
	}

	return false
}

func (ad *AnomalyDetector) updateStatisticalModel(userID string, activities []AdminAction) error {
	// Update the statistical model with new activity data
	if len(activities) < ad.config.MinDataPoints {
		return nil // Not enough data to update model
	}

	// Calculate new statistics
	frequencies := make([]float64, 0)
	for _, activity := range activities {
		// Extract relevant metrics for the model
		frequencies = append(frequencies, float64(activity.Timestamp.Hour()))
	}

	mean, stdDev := ad.calculateMeanAndStdDev(frequencies)

	// Update model
	ad.statisticalModel.Mean = mean
	ad.statisticalModel.StdDev = stdDev
	ad.statisticalModel.LastUpdate = time.Now()
	ad.statisticalModel.DataPoints = len(activities)

	// Calculate percentiles
	sort.Float64s(frequencies)
	ad.statisticalModel.Percentiles = make(map[int]float64)
	percentiles := []int{25, 50, 75, 90, 95, 99}
	for _, p := range percentiles {
		index := int(float64(p)/100.0*float64(len(frequencies))) - 1
		if index < 0 {
			index = 0
		}
		if index >= len(frequencies) {
			index = len(frequencies) - 1
		}
		ad.statisticalModel.Percentiles[p] = frequencies[index]
	}

	return nil
}

func (ad *AnomalyDetector) updateMLModel(userID string, activities []AdminAction) error {
	// Placeholder for ML model updates
	// In a real implementation, this would:
	// 1. Extract features from activities
	// 2. Update the ML model with new training data
	// 3. Retrain if necessary
	// 4. Validate model performance

	ad.mlModel.LastTrained = time.Now()
	ad.mlModel.Version = fmt.Sprintf("v%d", time.Now().Unix())

	return nil
}

// DefaultAnomalyDetectorConfig returns default configuration for anomaly detection
func DefaultAnomalyDetectorConfig() *AnomalyDetectorConfig {
	return &AnomalyDetectorConfig{
		Algorithm:           "statistical",
		SensitivityLevel:    2.0,                // 2 standard deviations
		LearningPeriod:      7 * 24 * time.Hour, // 7 days
		UpdateInterval:      1 * time.Hour,
		MinDataPoints:       10,
		ConfidenceThreshold: 0.7,
	}
}
