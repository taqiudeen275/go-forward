package auth

import (
	"fmt"
	"sync"
	"time"
)

// SecurityMonitor tracks and prevents suspicious OTP activities
type SecurityMonitor struct {
	// Rate limiting per recipient
	otpRequests map[string][]time.Time
	// Failed attempts per recipient
	failedAttempts map[string]int
	// Lockout timestamps per recipient
	lockoutTimes map[string]time.Time
	// Mutex for thread safety
	mutex sync.RWMutex
	// Configuration
	maxOTPsPerHour    int
	maxFailedAttempts int
	lockoutDuration   time.Duration
	cleanupInterval   time.Duration
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor() *SecurityMonitor {
	monitor := &SecurityMonitor{
		otpRequests:       make(map[string][]time.Time),
		failedAttempts:    make(map[string]int),
		lockoutTimes:      make(map[string]time.Time),
		maxOTPsPerHour:    10, // Max 10 OTP requests per hour per recipient
		maxFailedAttempts: 5,  // Max 5 failed attempts before lockout
		lockoutDuration:   30 * time.Minute,
		cleanupInterval:   1 * time.Hour,
	}

	// Start cleanup routine
	go monitor.cleanupRoutine()

	return monitor
}

// CheckOTPRequestRate checks if recipient can request another OTP
func (sm *SecurityMonitor) CheckOTPRequestRate(recipient string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	hourAgo := now.Add(-1 * time.Hour)

	// Get existing requests for this recipient
	requests := sm.otpRequests[recipient]

	// Filter out requests older than 1 hour
	var recentRequests []time.Time
	for _, req := range requests {
		if req.After(hourAgo) {
			recentRequests = append(recentRequests, req)
		}
	}

	// Check if limit exceeded
	if len(recentRequests) >= sm.maxOTPsPerHour {
		return fmt.Errorf("too many OTP requests. Please wait before requesting another OTP")
	}

	// Add current request
	recentRequests = append(recentRequests, now)
	sm.otpRequests[recipient] = recentRequests

	return nil
}

// RecordFailedAttempt records a failed OTP verification attempt
func (sm *SecurityMonitor) RecordFailedAttempt(recipient string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	sm.failedAttempts[recipient]++

	if sm.failedAttempts[recipient] >= sm.maxFailedAttempts {
		// Record lockout time
		sm.lockoutTimes[recipient] = time.Now()
		return fmt.Errorf("too many failed attempts. Account temporarily locked for %v", sm.lockoutDuration)
	}

	return nil
}

// IsLocked checks if a recipient is currently locked out
func (sm *SecurityMonitor) IsLocked(recipient string) bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// Check if user has exceeded max failed attempts
	if sm.failedAttempts[recipient] < sm.maxFailedAttempts {
		return false
	}

	// Check if lockout has expired
	lockoutTime, exists := sm.lockoutTimes[recipient]
	if !exists {
		return false
	}

	// If lockout has expired, clear it
	if time.Now().After(lockoutTime.Add(sm.lockoutDuration)) {
		// Note: We can't modify maps in a read lock, so we'll handle cleanup elsewhere
		return false
	}

	return true
}

// ClearFailedAttempts clears failed attempts for a recipient (on successful verification)
func (sm *SecurityMonitor) ClearFailedAttempts(recipient string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	delete(sm.failedAttempts, recipient)
	delete(sm.lockoutTimes, recipient)
}

// GetSecurityStats returns security statistics for monitoring
func (sm *SecurityMonitor) GetSecurityStats() map[string]interface{} {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return map[string]interface{}{
		"total_recipients_with_requests": len(sm.otpRequests),
		"total_locked_recipients":        len(sm.failedAttempts),
		"max_otps_per_hour":              sm.maxOTPsPerHour,
		"max_failed_attempts":            sm.maxFailedAttempts,
		"lockout_duration_minutes":       int(sm.lockoutDuration.Minutes()),
	}
}

// cleanupRoutine periodically cleans up old data
func (sm *SecurityMonitor) cleanupRoutine() {
	ticker := time.NewTicker(sm.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		sm.cleanup()
	}
}

// cleanup removes old data to prevent memory leaks
func (sm *SecurityMonitor) cleanup() {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	now := time.Now()
	hourAgo := now.Add(-1 * time.Hour)

	// Clean up old OTP requests
	for recipient, requests := range sm.otpRequests {
		var recentRequests []time.Time
		for _, req := range requests {
			if req.After(hourAgo) {
				recentRequests = append(recentRequests, req)
			}
		}

		if len(recentRequests) == 0 {
			delete(sm.otpRequests, recipient)
		} else {
			sm.otpRequests[recipient] = recentRequests
		}
	}

	// Clean up expired lockouts (simplified - in production, track lockout start time)
	// For now, we'll reset failed attempts after lockout duration
	for recipient := range sm.failedAttempts {
		// In a real implementation, you'd track when the lockout started
		// For simplicity, we'll just reset periodically
		if time.Now().Unix()%int64(sm.lockoutDuration.Seconds()) == 0 {
			delete(sm.failedAttempts, recipient)
		}
	}
}
