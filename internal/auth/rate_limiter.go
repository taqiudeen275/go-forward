package auth

import (
	"fmt"
	"sync"
	"time"
)

// InMemoryRateLimiter implements a simple in-memory rate limiter
type InMemoryRateLimiter struct {
	counters map[string]*RateLimitCounter
	mutex    sync.RWMutex
}

// RateLimitCounter tracks rate limit counters for different time windows
type RateLimitCounter struct {
	MinuteCount    int       `json:"minute_count"`
	HourCount      int       `json:"hour_count"`
	DayCount       int       `json:"day_count"`
	LastMinute     time.Time `json:"last_minute"`
	LastHour       time.Time `json:"last_hour"`
	LastDay        time.Time `json:"last_day"`
	BurstCount     int       `json:"burst_count"`
	LastBurstReset time.Time `json:"last_burst_reset"`
	mutex          sync.RWMutex
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		counters: make(map[string]*RateLimitCounter),
	}

	// Start cleanup goroutine
	go limiter.cleanupExpiredCounters()

	return limiter
}

// CheckLimit checks if the request is within the specified rate limits
func (r *InMemoryRateLimiter) CheckLimit(key string, limit *RateLimitConfig) (bool, error) {
	if limit == nil {
		return true, nil // No limits configured
	}

	r.mutex.Lock()
	counter, exists := r.counters[key]
	if !exists {
		counter = &RateLimitCounter{
			LastMinute:     time.Now(),
			LastHour:       time.Now(),
			LastDay:        time.Now(),
			LastBurstReset: time.Now(),
		}
		r.counters[key] = counter
	}
	r.mutex.Unlock()

	counter.mutex.Lock()
	defer counter.mutex.Unlock()

	now := time.Now()

	// Reset counters if time windows have passed
	r.resetCountersIfNeeded(counter, now)

	// Check burst limit first (most restrictive)
	if limit.BurstSize > 0 && counter.BurstCount >= limit.BurstSize {
		// Check if burst window has passed (1 minute)
		if now.Sub(counter.LastBurstReset) < time.Minute {
			return false, nil
		}
		// Reset burst counter
		counter.BurstCount = 0
		counter.LastBurstReset = now
	}

	// Check per-minute limit
	if limit.RequestsPerMinute > 0 && counter.MinuteCount >= limit.RequestsPerMinute {
		return false, nil
	}

	// Check per-hour limit
	if limit.RequestsPerHour > 0 && counter.HourCount >= limit.RequestsPerHour {
		return false, nil
	}

	// Note: RequestsPerDay not available in this RateLimitConfig
	// Could be added if needed

	return true, nil
}

// IncrementCounter increments the counter for the given key
func (r *InMemoryRateLimiter) IncrementCounter(key string) error {
	r.mutex.RLock()
	counter, exists := r.counters[key]
	r.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("counter not found for key: %s", key)
	}

	counter.mutex.Lock()
	defer counter.mutex.Unlock()

	now := time.Now()
	r.resetCountersIfNeeded(counter, now)
	_ = now // Use the variable

	// Increment all counters
	counter.MinuteCount++
	counter.HourCount++
	counter.DayCount++
	counter.BurstCount++

	return nil
}

// GetCurrentUsage returns the current usage for the given key
func (r *InMemoryRateLimiter) GetCurrentUsage(key string) (int, error) {
	r.mutex.RLock()
	counter, exists := r.counters[key]
	r.mutex.RUnlock()

	if !exists {
		return 0, nil
	}

	counter.mutex.RLock()
	defer counter.mutex.RUnlock()

	now := time.Now()
	_ = now // Use the variable

	// Return the highest usage across time windows
	usage := counter.MinuteCount
	if counter.HourCount > usage {
		usage = counter.HourCount
	}
	if counter.DayCount > usage {
		usage = counter.DayCount
	}

	return usage, nil
}

// ResetLimit resets the counter for the given key
func (r *InMemoryRateLimiter) ResetLimit(key string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	delete(r.counters, key)
	return nil
}

// resetCountersIfNeeded resets counters if their time windows have passed
func (r *InMemoryRateLimiter) resetCountersIfNeeded(counter *RateLimitCounter, now time.Time) {
	// Reset minute counter if a minute has passed
	if now.Sub(counter.LastMinute) >= time.Minute {
		counter.MinuteCount = 0
		counter.LastMinute = now
	}

	// Reset hour counter if an hour has passed
	if now.Sub(counter.LastHour) >= time.Hour {
		counter.HourCount = 0
		counter.LastHour = now
	}

	// Reset day counter if a day has passed
	if now.Sub(counter.LastDay) >= 24*time.Hour {
		counter.DayCount = 0
		counter.LastDay = now
	}

	// Reset burst counter if burst window has passed
	if now.Sub(counter.LastBurstReset) >= time.Minute {
		counter.BurstCount = 0
		counter.LastBurstReset = now
	}
}

// cleanupExpiredCounters removes expired counters to prevent memory leaks
func (r *InMemoryRateLimiter) cleanupExpiredCounters() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		r.mutex.Lock()
		now := time.Now()

		for key, counter := range r.counters {
			counter.mutex.RLock()
			// Remove counters that haven't been used in the last day
			if now.Sub(counter.LastDay) > 24*time.Hour &&
				now.Sub(counter.LastHour) > time.Hour &&
				now.Sub(counter.LastMinute) > time.Minute {
				counter.mutex.RUnlock()
				delete(r.counters, key)
			} else {
				counter.mutex.RUnlock()
			}
		}

		r.mutex.Unlock()
	}
}

// GetRateLimitStatus returns the current rate limit status for a key
func (r *InMemoryRateLimiter) GetRateLimitStatus(key string, limit *RateLimitConfig) (*RateLimitStatus, error) {
	r.mutex.RLock()
	counter, exists := r.counters[key]
	r.mutex.RUnlock()

	status := &RateLimitStatus{
		Key:   key,
		Limit: limit,
	}

	if !exists {
		return status, nil
	}

	counter.mutex.RLock()
	defer counter.mutex.RUnlock()

	now := time.Now()
	_ = now // Use the variable

	status.CurrentUsage = &RateLimitUsage{
		MinuteCount: counter.MinuteCount,
		HourCount:   counter.HourCount,
		DayCount:    counter.DayCount,
		BurstCount:  counter.BurstCount,
	}

	// Calculate remaining limits
	if limit != nil {
		status.Remaining = &RateLimitRemaining{}

		if limit.RequestsPerMinute > 0 {
			remaining := limit.RequestsPerMinute - counter.MinuteCount
			if remaining < 0 {
				remaining = 0
			}
			status.Remaining.MinuteRemaining = remaining
		}

		if limit.RequestsPerHour > 0 {
			remaining := limit.RequestsPerHour - counter.HourCount
			if remaining < 0 {
				remaining = 0
			}
			status.Remaining.HourRemaining = remaining
		}

		// Note: RequestsPerDay not available in this RateLimitConfig

		if limit.BurstSize > 0 {
			remaining := limit.BurstSize - counter.BurstCount
			if remaining < 0 {
				remaining = 0
			}
			status.Remaining.BurstRemaining = remaining
		}
	}

	// Calculate reset times
	status.ResetTimes = &RateLimitResetTimes{
		MinuteReset: counter.LastMinute.Add(time.Minute),
		HourReset:   counter.LastHour.Add(time.Hour),
		DayReset:    counter.LastDay.Add(24 * time.Hour),
		BurstReset:  counter.LastBurstReset.Add(time.Minute),
	}

	return status, nil
}

// RateLimitStatus represents the current rate limit status
type RateLimitStatus struct {
	Key          string               `json:"key"`
	Limit        *RateLimitConfig     `json:"limit"`
	CurrentUsage *RateLimitUsage      `json:"current_usage"`
	Remaining    *RateLimitRemaining  `json:"remaining"`
	ResetTimes   *RateLimitResetTimes `json:"reset_times"`
}

// RateLimitUsage represents current usage counts
type RateLimitUsage struct {
	MinuteCount int `json:"minute_count"`
	HourCount   int `json:"hour_count"`
	DayCount    int `json:"day_count"`
	BurstCount  int `json:"burst_count"`
}

// RateLimitRemaining represents remaining request counts
type RateLimitRemaining struct {
	MinuteRemaining int `json:"minute_remaining"`
	HourRemaining   int `json:"hour_remaining"`
	DayRemaining    int `json:"day_remaining"`
	BurstRemaining  int `json:"burst_remaining"`
}

// RateLimitResetTimes represents when counters will reset
type RateLimitResetTimes struct {
	MinuteReset time.Time `json:"minute_reset"`
	HourReset   time.Time `json:"hour_reset"`
	DayReset    time.Time `json:"day_reset"`
	BurstReset  time.Time `json:"burst_reset"`
}

// RedisRateLimiter implements a Redis-based rate limiter for distributed systems
type RedisRateLimiter struct {
	// This would be implemented with a Redis client
	// For now, it's a placeholder
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(redisURL string) *RedisRateLimiter {
	// Placeholder implementation
	return &RedisRateLimiter{}
}

// CheckLimit implements rate limiting using Redis
func (r *RedisRateLimiter) CheckLimit(key string, limit *RateLimitConfig) (bool, error) {
	// Placeholder implementation
	// In a real implementation, this would use Redis with Lua scripts for atomic operations
	return true, nil
}

// IncrementCounter increments counters in Redis
func (r *RedisRateLimiter) IncrementCounter(key string) error {
	// Placeholder implementation
	return nil
}

// GetCurrentUsage gets current usage from Redis
func (r *RedisRateLimiter) GetCurrentUsage(key string) (int, error) {
	// Placeholder implementation
	return 0, nil
}

// ResetLimit resets counters in Redis
func (r *RedisRateLimiter) ResetLimit(key string) error {
	// Placeholder implementation
	return nil
}
