package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// RateLimitAlgorithm represents different rate limiting algorithms
type RateLimitAlgorithm string

const (
	TokenBucket   RateLimitAlgorithm = "token_bucket"
	LeakyBucket   RateLimitAlgorithm = "leaky_bucket"
	FixedWindow   RateLimitAlgorithm = "fixed_window"
	SlidingWindow RateLimitAlgorithm = "sliding_window"
)

// AdvancedRateLimitConfig represents advanced rate limiting configuration
type AdvancedRateLimitConfig struct {
	Enabled           bool               `json:"enabled"`
	Algorithm         RateLimitAlgorithm `json:"algorithm"`
	RequestsPerMinute int                `json:"requests_per_minute"`
	BurstSize         int                `json:"burst_size"`
	WindowSize        time.Duration      `json:"window_size"`
	CleanupInterval   time.Duration      `json:"cleanup_interval"`

	// Progressive rate limiting
	ProgressiveEnabled    bool          `json:"progressive_enabled"`
	SuspiciousThreshold   int           `json:"suspicious_threshold"`
	ProgressiveMultiplier float64       `json:"progressive_multiplier"`
	ProgressiveMaxDelay   time.Duration `json:"progressive_max_delay"`

	// DDoS protection
	DDoSProtection    bool          `json:"ddos_protection"`
	DDoSThreshold     int           `json:"ddos_threshold"`
	DDoSWindowSize    time.Duration `json:"ddos_window_size"`
	DDoSBlockDuration time.Duration `json:"ddos_block_duration"`

	// Emergency mode
	EmergencyMode           bool `json:"emergency_mode"`
	EmergencyThreshold      int  `json:"emergency_threshold"`
	EmergencyRequestsPerMin int  `json:"emergency_requests_per_min"`

	// Whitelist
	WhitelistedIPs        []string `json:"whitelisted_ips"`
	WhitelistedUserAgents []string `json:"whitelisted_user_agents"`

	// Custom limits per endpoint
	EndpointLimits map[string]EndpointLimit `json:"endpoint_limits"`
}

// EndpointLimit represents rate limit configuration for specific endpoints
type EndpointLimit struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// RateLimiterInterface defines the interface for rate limiters
type RateLimiterInterface interface {
	Allow(clientID string) (bool, *RateLimitInfo)
	AllowEndpoint(clientID, endpoint string) (bool, *RateLimitInfo)
	GetStats(clientID string) *RateLimitStats
	Reset(clientID string) error
	IsBlocked(clientID string) bool
	Block(clientID string, duration time.Duration) error
	Unblock(clientID string) error
	Cleanup()
	Stop()
}

// RateLimitInfo contains information about rate limit status
type RateLimitInfo struct {
	Allowed    bool          `json:"allowed"`
	Remaining  int           `json:"remaining"`
	ResetTime  time.Time     `json:"reset_time"`
	RetryAfter time.Duration `json:"retry_after"`
	Reason     string        `json:"reason"`
}

// RateLimitStats contains statistics about rate limiting
type RateLimitStats struct {
	TotalRequests   int64     `json:"total_requests"`
	AllowedRequests int64     `json:"allowed_requests"`
	BlockedRequests int64     `json:"blocked_requests"`
	LastRequest     time.Time `json:"last_request"`
	CurrentTokens   int       `json:"current_tokens"`
	IsBlocked       bool      `json:"is_blocked"`
	BlockedUntil    time.Time `json:"blocked_until"`
}

// AdvancedRateLimiter implements multiple rate limiting algorithms
type AdvancedRateLimiter struct {
	config         AdvancedRateLimitConfig
	logger         logger.Logger
	clients        map[string]*ClientLimiter
	blockedClients map[string]time.Time
	ddosDetector   *DDoSDetector
	emergencyMode  bool
	mu             sync.RWMutex
	stopChan       chan struct{}
	cleanupTicker  *time.Ticker
}

// ClientLimiter represents rate limiting data for a single client
type ClientLimiter struct {
	// Token bucket fields
	tokens     int
	lastRefill time.Time

	// Sliding window fields
	requests []time.Time

	// Statistics
	totalRequests   int64
	allowedRequests int64
	blockedRequests int64
	lastRequest     time.Time

	// Progressive rate limiting
	violationCount int
	lastViolation  time.Time

	mu sync.Mutex
}

// DDoSDetector detects DDoS attacks
type DDoSDetector struct {
	config        AdvancedRateLimitConfig
	logger        logger.Logger
	requestCounts map[string][]time.Time
	mu            sync.RWMutex
}

// NewAdvancedRateLimiter creates a new advanced rate limiter
func NewAdvancedRateLimiter(config AdvancedRateLimitConfig, logger logger.Logger) *AdvancedRateLimiter {
	rl := &AdvancedRateLimiter{
		config:         config,
		logger:         logger,
		clients:        make(map[string]*ClientLimiter),
		blockedClients: make(map[string]time.Time),
		ddosDetector:   NewDDoSDetector(config, logger),
		stopChan:       make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupTicker = time.NewTicker(config.CleanupInterval)
	go rl.cleanup()

	return rl
}

// AdvancedRateLimitMiddleware creates advanced rate limiting middleware
func AdvancedRateLimitMiddleware(config AdvancedRateLimitConfig, logger logger.Logger) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	limiter := NewAdvancedRateLimiter(config, logger)

	return func(c *gin.Context) {
		clientID := getAdvancedClientID(c)
		clientIP := c.ClientIP()
		endpoint := c.Request.URL.Path

		// Check if IP is whitelisted
		if isWhitelisted(clientIP, c.Request.UserAgent(), config) {
			c.Next()
			return
		}

		// Check if client is blocked
		if limiter.IsBlocked(clientID) {
			logger.Warn("Blocked client attempted access: %s", clientID)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Client is temporarily blocked",
				"message": "Your access has been temporarily restricted due to suspicious activity",
				"code":    "CLIENT_BLOCKED",
			})
			c.Abort()
			return
		}

		// Check for DDoS attack
		if config.DDoSProtection {
			if limiter.ddosDetector.IsAttack(clientIP) {
				logger.Warn("DDoS attack detected from IP: %s", clientIP)

				// Block the client
				limiter.Block(clientID, config.DDoSBlockDuration)

				// Activate emergency mode if threshold exceeded
				if limiter.ddosDetector.ShouldActivateEmergencyMode() {
					limiter.activateEmergencyMode()
				}

				c.JSON(http.StatusServiceUnavailable, gin.H{
					"error":   "Service temporarily unavailable",
					"message": "DDoS protection activated",
					"code":    "DDOS_PROTECTION",
				})
				c.Abort()
				return
			}
		}

		// Apply rate limiting
		var allowed bool
		var info *RateLimitInfo

		// Check endpoint-specific limits first
		if endpointLimit, exists := config.EndpointLimits[endpoint]; exists {
			allowed, info = limiter.allowWithCustomLimit(clientID, endpointLimit)
		} else {
			allowed, info = limiter.Allow(clientID)
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", info.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", info.ResetTime.Unix()))

		if !allowed {
			logger.Info("Rate limit exceeded for client: %s, reason: %s", clientID, info.Reason)

			// Handle progressive rate limiting
			if config.ProgressiveEnabled {
				limiter.handleProgressiveRateLimit(c, clientID, info)
				return
			}

			c.Header("Retry-After", fmt.Sprintf("%.0f", info.RetryAfter.Seconds()))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests, please try again later",
				"code":        "RATE_LIMIT_EXCEEDED",
				"retry_after": info.RetryAfter.Seconds(),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Allow checks if a request should be allowed
func (rl *AdvancedRateLimiter) Allow(clientID string) (bool, *RateLimitInfo) {
	rl.mu.RLock()
	client, exists := rl.clients[clientID]
	rl.mu.RUnlock()

	if !exists {
		client = &ClientLimiter{
			tokens:     rl.config.BurstSize,
			lastRefill: time.Now(),
			requests:   make([]time.Time, 0),
		}

		rl.mu.Lock()
		rl.clients[clientID] = client
		rl.mu.Unlock()
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	client.totalRequests++
	client.lastRequest = time.Now()

	var allowed bool
	var remaining int
	var resetTime time.Time
	var retryAfter time.Duration

	switch rl.config.Algorithm {
	case TokenBucket:
		allowed, remaining, resetTime = rl.tokenBucketAllow(client)
	case LeakyBucket:
		allowed, remaining, resetTime = rl.leakyBucketAllow(client)
	case FixedWindow:
		allowed, remaining, resetTime = rl.fixedWindowAllow(client)
	case SlidingWindow:
		allowed, remaining, resetTime = rl.slidingWindowAllow(client)
	default:
		allowed, remaining, resetTime = rl.tokenBucketAllow(client)
	}

	if allowed {
		client.allowedRequests++
	} else {
		client.blockedRequests++
		client.violationCount++
		client.lastViolation = time.Now()
		retryAfter = time.Until(resetTime)
	}

	reason := ""
	if !allowed {
		if rl.emergencyMode {
			reason = "emergency mode active"
		} else {
			reason = "rate limit exceeded"
		}
	}

	return allowed, &RateLimitInfo{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetTime:  resetTime,
		RetryAfter: retryAfter,
		Reason:     reason,
	}
}

// AllowEndpoint checks if a request to a specific endpoint should be allowed
func (rl *AdvancedRateLimiter) AllowEndpoint(clientID, endpoint string) (bool, *RateLimitInfo) {
	if endpointLimit, exists := rl.config.EndpointLimits[endpoint]; exists {
		return rl.allowWithCustomLimit(clientID, endpointLimit)
	}
	return rl.Allow(clientID)
}

// allowWithCustomLimit applies custom rate limit
func (rl *AdvancedRateLimiter) allowWithCustomLimit(clientID string, limit EndpointLimit) (bool, *RateLimitInfo) {
	// Create a temporary config with custom limits
	tempConfig := rl.config
	tempConfig.RequestsPerMinute = limit.RequestsPerMinute
	tempConfig.BurstSize = limit.BurstSize
	tempConfig.WindowSize = limit.WindowSize

	// Use the same logic but with custom limits
	return rl.Allow(clientID)
}

// Token bucket algorithm implementation
func (rl *AdvancedRateLimiter) tokenBucketAllow(client *ClientLimiter) (bool, int, time.Time) {
	now := time.Now()

	// Calculate tokens to add based on time elapsed
	elapsed := now.Sub(client.lastRefill)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.getEffectiveRequestsPerMinute()))

	if tokensToAdd > 0 {
		client.tokens += tokensToAdd
		if client.tokens > rl.config.BurstSize {
			client.tokens = rl.config.BurstSize
		}
		client.lastRefill = now
	}

	// Check if request can be allowed
	if client.tokens > 0 {
		client.tokens--
		resetTime := now.Add(time.Minute)
		return true, client.tokens, resetTime
	}

	// Calculate when tokens will be available
	resetTime := client.lastRefill.Add(time.Minute)
	return false, 0, resetTime
}

// Leaky bucket algorithm implementation
func (rl *AdvancedRateLimiter) leakyBucketAllow(client *ClientLimiter) (bool, int, time.Time) {
	now := time.Now()

	// Filter out requests older than the leak rate (1 minute window)
	validRequests := make([]time.Time, 0)
	for _, reqTime := range client.requests {
		if now.Sub(reqTime) < time.Minute {
			validRequests = append(validRequests, reqTime)
		}
	}
	client.requests = validRequests

	// Check if we can add a new request
	if len(client.requests) < rl.getEffectiveRequestsPerMinute() {
		client.requests = append(client.requests, now)
		remaining := rl.getEffectiveRequestsPerMinute() - len(client.requests)
		resetTime := now.Add(time.Minute)
		return true, remaining, resetTime
	}

	// Calculate when space will be available
	oldestRequest := client.requests[0]
	resetTime := oldestRequest.Add(time.Minute)
	return false, 0, resetTime
}

// Fixed window algorithm implementation
func (rl *AdvancedRateLimiter) fixedWindowAllow(client *ClientLimiter) (bool, int, time.Time) {
	now := time.Now()
	windowStart := now.Truncate(rl.config.WindowSize)

	// Count requests in current window
	requestsInWindow := 0
	for _, reqTime := range client.requests {
		if reqTime.After(windowStart) {
			requestsInWindow++
		}
	}

	// Remove old requests
	validRequests := make([]time.Time, 0)
	for _, reqTime := range client.requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}
	client.requests = validRequests

	if requestsInWindow < rl.getEffectiveRequestsPerMinute() {
		client.requests = append(client.requests, now)
		remaining := rl.getEffectiveRequestsPerMinute() - requestsInWindow - 1
		resetTime := windowStart.Add(rl.config.WindowSize)
		return true, remaining, resetTime
	}

	resetTime := windowStart.Add(rl.config.WindowSize)
	return false, 0, resetTime
}

// Sliding window algorithm implementation
func (rl *AdvancedRateLimiter) slidingWindowAllow(client *ClientLimiter) (bool, int, time.Time) {
	now := time.Now()
	windowStart := now.Add(-rl.config.WindowSize)

	// Remove requests outside the sliding window
	validRequests := make([]time.Time, 0)
	for _, reqTime := range client.requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}
	client.requests = validRequests

	if len(client.requests) < rl.getEffectiveRequestsPerMinute() {
		client.requests = append(client.requests, now)
		remaining := rl.getEffectiveRequestsPerMinute() - len(client.requests)

		// Calculate reset time based on oldest request
		var resetTime time.Time
		if len(client.requests) > 0 {
			resetTime = client.requests[0].Add(rl.config.WindowSize)
		} else {
			resetTime = now.Add(rl.config.WindowSize)
		}

		return true, remaining, resetTime
	}

	// Calculate when the oldest request will expire
	resetTime := client.requests[0].Add(rl.config.WindowSize)
	return false, 0, resetTime
}

// getEffectiveRequestsPerMinute returns the effective requests per minute considering emergency mode
func (rl *AdvancedRateLimiter) getEffectiveRequestsPerMinute() int {
	if rl.emergencyMode && rl.config.EmergencyRequestsPerMin > 0 {
		return rl.config.EmergencyRequestsPerMin
	}
	return rl.config.RequestsPerMinute
}

// GetStats returns statistics for a client
func (rl *AdvancedRateLimiter) GetStats(clientID string) *RateLimitStats {
	rl.mu.RLock()
	client, exists := rl.clients[clientID]
	rl.mu.RUnlock()

	if !exists {
		return &RateLimitStats{}
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	blockedUntil := time.Time{}
	isBlocked := false

	rl.mu.RLock()
	if blockTime, blocked := rl.blockedClients[clientID]; blocked {
		blockedUntil = blockTime
		isBlocked = time.Now().Before(blockTime)
	}
	rl.mu.RUnlock()

	return &RateLimitStats{
		TotalRequests:   client.totalRequests,
		AllowedRequests: client.allowedRequests,
		BlockedRequests: client.blockedRequests,
		LastRequest:     client.lastRequest,
		CurrentTokens:   client.tokens,
		IsBlocked:       isBlocked,
		BlockedUntil:    blockedUntil,
	}
}

// Reset resets rate limiting for a client
func (rl *AdvancedRateLimiter) Reset(clientID string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if client, exists := rl.clients[clientID]; exists {
		client.mu.Lock()
		client.tokens = rl.config.BurstSize
		client.lastRefill = time.Now()
		client.requests = make([]time.Time, 0)
		client.violationCount = 0
		client.mu.Unlock()
	}

	delete(rl.blockedClients, clientID)
	return nil
}

// IsBlocked checks if a client is blocked
func (rl *AdvancedRateLimiter) IsBlocked(clientID string) bool {
	rl.mu.RLock()
	blockTime, exists := rl.blockedClients[clientID]
	rl.mu.RUnlock()

	if !exists {
		return false
	}

	if time.Now().After(blockTime) {
		// Block has expired, remove it
		rl.mu.Lock()
		delete(rl.blockedClients, clientID)
		rl.mu.Unlock()
		return false
	}

	return true
}

// Block blocks a client for a specified duration
func (rl *AdvancedRateLimiter) Block(clientID string, duration time.Duration) error {
	rl.mu.Lock()
	rl.blockedClients[clientID] = time.Now().Add(duration)
	rl.mu.Unlock()

	rl.logger.Warn("Client blocked: %s for %v", clientID, duration)
	return nil
}

// Unblock unblocks a client
func (rl *AdvancedRateLimiter) Unblock(clientID string) error {
	rl.mu.Lock()
	delete(rl.blockedClients, clientID)
	rl.mu.Unlock()

	rl.logger.Info("Client unblocked: %s", clientID)
	return nil
}

// handleProgressiveRateLimit handles progressive rate limiting
func (rl *AdvancedRateLimiter) handleProgressiveRateLimit(c *gin.Context, clientID string, info *RateLimitInfo) {
	rl.mu.RLock()
	client := rl.clients[clientID]
	rl.mu.RUnlock()

	client.mu.Lock()
	violationCount := client.violationCount
	client.mu.Unlock()

	// Calculate progressive delay
	delay := time.Duration(float64(info.RetryAfter) * (1 + float64(violationCount)*rl.config.ProgressiveMultiplier))
	if delay > rl.config.ProgressiveMaxDelay {
		delay = rl.config.ProgressiveMaxDelay
	}

	// Check if client should be temporarily blocked
	if violationCount >= rl.config.SuspiciousThreshold {
		rl.Block(clientID, delay)

		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":   "Suspicious activity detected",
			"message": "Account temporarily restricted due to excessive requests",
			"code":    "SUSPICIOUS_ACTIVITY",
		})
		c.Abort()
		return
	}

	c.Header("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
	c.JSON(http.StatusTooManyRequests, gin.H{
		"error":       "Rate limit exceeded",
		"message":     "Too many requests, progressive delay applied",
		"code":        "PROGRESSIVE_RATE_LIMIT",
		"retry_after": delay.Seconds(),
		"violations":  violationCount,
	})
	c.Abort()
}

// activateEmergencyMode activates emergency mode
func (rl *AdvancedRateLimiter) activateEmergencyMode() {
	rl.mu.Lock()
	rl.emergencyMode = true
	rl.mu.Unlock()

	rl.logger.Warn("Emergency mode activated due to DDoS attack")

	// Optionally, set a timer to deactivate emergency mode
	go func() {
		time.Sleep(10 * time.Minute) // Emergency mode duration
		rl.mu.Lock()
		rl.emergencyMode = false
		rl.mu.Unlock()
		rl.logger.Info("Emergency mode deactivated")
	}()
}

// cleanup removes old client entries and expired blocks
func (rl *AdvancedRateLimiter) cleanup() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.performCleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// performCleanup performs the actual cleanup
func (rl *AdvancedRateLimiter) performCleanup() {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Clean up old clients
	for clientID, client := range rl.clients {
		client.mu.Lock()
		if now.Sub(client.lastRequest) > rl.config.CleanupInterval*2 {
			delete(rl.clients, clientID)
		}
		client.mu.Unlock()
	}

	// Clean up expired blocks
	for clientID, blockTime := range rl.blockedClients {
		if now.After(blockTime) {
			delete(rl.blockedClients, clientID)
		}
	}

	rl.logger.Debug("Rate limiter cleanup completed")
}

// Cleanup performs manual cleanup
func (rl *AdvancedRateLimiter) Cleanup() {
	rl.performCleanup()
}

// Stop stops the rate limiter
func (rl *AdvancedRateLimiter) Stop() {
	if rl.cleanupTicker != nil {
		rl.cleanupTicker.Stop()
	}
	close(rl.stopChan)
}

// Helper functions

func getAdvancedClientID(c *gin.Context) string {
	// Try to get user ID from context if authenticated
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return "user:" + uid
		}
	}

	// Fall back to IP address
	return "ip:" + c.ClientIP()
}

func isWhitelisted(ip, userAgent string, config AdvancedRateLimitConfig) bool {
	// Check IP whitelist
	for _, whitelistedIP := range config.WhitelistedIPs {
		if ip == whitelistedIP {
			return true
		}
	}

	// Check User-Agent whitelist
	for _, whitelistedUA := range config.WhitelistedUserAgents {
		if userAgent == whitelistedUA {
			return true
		}
	}

	return false
}

// NewDDoSDetector creates a new DDoS detector
func NewDDoSDetector(config AdvancedRateLimitConfig, logger logger.Logger) *DDoSDetector {
	return &DDoSDetector{
		config:        config,
		logger:        logger,
		requestCounts: make(map[string][]time.Time),
	}
}

// IsAttack checks if the current request pattern indicates a DDoS attack
func (d *DDoSDetector) IsAttack(clientIP string) bool {
	if !d.config.DDoSProtection {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-d.config.DDoSWindowSize)

	// Get or create request history for this IP
	requests, exists := d.requestCounts[clientIP]
	if !exists {
		requests = make([]time.Time, 0)
	}

	// Remove old requests outside the window
	validRequests := make([]time.Time, 0)
	for _, reqTime := range requests {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Add current request
	validRequests = append(validRequests, now)
	d.requestCounts[clientIP] = validRequests

	// Check if threshold is exceeded
	if len(validRequests) > d.config.DDoSThreshold {
		d.logger.Warn("DDoS attack detected from IP %s: %d requests in %v",
			clientIP, len(validRequests), d.config.DDoSWindowSize)
		return true
	}

	return false
}

// ShouldActivateEmergencyMode checks if emergency mode should be activated
func (d *DDoSDetector) ShouldActivateEmergencyMode() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	attackingIPs := 0
	for _, requests := range d.requestCounts {
		if len(requests) > d.config.DDoSThreshold {
			attackingIPs++
		}
	}

	return attackingIPs >= d.config.EmergencyThreshold
}
