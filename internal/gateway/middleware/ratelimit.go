package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/internal/config"
)

// RateLimiter represents a rate limiter
type RateLimiter struct {
	config   config.RateLimitConfig
	clients  map[string]*clientLimiter
	mu       sync.RWMutex
	stopChan chan struct{}
}

// clientLimiter represents rate limiting data for a single client
type clientLimiter struct {
	tokens     int
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		config:   cfg,
		clients:  make(map[string]*clientLimiter),
		stopChan: make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// RateLimit creates a rate limiting middleware
func RateLimit(cfg config.RateLimitConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	limiter := NewRateLimiter(cfg)

	return func(c *gin.Context) {
		// Get client identifier (IP address or user ID if authenticated)
		clientID := getClientID(c)

		// Check rate limit
		if !limiter.Allow(clientID) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Allow checks if a request from the given client should be allowed
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.RLock()
	client, exists := rl.clients[clientID]
	rl.mu.RUnlock()

	if !exists {
		// Create new client limiter
		client = &clientLimiter{
			tokens:     rl.config.BurstSize,
			lastRefill: time.Now(),
		}

		rl.mu.Lock()
		rl.clients[clientID] = client
		rl.mu.Unlock()
	}

	client.mu.Lock()
	defer client.mu.Unlock()

	now := time.Now()

	// Calculate tokens to add based on time elapsed
	elapsed := now.Sub(client.lastRefill)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.config.RequestsPerMinute))

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
		return true
	}

	return false
}

// cleanup removes old client entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()

			for clientID, client := range rl.clients {
				client.mu.Lock()
				// Remove clients that haven't been active for more than cleanup interval
				if now.Sub(client.lastRefill) > rl.config.CleanupInterval*2 {
					delete(rl.clients, clientID)
				}
				client.mu.Unlock()
			}

			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

// getClientID extracts client identifier from the request
func getClientID(c *gin.Context) string {
	// Try to get user ID from JWT claims if authenticated
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(string); ok {
			return "user:" + uid
		}
	}

	// Fall back to IP address
	return "ip:" + c.ClientIP()
}
