package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/taqiudeen275/go-foward/pkg/logger"
)

// IPFilterConfig represents IP filtering configuration
type IPFilterConfig struct {
	Enabled           bool     `json:"enabled"`
	WhitelistedIPs    []string `json:"whitelisted_ips"`
	BlacklistedIPs    []string `json:"blacklisted_ips"`
	WhitelistedCIDRs  []string `json:"whitelisted_cidrs"`
	BlacklistedCIDRs  []string `json:"blacklisted_cidrs"`
	AllowPrivateIPs   bool     `json:"allow_private_ips"`
	GeolocationFilter bool     `json:"geolocation_filter"`
	AllowedCountries  []string `json:"allowed_countries"`
	BlockedCountries  []string `json:"blocked_countries"`
	TrustedProxies    []string `json:"trusted_proxies"`
}

// GeolocationInfo represents geolocation information for an IP
type GeolocationInfo struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Timezone    string  `json:"timezone"`
}

// GeolocationProvider interface for geolocation services
type GeolocationProvider interface {
	GetLocation(ip string) (*GeolocationInfo, error)
}

// IPFilter handles IP filtering and geolocation
type IPFilter struct {
	config              IPFilterConfig
	logger              logger.Logger
	geolocationProvider GeolocationProvider
	whitelistedNets     []*net.IPNet
	blacklistedNets     []*net.IPNet
	trustedProxyNets    []*net.IPNet
}

// NewIPFilter creates a new IP filter
func NewIPFilter(config IPFilterConfig, logger logger.Logger, geoProvider GeolocationProvider) *IPFilter {
	filter := &IPFilter{
		config:              config,
		logger:              logger,
		geolocationProvider: geoProvider,
		whitelistedNets:     make([]*net.IPNet, 0),
		blacklistedNets:     make([]*net.IPNet, 0),
		trustedProxyNets:    make([]*net.IPNet, 0),
	}

	// Parse CIDR ranges
	filter.parseCIDRRanges()

	return filter
}

// IPWhitelistMiddleware creates IP whitelist middleware
func IPWhitelistMiddleware(config IPFilterConfig, logger logger.Logger, geoProvider GeolocationProvider) gin.HandlerFunc {
	if !config.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	filter := NewIPFilter(config, logger, geoProvider)

	return func(c *gin.Context) {
		clientIP := filter.getRealClientIP(c)

		// Check if IP is allowed
		allowed, reason, err := filter.IsIPAllowed(clientIP)
		if err != nil {
			logger.Error("Error checking IP filter: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
				"code":  "IP_FILTER_ERROR",
			})
			c.Abort()
			return
		}

		if !allowed {
			logger.Warn("IP blocked: %s, reason: %s", clientIP, reason)

			// Log security event
			filter.logIPBlockEvent(c, clientIP, reason)

			c.JSON(http.StatusForbidden, gin.H{
				"error":  "Access denied",
				"reason": reason,
				"code":   "IP_BLOCKED",
			})
			c.Abort()
			return
		}

		// Set client IP in context for other middleware
		c.Set("real_client_ip", clientIP)
		c.Next()
	}
}

// GeolocationFilterMiddleware creates geolocation filtering middleware
func GeolocationFilterMiddleware(config IPFilterConfig, logger logger.Logger, geoProvider GeolocationProvider) gin.HandlerFunc {
	if !config.Enabled || !config.GeolocationFilter {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	filter := NewIPFilter(config, logger, geoProvider)

	return func(c *gin.Context) {
		clientIP := filter.getRealClientIP(c)

		// Skip geolocation check for private IPs
		if filter.isPrivateIP(clientIP) {
			c.Next()
			return
		}

		// Get geolocation info
		geoInfo, err := filter.geolocationProvider.GetLocation(clientIP)
		if err != nil {
			logger.Warn("Failed to get geolocation for IP %s: %v", clientIP, err)
			// Allow request if geolocation fails (fail open)
			c.Next()
			return
		}

		// Check country restrictions
		allowed, reason := filter.isCountryAllowed(geoInfo.CountryCode)
		if !allowed {
			logger.Warn("Country blocked: %s (%s) for IP %s", geoInfo.Country, geoInfo.CountryCode, clientIP)

			// Log security event
			filter.logGeolocationBlockEvent(c, clientIP, geoInfo, reason)

			c.JSON(http.StatusForbidden, gin.H{
				"error":  "Access denied from your location",
				"reason": reason,
				"code":   "GEOLOCATION_BLOCKED",
			})
			c.Abort()
			return
		}

		// Set geolocation info in context
		c.Set("geolocation_info", geoInfo)
		c.Next()
	}
}

// IsIPAllowed checks if an IP address is allowed
func (f *IPFilter) IsIPAllowed(ipStr string) (bool, string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "invalid IP address", nil
	}

	// Check blacklisted IPs first
	for _, blacklistedIP := range f.config.BlacklistedIPs {
		if ipStr == blacklistedIP {
			return false, "IP is blacklisted", nil
		}
	}

	// Check blacklisted CIDR ranges
	for _, network := range f.blacklistedNets {
		if network.Contains(ip) {
			return false, "IP is in blacklisted range", nil
		}
	}

	// Check if private IP is allowed
	if f.isPrivateIP(ipStr) && !f.config.AllowPrivateIPs {
		return false, "private IPs not allowed", nil
	}

	// If whitelist is configured, check whitelist
	if len(f.config.WhitelistedIPs) > 0 || len(f.whitelistedNets) > 0 {
		// Check whitelisted IPs
		for _, whitelistedIP := range f.config.WhitelistedIPs {
			if ipStr == whitelistedIP {
				return true, "IP is whitelisted", nil
			}
		}

		// Check whitelisted CIDR ranges
		for _, network := range f.whitelistedNets {
			if network.Contains(ip) {
				return true, "IP is in whitelisted range", nil
			}
		}

		// If whitelist is configured but IP is not in it, deny
		return false, "IP not in whitelist", nil
	}

	// If no whitelist configured and not blacklisted, allow
	return true, "IP allowed", nil
}

// getRealClientIP gets the real client IP considering trusted proxies
func (f *IPFilter) getRealClientIP(c *gin.Context) string {
	// Check X-Forwarded-For header if we have trusted proxies
	if len(f.trustedProxyNets) > 0 {
		remoteIP := net.ParseIP(c.ClientIP())
		if remoteIP != nil {
			// Check if the immediate client is a trusted proxy
			for _, proxyNet := range f.trustedProxyNets {
				if proxyNet.Contains(remoteIP) {
					// Get IP from X-Forwarded-For header
					xForwardedFor := c.GetHeader("X-Forwarded-For")
					if xForwardedFor != "" {
						ips := strings.Split(xForwardedFor, ",")
						if len(ips) > 0 {
							return strings.TrimSpace(ips[0])
						}
					}

					// Try X-Real-IP header
					xRealIP := c.GetHeader("X-Real-IP")
					if xRealIP != "" {
						return strings.TrimSpace(xRealIP)
					}
					break
				}
			}
		}
	}

	// Return the direct client IP
	return c.ClientIP()
}

// isPrivateIP checks if an IP is a private IP address
func (f *IPFilter) isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Define private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, rangeStr := range privateRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// isCountryAllowed checks if a country is allowed based on configuration
func (f *IPFilter) isCountryAllowed(countryCode string) (bool, string) {
	// Check blocked countries first
	for _, blocked := range f.config.BlockedCountries {
		if strings.EqualFold(countryCode, blocked) {
			return false, fmt.Sprintf("country %s is blocked", countryCode)
		}
	}

	// If allowed countries list is configured, check it
	if len(f.config.AllowedCountries) > 0 {
		for _, allowed := range f.config.AllowedCountries {
			if strings.EqualFold(countryCode, allowed) {
				return true, "country is allowed"
			}
		}
		return false, fmt.Sprintf("country %s not in allowed list", countryCode)
	}

	// If no allowed countries list and not blocked, allow
	return true, "country allowed"
}

// parseCIDRRanges parses CIDR ranges from configuration
func (f *IPFilter) parseCIDRRanges() {
	// Parse whitelisted CIDR ranges
	for _, cidr := range f.config.WhitelistedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			f.logger.Error("Invalid whitelisted CIDR range: %s, error: %v", cidr, err)
			continue
		}
		f.whitelistedNets = append(f.whitelistedNets, network)
	}

	// Parse blacklisted CIDR ranges
	for _, cidr := range f.config.BlacklistedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			f.logger.Error("Invalid blacklisted CIDR range: %s, error: %v", cidr, err)
			continue
		}
		f.blacklistedNets = append(f.blacklistedNets, network)
	}

	// Parse trusted proxy CIDR ranges
	for _, cidr := range f.config.TrustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			f.logger.Error("Invalid trusted proxy CIDR range: %s, error: %v", cidr, err)
			continue
		}
		f.trustedProxyNets = append(f.trustedProxyNets, network)
	}
}

// logIPBlockEvent logs an IP blocking event
func (f *IPFilter) logIPBlockEvent(c *gin.Context, clientIP, reason string) {
	event := SecurityEvent{
		Type:     "IP_BLOCKED",
		Severity: "MEDIUM",
		UserID:   "",
		Resource: c.Request.URL.Path,
		Action:   c.Request.Method,
		Details: map[string]interface{}{
			"client_ip": clientIP,
			"reason":    reason,
		},
		IPAddress: clientIP,
		UserAgent: c.Request.UserAgent(),
		Timestamp: time.Now(),
		Outcome:   "BLOCKED",
	}

	if requestID, exists := c.Get("request_id"); exists {
		if rid, ok := requestID.(string); ok {
			event.RequestID = rid
		}
	}

	f.logger.Warn("IP blocked: %+v", event)
}

// logGeolocationBlockEvent logs a geolocation blocking event
func (f *IPFilter) logGeolocationBlockEvent(c *gin.Context, clientIP string, geoInfo *GeolocationInfo, reason string) {
	event := SecurityEvent{
		Type:     "GEOLOCATION_BLOCKED",
		Severity: "MEDIUM",
		UserID:   "",
		Resource: c.Request.URL.Path,
		Action:   c.Request.Method,
		Details: map[string]interface{}{
			"client_ip":    clientIP,
			"country":      geoInfo.Country,
			"country_code": geoInfo.CountryCode,
			"region":       geoInfo.Region,
			"city":         geoInfo.City,
			"isp":          geoInfo.ISP,
			"reason":       reason,
		},
		IPAddress: clientIP,
		UserAgent: c.Request.UserAgent(),
		Timestamp: time.Now(),
		Outcome:   "BLOCKED",
	}

	if requestID, exists := c.Get("request_id"); exists {
		if rid, ok := requestID.(string); ok {
			event.RequestID = rid
		}
	}

	f.logger.Warn("Geolocation blocked: %+v", event)
}

// MockGeolocationProvider provides a mock implementation for testing
type MockGeolocationProvider struct {
	responses map[string]*GeolocationInfo
}

// NewMockGeolocationProvider creates a new mock geolocation provider
func NewMockGeolocationProvider() *MockGeolocationProvider {
	return &MockGeolocationProvider{
		responses: map[string]*GeolocationInfo{
			"8.8.8.8": {
				IP:          "8.8.8.8",
				Country:     "United States",
				CountryCode: "US",
				Region:      "California",
				City:        "Mountain View",
				Latitude:    37.4056,
				Longitude:   -122.0775,
				ISP:         "Google LLC",
				Timezone:    "America/Los_Angeles",
			},
			"1.1.1.1": {
				IP:          "1.1.1.1",
				Country:     "Australia",
				CountryCode: "AU",
				Region:      "New South Wales",
				City:        "Sydney",
				Latitude:    -33.8688,
				Longitude:   151.2093,
				ISP:         "Cloudflare, Inc.",
				Timezone:    "Australia/Sydney",
			},
		},
	}
}

// GetLocation returns mock geolocation data
func (m *MockGeolocationProvider) GetLocation(ip string) (*GeolocationInfo, error) {
	if info, exists := m.responses[ip]; exists {
		return info, nil
	}

	// Return default US location for unknown IPs
	return &GeolocationInfo{
		IP:          ip,
		Country:     "United States",
		CountryCode: "US",
		Region:      "Unknown",
		City:        "Unknown",
		Latitude:    0,
		Longitude:   0,
		ISP:         "Unknown",
		Timezone:    "UTC",
	}, nil
}

// HTTPGeolocationProvider provides geolocation via HTTP API
type HTTPGeolocationProvider struct {
	apiURL     string
	apiKey     string
	httpClient *http.Client
	logger     logger.Logger
}

// NewHTTPGeolocationProvider creates a new HTTP geolocation provider
func NewHTTPGeolocationProvider(apiURL, apiKey string, logger logger.Logger) *HTTPGeolocationProvider {
	return &HTTPGeolocationProvider{
		apiURL: apiURL,
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		logger: logger,
	}
}

// GetLocation gets geolocation data via HTTP API
func (h *HTTPGeolocationProvider) GetLocation(ip string) (*GeolocationInfo, error) {
	url := fmt.Sprintf("%s/%s", h.apiURL, ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if h.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.apiKey)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var geoInfo GeolocationInfo
	if err := json.NewDecoder(resp.Body).Decode(&geoInfo); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &geoInfo, nil
}
