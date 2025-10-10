package auth

import "time"

// APISecurityContext represents extended security context for API operations
type APISecurityContext struct {
	// Basic context (from SecurityContext)
	UserID      string            `json:"user_id"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
	SessionID   string            `json:"session_id"`
	RequestID   string            `json:"request_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Environment string            `json:"environment"`
	Metadata    map[string]string `json:"metadata"`

	// Extended context for API security
	UserRoles    []string          `json:"user_roles"`
	AdminLevel   AdminLevel        `json:"admin_level"`
	MFAVerified  bool              `json:"mfa_verified"`
	Capabilities AdminCapabilities `json:"capabilities"`
}

// ToSecurityContext converts APISecurityContext to SecurityContext
func (a *APISecurityContext) ToSecurityContext() *SecurityContext {
	return &SecurityContext{
		UserID:      a.UserID,
		IPAddress:   a.IPAddress,
		UserAgent:   a.UserAgent,
		SessionID:   a.SessionID,
		RequestID:   a.RequestID,
		Timestamp:   a.Timestamp,
		Environment: a.Environment,
		Metadata:    a.Metadata,
	}
}

// FromSecurityContext creates APISecurityContext from SecurityContext
func FromSecurityContext(sc *SecurityContext) *APISecurityContext {
	return &APISecurityContext{
		UserID:       sc.UserID,
		IPAddress:    sc.IPAddress,
		UserAgent:    sc.UserAgent,
		SessionID:    sc.SessionID,
		RequestID:    sc.RequestID,
		Timestamp:    sc.Timestamp,
		Environment:  sc.Environment,
		Metadata:     sc.Metadata,
		UserRoles:    []string{},
		AdminLevel:   AdminLevel(""),
		MFAVerified:  false,
		Capabilities: AdminCapabilities{},
	}
}
