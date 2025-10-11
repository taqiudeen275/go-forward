package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// AuditService defines the audit logging interface
type AuditService interface {
	// Audit logging
	LogAction(ctx context.Context, req *AuditLogRequest) error
	LogSecurityEvent(ctx context.Context, req *SecurityEventRequest) error

	// Audit retrieval
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error)
	GetSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error)

	// Security event management
	ResolveSecurityEvent(ctx context.Context, eventID uuid.UUID, resolvedBy uuid.UUID) error

	// Audit analysis
	GetUserActivity(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*AuditLog, error)
	GetFailedLoginAttempts(ctx context.Context, identifier string, since time.Time) ([]*AuditLog, error)
	DetectSuspiciousActivity(ctx context.Context, userID uuid.UUID) ([]*SecurityEvent, error)
}

// Request types for audit service
type AuditLogRequest struct {
	UserID     *uuid.UUID             `json:"user_id,omitempty"`
	Action     string                 `json:"action" validate:"required"`
	Resource   *string                `json:"resource,omitempty"`
	ResourceID *string                `json:"resource_id,omitempty"`
	Details    map[string]interface{} `json:"details,omitempty"`
	IPAddress  *string                `json:"ip_address,omitempty"`
	UserAgent  *string                `json:"user_agent,omitempty"`
	RequestID  *string                `json:"request_id,omitempty"`
	Success    bool                   `json:"success"`
	ErrorCode  *string                `json:"error_code,omitempty"`
	Severity   AuditSeverity          `json:"severity"`
}

type SecurityEventRequest struct {
	EventType string                 `json:"event_type" validate:"required"`
	UserID    *uuid.UUID             `json:"user_id,omitempty"`
	IPAddress *string                `json:"ip_address,omitempty"`
	UserAgent *string                `json:"user_agent,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Severity  AuditSeverity          `json:"severity"`
}

// auditService implements the AuditService interface
type auditService struct {
	repo Repository
}

// NewAuditService creates a new audit service
func NewAuditService(repo Repository) AuditService {
	return &auditService{
		repo: repo,
	}
}

// LogAction logs an audit action
func (s *auditService) LogAction(ctx context.Context, req *AuditLogRequest) error {
	auditLog := &AuditLog{
		ID:         uuid.New(),
		UserID:     req.UserID,
		Action:     req.Action,
		Resource:   req.Resource,
		ResourceID: req.ResourceID,
		Details:    req.Details,
		IPAddress:  req.IPAddress,
		UserAgent:  req.UserAgent,
		RequestID:  req.RequestID,
		Success:    req.Success,
		ErrorCode:  req.ErrorCode,
		Severity:   req.Severity,
		CreatedAt:  time.Now().UTC(),
	}

	return s.repo.CreateAuditLog(ctx, auditLog)
}

// LogSecurityEvent logs a security event
func (s *auditService) LogSecurityEvent(ctx context.Context, req *SecurityEventRequest) error {
	securityEvent := &SecurityEvent{
		ID:        uuid.New(),
		EventType: req.EventType,
		UserID:    req.UserID,
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		Details:   req.Details,
		Severity:  req.Severity,
		Resolved:  false,
		CreatedAt: time.Now().UTC(),
	}

	return s.repo.CreateSecurityEvent(ctx, securityEvent)
}

// GetAuditLogs retrieves audit logs with filtering
func (s *auditService) GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error) {
	return s.repo.ListAuditLogs(ctx, filter)
}

// GetSecurityEvents retrieves security events with filtering
func (s *auditService) GetSecurityEvents(ctx context.Context, filter *SecurityEventFilter) ([]*SecurityEvent, error) {
	return s.repo.ListSecurityEvents(ctx, filter)
}

// ResolveSecurityEvent marks a security event as resolved
func (s *auditService) ResolveSecurityEvent(ctx context.Context, eventID uuid.UUID, resolvedBy uuid.UUID) error {
	return s.repo.ResolveSecurityEvent(ctx, eventID, resolvedBy)
}

// GetUserActivity retrieves user activity within a date range
func (s *auditService) GetUserActivity(ctx context.Context, userID uuid.UUID, startDate, endDate time.Time) ([]*AuditLog, error) {
	filter := &AuditFilter{
		UserID:    &userID,
		StartDate: &startDate,
		EndDate:   &endDate,
		Limit:     1000, // Reasonable limit
	}

	return s.repo.ListAuditLogs(ctx, filter)
}

// GetFailedLoginAttempts retrieves failed login attempts for an identifier
func (s *auditService) GetFailedLoginAttempts(ctx context.Context, identifier string, since time.Time) ([]*AuditLog, error) {
	filter := &AuditFilter{
		Action:    "login",
		StartDate: &since,
		Success:   BoolPtr(false),
		Limit:     100,
	}

	logs, err := s.repo.ListAuditLogs(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Filter by identifier in details
	var failedAttempts []*AuditLog
	for _, log := range logs {
		if log.Details != nil {
			if email, ok := log.Details["email"].(string); ok && email == identifier {
				failedAttempts = append(failedAttempts, log)
			}
			if phone, ok := log.Details["phone"].(string); ok && phone == identifier {
				failedAttempts = append(failedAttempts, log)
			}
			if username, ok := log.Details["username"].(string); ok && username == identifier {
				failedAttempts = append(failedAttempts, log)
			}
		}
	}

	return failedAttempts, nil
}

// DetectSuspiciousActivity detects suspicious activity for a user
func (s *auditService) DetectSuspiciousActivity(ctx context.Context, userID uuid.UUID) ([]*SecurityEvent, error) {
	// Get recent security events for the user
	filter := &SecurityEventFilter{
		UserID:   &userID,
		Resolved: BoolPtr(false),
		Limit:    50,
	}

	events, err := s.repo.ListSecurityEvents(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Filter for suspicious events
	var suspiciousEvents []*SecurityEvent
	for _, event := range events {
		if s.isSuspiciousEvent(event) {
			suspiciousEvents = append(suspiciousEvents, event)
		}
	}

	return suspiciousEvents, nil
}

// Helper methods

// isSuspiciousEvent determines if an event is suspicious
func (s *auditService) isSuspiciousEvent(event *SecurityEvent) bool {
	suspiciousTypes := map[string]bool{
		SecurityEventTypes.LoginFailure:       true,
		SecurityEventTypes.UnauthorizedAccess: true,
		SecurityEventTypes.SuspiciousActivity: true,
		SecurityEventTypes.AccountLockout:     true,
	}

	return suspiciousTypes[event.EventType] && event.Severity >= AuditSeverityMedium
}

// BoolPtr returns a pointer to a boolean
func BoolPtr(b bool) *bool {
	return &b
}
