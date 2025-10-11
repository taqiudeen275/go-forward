package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// AdminService defines the admin management interface
type AdminService interface {
	// Admin promotion and demotion
	PromoteUserToAdmin(ctx context.Context, req *PromoteUserRequest) (*UnifiedUser, error)
	DemoteAdmin(ctx context.Context, req *DemoteAdminRequest) error
	UpdateAdminCapabilities(ctx context.Context, req *UpdateCapabilitiesRequest) error

	// Admin assignment
	AssignTablesToAdmin(ctx context.Context, req *AssignTablesRequest) error
	RemoveTablesFromAdmin(ctx context.Context, req *RemoveTablesRequest) error
	AssignUserGroupsToAdmin(ctx context.Context, req *AssignUserGroupsRequest) error

	// Admin management
	ListAdmins(ctx context.Context, filter *AdminManagementFilter) ([]*UnifiedUser, error)
	GetAdminByID(ctx context.Context, adminID uuid.UUID) (*UnifiedUser, error)
	GetAdminHierarchy(ctx context.Context, adminID uuid.UUID) (*AdminHierarchy, error)

	// Emergency access
	CreateEmergencyAccess(ctx context.Context, req *EmergencyAccessRequest) (*EmergencyAccess, error)
	RevokeEmergencyAccess(ctx context.Context, accessID uuid.UUID, revokedBy uuid.UUID) error
	ListEmergencyAccess(ctx context.Context, filter *EmergencyAccessFilter) ([]*EmergencyAccess, error)

	// Admin validation
	ValidateAdminAction(ctx context.Context, adminID uuid.UUID, action string, targetUserID *uuid.UUID) error
	ValidateAdminPromotion(ctx context.Context, promoterID uuid.UUID, targetLevel AdminLevel) error
}

// Request/Response types
type PromoteUserRequest struct {
	UserID         uuid.UUID          `json:"user_id" validate:"required"`
	AdminLevel     AdminLevel         `json:"admin_level" validate:"required"`
	PromotedBy     uuid.UUID          `json:"promoted_by" validate:"required"`
	Reason         string             `json:"reason"`
	CustomCaps     *AdminCapabilities `json:"custom_capabilities,omitempty"`
	AssignedTables []string           `json:"assigned_tables,omitempty"`
}

type DemoteAdminRequest struct {
	AdminID   uuid.UUID   `json:"admin_id" validate:"required"`
	DemotedBy uuid.UUID   `json:"demoted_by" validate:"required"`
	Reason    string      `json:"reason"`
	NewLevel  *AdminLevel `json:"new_level,omitempty"` // If nil, removes admin privileges entirely
}

type UpdateCapabilitiesRequest struct {
	AdminID      uuid.UUID         `json:"admin_id" validate:"required"`
	Capabilities AdminCapabilities `json:"capabilities" validate:"required"`
	UpdatedBy    uuid.UUID         `json:"updated_by" validate:"required"`
	Reason       string            `json:"reason"`
}

type AssignTablesRequest struct {
	AdminID    uuid.UUID `json:"admin_id" validate:"required"`
	Tables     []string  `json:"tables" validate:"required"`
	AssignedBy uuid.UUID `json:"assigned_by" validate:"required"`
}

type RemoveTablesRequest struct {
	AdminID   uuid.UUID `json:"admin_id" validate:"required"`
	Tables    []string  `json:"tables" validate:"required"`
	RemovedBy uuid.UUID `json:"removed_by" validate:"required"`
}

type AssignUserGroupsRequest struct {
	AdminID    uuid.UUID `json:"admin_id" validate:"required"`
	UserGroups []string  `json:"user_groups" validate:"required"`
	AssignedBy uuid.UUID `json:"assigned_by" validate:"required"`
}

type AdminManagementFilter struct {
	AdminLevel   *AdminLevel `json:"admin_level,omitempty"`
	SearchTerm   string      `json:"search_term,omitempty"`
	IncludeUsers bool        `json:"include_users"` // Include non-admin users
	Limit        int         `json:"limit"`
	Offset       int         `json:"offset"`
}

type EmergencyAccessRequest struct {
	CreatedBy     uuid.UUID     `json:"created_by" validate:"required"`
	Reason        string        `json:"reason" validate:"required"`
	Duration      time.Duration `json:"duration" validate:"required"`
	AdminLevel    AdminLevel    `json:"admin_level" validate:"required"`
	IPRestriction *string       `json:"ip_restriction,omitempty"`
}

type EmergencyAccess struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	AccessToken   string     `json:"access_token" db:"access_token"`
	CreatedBy     uuid.UUID  `json:"created_by" db:"created_by"`
	Reason        string     `json:"reason" db:"reason"`
	AdminLevel    AdminLevel `json:"admin_level" db:"admin_level"`
	IPRestriction *string    `json:"ip_restriction" db:"ip_restriction"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	UsedAt        *time.Time `json:"used_at" db:"used_at"`
	UsedBy        *uuid.UUID `json:"used_by" db:"used_by"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
	RevokedBy     *uuid.UUID `json:"revoked_by" db:"revoked_by"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

type EmergencyAccessFilter struct {
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	Active    *bool      `json:"active,omitempty"` // true for non-expired, non-revoked
	Limit     int        `json:"limit"`
	Offset    int        `json:"offset"`
}

// AdminHierarchy represents the admin hierarchy information (already defined in rbac.go)

// adminService implements the AdminService interface
type adminService struct {
	repo  Repository
	rbac  RBACService
	audit AuditService
}

// NewAdminService creates a new admin service
func NewAdminService(repo Repository, rbac RBACService, audit AuditService) AdminService {
	return &adminService{
		repo:  repo,
		rbac:  rbac,
		audit: audit,
	}
}

// PromoteUserToAdmin promotes a user to admin with specified level and capabilities
func (s *adminService) PromoteUserToAdmin(ctx context.Context, req *PromoteUserRequest) (*UnifiedUser, error) {
	// Validate the promotion request
	if err := s.ValidateAdminPromotion(ctx, req.PromotedBy, req.AdminLevel); err != nil {
		return nil, err
	}

	// Get the user to be promoted
	user, err := s.repo.GetUserByID(ctx, req.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get user for promotion")
	}

	// Check if user is already an admin
	if user.IsAdmin() {
		return nil, errors.NewAuthError("user is already an admin")
	}

	// Get capabilities for the admin level
	capabilities := GetDefaultCapabilities(req.AdminLevel)
	if req.CustomCaps != nil {
		// Validate custom capabilities don't exceed what the promoter can grant
		if err := s.validateCustomCapabilities(ctx, req.PromotedBy, req.CustomCaps); err != nil {
			return nil, err
		}
		capabilities = *req.CustomCaps
	}

	// Update user with admin privileges
	user.AdminLevel = &req.AdminLevel
	user.Capabilities = &capabilities
	user.AssignedTables = req.AssignedTables
	user.UpdatedBy = &req.PromotedBy
	user.UpdatedAt = time.Now().UTC()

	// Save the updated user
	if err := s.repo.UpdateUser(ctx, user); err != nil {
		return nil, errors.Wrap(err, "failed to promote user to admin")
	}

	// Invalidate RBAC cache for this user
	s.rbac.InvalidateUserCache(req.UserID)

	// Create audit log
	auditDetails := map[string]interface{}{
		"user_id":         req.UserID.String(),
		"admin_level":     req.AdminLevel,
		"promoted_by":     req.PromotedBy.String(),
		"reason":          req.Reason,
		"assigned_tables": req.AssignedTables,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.PromotedBy,
		Action:     AuditActions.AdminPromote,
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.UserID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityHigh,
	}); err != nil {
		// Log audit failure but don't fail the promotion
		fmt.Printf("Failed to create audit log for admin promotion: %v\n", err)
	}

	return user, nil
}

// DemoteAdmin demotes an admin or removes admin privileges entirely
func (s *adminService) DemoteAdmin(ctx context.Context, req *DemoteAdminRequest) error {
	// Validate the demotion request
	demotingUser, err := s.repo.GetUserByID(ctx, req.DemotedBy)
	if err != nil {
		return errors.Wrap(err, "failed to get demoting user")
	}

	targetAdmin, err := s.repo.GetUserByID(ctx, req.AdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Check if demoting user can manage the target admin
	if !demotingUser.CanManageUser(targetAdmin) {
		return errors.NewAuthError("insufficient privileges to demote this admin")
	}

	// Prevent self-demotion for system admins (safety measure)
	if req.DemotedBy == req.AdminID && targetAdmin.IsSystemAdmin() {
		return errors.NewAuthError("system admins cannot demote themselves")
	}

	// Update admin level
	if req.NewLevel != nil {
		// Demote to lower level
		targetAdmin.AdminLevel = req.NewLevel
		targetAdmin.Capabilities = GetDefaultCapabilitiesPtr(*req.NewLevel)
		// Clear assigned tables if demoting to moderator or below
		if *req.NewLevel == AdminLevelModerator {
			targetAdmin.AssignedTables = []string{}
		}
	} else {
		// Remove admin privileges entirely
		targetAdmin.AdminLevel = nil
		targetAdmin.Capabilities = nil
		targetAdmin.AssignedTables = []string{}
	}

	targetAdmin.UpdatedBy = &req.DemotedBy
	targetAdmin.UpdatedAt = time.Now().UTC()

	// Save the updated user
	if err := s.repo.UpdateUser(ctx, targetAdmin); err != nil {
		return errors.Wrap(err, "failed to demote admin")
	}

	// Invalidate RBAC cache for this user
	s.rbac.InvalidateUserCache(req.AdminID)

	// Create audit log
	auditDetails := map[string]interface{}{
		"admin_id":   req.AdminID.String(),
		"demoted_by": req.DemotedBy.String(),
		"reason":     req.Reason,
		"new_level":  req.NewLevel,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.DemotedBy,
		Action:     AuditActions.AdminDemote,
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityHigh,
	}); err != nil {
		fmt.Printf("Failed to create audit log for admin demotion: %v\n", err)
	}

	return nil
}

// UpdateAdminCapabilities updates an admin's capabilities
func (s *adminService) UpdateAdminCapabilities(ctx context.Context, req *UpdateCapabilitiesRequest) error {
	// Validate the update request
	updatingUser, err := s.repo.GetUserByID(ctx, req.UpdatedBy)
	if err != nil {
		return errors.Wrap(err, "failed to get updating user")
	}

	targetAdmin, err := s.repo.GetUserByID(ctx, req.AdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Check if updating user can manage the target admin
	if !updatingUser.CanManageUser(targetAdmin) {
		return errors.NewAuthError("insufficient privileges to update this admin's capabilities")
	}

	// Validate that the new capabilities don't exceed what the updating user can grant
	if err := s.validateCustomCapabilities(ctx, req.UpdatedBy, &req.Capabilities); err != nil {
		return err
	}

	// Update capabilities
	targetAdmin.Capabilities = &req.Capabilities
	targetAdmin.UpdatedBy = &req.UpdatedBy
	targetAdmin.UpdatedAt = time.Now().UTC()

	// Save the updated user
	if err := s.repo.UpdateUser(ctx, targetAdmin); err != nil {
		return errors.Wrap(err, "failed to update admin capabilities")
	}

	// Invalidate RBAC cache for this user
	s.rbac.InvalidateUserCache(req.AdminID)

	// Create audit log
	auditDetails := map[string]interface{}{
		"admin_id":     req.AdminID.String(),
		"updated_by":   req.UpdatedBy.String(),
		"reason":       req.Reason,
		"capabilities": req.Capabilities,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.UpdatedBy,
		Action:     "admin_capabilities_update",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to create audit log for capabilities update: %v\n", err)
	}

	return nil
}

// AssignTablesToAdmin assigns tables to an admin
func (s *adminService) AssignTablesToAdmin(ctx context.Context, req *AssignTablesRequest) error {
	// Validate the assignment request
	assigningUser, err := s.repo.GetUserByID(ctx, req.AssignedBy)
	if err != nil {
		return errors.Wrap(err, "failed to get assigning user")
	}

	targetAdmin, err := s.repo.GetUserByID(ctx, req.AdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Check if assigning user can manage the target admin
	if !assigningUser.CanManageUser(targetAdmin) {
		return errors.NewAuthError("insufficient privileges to assign tables to this admin")
	}

	// Only regular admins and moderators need table assignments
	if targetAdmin.IsSuperAdmin() {
		return errors.NewAuthError("super admins and system admins have access to all tables")
	}

	// Add new tables to assigned tables (avoid duplicates)
	existingTables := make(map[string]bool)
	for _, table := range targetAdmin.AssignedTables {
		existingTables[table] = true
	}

	for _, table := range req.Tables {
		if !existingTables[table] {
			targetAdmin.AssignedTables = append(targetAdmin.AssignedTables, table)
		}
	}

	targetAdmin.UpdatedBy = &req.AssignedBy
	targetAdmin.UpdatedAt = time.Now().UTC()

	// Save the updated user
	if err := s.repo.UpdateUser(ctx, targetAdmin); err != nil {
		return errors.Wrap(err, "failed to assign tables to admin")
	}

	// Invalidate RBAC cache for this user
	s.rbac.InvalidateUserCache(req.AdminID)

	// Create audit log
	auditDetails := map[string]interface{}{
		"admin_id":    req.AdminID.String(),
		"assigned_by": req.AssignedBy.String(),
		"tables":      req.Tables,
		"all_tables":  targetAdmin.AssignedTables,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.AssignedBy,
		Action:     "admin_tables_assign",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to create audit log for table assignment: %v\n", err)
	}

	return nil
}

// RemoveTablesFromAdmin removes tables from an admin's assignment
func (s *adminService) RemoveTablesFromAdmin(ctx context.Context, req *RemoveTablesRequest) error {
	// Validate the removal request
	removingUser, err := s.repo.GetUserByID(ctx, req.RemovedBy)
	if err != nil {
		return errors.Wrap(err, "failed to get removing user")
	}

	targetAdmin, err := s.repo.GetUserByID(ctx, req.AdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Check if removing user can manage the target admin
	if !removingUser.CanManageUser(targetAdmin) {
		return errors.NewAuthError("insufficient privileges to remove tables from this admin")
	}

	// Remove tables from assigned tables
	tablesToRemove := make(map[string]bool)
	for _, table := range req.Tables {
		tablesToRemove[table] = true
	}

	var newAssignedTables []string
	for _, table := range targetAdmin.AssignedTables {
		if !tablesToRemove[table] {
			newAssignedTables = append(newAssignedTables, table)
		}
	}

	targetAdmin.AssignedTables = newAssignedTables
	targetAdmin.UpdatedBy = &req.RemovedBy
	targetAdmin.UpdatedAt = time.Now().UTC()

	// Save the updated user
	if err := s.repo.UpdateUser(ctx, targetAdmin); err != nil {
		return errors.Wrap(err, "failed to remove tables from admin")
	}

	// Invalidate RBAC cache for this user
	s.rbac.InvalidateUserCache(req.AdminID)

	// Create audit log
	auditDetails := map[string]interface{}{
		"admin_id":         req.AdminID.String(),
		"removed_by":       req.RemovedBy.String(),
		"tables":           req.Tables,
		"remaining_tables": targetAdmin.AssignedTables,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.RemovedBy,
		Action:     "admin_tables_remove",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to create audit log for table removal: %v\n", err)
	}

	return nil
}

// AssignUserGroupsToAdmin assigns user groups to an admin (placeholder for future implementation)
func (s *adminService) AssignUserGroupsToAdmin(ctx context.Context, req *AssignUserGroupsRequest) error {
	// This is a placeholder for future user group functionality
	// For now, we'll just create an audit log
	auditDetails := map[string]interface{}{
		"admin_id":    req.AdminID.String(),
		"assigned_by": req.AssignedBy.String(),
		"user_groups": req.UserGroups,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.AssignedBy,
		Action:     "admin_user_groups_assign",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to create audit log for user group assignment: %v\n", err)
	}

	return errors.NewAuthError("user group functionality not yet implemented")
}

// ListAdmins returns a list of admins based on the filter
func (s *adminService) ListAdmins(ctx context.Context, filter *AdminManagementFilter) ([]*UnifiedUser, error) {
	// Convert to repository filter
	repoFilter := &AdminFilter{
		Level:  filter.AdminLevel,
		Search: filter.SearchTerm,
		Limit:  filter.Limit,
		Offset: filter.Offset,
	}
	return s.repo.ListAdmins(ctx, repoFilter)
}

// GetAdminByID returns an admin by ID
func (s *adminService) GetAdminByID(ctx context.Context, adminID uuid.UUID) (*UnifiedUser, error) {
	user, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, errors.NewNotFound("admin not found")
	}

	return user, nil
}

// GetAdminHierarchy returns the admin hierarchy information
func (s *adminService) GetAdminHierarchy(ctx context.Context, adminID uuid.UUID) (*AdminHierarchy, error) {
	return s.rbac.GetAdminHierarchy(ctx, adminID)
}

// CreateEmergencyAccess creates emergency access with time limits
func (s *adminService) CreateEmergencyAccess(ctx context.Context, req *EmergencyAccessRequest) (*EmergencyAccess, error) {
	// Validate the creator has permission to create emergency access
	creator, err := s.repo.GetUserByID(ctx, req.CreatedBy)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get creator")
	}

	if !creator.IsSystemAdmin() {
		return nil, errors.NewAuthError("only system admins can create emergency access")
	}

	// Validate duration (max 24 hours)
	if req.Duration > 24*time.Hour {
		return nil, errors.NewAuthError("emergency access duration cannot exceed 24 hours")
	}

	// Generate access token
	accessToken := uuid.New().String()

	emergencyAccess := &EmergencyAccess{
		ID:            uuid.New(),
		AccessToken:   accessToken,
		CreatedBy:     req.CreatedBy,
		Reason:        req.Reason,
		AdminLevel:    req.AdminLevel,
		IPRestriction: req.IPRestriction,
		ExpiresAt:     time.Now().UTC().Add(req.Duration),
		CreatedAt:     time.Now().UTC(),
	}

	// Save emergency access
	if err := s.repo.CreateEmergencyAccess(ctx, emergencyAccess); err != nil {
		return nil, errors.Wrap(err, "failed to create emergency access")
	}

	// Create audit log
	auditDetails := map[string]interface{}{
		"access_id":      emergencyAccess.ID.String(),
		"created_by":     req.CreatedBy.String(),
		"reason":         req.Reason,
		"admin_level":    req.AdminLevel,
		"duration":       req.Duration.String(),
		"ip_restriction": req.IPRestriction,
		"expires_at":     emergencyAccess.ExpiresAt,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.CreatedBy,
		Action:     "emergency_access_create",
		Resource:   StringPtr("emergency_access"),
		ResourceID: StringPtr(emergencyAccess.ID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityCritical,
	}); err != nil {
		fmt.Printf("Failed to create audit log for emergency access creation: %v\n", err)
	}

	return emergencyAccess, nil
}

// RevokeEmergencyAccess revokes emergency access
func (s *adminService) RevokeEmergencyAccess(ctx context.Context, accessID uuid.UUID, revokedBy uuid.UUID) error {
	// Validate the revoker has permission
	revoker, err := s.repo.GetUserByID(ctx, revokedBy)
	if err != nil {
		return errors.Wrap(err, "failed to get revoker")
	}

	if !revoker.IsSystemAdmin() {
		return errors.NewAuthError("only system admins can revoke emergency access")
	}

	// Get emergency access
	emergencyAccess, err := s.repo.GetEmergencyAccessByID(ctx, accessID)
	if err != nil {
		return errors.Wrap(err, "failed to get emergency access")
	}

	// Check if already revoked
	if emergencyAccess.RevokedAt != nil {
		return errors.NewAuthError("emergency access is already revoked")
	}

	// Revoke access
	now := time.Now().UTC()
	emergencyAccess.RevokedAt = &now
	emergencyAccess.RevokedBy = &revokedBy

	if err := s.repo.UpdateEmergencyAccess(ctx, emergencyAccess); err != nil {
		return errors.Wrap(err, "failed to revoke emergency access")
	}

	// Create audit log
	auditDetails := map[string]interface{}{
		"access_id":  accessID.String(),
		"revoked_by": revokedBy.String(),
		"revoked_at": now,
	}

	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &revokedBy,
		Action:     "emergency_access_revoke",
		Resource:   StringPtr("emergency_access"),
		ResourceID: StringPtr(accessID.String()),
		Details:    auditDetails,
		Severity:   AuditSeverityCritical,
	}); err != nil {
		fmt.Printf("Failed to create audit log for emergency access revocation: %v\n", err)
	}

	return nil
}

// ListEmergencyAccess returns a list of emergency access entries
func (s *adminService) ListEmergencyAccess(ctx context.Context, filter *EmergencyAccessFilter) ([]*EmergencyAccess, error) {
	return s.repo.ListEmergencyAccess(ctx, filter)
}

// ValidateAdminAction validates if an admin can perform a specific action
func (s *adminService) ValidateAdminAction(ctx context.Context, adminID uuid.UUID, action string, targetUserID *uuid.UUID) error {
	admin, err := s.repo.GetUserByID(ctx, adminID)
	if err != nil {
		return errors.Wrap(err, "failed to get admin")
	}

	if !admin.IsAdmin() {
		return errors.NewAuthError("user is not an admin")
	}

	// If action involves another user, check if admin can manage them
	if targetUserID != nil {
		targetUser, err := s.repo.GetUserByID(ctx, *targetUserID)
		if err != nil {
			return errors.Wrap(err, "failed to get target user")
		}

		if !admin.CanManageUser(targetUser) {
			return errors.NewAuthError("insufficient privileges to perform action on target user")
		}
	}

	// Check specific action permissions using RBAC
	var targetUserIDStr *string
	if targetUserID != nil {
		str := targetUserID.String()
		targetUserIDStr = &str
	}
	allowed, err := s.rbac.CanPerformAction(ctx, adminID, action, "admin", targetUserIDStr)
	if err != nil {
		return err
	}

	if !allowed {
		return errors.NewAuthError(fmt.Sprintf("insufficient privileges for action: %s", action))
	}

	return nil
}

// ValidateAdminPromotion validates if a user can promote someone to a specific admin level
func (s *adminService) ValidateAdminPromotion(ctx context.Context, promoterID uuid.UUID, targetLevel AdminLevel) error {
	promoter, err := s.repo.GetUserByID(ctx, promoterID)
	if err != nil {
		return errors.Wrap(err, "failed to get promoter")
	}

	return ValidateAdminPromotion(promoter, targetLevel)
}

// Helper methods

// validateCustomCapabilities validates that custom capabilities don't exceed what the granter can provide
func (s *adminService) validateCustomCapabilities(ctx context.Context, granterID uuid.UUID, capabilities *AdminCapabilities) error {
	granter, err := s.repo.GetUserByID(ctx, granterID)
	if err != nil {
		return errors.Wrap(err, "failed to get granter")
	}

	if granter.Capabilities == nil {
		return errors.NewAuthError("granter has no capabilities to grant")
	}

	// System admins can grant any capability
	if granter.IsSystemAdmin() {
		return nil
	}

	// Check each capability
	if capabilities.CanAccessSQL && !granter.Capabilities.CanAccessSQL {
		return errors.NewAuthError("granter cannot grant SQL access capability")
	}
	if capabilities.CanManageDatabase && !granter.Capabilities.CanManageDatabase {
		return errors.NewAuthError("granter cannot grant database management capability")
	}
	if capabilities.CanManageSystem && !granter.Capabilities.CanManageSystem {
		return errors.NewAuthError("granter cannot grant system management capability")
	}
	if capabilities.CanCreateSuperAdmin && !granter.Capabilities.CanCreateSuperAdmin {
		return errors.NewAuthError("granter cannot grant super admin creation capability")
	}
	if capabilities.CanInstallPlugins && !granter.Capabilities.CanInstallPlugins {
		return errors.NewAuthError("granter cannot grant plugin installation capability")
	}
	if capabilities.CanModifySecurityConfig && !granter.Capabilities.CanModifySecurityConfig {
		return errors.NewAuthError("granter cannot grant security config modification capability")
	}

	// Continue validation for other capabilities...
	// (Similar checks for all other capabilities)

	return nil
}

// GetDefaultCapabilitiesPtr returns a pointer to default capabilities
func GetDefaultCapabilitiesPtr(level AdminLevel) *AdminCapabilities {
	caps := GetDefaultCapabilities(level)
	return &caps
}

// StringPtr returns a pointer to a string
func StringPtr(s string) *string {
	return &s
}
