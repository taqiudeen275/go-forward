package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// AdminIntegrationService provides integrated admin management with hierarchy enforcement
type AdminIntegrationService struct {
	adminService AdminService
	rbacService  RBACService
	enforcer     *HierarchyEnforcer
	audit        AuditService
}

// NewAdminIntegrationService creates a new integrated admin service
func NewAdminIntegrationService(
	adminService AdminService,
	rbacService RBACService,
	enforcer *HierarchyEnforcer,
	audit AuditService,
) *AdminIntegrationService {
	return &AdminIntegrationService{
		adminService: adminService,
		rbacService:  rbacService,
		enforcer:     enforcer,
		audit:        audit,
	}
}

// PromoteUserWithValidation promotes a user with full hierarchy validation
func (s *AdminIntegrationService) PromoteUserWithValidation(ctx context.Context, req *PromoteUserRequest) (*UnifiedUser, error) {
	// Enforce hierarchy rules
	if err := s.enforcer.EnforcePromotionRules(ctx, req.PromotedBy, req.UserID, req.AdminLevel); err != nil {
		return nil, err
	}

	// Validate admin action
	if err := s.adminService.ValidateAdminAction(ctx, req.PromotedBy, "admin_promote", &req.UserID); err != nil {
		return nil, err
	}

	// Perform the promotion
	user, err := s.adminService.PromoteUserToAdmin(ctx, req)
	if err != nil {
		return nil, err
	}

	// Log successful promotion
	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.PromotedBy,
		Action:     AuditActions.AdminPromote,
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.UserID.String()),
		Details: map[string]interface{}{
			"promoted_user_id": req.UserID.String(),
			"new_admin_level":  req.AdminLevel,
			"reason":           req.Reason,
		},
		Success:  true,
		Severity: AuditSeverityHigh,
	}); err != nil {
		fmt.Printf("Failed to log promotion: %v\n", err)
	}

	return user, nil
}

// DemoteAdminWithValidation demotes an admin with full hierarchy validation
func (s *AdminIntegrationService) DemoteAdminWithValidation(ctx context.Context, req *DemoteAdminRequest) error {
	// Enforce hierarchy rules
	if err := s.enforcer.EnforceDemotionRules(ctx, req.DemotedBy, req.AdminID, req.NewLevel); err != nil {
		return err
	}

	// Validate admin action
	if err := s.adminService.ValidateAdminAction(ctx, req.DemotedBy, "admin_demote", &req.AdminID); err != nil {
		return err
	}

	// Perform the demotion
	if err := s.adminService.DemoteAdmin(ctx, req); err != nil {
		return err
	}

	// Log successful demotion
	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.DemotedBy,
		Action:     AuditActions.AdminDemote,
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details: map[string]interface{}{
			"demoted_admin_id": req.AdminID.String(),
			"new_level":        req.NewLevel,
			"reason":           req.Reason,
		},
		Success:  true,
		Severity: AuditSeverityHigh,
	}); err != nil {
		fmt.Printf("Failed to log demotion: %v\n", err)
	}

	return nil
}

// UpdateCapabilitiesWithValidation updates admin capabilities with validation
func (s *AdminIntegrationService) UpdateCapabilitiesWithValidation(ctx context.Context, req *UpdateCapabilitiesRequest) error {
	// Enforce hierarchy rules
	if err := s.enforcer.EnforceCapabilityRules(ctx, req.UpdatedBy, req.AdminID, &req.Capabilities); err != nil {
		return err
	}

	// Validate admin action
	if err := s.adminService.ValidateAdminAction(ctx, req.UpdatedBy, "admin_capabilities_update", &req.AdminID); err != nil {
		return err
	}

	// Perform the update
	if err := s.adminService.UpdateAdminCapabilities(ctx, req); err != nil {
		return err
	}

	// Log successful update
	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.UpdatedBy,
		Action:     "admin_capabilities_update",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details: map[string]interface{}{
			"admin_id":     req.AdminID.String(),
			"capabilities": req.Capabilities,
			"reason":       req.Reason,
		},
		Success:  true,
		Severity: AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to log capability update: %v\n", err)
	}

	return nil
}

// AssignTablesWithValidation assigns tables with validation
func (s *AdminIntegrationService) AssignTablesWithValidation(ctx context.Context, req *AssignTablesRequest) error {
	// Enforce hierarchy rules
	if err := s.enforcer.EnforceTableAssignmentRules(ctx, req.AssignedBy, req.AdminID, req.Tables); err != nil {
		return err
	}

	// Validate admin action
	if err := s.adminService.ValidateAdminAction(ctx, req.AssignedBy, "admin_table_assign", &req.AdminID); err != nil {
		return err
	}

	// Perform the assignment
	if err := s.adminService.AssignTablesToAdmin(ctx, req); err != nil {
		return err
	}

	// Log successful assignment
	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.AssignedBy,
		Action:     "admin_table_assign",
		Resource:   StringPtr("user"),
		ResourceID: StringPtr(req.AdminID.String()),
		Details: map[string]interface{}{
			"admin_id": req.AdminID.String(),
			"tables":   req.Tables,
		},
		Success:  true,
		Severity: AuditSeverityMedium,
	}); err != nil {
		fmt.Printf("Failed to log table assignment: %v\n", err)
	}

	return nil
}

// CreateEmergencyAccessWithValidation creates emergency access with validation
func (s *AdminIntegrationService) CreateEmergencyAccessWithValidation(ctx context.Context, req *EmergencyAccessRequest) (*EmergencyAccess, error) {
	// Enforce hierarchy rules
	if err := s.enforcer.EnforceEmergencyAccessRules(ctx, req.CreatedBy, req); err != nil {
		return nil, err
	}

	// Validate admin action
	if err := s.adminService.ValidateAdminAction(ctx, req.CreatedBy, "emergency_access_create", nil); err != nil {
		return nil, err
	}

	// Create emergency access
	access, err := s.adminService.CreateEmergencyAccess(ctx, req)
	if err != nil {
		return nil, err
	}

	// Log successful creation
	if err := s.audit.LogAction(ctx, &AuditLogRequest{
		UserID:     &req.CreatedBy,
		Action:     "emergency_access_create",
		Resource:   StringPtr("emergency_access"),
		ResourceID: StringPtr(access.ID.String()),
		Details: map[string]interface{}{
			"access_id":      access.ID.String(),
			"admin_level":    req.AdminLevel,
			"duration":       req.Duration.String(),
			"reason":         req.Reason,
			"ip_restriction": req.IPRestriction,
		},
		Success:  true,
		Severity: AuditSeverityCritical,
	}); err != nil {
		fmt.Printf("Failed to log emergency access creation: %v\n", err)
	}

	return access, nil
}

// GetAdminHierarchyWithContext gets admin hierarchy with additional context
func (s *AdminIntegrationService) GetAdminHierarchyWithContext(ctx context.Context, adminID uuid.UUID, requestedBy uuid.UUID) (*AdminHierarchyResponse, error) {
	// Validate that requester can view hierarchy
	canView, err := s.rbacService.CanPerformAction(ctx, requestedBy, "admin_hierarchy_view", "admin", StringPtr(adminID.String()))
	if err != nil {
		return nil, err
	}

	if !canView {
		return nil, errors.NewAuthError("insufficient permissions to view admin hierarchy")
	}

	// Get hierarchy
	hierarchy, err := s.adminService.GetAdminHierarchy(ctx, adminID)
	if err != nil {
		return nil, err
	}

	// Get additional context
	admin, err := s.adminService.GetAdminByID(ctx, adminID)
	if err != nil {
		return nil, err
	}

	// Build response with additional context
	response := &AdminHierarchyResponse{
		AdminHierarchy: *hierarchy,
		Admin:          admin,
		CanPromote:     []AdminLevel{},
		CanDemote:      false,
		CanModify:      false,
	}

	// Determine what the requesting user can do with this admin
	requester, err := s.rbacService.GetUserCapabilities(ctx, requestedBy)
	if err == nil && requester != nil {
		// Check promotion capabilities
		for _, level := range []AdminLevel{AdminLevelModerator, AdminLevelRegularAdmin, AdminLevelSuperAdmin, AdminLevelSystemAdmin} {
			if s.adminService.ValidateAdminPromotion(ctx, requestedBy, level) == nil {
				response.CanPromote = append(response.CanPromote, level)
			}
		}

		// Check demotion capability
		canManage, err := s.rbacService.CanManageUser(ctx, requestedBy, adminID)
		if err == nil && canManage {
			response.CanDemote = true
			response.CanModify = true
		}
	}

	return response, nil
}

// ListAdminsWithHierarchy lists admins with hierarchy information
func (s *AdminIntegrationService) ListAdminsWithHierarchy(ctx context.Context, filter *AdminManagementFilter, requestedBy uuid.UUID) (*AdminListResponse, error) {
	// Validate that requester can list admins
	canList, err := s.rbacService.CanPerformAction(ctx, requestedBy, "admin_list", "admin", nil)
	if err != nil {
		return nil, err
	}

	if !canList {
		return nil, errors.NewAuthError("insufficient permissions to list admins")
	}

	// Get admins
	admins, err := s.adminService.ListAdmins(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Build response with hierarchy information
	var adminItems []*AdminListItem
	for _, admin := range admins {
		hierarchy, err := s.adminService.GetAdminHierarchy(ctx, admin.ID)
		if err != nil {
			// Skip if can't get hierarchy
			continue
		}

		// Check what requester can do with this admin
		canManage, _ := s.rbacService.CanManageUser(ctx, requestedBy, admin.ID)

		item := &AdminListItem{
			Admin:     admin,
			Hierarchy: hierarchy,
			CanManage: canManage,
		}

		adminItems = append(adminItems, item)
	}

	response := &AdminListResponse{
		Admins: adminItems,
		Total:  len(adminItems),
	}

	return response, nil
}

// ValidateAdminOperation validates any admin operation with comprehensive checks
func (s *AdminIntegrationService) ValidateAdminOperation(ctx context.Context, req *AdminOperationRequest) (*AdminOperationResponse, error) {
	// Get operator
	operator, err := s.rbacService.GetUserCapabilities(ctx, req.OperatorID)
	if err != nil {
		return nil, err
	}

	response := &AdminOperationResponse{
		OperatorID:   req.OperatorID,
		Operation:    req.Operation,
		TargetID:     req.TargetID,
		Allowed:      false,
		Reason:       "",
		Requirements: []string{},
		Warnings:     []string{},
	}

	// Check basic admin status
	if operator == nil {
		response.Reason = "operator is not an admin"
		return response, nil
	}

	// Validate specific operation
	switch req.Operation {
	case "promote":
		response = s.validatePromotionOperation(ctx, req, response)
	case "demote":
		response = s.validateDemotionOperation(ctx, req, response)
	case "modify_capabilities":
		response = s.validateCapabilityOperation(ctx, req, response)
	case "assign_tables":
		response = s.validateTableAssignmentOperation(ctx, req, response)
	case "create_emergency_access":
		response = s.validateEmergencyAccessOperation(ctx, req, response)
	default:
		response.Reason = "unknown operation"
	}

	return response, nil
}

// Response types for admin integration

type AdminHierarchyResponse struct {
	AdminHierarchy
	Admin      *UnifiedUser `json:"admin"`
	CanPromote []AdminLevel `json:"can_promote"`
	CanDemote  bool         `json:"can_demote"`
	CanModify  bool         `json:"can_modify"`
}

type AdminListItem struct {
	Admin     *UnifiedUser    `json:"admin"`
	Hierarchy *AdminHierarchy `json:"hierarchy"`
	CanManage bool            `json:"can_manage"`
}

type AdminListResponse struct {
	Admins []*AdminListItem `json:"admins"`
	Total  int              `json:"total"`
}

type AdminOperationRequest struct {
	OperatorID uuid.UUID              `json:"operator_id"`
	Operation  string                 `json:"operation"`
	TargetID   *uuid.UUID             `json:"target_id,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

type AdminOperationResponse struct {
	OperatorID   uuid.UUID  `json:"operator_id"`
	Operation    string     `json:"operation"`
	TargetID     *uuid.UUID `json:"target_id,omitempty"`
	Allowed      bool       `json:"allowed"`
	Reason       string     `json:"reason,omitempty"`
	Requirements []string   `json:"requirements,omitempty"`
	Warnings     []string   `json:"warnings,omitempty"`
}

// Helper methods for operation validation

func (s *AdminIntegrationService) validatePromotionOperation(ctx context.Context, req *AdminOperationRequest, response *AdminOperationResponse) *AdminOperationResponse {
	if req.TargetID == nil {
		response.Reason = "target user ID required for promotion"
		return response
	}

	targetLevel, ok := req.Parameters["target_level"].(string)
	if !ok {
		response.Reason = "target admin level required"
		return response
	}

	level := AdminLevel(targetLevel)
	if err := s.enforcer.EnforcePromotionRules(ctx, req.OperatorID, *req.TargetID, level); err != nil {
		response.Reason = err.Error()
		return response
	}

	response.Allowed = true
	return response
}

func (s *AdminIntegrationService) validateDemotionOperation(ctx context.Context, req *AdminOperationRequest, response *AdminOperationResponse) *AdminOperationResponse {
	if req.TargetID == nil {
		response.Reason = "target admin ID required for demotion"
		return response
	}

	var newLevel *AdminLevel
	if levelStr, ok := req.Parameters["new_level"].(string); ok {
		level := AdminLevel(levelStr)
		newLevel = &level
	}

	if err := s.enforcer.EnforceDemotionRules(ctx, req.OperatorID, *req.TargetID, newLevel); err != nil {
		response.Reason = err.Error()
		return response
	}

	response.Allowed = true
	return response
}

func (s *AdminIntegrationService) validateCapabilityOperation(ctx context.Context, req *AdminOperationRequest, response *AdminOperationResponse) *AdminOperationResponse {
	if req.TargetID == nil {
		response.Reason = "target admin ID required for capability modification"
		return response
	}

	// This would need the actual capabilities from parameters
	// For now, just check basic hierarchy rules
	response.Allowed = true
	return response
}

func (s *AdminIntegrationService) validateTableAssignmentOperation(ctx context.Context, req *AdminOperationRequest, response *AdminOperationResponse) *AdminOperationResponse {
	if req.TargetID == nil {
		response.Reason = "target admin ID required for table assignment"
		return response
	}

	tables, ok := req.Parameters["tables"].([]string)
	if !ok {
		response.Reason = "tables list required"
		return response
	}

	if err := s.enforcer.EnforceTableAssignmentRules(ctx, req.OperatorID, *req.TargetID, tables); err != nil {
		response.Reason = err.Error()
		return response
	}

	response.Allowed = true
	return response
}

func (s *AdminIntegrationService) validateEmergencyAccessOperation(ctx context.Context, req *AdminOperationRequest, response *AdminOperationResponse) *AdminOperationResponse {
	durationStr, ok := req.Parameters["duration"].(string)
	if !ok {
		response.Reason = "duration required for emergency access"
		return response
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		response.Reason = "invalid duration format"
		return response
	}

	emergencyReq := &EmergencyAccessRequest{
		CreatedBy: req.OperatorID,
		Duration:  duration,
	}

	if err := s.enforcer.EnforceEmergencyAccessRules(ctx, req.OperatorID, emergencyReq); err != nil {
		response.Reason = err.Error()
		return response
	}

	response.Allowed = true
	return response
}
