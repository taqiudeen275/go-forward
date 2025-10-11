package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taqiudeen275/go-foward/pkg/errors"
)

// HierarchyEnforcer enforces admin hierarchy rules and constraints
type HierarchyEnforcer struct {
	repo  Repository
	rbac  RBACService
	audit AuditService
}

// NewHierarchyEnforcer creates a new hierarchy enforcer
func NewHierarchyEnforcer(repo Repository, rbac RBACService, audit AuditService) *HierarchyEnforcer {
	return &HierarchyEnforcer{
		repo:  repo,
		rbac:  rbac,
		audit: audit,
	}
}

// EnforcePromotionRules enforces rules for admin promotion
func (h *HierarchyEnforcer) EnforcePromotionRules(ctx context.Context, promoterID uuid.UUID, targetUserID uuid.UUID, targetLevel AdminLevel) error {
	// Get promoter
	promoter, err := h.repo.GetUserByID(ctx, promoterID)
	if err != nil {
		return errors.Wrap(err, "failed to get promoter")
	}

	// Get target user
	targetUser, err := h.repo.GetUserByID(ctx, targetUserID)
	if err != nil {
		return errors.Wrap(err, "failed to get target user")
	}

	// Rule 1: Only admins can promote users
	if !promoter.IsAdmin() {
		return h.logViolation(ctx, "non_admin_promotion_attempt", promoterID, targetUserID, map[string]interface{}{
			"promoter_level": "none",
			"target_level":   targetLevel,
		})
	}

	// Rule 2: Cannot promote to same or higher level than promoter
	if promoter.AdminLevel != nil && targetLevel.IsHigherOrEqual(*promoter.AdminLevel) {
		// Exception: System admins can promote to system admin
		if !promoter.IsSystemAdmin() || targetLevel != AdminLevelSystemAdmin {
			return h.logViolation(ctx, "invalid_promotion_level", promoterID, targetUserID, map[string]interface{}{
				"promoter_level": *promoter.AdminLevel,
				"target_level":   targetLevel,
			})
		}
	}

	// Rule 3: Validate specific promotion permissions
	if err := ValidateAdminPromotion(promoter, targetLevel); err != nil {
		return h.logViolation(ctx, "promotion_permission_denied", promoterID, targetUserID, map[string]interface{}{
			"promoter_level": *promoter.AdminLevel,
			"target_level":   targetLevel,
			"reason":         err.Error(),
		})
	}

	// Rule 4: Cannot promote already higher-level admin
	if targetUser.IsAdmin() && targetUser.AdminLevel != nil {
		if targetLevel.IsHigherOrEqual(*targetUser.AdminLevel) {
			// Allow same-level capability updates
			if targetLevel != *targetUser.AdminLevel {
				return h.logViolation(ctx, "invalid_admin_promotion", promoterID, targetUserID, map[string]interface{}{
					"current_level": *targetUser.AdminLevel,
					"target_level":  targetLevel,
				})
			}
		}
	}

	// Rule 5: Check promotion limits (e.g., max number of system admins)
	if err := h.checkPromotionLimits(ctx, targetLevel); err != nil {
		return err
	}

	return nil
}

// EnforceDemotionRules enforces rules for admin demotion
func (h *HierarchyEnforcer) EnforceDemotionRules(ctx context.Context, demotingUserID uuid.UUID, targetAdminID uuid.UUID, newLevel *AdminLevel) error {
	// Get demoting user
	demotingUser, err := h.repo.GetUserByID(ctx, demotingUserID)
	if err != nil {
		return errors.Wrap(err, "failed to get demoting user")
	}

	// Get target admin
	targetAdmin, err := h.repo.GetUserByID(ctx, targetAdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Rule 1: Only admins can demote
	if !demotingUser.IsAdmin() {
		return h.logViolation(ctx, "non_admin_demotion_attempt", demotingUserID, targetAdminID, map[string]interface{}{
			"demoting_user_level": "none",
		})
	}

	// Rule 2: Cannot demote higher or equal level admin (except self-demotion with restrictions)
	if targetAdmin.AdminLevel != nil && demotingUser.AdminLevel != nil {
		if demotingUserID != targetAdminID && !demotingUser.AdminLevel.IsHigherThan(*targetAdmin.AdminLevel) {
			return h.logViolation(ctx, "insufficient_demotion_authority", demotingUserID, targetAdminID, map[string]interface{}{
				"demoting_user_level": *demotingUser.AdminLevel,
				"target_admin_level":  *targetAdmin.AdminLevel,
			})
		}
	}

	// Rule 3: System admin self-demotion restrictions
	if demotingUserID == targetAdminID && targetAdmin.IsSystemAdmin() {
		// Check if there are other system admins
		systemAdmins, err := h.getSystemAdminCount(ctx)
		if err != nil {
			return err
		}

		if systemAdmins <= 1 {
			return h.logViolation(ctx, "last_system_admin_demotion", demotingUserID, targetAdminID, map[string]interface{}{
				"system_admin_count": systemAdmins,
			})
		}
	}

	// Rule 4: Validate new level is lower than current
	if newLevel != nil && targetAdmin.AdminLevel != nil {
		if !targetAdmin.AdminLevel.IsHigherThan(*newLevel) {
			return h.logViolation(ctx, "invalid_demotion_level", demotingUserID, targetAdminID, map[string]interface{}{
				"current_level": *targetAdmin.AdminLevel,
				"new_level":     *newLevel,
			})
		}
	}

	return nil
}

// EnforceCapabilityRules enforces rules for capability modifications
func (h *HierarchyEnforcer) EnforceCapabilityRules(ctx context.Context, granterID uuid.UUID, targetAdminID uuid.UUID, newCapabilities *AdminCapabilities) error {
	// Get granter
	granter, err := h.repo.GetUserByID(ctx, granterID)
	if err != nil {
		return errors.Wrap(err, "failed to get granter")
	}

	// Get target admin
	targetAdmin, err := h.repo.GetUserByID(ctx, targetAdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Rule 1: Only admins can modify capabilities
	if !granter.IsAdmin() {
		return h.logViolation(ctx, "non_admin_capability_modification", granterID, targetAdminID, nil)
	}

	// Rule 2: Cannot grant capabilities you don't have (except system admin)
	if !granter.IsSystemAdmin() {
		if err := h.validateCapabilityGrant(granter.Capabilities, newCapabilities); err != nil {
			return h.logViolation(ctx, "invalid_capability_grant", granterID, targetAdminID, map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Rule 3: Cannot modify capabilities of higher-level admin
	if targetAdmin.AdminLevel != nil && granter.AdminLevel != nil {
		if !granter.AdminLevel.IsHigherThan(*targetAdmin.AdminLevel) && granterID != targetAdminID {
			return h.logViolation(ctx, "insufficient_capability_authority", granterID, targetAdminID, map[string]interface{}{
				"granter_level": *granter.AdminLevel,
				"target_level":  *targetAdmin.AdminLevel,
			})
		}
	}

	return nil
}

// EnforceTableAssignmentRules enforces rules for table assignments
func (h *HierarchyEnforcer) EnforceTableAssignmentRules(ctx context.Context, assignerID uuid.UUID, targetAdminID uuid.UUID, tables []string) error {
	// Get assigner
	assigner, err := h.repo.GetUserByID(ctx, assignerID)
	if err != nil {
		return errors.Wrap(err, "failed to get assigner")
	}

	// Get target admin
	targetAdmin, err := h.repo.GetUserByID(ctx, targetAdminID)
	if err != nil {
		return errors.Wrap(err, "failed to get target admin")
	}

	// Rule 1: Only admins can assign tables
	if !assigner.IsAdmin() {
		return h.logViolation(ctx, "non_admin_table_assignment", assignerID, targetAdminID, nil)
	}

	// Rule 2: Cannot assign tables to higher-level admin
	if targetAdmin.AdminLevel != nil && assigner.AdminLevel != nil {
		if !assigner.AdminLevel.IsHigherThan(*targetAdmin.AdminLevel) && assignerID != targetAdminID {
			return h.logViolation(ctx, "insufficient_table_assignment_authority", assignerID, targetAdminID, map[string]interface{}{
				"assigner_level": *assigner.AdminLevel,
				"target_level":   *targetAdmin.AdminLevel,
			})
		}
	}

	// Rule 3: Super admins and system admins don't need table assignments
	if targetAdmin.IsSuperAdmin() {
		return h.logViolation(ctx, "unnecessary_table_assignment", assignerID, targetAdminID, map[string]interface{}{
			"target_level": *targetAdmin.AdminLevel,
		})
	}

	// Rule 4: Validate table access permissions for assigner
	if !assigner.IsSuperAdmin() {
		for _, table := range tables {
			if !assigner.CanAccessTable(table) {
				return h.logViolation(ctx, "unauthorized_table_assignment", assignerID, targetAdminID, map[string]interface{}{
					"table": table,
				})
			}
		}
	}

	return nil
}

// EnforceEmergencyAccessRules enforces rules for emergency access creation
func (h *HierarchyEnforcer) EnforceEmergencyAccessRules(ctx context.Context, creatorID uuid.UUID, req *EmergencyAccessRequest) error {
	// Get creator
	creator, err := h.repo.GetUserByID(ctx, creatorID)
	if err != nil {
		return errors.Wrap(err, "failed to get creator")
	}

	// Rule 1: Only system admins can create emergency access
	if !creator.IsSystemAdmin() {
		return h.logViolation(ctx, "unauthorized_emergency_access_creation", creatorID, uuid.Nil, map[string]interface{}{
			"creator_level": creator.AdminLevel,
		})
	}

	// Rule 2: Validate duration limits
	maxDuration := 24 * time.Hour
	if req.Duration > maxDuration {
		return h.logViolation(ctx, "excessive_emergency_access_duration", creatorID, uuid.Nil, map[string]interface{}{
			"requested_duration": req.Duration.String(),
			"max_duration":       maxDuration.String(),
		})
	}

	// Rule 3: Validate admin level for emergency access
	if req.AdminLevel == AdminLevelSystemAdmin {
		// Additional validation for system admin emergency access
		return h.logViolation(ctx, "system_admin_emergency_access_denied", creatorID, uuid.Nil, map[string]interface{}{
			"requested_level": req.AdminLevel,
		})
	}

	// Rule 4: Check for existing active emergency access
	activeAccess, err := h.getActiveEmergencyAccessCount(ctx)
	if err != nil {
		return err
	}

	if activeAccess >= 3 { // Max 3 concurrent emergency access
		return h.logViolation(ctx, "too_many_emergency_access", creatorID, uuid.Nil, map[string]interface{}{
			"active_count": activeAccess,
			"max_allowed":  3,
		})
	}

	return nil
}

// Helper methods

// logViolation logs a hierarchy rule violation
func (h *HierarchyEnforcer) logViolation(ctx context.Context, violationType string, actorID uuid.UUID, targetID uuid.UUID, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}

	details["violation_type"] = violationType
	details["actor_id"] = actorID.String()
	if targetID != uuid.Nil {
		details["target_id"] = targetID.String()
	}

	// Log security event
	if err := h.audit.LogSecurityEvent(ctx, &SecurityEventRequest{
		EventType: SecurityEventTypes.UnauthorizedAccess,
		UserID:    &actorID,
		Details:   details,
		Severity:  AuditSeverityHigh,
	}); err != nil {
		// Don't fail the operation if audit logging fails
		fmt.Printf("Failed to log hierarchy violation: %v\n", err)
	}

	return errors.NewAuthError(fmt.Sprintf("hierarchy rule violation: %s", violationType))
}

// checkPromotionLimits checks if promotion would exceed limits
func (h *HierarchyEnforcer) checkPromotionLimits(ctx context.Context, targetLevel AdminLevel) error {
	switch targetLevel {
	case AdminLevelSystemAdmin:
		// Check system admin limit (e.g., max 5 system admins)
		count, err := h.getAdminCountByLevel(ctx, AdminLevelSystemAdmin)
		if err != nil {
			return err
		}
		if count >= 5 {
			return errors.NewAuthError("maximum number of system admins reached")
		}
	case AdminLevelSuperAdmin:
		// Check super admin limit (e.g., max 20 super admins)
		count, err := h.getAdminCountByLevel(ctx, AdminLevelSuperAdmin)
		if err != nil {
			return err
		}
		if count >= 20 {
			return errors.NewAuthError("maximum number of super admins reached")
		}
	}

	return nil
}

// validateCapabilityGrant validates that granter can grant the requested capabilities
func (h *HierarchyEnforcer) validateCapabilityGrant(granterCaps *AdminCapabilities, newCaps *AdminCapabilities) error {
	if granterCaps == nil {
		return errors.NewAuthError("granter has no capabilities")
	}

	// Check each capability
	if newCaps.CanAccessSQL && !granterCaps.CanAccessSQL {
		return errors.NewAuthError("cannot grant SQL access capability")
	}
	if newCaps.CanManageDatabase && !granterCaps.CanManageDatabase {
		return errors.NewAuthError("cannot grant database management capability")
	}
	if newCaps.CanManageSystem && !granterCaps.CanManageSystem {
		return errors.NewAuthError("cannot grant system management capability")
	}
	if newCaps.CanCreateSuperAdmin && !granterCaps.CanCreateSuperAdmin {
		return errors.NewAuthError("cannot grant super admin creation capability")
	}
	if newCaps.CanInstallPlugins && !granterCaps.CanInstallPlugins {
		return errors.NewAuthError("cannot grant plugin installation capability")
	}
	if newCaps.CanModifySecurityConfig && !granterCaps.CanModifySecurityConfig {
		return errors.NewAuthError("cannot grant security config modification capability")
	}
	if newCaps.CanCreateAdmins && !granterCaps.CanCreateAdmins {
		return errors.NewAuthError("cannot grant admin creation capability")
	}
	if newCaps.CanManageAllTables && !granterCaps.CanManageAllTables {
		return errors.NewAuthError("cannot grant all tables management capability")
	}
	if newCaps.CanManageAuth && !granterCaps.CanManageAuth {
		return errors.NewAuthError("cannot grant auth management capability")
	}
	if newCaps.CanManageStorage && !granterCaps.CanManageStorage {
		return errors.NewAuthError("cannot grant storage management capability")
	}
	if newCaps.CanViewAllLogs && !granterCaps.CanViewAllLogs {
		return errors.NewAuthError("cannot grant all logs viewing capability")
	}
	if newCaps.CanManageTemplates && !granterCaps.CanManageTemplates {
		return errors.NewAuthError("cannot grant template management capability")
	}
	if newCaps.CanManageCronJobs && !granterCaps.CanManageCronJobs {
		return errors.NewAuthError("cannot grant cron job management capability")
	}

	return nil
}

// getSystemAdminCount returns the number of system admins
func (h *HierarchyEnforcer) getSystemAdminCount(ctx context.Context) (int, error) {
	return h.getAdminCountByLevel(ctx, AdminLevelSystemAdmin)
}

// getAdminCountByLevel returns the number of admins at a specific level
func (h *HierarchyEnforcer) getAdminCountByLevel(ctx context.Context, level AdminLevel) (int, error) {
	filter := &AdminFilter{
		Level: &level,
		Limit: 1000, // High limit to get all
	}

	admins, err := h.repo.ListAdmins(ctx, filter)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get admin count")
	}

	return len(admins), nil
}

// getActiveEmergencyAccessCount returns the number of active emergency access entries
func (h *HierarchyEnforcer) getActiveEmergencyAccessCount(ctx context.Context) (int, error) {
	active := true
	filter := &EmergencyAccessFilter{
		Active: &active,
		Limit:  100,
	}

	accessList, err := h.repo.ListEmergencyAccess(ctx, filter)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get emergency access count")
	}

	return len(accessList), nil
}
