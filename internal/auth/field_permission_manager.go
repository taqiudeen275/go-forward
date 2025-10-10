package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// FieldPermissionManagerImpl implements the FieldPermissionManager interface
type FieldPermissionManagerImpl struct {
	configService TableSecurityConfigService
	encryptionKey []byte // 32 bytes for AES-256
}

// NewFieldPermissionManager creates a new field permission manager
func NewFieldPermissionManager(configService TableSecurityConfigService, encryptionKey []byte) *FieldPermissionManagerImpl {
	return &FieldPermissionManagerImpl{
		configService: configService,
		encryptionKey: encryptionKey,
	}
}

// GetReadableFields returns fields that the user can read based on their roles
func (f *FieldPermissionManagerImpl) GetReadableFields(tableName, schemaName string, userRoles []string) ([]string, error) {
	config, err := f.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return nil, fmt.Errorf("failed to get security config: %w", err)
	}

	// If no field restrictions, return empty slice (meaning all fields are readable)
	if len(config.ReadableFields) == 0 {
		return []string{}, nil
	}

	// Check role-based access to readable fields
	readableFields := []string{}
	for _, field := range config.ReadableFields {
		if f.hasFieldAccess(field, userRoles, "read") {
			readableFields = append(readableFields, field)
		}
	}

	return readableFields, nil
}

// GetWritableFields returns fields that the user can write based on their roles
func (f *FieldPermissionManagerImpl) GetWritableFields(tableName, schemaName string, userRoles []string) ([]string, error) {
	config, err := f.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return nil, fmt.Errorf("failed to get security config: %w", err)
	}

	// If no field restrictions, return empty slice (meaning all fields are writable)
	if len(config.WritableFields) == 0 {
		return []string{}, nil
	}

	// Check role-based access to writable fields
	writableFields := []string{}
	for _, field := range config.WritableFields {
		if f.hasFieldAccess(field, userRoles, "write") {
			writableFields = append(writableFields, field)
		}
	}

	return writableFields, nil
}

// GetHiddenFields returns fields that should be hidden from the user
func (f *FieldPermissionManagerImpl) GetHiddenFields(tableName, schemaName string, userRoles []string) ([]string, error) {
	config, err := f.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return nil, fmt.Errorf("failed to get security config: %w", err)
	}

	// Always hide these fields regardless of configuration
	alwaysHidden := []string{"password_hash", "secret", "private_key", "api_key_hash"}
	hiddenFields := make([]string, len(alwaysHidden))
	copy(hiddenFields, alwaysHidden)

	// Add configured hidden fields
	for _, field := range config.HiddenFields {
		if !f.hasFieldAccess(field, userRoles, "read") {
			hiddenFields = append(hiddenFields, field)
		}
	}

	return hiddenFields, nil
}

// MaskPIIFields masks personally identifiable information based on user roles
func (f *FieldPermissionManagerImpl) MaskPIIFields(tableName, schemaName string, data map[string]interface{}, userRoles []string) (map[string]interface{}, error) {
	// Define PII fields that should be masked
	piiFields := map[string]string{
		"email":         "email",
		"phone":         "phone",
		"ssn":           "ssn",
		"credit_card":   "credit_card",
		"address":       "address",
		"full_name":     "name",
		"first_name":    "name",
		"last_name":     "name",
		"date_of_birth": "date",
		"ip_address":    "ip",
	}

	maskedData := make(map[string]interface{})
	for key, value := range data {
		// Check if field is PII and user doesn't have admin privileges
		if piiType, isPII := piiFields[strings.ToLower(key)]; isPII && !f.hasAdminRole(userRoles) {
			maskedData[key] = f.maskValue(value, piiType)
		} else {
			maskedData[key] = value
		}
	}

	return maskedData, nil
}

// EncryptSensitiveFields encrypts sensitive fields before storage
func (f *FieldPermissionManagerImpl) EncryptSensitiveFields(tableName, schemaName string, data map[string]interface{}) (map[string]interface{}, error) {
	// Define fields that should be encrypted
	sensitiveFields := []string{
		"password", "secret", "private_key", "api_key", "token",
		"ssn", "credit_card", "bank_account", "passport_number",
	}

	encryptedData := make(map[string]interface{})
	for key, value := range data {
		if f.isSensitiveField(key, sensitiveFields) {
			if strValue, ok := value.(string); ok && strValue != "" {
				encrypted, err := f.encryptValue(strValue)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt field %s: %w", key, err)
				}
				encryptedData[key] = encrypted
			} else {
				encryptedData[key] = value
			}
		} else {
			encryptedData[key] = value
		}
	}

	return encryptedData, nil
}

// DecryptSensitiveFields decrypts sensitive fields for authorized users
func (f *FieldPermissionManagerImpl) DecryptSensitiveFields(tableName, schemaName string, data map[string]interface{}, userRoles []string) (map[string]interface{}, error) {
	// Only decrypt for admin users
	if !f.hasAdminRole(userRoles) {
		return data, nil
	}

	// Define fields that might be encrypted
	sensitiveFields := []string{
		"password", "secret", "private_key", "api_key", "token",
		"ssn", "credit_card", "bank_account", "passport_number",
	}

	decryptedData := make(map[string]interface{})
	for key, value := range data {
		if f.isSensitiveField(key, sensitiveFields) {
			if strValue, ok := value.(string); ok && strValue != "" {
				// Check if value looks encrypted (base64 encoded)
				if f.looksEncrypted(strValue) {
					decrypted, err := f.decryptValue(strValue)
					if err != nil {
						// If decryption fails, return original value
						decryptedData[key] = value
					} else {
						decryptedData[key] = decrypted
					}
				} else {
					decryptedData[key] = value
				}
			} else {
				decryptedData[key] = value
			}
		} else {
			decryptedData[key] = value
		}
	}

	return decryptedData, nil
}

// EvaluateFieldPermission evaluates if a user has permission for a specific field operation
func (f *FieldPermissionManagerImpl) EvaluateFieldPermission(tableName, schemaName, fieldName string, operation string, userContext *APISecurityContext) (bool, error) {
	config, err := f.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return false, fmt.Errorf("failed to get security config: %w", err)
	}

	// System and Super admins have access to all fields
	if userContext.AdminLevel == SystemAdmin || userContext.AdminLevel == SuperAdmin {
		return true, nil
	}

	// Get table security configuration to check field permissions
	tableConfig, err := f.configService.GetTableSecurityConfig(tableName, schemaName)
	if err != nil {
		// If no specific config, use default behavior
		return f.evaluateDefaultFieldPermission(fieldName, operation, userContext)
	}

	// Check field-level permissions from table configuration
	if fieldPerm, exists := tableConfig.FieldPermissions[fieldName]; exists {
		return f.evaluateFieldPermissionRule(fieldPerm, operation, userContext)
	}

	// Fall back to API config field lists
	switch operation {
	case "read":
		// Check if field is explicitly readable
		if len(config.ReadableFields) > 0 {
			return f.containsField(config.ReadableFields, fieldName), nil
		}
		// Check if field is hidden
		if len(config.HiddenFields) > 0 {
			return !f.containsField(config.HiddenFields, fieldName), nil
		}
		// Check if field is always hidden (security fields)
		if f.isAlwaysHiddenField(fieldName) && !f.hasAdminRole(userContext.UserRoles) {
			return false, nil
		}
		// Default: allow read if no restrictions
		return true, nil

	case "write":
		// Check if field is explicitly writable
		if len(config.WritableFields) > 0 {
			return f.containsField(config.WritableFields, fieldName), nil
		}
		// Check if field is read-only (system fields)
		if f.isReadOnlyField(fieldName) {
			return false, nil
		}
		// Regular admins can write to assigned tables
		if userContext.AdminLevel == RegularAdmin && userContext.Capabilities.CanManageUsers {
			return f.isUserManageableField(fieldName), nil
		}
		// Default: deny write if no explicit permission
		return false, nil

	default:
		return false, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// evaluateFieldPermissionRule evaluates a specific field permission rule
func (f *FieldPermissionManagerImpl) evaluateFieldPermissionRule(fieldPerm FieldPermission, operation string, userContext *APISecurityContext) (bool, error) {
	switch operation {
	case "read":
		if !fieldPerm.Read {
			return false, nil
		}
	case "write":
		if !fieldPerm.Write {
			return false, nil
		}
	default:
		return false, fmt.Errorf("unsupported operation: %s", operation)
	}

	// Check role requirements
	if len(fieldPerm.Roles) > 0 {
		hasRequiredRole := false
		for _, userRole := range userContext.UserRoles {
			for _, requiredRole := range fieldPerm.Roles {
				if strings.EqualFold(userRole, requiredRole) {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}
		if !hasRequiredRole {
			return false, nil
		}
	}

	// Evaluate condition if specified
	if fieldPerm.Condition != "" {
		return f.evaluateFieldCondition(fieldPerm.Condition, userContext)
	}

	return true, nil
}

// evaluateFieldCondition evaluates a field permission condition
func (f *FieldPermissionManagerImpl) evaluateFieldCondition(condition string, userContext *APISecurityContext) (bool, error) {
	// Replace placeholders in condition
	processedCondition := f.processConditionPlaceholders(condition, userContext)

	// Simple condition evaluation (in production, use a proper expression evaluator)
	switch {
	case strings.Contains(processedCondition, "admin_level"):
		return f.evaluateAdminLevelCondition(processedCondition, userContext.AdminLevel)
	case strings.Contains(processedCondition, "user_id"):
		return f.evaluateUserCondition(processedCondition, userContext.UserID)
	case strings.Contains(processedCondition, "mfa_verified"):
		return f.evaluateMFACondition(processedCondition, userContext.MFAVerified)
	case strings.Contains(processedCondition, "ip_address"):
		return f.evaluateIPCondition(processedCondition, userContext.IPAddress)
	default:
		// Default to true for unknown conditions (fail open for flexibility)
		return true, nil
	}
}

// processConditionPlaceholders replaces placeholders in conditions
func (f *FieldPermissionManagerImpl) processConditionPlaceholders(condition string, userContext *APISecurityContext) string {
	processed := condition
	processed = strings.ReplaceAll(processed, "{user_id}", userContext.UserID)
	processed = strings.ReplaceAll(processed, "{admin_level}", string(userContext.AdminLevel))
	processed = strings.ReplaceAll(processed, "{mfa_verified}", fmt.Sprintf("%t", userContext.MFAVerified))
	processed = strings.ReplaceAll(processed, "{ip_address}", userContext.IPAddress)

	if len(userContext.UserRoles) > 0 {
		rolesStr := "'" + strings.Join(userContext.UserRoles, "','") + "'"
		processed = strings.ReplaceAll(processed, "{user_roles}", rolesStr)
	}

	return processed
}

// evaluateDefaultFieldPermission provides default field permission logic
func (f *FieldPermissionManagerImpl) evaluateDefaultFieldPermission(fieldName, operation string, userContext *APISecurityContext) (bool, error) {
	switch operation {
	case "read":
		// Always hidden fields
		if f.isAlwaysHiddenField(fieldName) && !f.hasAdminRole(userContext.UserRoles) {
			return false, nil
		}
		// PII fields require admin or owner access
		if f.isPIIField(fieldName) && !f.hasAdminRole(userContext.UserRoles) {
			// Could add ownership check here
			return false, nil
		}
		return true, nil

	case "write":
		// Read-only system fields
		if f.isReadOnlyField(fieldName) {
			return false, nil
		}
		// Sensitive fields require admin access
		if f.isSensitiveField(fieldName, []string{"password", "secret", "key", "token"}) {
			return f.hasAdminRole(userContext.UserRoles), nil
		}
		// Regular users can write to basic fields
		return true, nil

	default:
		return false, fmt.Errorf("unsupported operation: %s", operation)
	}
}

// isAlwaysHiddenField checks if a field should always be hidden from non-admins
func (f *FieldPermissionManagerImpl) isAlwaysHiddenField(fieldName string) bool {
	alwaysHidden := []string{
		"password_hash", "password", "secret", "private_key", "api_key", "api_key_hash",
		"token", "refresh_token", "reset_token", "verification_token",
		"salt", "hash", "encrypted_", "internal_",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, hidden := range alwaysHidden {
		if strings.Contains(fieldLower, hidden) {
			return true
		}
	}
	return false
}

// isReadOnlyField checks if a field is read-only (system managed)
func (f *FieldPermissionManagerImpl) isReadOnlyField(fieldName string) bool {
	readOnlyFields := []string{
		"id", "created_at", "updated_at", "deleted_at",
		"created_by", "updated_by", "deleted_by",
		"version", "revision", "last_login", "login_count",
		"email_verified_at", "phone_verified_at",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, readOnly := range readOnlyFields {
		if fieldLower == readOnly {
			return true
		}
	}
	return false
}

// isPIIField checks if a field contains personally identifiable information
func (f *FieldPermissionManagerImpl) isPIIField(fieldName string) bool {
	piiFields := []string{
		"email", "phone", "ssn", "social_security", "passport",
		"driver_license", "credit_card", "bank_account",
		"address", "street", "city", "zip", "postal",
		"first_name", "last_name", "full_name", "name",
		"date_of_birth", "birth_date", "dob",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, pii := range piiFields {
		if strings.Contains(fieldLower, pii) {
			return true
		}
	}
	return false
}

// isUserManageableField checks if a field can be managed by regular admins
func (f *FieldPermissionManagerImpl) isUserManageableField(fieldName string) bool {
	manageableFields := []string{
		"email", "phone", "username", "first_name", "last_name",
		"display_name", "bio", "avatar", "status", "role",
		"email_verified", "phone_verified", "active", "enabled",
	}

	fieldLower := strings.ToLower(fieldName)
	for _, manageable := range manageableFields {
		if fieldLower == manageable {
			return true
		}
	}
	return false
}

// Condition evaluation helpers

func (f *FieldPermissionManagerImpl) evaluateAdminLevelCondition(condition string, adminLevel AdminLevel) (bool, error) {
	// Simple admin level comparison
	if strings.Contains(condition, ">=") {
		// Extract level from condition and compare
		return true, nil // Simplified for now
	}
	return true, nil
}

func (f *FieldPermissionManagerImpl) evaluateUserCondition(condition string, userID string) (bool, error) {
	// User-specific conditions
	return userID != "", nil
}

func (f *FieldPermissionManagerImpl) evaluateMFACondition(condition string, mfaVerified bool) (bool, error) {
	// MFA-related conditions
	if strings.Contains(condition, "mfa_verified = true") {
		return mfaVerified, nil
	}
	return true, nil
}

func (f *FieldPermissionManagerImpl) evaluateIPCondition(condition string, ipAddress string) (bool, error) {
	// IP-based conditions (simplified)
	return ipAddress != "", nil
}

// hasFieldAccess checks if user roles have access to a specific field
func (f *FieldPermissionManagerImpl) hasFieldAccess(fieldName string, userRoles []string, operation string) bool {
	// This is a simplified implementation
	// In a full implementation, you would have field-level role mappings

	// Admin roles have access to all fields
	for _, role := range userRoles {
		if f.isAdminRole(role) {
			return true
		}
	}

	// For non-admin users, implement field-specific logic
	// This could be extended to check field-specific role mappings
	return true // Default allow for now
}

// hasAdminRole checks if user has any admin role
func (f *FieldPermissionManagerImpl) hasAdminRole(userRoles []string) bool {
	for _, role := range userRoles {
		if f.isAdminRole(role) {
			return true
		}
	}
	return false
}

// isAdminRole checks if a role is an admin role
func (f *FieldPermissionManagerImpl) isAdminRole(role string) bool {
	adminRoles := []string{"System Admin", "Super Admin", "Regular Admin"}
	for _, adminRole := range adminRoles {
		if strings.EqualFold(role, adminRole) {
			return true
		}
	}
	return false
}

// isSensitiveField checks if a field is considered sensitive
func (f *FieldPermissionManagerImpl) isSensitiveField(fieldName string, sensitiveFields []string) bool {
	fieldLower := strings.ToLower(fieldName)
	for _, sensitive := range sensitiveFields {
		if strings.Contains(fieldLower, strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}

// containsField checks if a field is in a list of fields
func (f *FieldPermissionManagerImpl) containsField(fields []string, fieldName string) bool {
	for _, field := range fields {
		if strings.EqualFold(field, fieldName) {
			return true
		}
	}
	return false
}

// maskValue masks a value based on its type
func (f *FieldPermissionManagerImpl) maskValue(value interface{}, valueType string) interface{} {
	strValue, ok := value.(string)
	if !ok || strValue == "" {
		return value
	}

	switch valueType {
	case "email":
		return f.maskEmail(strValue)
	case "phone":
		return f.maskPhone(strValue)
	case "ssn":
		return f.maskSSN(strValue)
	case "credit_card":
		return f.maskCreditCard(strValue)
	case "name":
		return f.maskName(strValue)
	case "address":
		return f.maskAddress(strValue)
	case "ip":
		return f.maskIP(strValue)
	case "date":
		return f.maskDate(strValue)
	default:
		return f.maskGeneric(strValue)
	}
}

// maskEmail masks an email address
func (f *FieldPermissionManagerImpl) maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return f.maskGeneric(email)
	}

	username := parts[0]
	domain := parts[1]

	if len(username) <= 2 {
		return "**@" + domain
	}

	return username[:1] + strings.Repeat("*", len(username)-2) + username[len(username)-1:] + "@" + domain
}

// maskPhone masks a phone number
func (f *FieldPermissionManagerImpl) maskPhone(phone string) string {
	// Remove non-digit characters for processing
	digits := regexp.MustCompile(`\D`).ReplaceAllString(phone, "")
	if len(digits) < 4 {
		return strings.Repeat("*", len(phone))
	}

	// Keep last 4 digits
	masked := strings.Repeat("*", len(digits)-4) + digits[len(digits)-4:]

	// Try to preserve original formatting
	result := phone
	digitIndex := 0
	for i, char := range phone {
		if char >= '0' && char <= '9' {
			if digitIndex < len(masked) {
				result = result[:i] + string(masked[digitIndex]) + result[i+1:]
				digitIndex++
			}
		}
	}

	return result
}

// maskSSN masks a social security number
func (f *FieldPermissionManagerImpl) maskSSN(ssn string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(ssn, "")
	if len(digits) != 9 {
		return strings.Repeat("*", len(ssn))
	}
	return "***-**-" + digits[5:]
}

// maskCreditCard masks a credit card number
func (f *FieldPermissionManagerImpl) maskCreditCard(cc string) string {
	digits := regexp.MustCompile(`\D`).ReplaceAllString(cc, "")
	if len(digits) < 4 {
		return strings.Repeat("*", len(cc))
	}
	return "**** **** **** " + digits[len(digits)-4:]
}

// maskName masks a name
func (f *FieldPermissionManagerImpl) maskName(name string) string {
	parts := strings.Fields(name)
	if len(parts) == 0 {
		return name
	}

	masked := make([]string, len(parts))
	for i, part := range parts {
		if len(part) <= 1 {
			masked[i] = "*"
		} else {
			masked[i] = part[:1] + strings.Repeat("*", len(part)-1)
		}
	}

	return strings.Join(masked, " ")
}

// maskAddress masks an address
func (f *FieldPermissionManagerImpl) maskAddress(address string) string {
	// Simple masking - replace middle portion with asterisks
	if len(address) <= 10 {
		return strings.Repeat("*", len(address))
	}
	return address[:3] + strings.Repeat("*", len(address)-6) + address[len(address)-3:]
}

// maskIP masks an IP address
func (f *FieldPermissionManagerImpl) maskIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + ".***.***.***"
	}
	// IPv6 or other format
	if len(ip) > 8 {
		return ip[:4] + strings.Repeat("*", len(ip)-8) + ip[len(ip)-4:]
	}
	return strings.Repeat("*", len(ip))
}

// maskDate masks a date
func (f *FieldPermissionManagerImpl) maskDate(date string) string {
	// Keep year, mask month and day
	if len(date) >= 4 {
		return "**/**/****"
	}
	return strings.Repeat("*", len(date))
}

// maskGeneric provides generic masking for unknown types
func (f *FieldPermissionManagerImpl) maskGeneric(value string) string {
	if len(value) <= 2 {
		return strings.Repeat("*", len(value))
	}
	return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
}

// encryptValue encrypts a string value using AES-256-GCM
func (f *FieldPermissionManagerImpl) encryptValue(plaintext string) (string, error) {
	if len(f.encryptionKey) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(f.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptValue decrypts a string value using AES-256-GCM
func (f *FieldPermissionManagerImpl) decryptValue(ciphertext string) (string, error) {
	if len(f.encryptionKey) != 32 {
		return "", fmt.Errorf("encryption key must be 32 bytes for AES-256")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(f.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_bytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_bytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// looksEncrypted checks if a string looks like it might be encrypted (base64 encoded)
func (f *FieldPermissionManagerImpl) looksEncrypted(value string) bool {
	// Check if it's valid base64 and has reasonable length for encrypted data
	if len(value) < 16 { // Too short to be encrypted
		return false
	}

	_, err := base64.StdEncoding.DecodeString(value)
	return err == nil
}

// FilterFieldsByPermission filters a data map to only include fields the user can access
func (f *FieldPermissionManagerImpl) FilterFieldsByPermission(tableName, schemaName string, data map[string]interface{}, userRoles []string, operation string) (map[string]interface{}, error) {
	var allowedFields []string
	var err error

	switch operation {
	case "read":
		allowedFields, err = f.GetReadableFields(tableName, schemaName, userRoles)
	case "write":
		allowedFields, err = f.GetWritableFields(tableName, schemaName, userRoles)
	default:
		return nil, fmt.Errorf("unsupported operation: %s", operation)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get allowed fields: %w", err)
	}

	// If no restrictions, return all data
	if len(allowedFields) == 0 {
		return data, nil
	}

	// Filter data to only include allowed fields
	filteredData := make(map[string]interface{})
	allowedFieldsMap := make(map[string]bool)
	for _, field := range allowedFields {
		allowedFieldsMap[field] = true
	}

	for key, value := range data {
		if allowedFieldsMap[key] {
			filteredData[key] = value
		}
	}

	return filteredData, nil
}

// ValidateFieldPermissions validates that a user has permission to access specific fields
func (f *FieldPermissionManagerImpl) ValidateFieldPermissions(tableName, schemaName string, fields []string, userRoles []string, operation string) error {
	for _, field := range fields {
		hasPermission := f.hasFieldAccess(field, userRoles, operation)
		if !hasPermission {
			return fmt.Errorf("insufficient permission for field '%s' operation '%s'", field, operation)
		}
	}
	return nil
}

// ApplyFieldLevelSecurity applies comprehensive field-level security to data
func (f *FieldPermissionManagerImpl) ApplyFieldLevelSecurity(tableName, schemaName string, data map[string]interface{}, userContext *APISecurityContext, operation string) (map[string]interface{}, error) {
	// Step 1: Filter fields based on permissions
	filteredData, err := f.FilterFieldsByPermission(tableName, schemaName, data, userContext.UserRoles, operation)
	if err != nil {
		return nil, fmt.Errorf("failed to filter fields: %w", err)
	}

	// Step 2: Apply PII masking for read operations
	if operation == "read" {
		maskedData, err := f.MaskPIIFields(tableName, schemaName, filteredData, userContext.UserRoles)
		if err != nil {
			return nil, fmt.Errorf("failed to mask PII fields: %w", err)
		}
		filteredData = maskedData
	}

	// Step 3: Decrypt sensitive fields for authorized users
	if operation == "read" && f.hasAdminRole(userContext.UserRoles) {
		decryptedData, err := f.DecryptSensitiveFields(tableName, schemaName, filteredData, userContext.UserRoles)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt sensitive fields: %w", err)
		}
		filteredData = decryptedData
	}

	// Step 4: Encrypt sensitive fields for write operations
	if operation == "write" {
		encryptedData, err := f.EncryptSensitiveFields(tableName, schemaName, filteredData)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt sensitive fields: %w", err)
		}
		filteredData = encryptedData
	}

	return filteredData, nil
}

// GetFieldSecurityMetadata returns metadata about field-level security for a table
func (f *FieldPermissionManagerImpl) GetFieldSecurityMetadata(tableName, schemaName string, userContext *APISecurityContext) (*FieldSecurityMetadata, error) {
	config, err := f.configService.GetSecurityConfigForTable(tableName, schemaName)
	if err != nil {
		return nil, fmt.Errorf("failed to get security config: %w", err)
	}

	metadata := &FieldSecurityMetadata{
		TableName:  tableName,
		SchemaName: schemaName,
		UserID:     userContext.UserID,
		AdminLevel: userContext.AdminLevel,
		Fields:     make(map[string]*FieldMetadata),
	}

	// Get all fields from configuration
	allFields := make(map[string]bool)
	for _, field := range config.ReadableFields {
		allFields[field] = true
	}
	for _, field := range config.WritableFields {
		allFields[field] = true
	}
	for _, field := range config.HiddenFields {
		allFields[field] = true
	}

	// Add field permissions from table config
	tableConfig, err := f.configService.GetTableSecurityConfig(tableName, schemaName)
	if err == nil {
		for fieldName := range tableConfig.FieldPermissions {
			allFields[fieldName] = true
		}
	}

	// Evaluate permissions for each field
	for fieldName := range allFields {
		canRead, _ := f.EvaluateFieldPermission(tableName, schemaName, fieldName, "read", userContext)
		canWrite, _ := f.EvaluateFieldPermission(tableName, schemaName, fieldName, "write", userContext)

		metadata.Fields[fieldName] = &FieldMetadata{
			Name:         fieldName,
			CanRead:      canRead,
			CanWrite:     canWrite,
			IsPII:        f.isPIIField(fieldName),
			IsSensitive:  f.isSensitiveField(fieldName, []string{"password", "secret", "key", "token"}),
			IsReadOnly:   f.isReadOnlyField(fieldName),
			RequiresMask: f.isPIIField(fieldName) && !f.hasAdminRole(userContext.UserRoles),
		}
	}

	return metadata, nil
}

// ValidateFieldAccess validates field access for a batch of operations
func (f *FieldPermissionManagerImpl) ValidateFieldAccess(tableName, schemaName string, fieldOperations []FieldOperation, userContext *APISecurityContext) (*FieldAccessValidationResult, error) {
	result := &FieldAccessValidationResult{
		Valid:      true,
		Violations: []FieldAccessViolation{},
		Warnings:   []string{},
	}

	for _, op := range fieldOperations {
		allowed, err := f.EvaluateFieldPermission(tableName, schemaName, op.FieldName, op.Operation, userContext)
		if err != nil {
			result.Valid = false
			result.Violations = append(result.Violations, FieldAccessViolation{
				FieldName: op.FieldName,
				Operation: op.Operation,
				Reason:    fmt.Sprintf("Evaluation error: %v", err),
				Severity:  "ERROR",
			})
			continue
		}

		if !allowed {
			result.Valid = false
			result.Violations = append(result.Violations, FieldAccessViolation{
				FieldName: op.FieldName,
				Operation: op.Operation,
				Reason:    "Insufficient permissions",
				Severity:  "DENIED",
			})
		}

		// Add warnings for sensitive operations
		if allowed && f.isSensitiveField(op.FieldName, []string{"password", "secret", "key"}) {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Accessing sensitive field '%s' - ensure proper audit logging", op.FieldName))
		}
	}

	return result, nil
}

// CreateFieldPermissionRule creates a new field permission rule
func (f *FieldPermissionManagerImpl) CreateFieldPermissionRule(tableName, schemaName, fieldName string, permission FieldPermission) error {
	// This would typically update the table configuration
	// For now, we'll validate the permission rule
	if fieldName == "" {
		return fmt.Errorf("field name cannot be empty")
	}

	// Validate roles
	for _, role := range permission.Roles {
		if role == "" {
			return fmt.Errorf("role name cannot be empty")
		}
	}

	// Validate condition syntax
	if permission.Condition != "" {
		if err := f.validateConditionSyntax(permission.Condition); err != nil {
			return fmt.Errorf("invalid condition syntax: %w", err)
		}
	}

	// In a real implementation, this would save to the database
	return nil
}

// validateConditionSyntax validates field permission condition syntax
func (f *FieldPermissionManagerImpl) validateConditionSyntax(condition string) error {
	// Basic validation for security
	if condition == "" {
		return fmt.Errorf("condition cannot be empty")
	}

	// Check for dangerous patterns
	dangerousPatterns := []string{
		"DROP", "DELETE", "INSERT", "UPDATE", "ALTER", "CREATE",
		"--", "/*", "*/", ";", "EXEC", "EXECUTE",
	}

	upperCondition := strings.ToUpper(condition)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(upperCondition, pattern) {
			return fmt.Errorf("condition contains potentially dangerous pattern: %s", pattern)
		}
	}

	// Validate placeholder usage
	validPlaceholders := []string{
		"{user_id}", "{admin_level}", "{mfa_verified}",
		"{ip_address}", "{user_roles}",
	}

	// Check that only valid placeholders are used
	for _, placeholder := range validPlaceholders {
		if strings.Contains(condition, placeholder) {
			// Valid placeholder found
			continue
		}
	}

	return nil
}

// Data structures for field security metadata

// FieldSecurityMetadata represents security metadata for table fields
type FieldSecurityMetadata struct {
	TableName  string                    `json:"table_name"`
	SchemaName string                    `json:"schema_name"`
	UserID     string                    `json:"user_id"`
	AdminLevel AdminLevel                `json:"admin_level"`
	Fields     map[string]*FieldMetadata `json:"fields"`
}

// FieldMetadata represents metadata for a single field
type FieldMetadata struct {
	Name         string `json:"name"`
	CanRead      bool   `json:"can_read"`
	CanWrite     bool   `json:"can_write"`
	IsPII        bool   `json:"is_pii"`
	IsSensitive  bool   `json:"is_sensitive"`
	IsReadOnly   bool   `json:"is_read_only"`
	RequiresMask bool   `json:"requires_mask"`
}

// FieldOperation represents a field operation for validation
type FieldOperation struct {
	FieldName string `json:"field_name"`
	Operation string `json:"operation"` // "read" or "write"
}

// FieldAccessValidationResult represents the result of field access validation
type FieldAccessValidationResult struct {
	Valid      bool                   `json:"valid"`
	Violations []FieldAccessViolation `json:"violations"`
	Warnings   []string               `json:"warnings"`
}

// FieldAccessViolation represents a field access violation
type FieldAccessViolation struct {
	FieldName string `json:"field_name"`
	Operation string `json:"operation"`
	Reason    string `json:"reason"`
	Severity  string `json:"severity"` // "ERROR", "DENIED", "WARNING"
}
