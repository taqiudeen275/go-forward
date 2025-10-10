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

	// Admin users have access to all fields
	if userContext.AdminLevel <= SuperAdmin {
		return true, nil
	}

	switch operation {
	case "read":
		// Check if field is in readable fields list
		if len(config.ReadableFields) > 0 {
			return f.containsField(config.ReadableFields, fieldName), nil
		}
		// Check if field is in hidden fields list
		if len(config.HiddenFields) > 0 {
			return !f.containsField(config.HiddenFields, fieldName), nil
		}
		// Default: allow read if no restrictions
		return true, nil

	case "write":
		// Check if field is in writable fields list
		if len(config.WritableFields) > 0 {
			return f.containsField(config.WritableFields, fieldName), nil
		}
		// Default: deny write if no explicit permission
		return false, nil

	default:
		return false, fmt.Errorf("unsupported operation: %s", operation)
	}
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
